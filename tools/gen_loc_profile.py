#!/usr/bin/env python3
"""Check reviewed AArch64 LOC artifacts and emit a compile-time SHA/minor pin.

Reads ELF bytes only, with no dlopen, disassembler subprocess, device, or network.
An allowlist entry is required even if a previously unreviewed artifact appears
to use the same ABI. This is deliberately not a general QMI IDL parser.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

MAX_BLOB = 16 * 1024 * 1024
CALLBACK_IDS = frozenset((0x60FE25719B61B8CB, 0xC5FFB35DFFBEF12E, 0x9042BABC3EE38E2D))
FUNCTIONS = ("__cfi_check", "loc_get_service_object_internal_v02", "locClientOpen",
             "locClientSendReq", "locClientClose", "locClientGetSizeByRespIndId")
SERVICE = "loc_qmi_idl_service_object_v02"


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def unique_keys(items):
    out = dict(items)
    require(len(out) == len(items), "duplicate profile JSON key")
    return out


def load_profiles(path):
    doc = json.loads(path.read_text(), object_pairs_hook=unique_keys)
    require(isinstance(doc, dict) and set(doc) == {"schema", "profiles"} and
            type(doc["schema"]) is int and doc["schema"] == 1, "unsupported profile schema")
    profiles = doc["profiles"]
    require(isinstance(profiles, dict) and profiles, "no reviewed LOC profiles")
    for sha, p in profiles.items():
        require(re.fullmatch(r"[0-9a-f]{64}", sha) is not None, "invalid reviewed SHA-256")
        require(isinstance(p, dict) and set(p) == {"minor", "types"} and type(p["minor"]) is int
                and 1 <= p["minor"] <= 255, "invalid LOC minor")
        types = p["types"]
        require(isinstance(types, dict) and set(types) == {"limits", "servers", "url", "file_info"}
                and all(type(i) is int and 0 <= i <= 255 for i in types.values())
                and len(set(types.values())) == len(types), "invalid ABI aggregate indices")
    return profiles


class Elf:
    def __init__(self, data):
        self.data = data
        require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01"
                and self.unpack("<HH", 16) == (3, 183), "expected AArch64 little-endian ELF DSO")
        phoff, shoff = self.unpack("<QQ", 32)
        phsize, nph, shsize, nsh = self.unpack("<HHHH", 54)
        require(phsize == 56 and 0 < nph <= 128 and shsize == 64 and 0 < nsh <= 4096,
                "unexpected ELF table shape")
        self.read(phoff, nph * phsize)
        self.read(shoff, nsh * shsize)
        self.ph = [self.unpack("<II6Q", phoff + 56 * i) for i in range(nph)]
        self.sh = [self.unpack("<II4QII2Q", shoff + 64 * i) for i in range(nsh)]

    def read(self, off, size):
        require(0 <= off <= len(self.data) and 0 <= size <= len(self.data) - off,
                "ELF read outside file")
        return self.data[off:off + size]

    def unpack(self, fmt, off):
        return struct.unpack(fmt, self.read(off, struct.calcsize(fmt)))

    def va(self, address, size, execute=False):
        candidates = [off + address - vaddr
                      for typ, flags, off, vaddr, _, filesz, _, _ in self.ph
                      if typ == 1 and vaddr <= address and address + size <= vaddr + filesz
                      and (not execute or flags & 1)]
        require(len(candidates) == 1, "unmapped or ambiguous ELF address")
        return self.read(candidates[0], size)

    def at(self, fmt, address):
        return struct.unpack(fmt, self.va(address, struct.calcsize(fmt)))

    def symbols(self):
        dyn = [s for s in self.sh if s[1] == 11]  # SHT_DYNSYM
        require(len(dyn) == 1, "missing or ambiguous dynamic symbols")
        _, _, _, _, offset, size, link, _, _, itemsize = dyn[0]
        require(link < len(self.sh) and itemsize == 24 and size % itemsize == 0,
                "invalid dynamic symbol table")
        table = self.read(offset, size)
        require(self.sh[link][1] == 3, "invalid dynamic string table")
        strings = self.read(self.sh[link][4], self.sh[link][5])
        wanted = {n.encode(): (1 if n == SERVICE else 2) for n in (*FUNCTIONS, SERVICE)}
        found = {}
        for name_off, info, other, shndx, address, width in struct.iter_unpack("<IBBHQQ", table):
            end = strings.find(b"\0", name_off)
            require(end >= name_off, "invalid dynamic symbol name")
            name = strings[name_off:end]
            if name not in wanted:
                continue
            require(name not in found and 0 < shndx < len(self.sh) and width > 0 and
                    info & 15 == wanted[name] and info >> 4 in (1, 2) and other & 3 == 0,
                    f"invalid LOC export {name.decode()}")
            found[name] = (address, width)
        require(set(found) == set(wanted), "required LOC exports missing")
        return {k.decode(): v for k, v in found.items()}


def compare_ids(code):
    """Materialized u64 immediately tested against __cfi_check's type arg x0."""
    require(len(code) % 4 == 0, "unaligned CFI code")
    words = tuple(w for w, in struct.iter_unpack("<I", code))
    found = set()
    for i, insn in enumerate(words):
        if insn & 0xFF800000 != 0xD2800000:  # 64-bit MOVZ
            continue
        reg = insn & 31
        if reg in (0, 31):
            continue
        val = (insn >> 5 & 0xffff) << ((insn >> 21 & 3) * 16)
        j = i + 1
        while j < len(words) and words[j] & 0xFF80001F == 0xF2800000 | reg:  # MOVK, same reg
            w = words[j]
            shift = (w >> 21 & 3) * 16
            val = (val & ~(0xffff << shift)) | (w >> 5 & 0xffff) << shift
            j += 1
        if j < len(words) and words[j] == (0xEB00001F | reg << 16):  # cmp x0, Xn
            found.add(val)
    return found


def validate_idl(elf, address, width, profile):
    fmt = "<4I3H2x3QQI4xQ"
    require(width == struct.calcsize(fmt), "LOC service object size changed")
    service = elf.at(fmt, address)
    require(service[:3] == (6, 2, 16) and service[11:] == (profile["minor"], 0),
            "LOC service object version mismatch")
    nt, nm, _, types, messages, _, _ = elf.at("<HHB3x4Q", service[10])
    require(0 < nt <= 1024 and 0 < nm <= 4096, "invalid IDL type table counts")
    t = profile["types"]
    limits, servers, url, meta = (t[k] for k in ("limits", "servers", "url", "file_info"))
    common = "82 07 00 00 01"
    expected = {
        (0, 0x21): (24, 29, "01 03 00 41 10 56 09 04 42 11 02 10 c1 12 00 15"),
        (1, 0x21): (8, 7, common),
        (2, 0x29): (832, 819,
            f"01 07 00 {limits:02x} 00 44 10 07 0c {servers:02x} 00 "
            f"48 11 83 18 03 44 12 82 24 03 44 13 82 2c 03 c4 14 87 34 03 {meta:02x} 00"),
        (0, 0xa7): (1056, 1064,
            f"01 02 00 02 01 04 03 01 06 04 70 0c 00 04 04 44 10 82 10 04 c4 11 87 18 04 {meta:02x} 00"),
        (1, 0xa7): (8, 7, common),
        (2, 0xa7): (24, 23, "01 02 00 42 10 01 06 c8 11 03 10"),
    }
    seen = set()
    for kind, (count, table) in enumerate(zip(service[4:7], service[7:10])):
        require(0 < count <= 4096, "invalid IDL message table count")
        for mid, index, wire in struct.iter_unpack("<HHH", elf.va(table, count * 6)):
            key = kind, mid
            if key not in expected:
                continue
            require(key not in seen and index < nm, f"ambiguous or external message {mid:#x}")
            native, expected_wire, desc = expected[key]
            size, ptr = elf.at("<I4xQ", messages + 16 * index)
            desc = bytes.fromhex(desc)
            require((size, wire) == (native, expected_wire) and elf.va(ptr, len(desc)) == desc,
                    f"LOC descriptor/layout mismatch for {mid:#x} direction {kind}")
            seen.add(key)
    require(seen == set(expected), "LOC message declarations missing")
    for idx, size, desc in ((limits, 8, "02 00 02 04 20"),
                            (servers, 772, f"57 04 03 04 {url:02x} 00 20"),
                            (url, 256, "56 00 ff 20"), (meta, 8, "02 00 02 04 20")):
        require(idx < nt, "IDL aggregate outside table")
        native, ptr = elf.at("<I4xQ", types + idx * 16)
        desc = bytes.fromhex(desc)
        require(native == size and elf.va(ptr, len(desc)) == desc, "LOC aggregate layout mismatch")


def verify_blob(data, profiles):
    require(len(data) <= MAX_BLOB, "LOC artifact exceeds local size cap")
    sha = hashlib.sha256(data).hexdigest()
    require(sha in profiles, f"unreviewed vendor LOC SHA-256: {sha}; ABI review required")
    profile = profiles[sha]
    elf = Elf(data)
    symbols = elf.symbols()
    validate_idl(elf, *symbols[SERVICE], profile)
    addr, width = symbols["__cfi_check"]
    require(CALLBACK_IDS <= compare_ids(elf.va(addr, width, execute=True)),
            "required callback type comparisons missing in vendor __cfi_check")
    return sha, profile["minor"]


def header(proofs):
    require(proofs and len(proofs) == len(set(sha for sha, _ in proofs)),
            "duplicate or empty generated LOC profiles")
    entries = "".join(f'    {{"{sha}", {minor}}},\n' for sha, minor in sorted(proofs))
    return ("// Generated from reviewed LOC artifact(s); do not edit.\n"
            "#pragma once\n#include <cstdint>\nnamespace xtra::compat {\n"
            "struct LocPin { const char* sha256; int32_t minor; };\n"
            "inline constexpr LocPin kReviewedLoc[] = {\n" + entries + "};\n}\n")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--profiles", type=Path, required=True)
    p.add_argument("--library", type=Path, action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        profiles = load_profiles(args.profiles)
        proofs = []
        for path in args.library:
            with path.open("rb") as f:
                proofs.append(verify_blob(f.read(MAX_BLOB + 1), profiles))
        # Only write after all inputs pass; do not overwrite input/old artifacts.
        generated = header(proofs)
        with args.output.open("x") as out:
            out.write(generated)
    except (OSError, ValueError, struct.error) as e:
        p.exit(1, f"LOC profile rejected: {e}\n")


if __name__ == "__main__":
    main()
