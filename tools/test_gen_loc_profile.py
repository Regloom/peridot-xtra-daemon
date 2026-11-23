"""Host-only ELF and generation regressions; never loads a vendor library."""

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

import gen_loc_profile as g

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ROOT / "compat/loc_profiles.json"
LIBS = [ROOT.parent / "artifacts" / s / "lib64/libloc_api_v02.so"
        for s in ("vendor", "vendor-20261115")]


def changed(data, at, value):
    return data[:at] + value + data[at + len(value):]


def va_offset(elf, address):
    found = [off + address - base for typ, _, off, base, _, size, _, _ in elf.ph
             if typ == 1 and base <= address < base + size]
    assert len(found) == 1
    return found[0]


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.profiles = g.load_profiles(PROFILES)

    def test_reviewed_keys_and_header_multiple_entries(self):
        pins = g.header([(k, v["minor"]) for k, v in self.profiles.items()])
        self.assertEqual(pins.count('{"'), 2)
        self.assertIn(", 161}", pins)
        self.assertIn(", 170}", pins)

    def test_profile_rejects_duplicate_invalid_types_and_minor(self):
        cases = [
            '{"schema":1,"schema":1,"profiles":{}}',
            '{"schema":true,"profiles":{}}',
            json.dumps({"schema": 1, "profiles": {"b" * 64: {"minor": True, "types": {}}}}),
            json.dumps({"schema": 1, "profiles": {"b" * 64: {
                "minor": 161, "types": {"limits": 0, "servers": 0, "url": 1, "file_info": 2}}}}),
        ]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "profiles.json"
            for case in cases:
                path.write_text(case)
                with self.assertRaises(ValueError):
                    g.load_profiles(path)

    def test_unreviewed_and_oversize_fails(self):
        with self.assertRaisesRegex(ValueError, "unreviewed vendor LOC SHA"):
            g.verify_blob(b"not a reviewed ELF", self.profiles)
        with self.assertRaisesRegex(ValueError, "size cap"):
            g.verify_blob(bytes(g.MAX_BLOB + 1), self.profiles)

    def test_cfi_constant_must_be_compared_to_x0(self):
        # Same synthetic instruction form as the reviewed vendor compiler's checks.
        n = 8
        val = 0x60FE25719B61B8CB
        seq = [(0xD2800000 if not i else 0xF2800000) | i << 21 |
               ((val >> (16*i)) & 0xffff) << 5 | n for i in range(4)]
        seq.append(0xEB00001F | n << 16)
        self.assertEqual(g.compare_ids(struct.pack("<5I", *seq)), {val})
        seq[-1] |= 1 << 5  # cmp x1, Xn rather than the type argument
        self.assertEqual(g.compare_ids(struct.pack("<5I", *seq)), set())

    @unittest.skipUnless(all(p.is_file() for p in LIBS), "private vendor artifacts are not part of public project")
    def test_actual_artifacts_produce_only_the_candidate_pin(self):
        for lib, minor in zip(LIBS, (161, 170)):
            data = lib.read_bytes()
            key, got_minor = g.verify_blob(data, self.profiles)
            self.assertEqual(got_minor, minor)
            self.assertEqual(g.header([(key, minor)]).count('{"'), 1)
            self.assertIn(key, g.header([(key, minor)]))

    @unittest.skipUnless(LIBS[1].is_file(), "private vendor artifact unavailable")
    def test_structural_checks_even_given_a_synthetic_matching_hash(self):
        data = LIBS[1].read_bytes()
        elf = g.Elf(data)
        symbols = elf.symbols()
        baseline = self.profiles[hashlib.sha256(data).hexdigest()]
        service = symbols[g.SERVICE][0]
        service_fields = elf.at("<4I3H2x3QQI4xQ", service)
        records = list(struct.iter_unpack("<HHH", elf.va(service_fields[9], service_fields[6] * 6)))
        ack_index = next(idx for mid, idx, _ in records if mid == 0xA7)
        _, _, _, _, messages, _, _ = elf.at("<HHB3x4Q", service_fields[10])
        _, ack_desc = elf.at("<I4xQ", messages + ack_index * 16)
        cfi_addr, width = symbols["__cfi_check"]
        cases = (
            (changed(data, va_offset(elf, service) + 56, struct.pack("<I", 161)), "version mismatch"),
            (changed(data, va_offset(elf, ack_desc), b"\x02"), "descriptor/layout mismatch"),
            (changed(data, va_offset(elf, cfi_addr), b"\0" * width), "callback type comparisons missing"),
        )
        for mutant, reason in cases:
            # Test only: pretending this mutant was reviewed must not sidestep
            # the additional structural checks. Never add it to a real profile.
            with self.assertRaisesRegex(ValueError, reason):
                g.verify_blob(mutant, {hashlib.sha256(mutant).hexdigest(): baseline})

    def test_cli_does_not_write_on_failure(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            blob = base / "unknown.so"
            blob.write_bytes(b"unreviewed")
            out = base / "xtra_loc_profile.h"
            p = subprocess.run([sys.executable, "-B", str(ROOT / "tools/gen_loc_profile.py"),
                                "--profiles", str(PROFILES), "--library", str(blob),
                                "--output", str(out)], capture_output=True, timeout=5)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn(b"ABI review required", p.stderr)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
