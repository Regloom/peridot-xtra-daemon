# Peridot ROM integration

This integration preserves `loc_launcher`, `/vendor/etc/izat.conf`, the stock
`xtra-daemon` executable path and SELinux transition, and the vendor LOC/GNSS
libraries. It requires no new init service, root app, public IPC or property
override.

1. Sync the standalone repository at `external/peridot-xtra-daemon` through
   the product manifest, pinned to a reviewed commit. Select
   `peridot_xtra_daemon` in the device product's `PRODUCT_PACKAGES`.
2. Remove just `vendor/bin/xtra-daemon` from the device's
   `proprietary-files.txt` and its entry in the shared binder-shim fixup in
   `extract-files.py`. Keep all other entries. Regenerate the proprietary
   module list from the matching vendor tree, or apply the matching vendor
   integration patch, so `xtra-daemon` no longer has a `cc_prebuilt_binary`
   producer or a `PRODUCT_PACKAGES` entry. Do not remove the rest of QCC or
   GNSS as part of this integration.
3. Before deployment, inspect an approved build: exactly one arm64 binary
   installs at `/vendor/bin/xtra-daemon`; `libloc_api_v02.so` is present and
   pinned; the image retains the existing executable label. Check PIE, BTI,
   cross-DSO CFI and all three callback type IDs against the vendor library.
   A `sanitize.cfi` declaration is not proof the product kept those flags.
4. On a device already using a KernelSU overlay for this path, the overlay
   may still mask the ROM binary after an update. Plan removing/disabling
   **only that overlay** with a separate approval and a recovery path before
   testing the ROM-integrated variant. Do not change anything on the phone
   just by applying these source changes.

Keep the changes in the device tree and proprietary module list paired when
rolling forward or back. Do not publish the proprietary tree or blobs with
this source release.

## Vendor LOC compatibility

The `cc_genrule` consumes the arm64 vendor output of
`//vendor/xiaomi/peridot:libloc_api_v02` and `compat/loc_profiles.json`. It
requires an explicitly reviewed SHA-256, then checks the service object/version,
the decoded layouts and vendor descriptors for `0x21`, `0x29` and `0xA7`, the
referenced `0x29`/`0xA7` aggregate types, and the three known callback type-ID
comparisons in the vendor CFI dispatcher. Only this build's reviewed pair is
compiled into the daemon. The runtime hash, service and layout checks remain.
These static checks do not verify the final daemon's own CFI/BTI or real modem
behavior; those are separate image/device checks.

Do not adopt a new blob simply by copying its SHA into the review file.
Independently review the ABI first. On an unknown build input, validation stops
instead of lowering the live guard or falling back to the stock downloader.
