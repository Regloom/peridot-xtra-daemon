# Peridot ROM integration

This integration preserves `loc_launcher`, `/vendor/etc/izat.conf`, the stock
`xtra-daemon` executable path and SELinux transition, and the vendor LOC/GNSS
libraries. It requires no new init service, root app, public IPC or property
override.

1. Place the release sources and `Android.bp` under `device/xiaomi/peridot/xtra`.
   Select `peridot_xtra_daemon` in the device product's `PRODUCT_PACKAGES`.
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
