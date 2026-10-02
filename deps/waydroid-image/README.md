# Android GSI image for the Waydroid bring-up (ANDROID phase A9)

The Android userland (A9.3+) runs from the Waydroid LineageOS images. They are multi-GB and
**not vendored** — drop them here. This directory is git-ignored except this README.

## What to fetch (x86_64, for anonymOS)

Two images, both for **`waydroid_x86_64`** (anonymOS is x86-64):

1. **System** — variant **VANILLA** (no Google apps; GAPPS also exists if you want Play Services):
   - Browse: https://sourceforge.net/projects/waydroid/files/images/system/lineage/waydroid_x86_64/
   - Take the newest `lineage-20.0-YYYYMMDD-VANILLA-waydroid_x86_64-system.zip` (LineageOS 20, Android 13).

2. **Vendor** — variant **MAINLINE** (the generic/non-Halium host vendor):
   - Browse: https://sourceforge.net/projects/waydroid/files/images/vendor/waydroid_x86_64/
   - Take the newest `lineage-20.0-YYYYMMDD-MAINLINE-waydroid_x86_64-vendor.zip`.

Pick a **matching date** for both where possible. (The same images are what `waydroid init
--rom_type lineage --system_type VANILLA` pulls from the OTA channels `https://ota.waydro.id/system`
and `https://ota.waydro.id/vendor`.)

## Where to put them

Each `.zip` contains exactly one raw **ext4** image. Unzip and place the two images here with these
exact names (the build/OS ingest looks for these):

```
deps/waydroid-image/system.img     # from …-VANILLA-…-system.zip   (the Android /system, ~0.7–1 GB)
deps/waydroid-image/vendor.img     # from …-MAINLINE-…-vendor.zip  (the Android /vendor, ~0.2 GB)
```

```sh
cd deps/waydroid-image
unzip -p lineage-20.0-*-VANILLA-waydroid_x86_64-system.zip  > system.img
unzip -p lineage-20.0-*-MAINLINE-waydroid_x86_64-vendor.zip > vendor.img
```

(If a `.zip` contains the image under a subpath rather than at the root, extract that one entry to
the name above. `unzip -l <zip>` lists the entry; it is normally just `system.img` / `vendor.img`.)

## What happens next (A9.3+)

Once `system.img` and `vendor.img` are here, the next bring-up steps are Android's own userland on
the A1–A9.2 kernel surface: mount the images read-only into a container rootfs, run bionic's
`/system/bin/linker64` + `init`, bring up `servicemanager` (on the binder that already works), then
the HAL/gralloc surface and SurfaceFlinger→Wayland. Those are tracked in
`docs/hw-bringup/ANDROID.md` (A9.3–A9.5). The kernel substrate they build on — binder, ashmem,
cgroup2, namespaces, the container runtime, selinuxfs, and the `/dev/__properties__` area — is in
and VM-verified.
