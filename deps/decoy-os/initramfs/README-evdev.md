# `evdev_drv.so` — why this binary is vendored here

The decoy desktop came up with a working XFCE session and a cursor that could not move.  The cause
is not the kernel: `psmouse`, `evdev`, `usbhid` and `hid` all load, `/dev/input/event*` exist with
`root:input 0660`, and `alex` is in the `input` group.

The cause is that this rootfs has **no `udevd`**.  It ships `libudev.so.1` but device management is
busybox `mdev`, which creates device nodes and maintains no udev database.  `xf86-input-libinput`
—the only X input driver in the image—cannot work without it.  Both of its backends fail:

    (EE) libinput bug: udev device never initialized (/dev/input/event4)
    (EE) client bug: Invalid path /dev/input/event4
    (EE) libinput: static-event4: Failed to create a device for /dev/input/event4

Naming devices explicitly does not help: libinput's *path* backend still calls
`udev_device_get_is_initialized()`, which stays false forever with no daemon to set it.  X then
falls back to the legacy `mouse`/`kbd` drivers, which are not installed either, and ends up with no
pointer and no keyboard — while still drawing its core-pointer cursor in the middle of the screen.

`xf86-input-evdev` opens `/dev/input/eventN` directly and needs no udev database, so it works on a
`mdev` system.  Its three shared-library dependencies (`libevdev.so.2`, `libmtdev.so.1`,
`libudev.so.1`) are already present in the rootfs, so only this 100 KB driver is needed.

Source: Alpine v3.19 community, `xf86-input-evdev-2.10.6-r2.apk`, x86_64.

The alternative, and the better long-term fix, is to add `eudev` to the decoy rootfs
(`apk add eudev && setup-devd udev`) and let X autoconfigure input the normal way.  That needs the
rootfs image rebuilt as root, which is why the driver is vendored instead: `init-crypt` can install
it into the overlay at boot with no privileged build step.
