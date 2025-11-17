# Boot sequence

The build harness emits a bootable ISO that uses GRUB to hand off control to
`kernel.elf`.  The GRUB configuration now lives in `src/grub/grub.cfg`, which is
copied verbatim into the ISO image.  The default configuration exposes a single
entry named **AnonymOS** so the operating system boots without broadcasting
internal project names.

The copy step can be overridden by pointing the `GRUB_CFG_SRC` environment
variable at another configuration file before running `./buildscript.sh`.  The
script falls back to the anonymous configuration bundled in the repository when
no external file is provided, ensuring GRUB is always part of the boot sequence.

Once GRUB transfers control to `boot.s`, the kernel switches into long mode and
expects to print status text by writing directly to the VGA buffer at
`0xB8000`.  See `docs/PRINTING.md` for details on the supported output paths
during each boot stage.
