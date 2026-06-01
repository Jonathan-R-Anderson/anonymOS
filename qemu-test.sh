qemu-system-x86_64 \
  -boot d \
  -cdrom hos.iso \
  -d cpu,int,in_asm,exec,mmu,page \
  -D qemu.log \
  -serial stdio \
  -no-reboot \
  -no-shutdown
