# SMP_ROADMAP S4.4b — the AP's OWN userspace entry/exit path.
#
# A faithful copy of the BSP's x64SwitchToUserspace / serviceSyscall / restoreKernelState
# (context.S), but addressing the AP's OWN per-CPU buffers (ap*) instead of the single global
# ones — so the BSP's path stays byte-for-byte untouched and the two never collide.
#
# Simplifications valid for S4.4b (one active AP, single buffers, a stub that never touches GS):
#   - NO swapgs: GS stays = the AP's per-CPU area in both kernel and user; the stub doesn't use GS,
#     and the buffers are absolute-addressed (not GS-relative). swapgs + GS-relative per-CPU buffers
#     arrive in S4.4d (multiple APs running real tasks).
#   - NO IST1 manipulation: the AP's TSS.ist1 stays = g_apIstStack[idx] (S4.1), valid for any AP
#     trap; the BSP's kernelTmpStack/kernelFaultStack IST1 dance is not needed.
#
# Coroutine model (same as the BSP): apKernelLoopBody (running on g_apKernelStack) calls
# apSwitchToUserspace, which saves the kernel C regs to apKernelState and iretq's to ring 3; the
# stub's `syscall` enters apServiceSyscall, which saves the user regs to apCurUserSpaceState,
# restores apKernelState, and `ret`s straight back into apKernelLoopBody with the reason in RAX.

.section .bss
	.align 16
	.skip 0x8                  # keep `reason` 8-byte (not 16-byte) aligned → SSE area 16-byte aligned
.global apCurUserSpaceState
apCurUserSpaceState:
	.skip 0x298                # reason (8) + 18 regs (144) + 512-byte fxsave
.global apKernelState
apKernelState:
	.skip 0x290                # 18 regs + 512-byte fxsave

	.align 8
.global apLastSyscallRax
.global apLastSyscallRdi
.global apLastSyscallRsi
.global apLastSyscallRdx
.global apLastSyscallR10
.global apLastSyscallR8
.global apLastSyscallR9
.global apLastSyscallRip
apLastSyscallRax:	.skip 8
apLastSyscallRdi:	.skip 8
apLastSyscallRsi:	.skip 8
apLastSyscallRdx:	.skip 8
apLastSyscallR10:	.skip 8
apLastSyscallR8:	.skip 8
apLastSyscallR9:	.skip 8
apLastSyscallRip:	.skip 8

	.align 16
apKernelExecRetAddr:
	.quad 0

.section .text
	# Register-index + selector constants (file-local; context.S has its own copies).
	.set RAX_I, 0
	.set RBX_I, 1
	.set RCX_I, 2
	.set RDX_I, 3
	.set RSI_I, 4
	.set RDI_I, 5
	.set R8_I,  6
	.set R9_I,  7
	.set R10_I, 8
	.set R11_I, 9
	.set R12_I, 10
	.set R13_I, 11
	.set R14_I, 12
	.set R15_I, 13
	.set RIP_I, 14
	.set RSP_I, 15
	.set RBP_I, 16
	.set RFLAGS_I, 17
	.set SSE_OFFSET, 0x90
	.set SYSCALL_REASON, 1
	.set USERSPACE_CODE_SELECTOR, 0x23
	.set USERSPACE_DATA_SELECTOR, 0x1b

# extern(C) ulong apSwitchToUserspace(void* userState /*rdi*/, void* kernelState /*rsi*/);
# Saves the kernel C state to apKernelState, loads the user state from apCurUserSpaceState, iretq.
.global apSwitchToUserspace
apSwitchToUserspace:
	cli
	movq %rax, (RAX_I * 8)(%rsi)
	movq %rbx, (RBX_I * 8)(%rsi)
	movq %rcx, (RCX_I * 8)(%rsi)
	movq %rdx, (RDX_I * 8)(%rsi)
	movq %rsi, (RSI_I * 8)(%rsi)
	movq %rdi, (RDI_I * 8)(%rsi)
	movq %r8,  (R8_I * 8)(%rsi)
	movq %r9,  (R9_I * 8)(%rsi)
	movq %r10, (R10_I * 8)(%rsi)
	movq %r11, (R11_I * 8)(%rsi)
	movq %r12, (R12_I * 8)(%rsi)
	movq %r13, (R13_I * 8)(%rsi)
	movq %r14, (R14_I * 8)(%rsi)
	movq %r15, (R15_I * 8)(%rsi)
	movq %rsp, (RSP_I * 8)(%rsi)
	movq %rbp, (RBP_I * 8)(%rsi)
	# Save the return address (top of the C stack) — symmetry with the BSP path.
	movq (%rsp), %rax
	movabsq $apKernelExecRetAddr, %rcx
	movq %rax, (%rcx)
	# Load the user state from apCurUserSpaceState (RDI), skipping the reason word.
	mov (%rdi), %rax
	addq $0x8, %rdi
	movq (RCX_I * 8)(%rdi), %rcx
	movq (RDX_I * 8)(%rdi), %rdx
	movq (RSI_I * 8)(%rdi), %rsi
	movq (R8_I * 8)(%rdi), %r8
	movq (R9_I * 8)(%rdi), %r9
	movq (R10_I * 8)(%rdi), %r10
	movq (R11_I * 8)(%rdi), %r11
	movq (R12_I * 8)(%rdi), %r12
	movq (R13_I * 8)(%rdi), %r13
	movq (R14_I * 8)(%rdi), %r14
	movq (R15_I * 8)(%rdi), %r15
	movq (RBP_I * 8)(%rdi), %rbp
	fxrstor SSE_OFFSET(%rdi)
	mov $USERSPACE_DATA_SELECTOR, %rbx
	mov %bx, %ds
	mov %bx, %es
	# Do not touch FS/GS (TLS base must survive); no swapgs in S4.4b.
	movq (RBX_I * 8)(%rdi), %rbx
	# Build the iretq frame (all reasons → iret; a fresh task uses REASON_TRAP).
	movq (RAX_I * 8)(%rdi), %rax
	pushq $USERSPACE_DATA_SELECTOR     # SS
	pushq (RSP_I * 8)(%rdi)            # user RSP
	pushq (RFLAGS_I * 8)(%rdi)         # RFLAGS
	pushq $USERSPACE_CODE_SELECTOR     # CS
	pushq (RIP_I * 8)(%rdi)            # RIP
	movq (RDI_I * 8)(%rdi), %rdi
	iretq

# The AP's syscall entry (LSTAR target once apKernelLoopBody runs).  On `syscall`: RCX=return RIP,
# R11=RFLAGS, CS/SS=kernel (from STAR), RSP=still the user stack.  Save user regs to
# apCurUserSpaceState, switch to the saved kernel C stack, restore apKernelState, ret to the caller.
.global apServiceSyscall
apServiceSyscall:
	movq %rax, apLastSyscallRax(%rip)
	movq %rdi, apLastSyscallRdi(%rip)
	movq %rsi, apLastSyscallRsi(%rip)
	movq %rdx, apLastSyscallRdx(%rip)
	movq %r10, apLastSyscallR10(%rip)
	movq %r8,  apLastSyscallR8(%rip)
	movq %r9,  apLastSyscallR9(%rip)
	movq %rcx, apLastSyscallRip(%rip)
	movabsq $apCurUserSpaceState, %r10
	movq $SYSCALL_REASON, (%r10)
	addq $0x8, %r10
	movq %rsp, (RSP_I * 8)(%r10)
	mov %rbp, (RBP_I * 8)(%r10)
	mov %rbx, (RBX_I * 8)(%r10)
	mov %r12, (R12_I * 8)(%r10)
	mov %r13, (R13_I * 8)(%r10)
	mov %r14, (R14_I * 8)(%r10)
	mov %r15, (R15_I * 8)(%r10)
	movq apLastSyscallRax(%rip), %rax
	movq %rax, (RAX_I * 8)(%r10)
	mov %rdi, (RDI_I * 8)(%r10)
	mov %rsi, (RSI_I * 8)(%r10)
	movq apLastSyscallRdx(%rip), %rax
	movq %rax, (RDX_I * 8)(%r10)
	mov %r8, (R8_I * 8)(%r10)
	mov %r9, (R9_I * 8)(%r10)
	movq apLastSyscallR10(%rip), %rax
	movq %rax, (R10_I * 8)(%r10)
	movq %rcx, (RCX_I * 8)(%r10)
	movq %rcx, (RIP_I * 8)(%r10)
	orq $(1 << 9), %r11
	movq %r11, (R11_I * 8)(%r10)
	movq %r11, (RFLAGS_I * 8)(%r10)
	fxsave SSE_OFFSET(%r10)
	mov $0x10, %ax
	mov %ax, %ds
	mov %ax, %es
	# syscall did not switch RSP — switch to the saved kernel C stack before any push lands on user.
	movabsq $apKernelState, %r10
	movq (RSP_I * 8)(%r10), %rsp
	mov $0x100, %rax
	jmp apRestoreKernelState

apRestoreKernelState:
	movabsq $apKernelState, %rdi
	movq (RBX_I * 8)(%rdi), %rbx
	movq (RCX_I * 8)(%rdi), %rcx
	movq (RDX_I * 8)(%rdi), %rdx
	movq (RSI_I * 8)(%rdi), %rsi
	movq (R8_I * 8)(%rdi), %r8
	movq (R9_I * 8)(%rdi), %r9
	movq (R10_I * 8)(%rdi), %r10
	movq (R11_I * 8)(%rdi), %r11
	movq (R12_I * 8)(%rdi), %r12
	movq (R13_I * 8)(%rdi), %r13
	movq (R14_I * 8)(%rdi), %r14
	movq (R15_I * 8)(%rdi), %r15
	movq (RBP_I * 8)(%rdi), %rbp
	movq (RSP_I * 8)(%rdi), %rsp       # the `call apSwitchToUserspace` return addr sits here
	ret

# extern(C) void apEnterKernelLoop(uint idx /*edi*/, void* kstackTop /*rsi*/);
# Switch to the dedicated AP kernel C stack, repoint LSTAR to the FULL apServiceSyscall (replacing
# the S4.3 trivial self-test stub), then run apKernelLoopBody (D, never returns).
.global apEnterKernelLoop
apEnterKernelLoop:
	movq %rsi, %rsp
	movq $0xC0000082, %rcx            # IA32_LSTAR
	movabsq $apServiceSyscall, %rax
	movq %rax, %rdx
	shrq $32, %rdx
	wrmsr
	call apKernelLoopBody             # rdi (idx) preserved across the wrmsr; never returns
1:	hlt
	jmp 1b
