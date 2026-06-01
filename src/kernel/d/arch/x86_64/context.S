# Contains assembler code for context switching. Called directly from Haskell-land.
.section .data
xmmNextState:	.quad 0
xmmPrevState:	.quad 0

.section .bss
	.align 16
	.skip 0x8 # Ensure that the reason is 8-byte aligned, but not 16-byte aligned, which means the sse save area will be 16 byte aligned...
curUserSpaceState:
	.skip 0x298 # 1quad word reason + 18 registers + 512-byte fxsave area
		  # indicator
kernelState:
	.skip 0x290 # 18 registers  + 512-byte fxsave area
.global kernelState
.global curUserSpaceState



	.align 8
.global x64LastSyscallRax
.global x64LastSyscallRdi
.global x64LastSyscallRsi
.global x64LastSyscallRdx
.global x64LastSyscallR10
.global x64LastSyscallR8
.global x64LastSyscallR9
.global x64LastSyscallRip
x64LastSyscallRax:
	.skip 8
x64LastSyscallRdi:
	.skip 8
x64LastSyscallRsi:
	.skip 8
x64LastSyscallRdx:
	.skip 8
x64LastSyscallR10:
	.skip 8
x64LastSyscallR8:
	.skip 8
x64LastSyscallR9:
	.skip 8
x64LastSyscallRip:
	.skip 8

.align 16
.global kernelTmpStack
.global kernelTmpStack_top
.global kernelFaultStack
.global kernelFaultStack_top
kernelFaultStack:
	.skip 8192
kernelFaultStack_top:
kernelTmpStack:
	.skip 8192
kernelTmpStack_top:

	# kernelExecRetAddr: BSS slot for the return address saved by
	# x64SwitchToUserspace before entering userspace.  restoreKernelState
	# reads it back and jumps to it via a fresh exec stack, breaking the
	# ever-growing C call chain that accumulates with the recursive
	# kernelize → dispatchFn → resumeKernel → kernelize pattern.
	.align 16
.global kernelExecRetAddr
kernelExecRetAddr:
	.quad 0

	# Scratch area used by the serviceISR diagnostic call.  Two quads:
	# [0] = old IST1 value, [8] = raw vector number from the trap stub.
.global dbg_sisr_saves
dbg_sisr_saves:
	.skip 16

	# 512 KB dedicated kernel execution stack.  Every kernel event handler
	# chain runs on this stack from the top, so the C stack depth never
	# exceeds one chain's worth of frames regardless of how many events
	# have been processed.
.global kernelExecStack
.global kernelExecStack_top
kernelExecStack:
	.skip (512 * 1024)
kernelExecStack_top:

	.set IST1, tssArea + 0x24

.section .text
# We are called here from an interrupt. The interrupt number is on the stack,
# and after it, the stuff for the iret instruction.
#
# We're going first check to see if we're being called from userspace or from
# within the kernel. If from within the kernel, and the interrupt number corresponds
# to a fault, we will call the C instrumentation functions to report the error.
#
# If from userspace, then we will switch to the Haskell stack, and fake a "return"
# value for the interrupt number being called.
serviceISR:
	.set SYSCALL_REASON, 1
	.set TRAP_REASON, 2
	.set IRQ_REASON, 3

	.set PUSHES_ERROR_CODE_FLAG, 0x100
	.set IS_TRAP_FLAG, 0x80

	.set USERSPACE_CODE_SELECTOR, 0x23
	.set USERSPACE_DATA_SELECTOR, 0x1b
	cli # Clear the interrupt flag
	pushq %rax
	pushq %rbx
	pushq %rcx

	mov $0x10, %ax
	mov %ax, %ds
	mov %ax, %es
	mov %ax, %ss

	# We set the interrupts to use the new fault stack so that we can
	# detect if the error was in the kernel or not
	movabsq $IST1, %rbx
	movq (%rbx), %rcx # Save the old IST1 to check if the interrupt was from
                          # within the kernel
	movabsq $kernelFaultStack_top, %rax
	mov %rax, (%rbx)

	# Load the interrupt/trap number into rbx
	# If bit 7 is set, then this is an IRQ. Otherwise, it's a trap
	movq 0x18(%rsp), %rbx
	test $IS_TRAP_FLAG, %rbx
	jz itsATrap
	movq $IRQ_REASON, %rax
	jmp continueServiceISR
itsATrap:
	# If it's a trap, check if it may be the kernel by checking the IST1
	# entry
	movabsq $kernelFaultStack_top, %rax
	cmpq %rax, %rcx
	je inKernelFault
	movq $TRAP_REASON, %rax
continueServiceISR:
	movabsq $curUserSpaceState, %rcx
	movq %rax, (%rcx)
	# Now check if we're dealing with an error code or not
	test $PUSHES_ERROR_CODE_FLAG, %rbx
	mov $0x20, %rbx # Since rbx, rcx, and rax, and the interrupt number are on the stack, the exception information is
	# 32 off the stack
	jz noErrorCode # If there is no error code, continue with the ISR
	mov 0x20(%rsp), %rbx # Save the error code
	movabsq $x64TrapErrorCode, %rcx
	movq %rbx, (%rcx)
	mov $0x28, %rbx # We want to skip the error code
noErrorCode:
	movabsq $(curUserSpaceState + 8), %rax
	# Now, save the rip and eflags from the stack
	mov (%rsp, %rbx, 1), %rcx
	mov %rcx, (RIP_I * 8)(%rax)
	mov 0x10(%rsp, %rbx, 1), %rcx
	orq $(1 << 9), %rcx # Interrupt flags
	mov %rcx, (RFLAGS_I * 8)(%rax)

	# Now, check if this was from userspace or kernel land, and set the
	# stack approrpriately
	mov 0x8(%rsp, %rbx, 1), %rcx
	cmp $USERSPACE_CODE_SELECTOR, %rcx
	jz fromUserspace

	# We're coming from the kernel, so rsp is simply the %rsp + %rbx + 24
	leaq 0x18(%rsp, %rbx, 1), %rbx
	jmp doneWithStack

fromUserspace:
	movq 0x18(%rsp, %rbx, 1), %rbx
doneWithStack:
	movq %rbx, (RSP_I * 8)(%rax)
	popq %rcx
	popq %rbx

	# now save user space state
	movq %rbx, (RBX_I * 8)(%rax)
	movq %rcx, (RCX_I * 8)(%rax)
	movq %rdx, (RDX_I * 8)(%rax)
	movq %rax, %rbx
	popq %rax
	movq %rax, (RAX_I * 8)(%rbx)

	movq %rsi, (RSI_I * 8)(%rbx)
	movq %rdi, (RDI_I * 8)(%rbx)
	movq %r8, (R8_I * 8)(%rbx)
	movq %r9, (R9_I * 8)(%rbx)
	movq %r10, (R10_I * 8)(%rbx)
	movq %r11, (R11_I * 8)(%rbx)
	movq %r12, (R12_I * 8)(%rbx)
	movq %r13, (R13_I * 8)(%rbx)
	movq %r14, (R14_I * 8)(%rbx)
	movq %r15, (R15_I * 8)(%rbx)

	movq %rbp, (RBP_I * 8)(%rbx)

	# Now, save SSE state
	fxsave SSE_OFFSET(%rbx)

	# Pop the interrupt number from rax and call restoreKernelState
	popq %rax
	# We don't pass along information on the error pointer to Haskell
	# The x64-specific code already knows which ones produced an error
	# code or not
	andq $(0xff | IS_TRAP_FLAG), %rax
	jmp restoreKernelState

inKernelFault:
	# Test if the RTS can handle this fault. Nothing here yet...
continueInKernelFault:
	popq %rcx
	popq %rbx
	movabsq $(kernelState + 8), %rax
	movq %rbx, (RBX_I*8)(%rax)
	popq %rax

	# Save kernel state
	movabsq $(kernelState + 8), %rbx
	movq %rax, (RAX_I*8)(%rbx)
	movq %rcx, (RCX_I*8)(%rbx)
	movq %rdx, (RDX_I*8)(%rbx)
	movq %rsi, (RSI_I * 8)(%rbx)
	movq %rdi, (RDI_I * 8)(%rbx)
	movq %r8, (R8_I * 8)(%rbx)
	movq %r9, (R9_I * 8)(%rbx)
	movq %r10, (R10_I * 8)(%rbx)
	movq %r11, (R11_I * 8)(%rbx)
	movq %r12, (R12_I * 8)(%rbx)
	movq %r13, (R13_I * 8)(%rbx)
	movq %r14, (R14_I * 8)(%rbx)
	movq %r15, (R15_I * 8)(%rbx)

	# Load %rdi with the trap number
	popq %rdi

	movq %rsp, (RSP_I * 8)(%rbx)
	movq %rbp, (RBP_I * 8)(%rbx)

	# Check if we pushed an error code, and if so, put it in %rsi
	movq $0x0, %rsi
	test $PUSHES_ERROR_CODE_FLAG, %rdi
	je continueWithPanic
	popq %rsi
continueWithPanic:
	movq (%rsp), %rdx # RIP
	movq 0x10(%rsp), %rcx # EFLAGS
	subq $8, %rsp
	callq report_kernel_fault
	addq $8, %rsp
	# report_kernel_fault should not return; if it does, stop here.
.Lkf_halt:
	cli
	hlt
	jmp .Lkf_halt

callNMPanic:
	movabsq $report_sse_panic, %rax
	callq *%rax

# We can switch contexts by loading the temp userspace stack,
# changing the registers, and then far returning to userspace.
#
# We also will save the current rsp value. When an interrupt is received, the
# CPU will set rsp to the ISR stack pointer. This stack is only used to service
# ISRs. The serviceISR function will switch stacks to the Haskell stack, and
# that's the one that will be used to execute code in kernel-land.
#
# Haskell never returns an interrupt (IRQ or INT instruction) will set the correct RSP
# for processing
.global x64SwitchToUserspace
x64SwitchToUserspace:
	cli  # disable interrupts until iretq restores RFLAGS (IF=1 in userspace)
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

	# Assumptions: Called when the kernel wants to restore the state of a
	# userspace task and give control back to userspace.
	# Called using x86_64 abi with two arguments, so RDI points to a struct
	# containing the userspace state and RSI points to a place where
	# we should save the current state.

	# First save all the registers in the %RSI structure
	movq %rax, (RAX_I * 8)(%rsi)
	movq %rbx, (RBX_I * 8)(%rsi)
	movq %rcx, (RCX_I * 8)(%rsi)
	movq %rdx, (RDX_I * 8)(%rsi)
	movq %rsi, (RSI_I * 8)(%rsi)
	movq %rdi, (RDI_I * 8)(%rsi)
	movq %r8, (R8_I * 8)(%rsi)
	movq %r9, (R9_I * 8)(%rsi)
	movq %r10, (R10_I * 8)(%rsi)
	movq %r11, (R11_I * 8)(%rsi)
	movq %r12, (R12_I * 8)(%rsi)
	movq %r13, (R13_I * 8)(%rsi)
	movq %r14, (R14_I * 8)(%rsi)
	movq %r15, (R15_I * 8)(%rsi)
	# We skip rip, since we don't really need to ever return to *this* function
	movq %rsp, (RSP_I * 8)(%rsi)
	movq %rbp, (RBP_I * 8)(%rsi)
	# We skip rflags, since the caller expects this to be convoluted after a
	# function call

	# Save the return address (top of current C stack) so restoreKernelState
	# can reach it via the fresh exec stack.  rax and rcx are already saved
	# to kernelState above, so it is safe to clobber them here.
	movq (%rsp), %rax
	movabsq $kernelExecRetAddr, %rcx
	movq %rax, (%rcx)

	# We're going to use rax to store the means by which we will exit
	# userspace
	mov (%rdi), %rax

	# Now restore the user state
	addq $0x8, %rdi
	movq (RCX_I * 8)(%rdi), %rcx
	movq (RDX_I * 8)(%rdi), %rdx
	movq (RSI_I * 8)(%rdi), %rsi
	# skip rdi for now
	movq (R8_I * 8)(%rdi), %r8
	movq (R9_I * 8)(%rdi), %r9
	movq (R10_I * 8)(%rdi), %r10
	movq (R11_I * 8)(%rdi), %r11
	movq (R12_I * 8)(%rdi), %r12
	movq (R13_I * 8)(%rdi), %r13
	movq (R14_I * 8)(%rdi), %r14
	movq (R15_I * 8)(%rdi), %r15
	# skip rsp and rip
	movq (RBP_I * 8)(%rdi), %rbp
	# skip rflags

	# Now, restore the sse state...
	fxrstor SSE_OFFSET(%rdi)

	# Now restore segment selectors to the userspace ones
	mov $USERSPACE_DATA_SELECTOR, %rbx
	mov %bx, %ds
	mov %bx, %es
	# Do not reload FS/GS here. Linux userspace sets FS.base via arch_prctl,
	# and touching the selectors in long mode trashes the TLS base that glibc
	# expects to survive across syscalls and faults.

	movq (RBX_I * 8)(%rdi), %rbx

	# Now we're going to determine why we entered kernel space to begin
	# with, and enter userspace accordingly.
	#
	# We either entered kernel space because of a syscall, trap (exception), or irq
	cmp $SYSCALL_REASON, %rax
	je ret_syscall
	cmp $TRAP_REASON, %rax
	je ret_trap
	cmp $IRQ_REASON, %rax
	je ret_irq

	# If we don't know why we entered from userspace, give up on life...
	cli
	hlt

ret_syscall:
	# Temporary debugging path:
	# return syscall exits via iretq instead of sysretq.
	#
	# sysretq is extremely sensitive to RCX/R11 canonical state and is
	# currently faulting immediately after fork returns.
	#
	# By forcing the syscall path through the same iretq logic as traps,
	# we can stabilize userspace returns first.

	jmp ret_trap

ret_irq:
ret_trap:
	# We're going to iret from this now. This will set the stack back to the
	# normal kernel stack. We will need to push the old rip, the userspace
	# cs, the old rflags, the userspace rsp, and the userspace ss

	# We also want to restore the IST1 entry to simply be the normal tmp
	# stack
	pushq %rbx
	movabsq $IST1, %rax
	movabsq $kernelTmpStack_top, %rbx
	movq %rbx, (%rax)
	popq %rbx

	mov $USERSPACE_DATA_SELECTOR, %ax
	mov %ax, %ds
	mov %ax, %es

	movq (RAX_I * 8)(%rdi), %rax
	pushq $USERSPACE_DATA_SELECTOR # Userspace SS
	pushq (RSP_I * 8)(%rdi)
	pushq (RFLAGS_I * 8)(%rdi)
	pushq $USERSPACE_CODE_SELECTOR # Userspace CS
	pushq (RIP_I * 8)(%rdi)
	movq (RDI_I * 8)(%rdi), %rdi
	iretq

serviceSyscall:
	movq %rax, x64LastSyscallRax(%rip)
	movq %rdi, x64LastSyscallRdi(%rip)
	movq %rsi, x64LastSyscallRsi(%rip)
	movq %rdx, x64LastSyscallRdx(%rip)
	movq %r10, x64LastSyscallR10(%rip)
	movq %r8, x64LastSyscallR8(%rip)
	movq %r9, x64LastSyscallR9(%rip)
	movq %rcx, x64LastSyscallRip(%rip)
	# First, we're going to store the state that we should return to in
	# curUserSpaceState. Since this is a syscall. The calling program
	# is responsible for storing any register that is not rbp, rbx, or
	# r12-r15. This means we're free to mess around with the other
	# registers, so we're not as strict about saving things as in serviceISR.
	#
	# This will be read by the haskell interrupt/syscall
	# handler and saved as the current task context. Also in this structure
	# is a field indicating how we entered kernel space. This determines how
	# exactly we switch back into userspace.

	# Stash the raw syscall entry registers separately. The shared task-state
	# buffer gets reused across return paths, and early userspace startup is
	# sensitive to seeing the exact syscall number/args here.


	# We're going to save the rsp pointer first so we can get a new stack
	movabsq $curUserSpaceState, %r10
	movq $SYSCALL_REASON, (%r10)

	# Now save the registers
	addq $0x8, %r10
	movq %rsp, (RSP_I * 8)(%r10)

	# We only need to save rbp, rbx, r12, r13, r14, and r15 to conform to
	# the ABI

	mov %rbp, (RBP_I * 8)(%r10)
	mov %rbx, (RBX_I * 8)(%r10)
	mov %r12, (R12_I * 8)(%r10)
	mov %r13, (R13_I * 8)(%r10)
	mov %r14, (R14_I * 8)(%r10)
	mov %r15, (R15_I * 8)(%r10)

	# We also have to save rax, rdi, rsi, rdx, r8, and r9 to pass in kernel
	# arguments.
	# Restore rax and rdx from the stash (recorded before any clobber).
	movq x64LastSyscallRax(%rip), %rax
	movq %rax, (RAX_I * 8)(%r10)
	mov %rdi, (RDI_I * 8)(%r10)
	mov %rsi, (RSI_I * 8)(%r10)
	movq x64LastSyscallRdx(%rip), %rax
	movq %rax, (RDX_I * 8)(%r10)
	mov %r8, (R8_I * 8)(%r10)
	mov %r9, (R9_I * 8)(%r10)
	# Restore the ORIGINAL userspace R10 value from the syscall stash.
	movq x64LastSyscallR10(%rip), %rax
	movq %rax, (R10_I * 8)(%r10)

	# Since we came from a syscall, rcx contains the rip to return to, and
	# r11 the old rflags
	movq %rcx, (RCX_I * 8)(%r10)
	movq %rcx, (RIP_I * 8)(%r10)
	orq $(1 << 9), %r11 # Set interrupt flag
	movq %r11, (R11_I * 8)(%r10)
	movq %r11, (RFLAGS_I * 8)(%r10)

	# Now save the SSE state
	fxsave SSE_OFFSET(%r10)

	# We set the interrupts to use the new fault stack so that we can
	# detect if the error was in the kernel or not
	movabsq $kernelFaultStack_top, %r11
	movabsq $IST1, %r10
	movq %r11, (%r10)

	# Now, we're going to restore the kernel state, which will involve switching
	# to the kernel stack. Once on that stack, we can simply do a ret to
	# return back to the calling X86_64-arch-specific interrupt/syscall
	# routine.
	#
	# This routine will inspect the values of the rax (return value)
	# register to determine what transferred control to kernel land. The
	# return value 256 indicates a syscall from userspace. We set rax here,
	# and then fall through to restoreKernelState, which does not set rax
	mov $0x10, %ax
	mov %ax, %ds
	mov %ax, %es

	# SYSCALL does not switch RSP — it remains the userspace stack value.
	# Switch to the saved kernel C stack now so that restoreKernelState's
	# sentinel pushes land on a mapped kernel page, not the userspace stack.
	movabsq $kernelState, %r10
	movq (RSP_I * 8)(%r10), %rsp

	mov $0x100, %rax
restoreKernelState:
	movabsq $kernelState, %rdi
	movq (RBX_I * 8)(%rdi), %rbx
	movq (RCX_I * 8)(%rdi), %rcx
	movq (RDX_I * 8)(%rdi), %rdx
	movq (RSI_I * 8)(%rdi), %rsi
	# skip rdi for now
	movq (R8_I * 8)(%rdi), %r8
	movq (R9_I * 8)(%rdi), %r9
	movq (R10_I * 8)(%rdi), %r10
	movq (R11_I * 8)(%rdi), %r11
	movq (R12_I * 8)(%rdi), %r12
	movq (R13_I * 8)(%rdi), %r13
	movq (R14_I * 8)(%rdi), %r14
	movq (R15_I * 8)(%rdi), %r15
	# skip rip
	movq (RBP_I * 8)(%rdi), %rbp
	# Restore the original C stack RSP saved by x64SwitchToUserspace.
	# The return address pushed by `call x64SwitchToUserspace` is already
	# sitting at [kernelState.rsp], so a plain `ret` delivers the correct
	# C ABI return with the JHC thunk's full frame intact.
	# The previous exec-stack approach (kernelExecStack_top) corrupted gc_t
	# because the thunk had spilled it to the original stack → #GP at resume.
	movq (RSP_I * 8)(%rdi), %rsp
	ret

.global setupSysCalls
setupSysCalls:
	.set STAR_MSR,   0xC0000081
	.set LSTAR_MSR,  0xC0000082
	.set SFMASK_MSR, 0xC0000084
	.set EFER_MSR,   0xC0000080

	pushq %rbx
	pushq %rbp
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15

	# STAR: SYSCALL CS/SS = 0x08/0x10; SYSRET CS/SS base = 0x10
	movq  $STAR_MSR, %rcx
	movl  $0x0, %eax
	movl  $0x00100008, %edx
	wrmsr

	# LSTAR: 64-bit entry point for SYSCALL
	movq  $LSTAR_MSR, %rcx
	movabsq $serviceSyscall, %rax
	movq  %rax, %rdx
	shrq  $32, %rdx
	wrmsr

	# SFMASK: clear TF(8) IF(9) DF(10) IOPL(12,13) NT(14) AC(18) on SYSCALL
	movq  $SFMASK_MSR, %rcx
	movl  $0x47700, %eax
	movl  $0, %edx
	wrmsr

	# EFER: read-modify-write to set SCE (bit 0); preserve all other bits
	movq  $EFER_MSR, %rcx
	rdmsr
	orl   $0x1, %eax
	wrmsr

	popq  %r15
	popq  %r14
	popq  %r13
	popq  %r12
	popq  %rbp
	popq  %rbx
	ret

	.global trap0
	.global trap1
	.global trap2
	.global trap3
	.global trap4
	.global trap5
	.global trap6
	.global trap7
	.global trap8
	.global trap9
	.global trap10
	.global trap11
	.global trap12
	.global trap13
	.global trap14
	.global trap15
	.global trap16
	.global trap17
	.global trap18
	.global trap19
	.global trap20
	.global trap21
	.global trap22
	.global trap23
	.global trap24
	.global trap25
	.global trap26
	.global trap27
	.global trap28
	.global trap29
	.global trap30
	.global trap31
trap0:
	pushq $0
	jmp serviceISR
trap1:
	pushq $1
	jmp serviceISR
trap2:
	pushq $2
	jmp serviceISR
trap3:
	pushq $3
	jmp serviceISR
trap4:
	pushq $4
	jmp serviceISR
trap5:
	pushq $5
	jmp serviceISR
trap6:
	pushq $6
	jmp serviceISR
trap7:
	pushq $7
	jmp serviceISR
trap8:
	pushq $(8 | PUSHES_ERROR_CODE_FLAG)
	jmp serviceISR
trap9:
	pushq $9
	jmp serviceISR
trap10:
	pushq $(10 | PUSHES_ERROR_CODE_FLAG)
	jmp serviceISR
trap11:
	pushq $(11 | PUSHES_ERROR_CODE_FLAG)
	jmp serviceISR
trap12:
	pushq $(12 | PUSHES_ERROR_CODE_FLAG)
	jmp serviceISR
trap13:
	# sentinel 0x3f '?': #GP (#13) stub entered; use memory-save to avoid
	# touching the stack before the vector push that serviceISR expects.
	movq %rax, dbg_sisr_saves(%rip)
	movq %rdx, dbg_sisr_saves+8(%rip)
.L_trap13_serial_wait:
	movl $0x3FD, %edx
	inb %dx, %al
	testb $0x20, %al
	jz .L_trap13_serial_wait
	movb $0x3f, %al
	movl $0x3F8, %edx
	outb %al, %dx
	movq dbg_sisr_saves(%rip), %rax
	movq dbg_sisr_saves+8(%rip), %rdx
	pushq $(13 | PUSHES_ERROR_CODE_FLAG)
	jmp serviceISR
trap14:
	# sentinel 0x3e '>': #PF (#14) stub entered
	movq %rax, dbg_sisr_saves(%rip)
	movq %rdx, dbg_sisr_saves+8(%rip)
.L_trap14_serial_wait:
	movl $0x3FD, %edx
	inb %dx, %al
	testb $0x20, %al
	jz .L_trap14_serial_wait
	movb $0x3e, %al
	movl $0x3F8, %edx
	outb %al, %dx
	movq dbg_sisr_saves(%rip), %rax
	movq dbg_sisr_saves+8(%rip), %rdx
	pushq $(14 | PUSHES_ERROR_CODE_FLAG)
	jmp serviceISR
trap15:
	pushq $15
	jmp serviceISR
trap16:
	pushq $16
	jmp serviceISR
trap17:
	pushq $(17 | PUSHES_ERROR_CODE_FLAG)
	jmp serviceISR
trap18:
	pushq $18
	jmp serviceISR
trap19:
	pushq $19
	jmp serviceISR
trap20:
	pushq $20
	jmp serviceISR
trap21:
	pushq $21
	jmp serviceISR
trap22:
	pushq $22
	jmp serviceISR
trap23:
	pushq $23
	jmp serviceISR
trap24:
	pushq $24
	jmp serviceISR
trap25:
	pushq $25
	jmp serviceISR
trap26:
	pushq $26
	jmp serviceISR
trap27:
	pushq $27
	jmp serviceISR
trap28:
	pushq $28
	jmp serviceISR
trap29:
	pushq $29
	jmp serviceISR
trap30:
	pushq $30
	jmp serviceISR
trap31:
	pushq $31
	jmp serviceISR

	.global irq0
	.global irq1
	.global irq2
	.global irq3
	.global irq4
	.global irq5
	.global irq6
	.global irq7
	.global irq8
	.global irq9
	.global irq10
	.global irq11
	.global irq12
	.global irq13
	.global irq14
	.global irq15
irq0:
	pushq $0x80
	jmp serviceISR
irq1:
	pushq $0x81
	jmp serviceISR
irq2:
	pushq $0x82
	jmp serviceISR
irq3:
	pushq $0x83
	jmp serviceISR
irq4:
	pushq $0x84
	jmp serviceISR
irq5:
	pushq $0x85
	jmp serviceISR
irq6:
	pushq $0x86
	jmp serviceISR
irq7:
	pushq $0x87
	jmp serviceISR
irq8:
	pushq $0x88
	jmp serviceISR
irq9:
	pushq $0x89
	jmp serviceISR
irq10:
	pushq $0x8A
	jmp serviceISR
irq11:
	pushq $0x8B
	jmp serviceISR
irq12:
	pushq $0x8C
	jmp serviceISR
irq13:
	pushq $0x8D
	jmp serviceISR
irq14:
	pushq $0x8E
	jmp serviceISR
irq15:
	pushq $0x8F
	jmp serviceISR

.section .data
kernel_panic_msg: .asciz "Kernel Fault"

	.align 8
x64TrapErrorCode:
	.global x64TrapErrorCode
	.quad 0
