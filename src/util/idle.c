// idle.c — the scheduler's idle task.
//
// The kernel is a cooperative single-core scheduler and has NO kernel-mode IRQ
// handlers (the IDT only maps CPU exceptions; hardware IRQs are delivered only
// while a task is in userspace).  So the kernel cannot HLT to idle — *something*
// must be in userspace for the PIT/keyboard/mouse IRQs to keep firing.
//
// When every real task is parked (blocked in poll/epoll), the scheduler runs THIS
// task instead of repeatedly re-running the parked tasks' (expensive) epoll scans,
// which otherwise saturate the kernel and starve the compositor.  This task just
// spins with PAUSE — cheap, no syscalls — so the kernel only re-enters on real
// interrupts and the compositor gets the core the instant it has work.
int main(void)
{
	for (;;)
		__asm__ __volatile__("pause");
	return 0;
}
