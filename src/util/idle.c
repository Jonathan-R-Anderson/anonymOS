// idle.c — the scheduler's idle task.
//
// LARGELY SUPERSEDED as of ROADMAP 3.4.  The reason this task existed was that the kernel had no
// kernel-mode IRQ handlers -- hardware IRQs were delivered only while a task was in userspace, so
// the kernel could not HLT and *something* had to be in ring 3 for the timer/keyboard/mouse IRQs
// to keep firing.  Burning a core to stay interruptible was the price.
//
// serviceIRQ/kernelIRQ (arch/x86_64/context.S) removed that constraint: an IRQ taken while the
// kernel is running is now handled and iret'd back.  The scheduler therefore idles with `sti;hlt`
// instead of dispatching this task, so in the normal case it is spawned and never runs.
//
// It is kept deliberately, as the fallback for any path that still needs a runnable ring-3 task,
// and because removing it would couple the scheduler's idle handling to the IRQ work landing
// perfectly on every boot.  If it ever does run, PAUSE keeps it cheap and syscall-free.
int main(void)
{
	for (;;)
		__asm__ __volatile__("pause");
	return 0;
}
