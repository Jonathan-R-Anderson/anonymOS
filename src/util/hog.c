// hog.c — a deliberate userspace CPU hog, for ROADMAP 3.5 (DESKTOP_RESP R6).
//
// R6's verify condition is "a deliberate userspace busy-loop no longer freezes the desktop;
// input/repaint latency stays bounded under load".  This is that busy-loop.  It exists to MEASURE
// the claim rather than argue about it: run several of these and see whether the bar clock still
// advances and the desktop still repaints.
//
// It deliberately makes no syscalls in the loop.  A spinner that called anything would yield to
// the scheduler through the syscall path and prove nothing about preemption -- the whole question
// is whether a task that NEVER yields voluntarily can be taken off the core anyway.
//
// Unlike idle.c this does not PAUSE: pause hints to the CPU that this is a spin-wait, which is
// exactly the opposite of what a hog should look like.  The volatile counter keeps the compiler
// from optimising the loop away.
static volatile unsigned long sink;

int main(void)
{
	unsigned long n = 0;
	for (;;) {
		n++;
		if ((n & 0xFFFFFF) == 0)
			sink = n;      // keep the loop observable and un-eliminable
	}
	return 0;
}
