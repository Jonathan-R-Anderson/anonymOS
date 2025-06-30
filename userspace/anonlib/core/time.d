module core.time;

// Minimal placeholders so other Phobos modules compile.

enum ClockType { Monotonic, Realtime }

struct Duration { long nsecs; }

pure nothrow @nogc Duration durFromNsecs(long n) { return Duration(n); } 