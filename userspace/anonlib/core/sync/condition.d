module core.sync.condition;
public import core.sync.mutex : Mutex;
class Condition{ this(ref Mutex m){} void notifyOne(){} void wait(){} } 