module core.sync.condition;
import core.sync.mutex : Mutex;
class Condition{ this(Mutex m){} void notifyOne(){} void wait(){} } 