module core.thread.osthread;

class Thread {
    this() {}
    void join() {}
    bool isRunning() { return false; }
}

extern(C):
void callWithStackShellDg() {} 