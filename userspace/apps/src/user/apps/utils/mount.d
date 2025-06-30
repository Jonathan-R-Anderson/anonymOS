import std.stdio;
import std.string : toStringz;

extern(C) int mount(const char* source, const char* target,
                    const char* filesystemtype, ulong flags,
                    const char* data);

void main(string[] args) {
    if (args.length < 3) {
        writeln("Usage: mount SOURCE TARGET [TYPE]");
        return;
    }
    const char* fstype = args.length > 3 ? args[3].toStringz : null;
    int res = mount(args[1].toStringz, args[2].toStringz, fstype, 0, null);
    if (res != 0) {
        stderr.writeln("mount: failed to mount ", args[1], " on ", args[2]);
    }
}
