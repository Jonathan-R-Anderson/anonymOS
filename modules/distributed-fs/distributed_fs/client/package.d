module distributed_fs.client;

import std.stdio;

/// Mount the remote filesystem (stub).
void mountFs(string addr, string mountpoint) {
    writeln("mounting " ~ addr ~ " at " ~ mountpoint ~ " (stub)");
}
