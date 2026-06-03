module klist;

import std.stdio;

void klistCommand(string[] tokens) {
    // Mock kerberos output or just say no tickets
    writeln("klist: No credentials cache found (FILE:/tmp/krb5cc_0)");
}
