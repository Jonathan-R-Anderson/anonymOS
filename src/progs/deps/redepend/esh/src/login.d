module login;

import std.stdio;
import std.process : environment;
import std.string : strip;
import shell.syscalls;

void loginCommand(string[] tokens) {
    string user;
    if (tokens.length < 2) {
        write("login: ");
        // Read user
        ubyte[256] buf;
        long n = sys_read(0, buf.ptr, 256);
        if (n > 0) user = (cast(string)buf[0..n]).strip();
    } else {
        user = tokens[1];
    }
    
    if (user.length == 0) return;

    // Minimal auth logic
    if (user == "root") {
        environment["USER"] = "root";
        environment["LOGNAME"] = "root";
        environment["HOME"] = "/root";
        writeln("Welcome to AnonymOS (Minimal)");
    } else {
        writeln("Login incorrect"); // Only root allowed
    }
}
