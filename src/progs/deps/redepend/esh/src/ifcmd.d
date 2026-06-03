module ifcmd;

import std.stdio;
import std.string;
import std.conv;
import shell.syscalls;
import interpreter;

bool checkFile(string op, string path) {
    stat_t st;
    if(sys_stat(path.toStringz, &st) < 0) return false;
    
    if(op == "-e") return true;
    if(op == "-f") return (st.st_mode & 0xF000) == 0x8000;
    if(op == "-d") return (st.st_mode & 0xF000) == 0x4000;
    return false;
}

void ifCommand(string[] tokens) {
    string[] args = tokens.length > 1 ? tokens[1..$] : [];
    if(args.length > 0 && args[0] == "ifcmd") args = args[1..$]; // In case
    
    // strip [ ]
    if(args.length > 0 && args[0] == "[") args = args[1..$];
    if(args.length > 0 && args[$-1] == "]") args = args[0..$-1];

    if(args.length == 0) {
        variables["?"] = "1";
        return;
    }
    
    bool result = false;
    
    if(args.length == 1) {
        result = args[0].length > 0;
    } else if(args.length == 2) {
        string op = args[0];
        string arg = args[1];
        if(op.startsWith("-")) result = checkFile(op, arg);
    } else if(args.length == 3) {
        string a = args[0];
        string op = args[1];
        string b = args[2];
        if(op == "=" || op == "==") result = (a == b);
        else if(op == "!=") result = (a != b);
    }
    
    variables["?"] = result ? "0" : "1";
}
