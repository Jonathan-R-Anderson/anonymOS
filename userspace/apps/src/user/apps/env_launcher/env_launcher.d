import std.stdio;
import std.json;
import std.file;
import std.string;

extern(C):
struct KernelContainerConfig {
    char[64] baseImage;
    char[64] cmd;
}
long do_syscall(ulong id, ulong a1, ulong a2, ulong a3, ulong a4, ulong a5, ulong a6);
extern(D):

enum SYS_CONTAINER_START = 43;

struct ContainerConfig {
    string name;
    string baseImage;
    string cmd;
}

ContainerConfig parseConfig(string path) {
    auto cfg = ContainerConfig();
    auto jsonData = parseJSON(readText(path));

    if ("name" in jsonData) {
        cfg.name = jsonData["name"].str;
    }
    if ("base_image" in jsonData) {
        cfg.baseImage = jsonData["base_image"].str;
    }
    if ("startup_command" in jsonData && jsonData["startup_command"].type == JSONType.array) {
        auto arr = jsonData["startup_command"].array;
        if (arr.length) {
            cfg.cmd = arr[0].str;
        }
    }
    return cfg;
}

void main(string[] args) {
    writeln("anonymOS Environment Launcher");
    string configPath = "anonymos_config/my-container.json";
    if (args.length > 1) {
        configPath = args[1];
    }
    if (!exists(configPath)) {
        stderr.writeln("Config file not found: ", configPath);
        return;
    }

    auto cfg = parseConfig(configPath);
    writeln("Loaded config:");
    writeln("  Name: ", cfg.name);
    writeln("  Base Image: ", cfg.baseImage);
    writeln("  Command: ", cfg.cmd);

    KernelContainerConfig kcfg;
    auto bLen = cfg.baseImage.length;
    if (bLen >= kcfg.baseImage.length) bLen = kcfg.baseImage.length - 1;
    kcfg.baseImage[0 .. bLen] = cfg.baseImage[0 .. bLen];
    kcfg.baseImage[bLen] = 0;

    auto cLen = cfg.cmd.length;
    if (cLen >= kcfg.cmd.length) cLen = kcfg.cmd.length - 1;
    kcfg.cmd[0 .. cLen] = cfg.cmd[0 .. cLen];
    kcfg.cmd[cLen] = 0;

    writeln("Requesting kernel to start container via syscall...");
    do_syscall(SYS_CONTAINER_START, cast(ulong)&kcfg, 0, 0, 0, 0, 0);
}

