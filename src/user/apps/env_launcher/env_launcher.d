import std.stdio;
import std.json;
import std.file;
import std.string;

extern(C):
struct KernelContainerConfig {
    const(char)* baseImage;
    const(char)* cmd;
}

void start_container(KernelContainerConfig* cfg);

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
    kcfg.baseImage = toStringz(cfg.baseImage);
    kcfg.cmd = toStringz(cfg.cmd);

    writeln("Requesting kernel to start container...");
    start_container(&kcfg);
}

