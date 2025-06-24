import std.stdio;
import std.string;
import std.file;
import std.process;
import std.path;

extern(C):
struct KernelContainerConfig {
    const(char)* baseImage;
    const(char)* cmd;
}

void start_container(KernelContainerConfig* cfg);

struct ContainerConfig {
    string baseImage;
    string cmd;
}

ContainerConfig parseContainerfile(string path) {
    ContainerConfig cfg;
    foreach(line; readText(path).splitLines) {
        auto trimmed = line.strip;
        if (trimmed.length == 0 || trimmed.startsWith("#")) {
            continue;
        }
        auto parts = trimmed.split();
        if (parts.length < 2) continue;
        auto key = parts[0];
        auto value = trimmed[key.length..$].strip;
        if (key == "FROM") {
            cfg.baseImage = value;
        } else if (key == "CMD") {
            cfg.cmd = value;
        }
    }
    return cfg;
}

void main(string[] args) {
    writeln("anonymOS Container Service");
    if (args.length < 2) {
        writeln("Usage: container_service <Containerfile> [--run]");
        return;
    }
    string filePath = args[1];
    if (!exists(filePath)) {
        stderr.writeln("Containerfile not found: ", filePath);
        return;
    }
    auto cfg = parseContainerfile(filePath);
    writeln("Parsed configuration:");
    writeln("  Base image: ", cfg.baseImage);
    writeln("  Command: ", cfg.cmd);

    if (args.length > 2 && args[2] == "--run") {
        KernelContainerConfig kcfg;
        kcfg.baseImage = toStringz(cfg.baseImage);
        kcfg.cmd = toStringz(cfg.cmd);
        writeln("Requesting kernel to start container...");
        start_container(&kcfg);
    }
}

