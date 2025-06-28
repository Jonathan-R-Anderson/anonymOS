import std.stdio;
import std.file;
import std.path;

void main() {
    string root = "/sys/bus/pci/devices";
    if (!exists(root)) {
        stderr.writeln("lspci: /sys/bus/pci/devices not found");
        return;
    }
    foreach (entry; dirEntries(root, SpanMode.shallow)) {
        string vendorFile = buildPath(entry.name, "vendor");
        string deviceFile = buildPath(entry.name, "device");
        string vendor = exists(vendorFile) ? strip(readText(vendorFile)) : "";
        string device = exists(deviceFile) ? strip(readText(deviceFile)) : "";
        writeln(entry.name.baseName, " \t", vendor, " ", device);
    }
}
