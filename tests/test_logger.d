import kernel.logger;
import std.conv : to;
import std.string : indexOf;
import core.stdc.string : strcmp;

void main() {
    logger_init();
    log_message("ABC");
    assert(logger_get_index() == 3);
    auto buf = logger_get_buffer()[0 .. logger_get_index()];
    assert(to!string(buf) == "ABC");
    logger_init();
    log_hex(0xAB);
    buf = logger_get_buffer()[0 .. logger_get_index()];
    assert(to!string(buf) == "0x00000000000000AB");

    logger_init();
    ubyte[4] data = [1,2,3,4];
    log_mem_dump(data.ptr, data.length);
    buf = logger_get_buffer()[0 .. logger_get_index()];
    assert(to!string(buf).indexOf("01 02 03 04") != -1);
}
