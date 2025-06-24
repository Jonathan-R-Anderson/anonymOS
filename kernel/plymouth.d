module kernel.plymouth;

import kernel.terminal : terminal_writestring_color, terminal_putchar, terminal_writestring;
import kernel.types : VGAColor;
import kernel.logger : log_message;
import kernel.utils.plymouth_logo : ansiArtData;

__gshared size_t spinnerIndex = 0;
private immutable string[4] spinner = ["|", "/", "-", "\\"];

extern(C) void plymouth_start()
{
    terminal_writestring_color(ansiArtData.ptr, VGAColor.LIGHT_BLUE, VGAColor.BLACK);
    terminal_putchar('\n');
    log_message("plymouth: start\n");
}

extern(C) void plymouth_message(const(char)* msg)
{
    if (msg is null) return;
    terminal_writestring_color(msg, VGAColor.LIGHT_GREY, VGAColor.BLACK);
    terminal_putchar('\n');
    log_message(msg);
    log_message("\n");
}

extern(C) void plymouth_tick()
{
    auto c = spinner[spinnerIndex][0];
    terminal_putchar(c);
    terminal_putchar('\b');
    spinnerIndex = (spinnerIndex + 1) % spinner.length;
}

extern(C) void plymouth_finish()
{
    terminal_writestring_color("Boot complete.\n", VGAColor.GREEN, VGAColor.BLACK);
    log_message("plymouth: finish\n");
}

