module kernel.login;

import kernel.terminal : terminal_writestring, terminal_putchar, terminal_writestring_color;
import kernel.device.vga : clear_screen;
import kernel.keyboard : keyboard_getchar;
import kernel.types : VGAColor, strlen, memcmp;

private void draw_login_banner()
{
    terminal_writestring_color("+-----------------------+\n", VGAColor.CYAN, VGAColor.BLACK);
    terminal_writestring_color("|     anonymOS Login    |\n", VGAColor.CYAN, VGAColor.BLACK);
    terminal_writestring_color("+-----------------------+\n", VGAColor.CYAN, VGAColor.BLACK);
}

/// Simple login prompt. Returns true if username/password match defaults.
extern(C) bool login_prompt()
{
    clear_screen();
    draw_login_banner();
    char[32] user;
    size_t ulen = 0;
    terminal_writestring("Username: ");
    while(true) {
        char c = keyboard_getchar();
        if(c == '\n') { terminal_writestring("\r\n"); break; }
        else if(c == '\b') {
            if(ulen > 0) { ulen--; terminal_writestring("\b \b"); }
        } else if(ulen < user.length - 1) {
            user[ulen++] = c;
            terminal_putchar(c);
        }
    }
    user[ulen] = 0;

    char[32] pass;
    size_t plen = 0;
    terminal_writestring("Password: ");
    while(true) {
        char c = keyboard_getchar();
        if(c == '\n') { terminal_writestring("\r\n"); break; }
        else if(c == '\b') {
            if(plen > 0) { plen--; terminal_writestring("\b \b"); }
        } else if(plen < pass.length - 1) {
            pass[plen++] = c;
            terminal_putchar('*');
        }
    }
    pass[plen] = 0;

    const(char)* expected_user = "wcuser";
    const(char)* expected_pass = "wcpass";

    if(ulen == strlen(expected_user) && plen == strlen(expected_pass) &&
       memcmp(user.ptr, expected_user, ulen) == 0 &&
       memcmp(pass.ptr, expected_pass, plen) == 0)
    {
        terminal_writestring("Login successful\n");
        return true;
    }
    else
    {
        terminal_writestring("Invalid credentials\n");
        return false;
    }
}
