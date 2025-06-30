module user.lib.termgl;

/**
 * Minimal placeholder implementation inspired by TermGL.
 * Provides simple routines to draw colored rectangles
 * in terminal using ANSI escape codes. This is not a
 * full port of the C++ library, but offers a small
 * subset for demonstration purposes.
 */

import std.stdio;

alias Color = string;

struct Vec2i {
    int x;
    int y;
}

/// Clear terminal screen
void tgClearScreen() {
    write("\033[2J\033[H");
}

/// Draw a filled rectangle at position with size and color
void tgFillRect(Vec2i pos, Vec2i size, Color fg, Color bg) {
    foreach(y; 0 .. size.y) {
        writef("\033[%d;%dH", pos.y + y + 1, pos.x + 1);
        auto line = "";
        foreach(x; 0 .. size.x) {
            line ~= " ";
        }
        // Set foreground/background then print line
        writef("\033[48;5;%sm\033[38;5;%sm%s\033[0m",
               bg, fg, line);
    }
}
