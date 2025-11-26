module anonymos.display.wallpaper_builtin;

import anonymos.display.wallpaper_types;

nothrow:
@nogc:

// Simple built-in wallpaper so the desktop still looks polished when no
// custom image has been provided. This is intentionally tiny so it does not
// bloat the binary; it will be scaled to the framebuffer at runtime.
enum uint wallpaperWidth  = 8;
enum uint wallpaperHeight = 8;

enum uint[] wallpaperFrameDurations = [100];

enum uint[] wallpaperFrame0 = [
    0xFF2E1F47, 0xFF352353, 0xFF3B275F, 0xFF422C6B, 0xFF483078, 0xFF4F3584, 0xFF563990, 0xFF5C3E9C,
    0xFF2E1F47, 0xFF332350, 0xFF39275A, 0xFF3E2C64, 0xFF442F6F, 0xFF4A3379, 0xFF503883, 0xFF573C8E,
    0xFF2E1F47, 0xFF32234E, 0xFF372758, 0xFF3B2B61, 0xFF402F6B, 0xFF453475, 0xFF4B387F, 0xFF503C88,
    0xFF2E1F47, 0xFF31234C, 0xFF352755, 0xFF392B5E, 0xFF3D2F67, 0xFF423470, 0xFF463879, 0xFF4B3C82,
    0xFF2E1F47, 0xFF30234A, 0xFF332753, 0xFF372B5B, 0xFF3A2F64, 0xFF3E336C, 0xFF423875, 0xFF463C7E,
    0xFF2E1F47, 0xFF2F2348, 0xFF322751, 0xFF342B59, 0xFF372F61, 0xFF3B336A, 0xFF3E3772, 0xFF423B7B,
    0xFF2E1F47, 0xFF2F2347, 0xFF312750, 0xFF332B58, 0xFF352F60, 0xFF382F68, 0xFF3B346F, 0xFF3E3877,
    0xFF2E1F47, 0xFF2F2347, 0xFF31274E, 0xFF322B56, 0xFF332F5D, 0xFF353365, 0xFF38376C, 0xFF3A3B73,
];

enum const(uint[])[] wallpaperFrames = [wallpaperFrame0];
