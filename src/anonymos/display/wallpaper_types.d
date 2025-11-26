module anonymos.display.wallpaper_types;

nothrow:
@nogc:

alias FramePixels = const(uint)[];

struct WallpaperData
{
    uint width;
    uint height;
    const(uint)[] frameDurationsMs;
    FramePixels[] frames;
}

