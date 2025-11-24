module minimal_os.display.font_stack;

import minimal_os.display.bitmap_font;
import minimal_os.display.framebuffer : glyphHeight, glyphWidth;

/// Simple bookkeeping structure describing which font rendering backends have
/// been wired up. Real integrations would link against FreeType and HarfBuzz,
/// but this scaffold lets the kernel track readiness and provides a single
/// status object for the desktop to consult.
struct FontStack
{
    bool freetypeEnabled;
    bool harfbuzzEnabled;
    bool bitmapEnabled;
    bool fallbackGlyphAvailable = true;
    size_t registeredFonts;
    BitmapFont bitmapFont;
}

/// Initialize the stack with only the built-in fallback glyph renderer.
FontStack createFallbackOnlyFontStack() @nogc nothrow
{
    FontStack stack;
    stack.fallbackGlyphAvailable = true;
    stack.bitmapFont = createBuiltInBitmapFont();
    stack.bitmapEnabled = stack.bitmapFont.available;
    if (stack.bitmapEnabled)
    {
        stack.registeredFonts = 1;
    }
    return stack;
}

/// Record that a FreeType-like vector rasterizer is online.
void enableFreetype(ref FontStack stack) @nogc nothrow
{
    stack.freetypeEnabled = true;
}

/// Record that a HarfBuzz-like shaping engine is available. In practice this
/// would be gated on FreeType, but the function exists to keep call sites
/// explicit about expectations.
void enableHarfBuzz(ref FontStack stack) @nogc nothrow
{
    stack.harfbuzzEnabled = true;
}

/// Register a bitmap font. This satisfies the font availability requirement
/// for simple UTF-8 rendering paths when vector engines are absent.
bool registerBitmapFont(ref FontStack stack, BitmapFont font) @nogc nothrow
{
    if (!font.available)
    {
        return false;
    }

    stack.bitmapFont = font;
    stack.bitmapEnabled = true;
    ++stack.registeredFonts;
    return true;
}

/// Register an additional font face. The implementation is intentionally
/// minimal: the goal is to avoid hardcoding a single glyph bitmap.
void registerFont(ref FontStack stack) @nogc nothrow
{
    ++stack.registeredFonts;
}

/// Determine whether higher-level rendering APIs can rely on proper font
/// support. For now we consider the stack ready if both engines are marked as
/// enabled and at least one font has been registered.
bool fontStackReady(const FontStack* stack) @nogc nothrow
{
    if (stack is null)
    {
        return false;
    }

    const bool vectorReady = stack.freetypeEnabled && stack.harfbuzzEnabled && stack.registeredFonts > 0;
    const bool bitmapReady = stack.bitmapEnabled && stack.registeredFonts > 0;
    return vectorReady || bitmapReady;
}

/// Lookup helper used by the canvas/text rendering path.
bool glyphMaskFromStack(const FontStack* stack, dchar codepoint, ref ubyte[glyphWidth * glyphHeight] mask) @nogc nothrow
{
    if (stack is null)
    {
        return false;
    }

    if (stack.bitmapEnabled && glyphMask(&stack.bitmapFont, codepoint, mask))
    {
        return true;
    }

    if (!stack.fallbackGlyphAvailable)
    {
        return false;
    }

    // Paint a simple box glyph if all other paths failed.
    foreach (row; 0 .. glyphHeight)
    {
        const ubyte bits = (row == 0 || row == glyphHeight - 1) ? 0xFF : 0x81;
        foreach (col; 0 .. glyphWidth)
        {
            const maskBit = cast(ubyte)(0x01 << col);
            mask[row * glyphWidth + col] = (bits & maskBit) ? 0xFF : 0x00;
        }
    }

    return true;
}

/// Module-level shared stack so UI helpers can draw text without having to
/// construct their own font registry first.
FontStack* activeFontStack() @nogc nothrow
{
    static FontStack stack;
    static bool initialized;
    if (!initialized)
    {
        stack = createFallbackOnlyFontStack();
        initialized = true;
    }
    return &stack;
}
