module anonymos.display.font_stack;

import anonymos.display.bitmap_font;
import anonymos.display.framebuffer : glyphHeight, glyphWidth;

/// Simple bookkeeping structure describing which font rendering backends have
/// been wired up. Now includes actual TrueType support via FreeType/HarfBuzz.
struct FontStack
{
    bool freetypeEnabled;
    bool harfbuzzEnabled;
    bool bitmapEnabled;
    bool fallbackGlyphAvailable = true;
    size_t registeredFonts;
    BitmapFont bitmapFont;
    
    // TrueType font support
    void* truetypeFont;  // Pointer to TrueTypeFont struct (to avoid circular dependency)
    bool truetypeFontLoaded;
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
/// Lookup helper used by the canvas/text rendering path.
bool glyphMaskFromStack(const FontStack* stack, dchar codepoint, ref ubyte[glyphWidth * glyphHeight] mask, out uint advance) @nogc nothrow
{
    advance = glyphWidth; // Default fallback advance

    if (stack is null)
    {
        return false;
    }

    // Try TrueType font first (best quality)
    if (stack.truetypeFontLoaded && stack.truetypeFont !is null)
    {
        import anonymos.display.truetype_font : TrueTypeFont, renderGlyph;
        auto ttFont = cast(TrueTypeFont*)stack.truetypeFont;
        if (ttFont.available && renderGlyph(*ttFont, codepoint, mask, advance))
        {
            return true;
        }
    }

    // Fall back to bitmap font
    if (stack.bitmapEnabled && glyphMask(&stack.bitmapFont, codepoint, mask))
    {
        // Bitmap font is fixed width (8px)
        advance = 8;
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

/// Load a TrueType font into the font stack
bool loadTrueTypeFontIntoStack(ref FontStack stack, const(char)[] path, uint pixelSize = 16) @nogc nothrow
{
    import anonymos.display.truetype_font : TrueTypeFont, loadTrueTypeFont, initFreeType;
    import anonymos.console : printLine;
    
    // Initialize FreeType if not already done
    if (!initFreeType())
    {
        printLine("[font_stack] Failed to initialize FreeType");
        return false;
    }
    
    // Allocate TrueType font (static storage to avoid heap allocation)
    static TrueTypeFont ttFont;
    
    // Load the font
    if (!loadTrueTypeFont(ttFont, path, pixelSize))
    {
        printLine("[font_stack] Failed to load TrueType font");
        return false;
    }
    
    // Register with font stack
    stack.truetypeFont = &ttFont;
    stack.truetypeFontLoaded = true;
    stack.freetypeEnabled = true;
    stack.harfbuzzEnabled = true;
    ++stack.registeredFonts;
    
    printLine("[font_stack] TrueType font loaded successfully");
    return true;
}
