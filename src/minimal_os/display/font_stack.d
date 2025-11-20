module minimal_os.display.font_stack;

/// Simple bookkeeping structure describing which font rendering backends have
/// been wired up. Real integrations would link against FreeType and HarfBuzz,
/// but this scaffold lets the kernel track readiness and provides a single
/// status object for the desktop to consult.
struct FontStack
{
    bool freetypeEnabled;
    bool harfbuzzEnabled;
    bool fallbackGlyphAvailable = true;
    size_t registeredFonts;
}

/// Initialize the stack with only the built-in fallback glyph renderer.
FontStack createFallbackOnlyFontStack() @nogc nothrow
{
    FontStack stack;
    stack.fallbackGlyphAvailable = true;
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

    return stack.freetypeEnabled && stack.harfbuzzEnabled && stack.registeredFonts > 0;
}
