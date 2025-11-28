module anonymos.display.truetype_font;

import anonymos.display.freetype_bindings;
import anonymos.display.harfbuzz_bindings;
import anonymos.display.framebuffer : glyphWidth, glyphHeight;

@nogc nothrow:

/// TrueType font face loaded via FreeType
struct TrueTypeFont
{
    FT_Face ftFace;
    hb_font_t* hbFont;
    bool available;
    uint pixelSize;
    char[256] path;
}

/// Global FreeType library instance
private __gshared FT_Library g_ftLibrary;
private __gshared bool g_ftInitialized = false;

/// Initialize FreeType library
bool initFreeType() @nogc nothrow
{
    if (g_ftInitialized)
        return true;
    
    FT_Error error = FT_Init_FreeType(&g_ftLibrary);
    if (error != 0)
    {
        import anonymos.console : print, printLine, printUnsigned;
        print("[freetype] Failed to initialize FreeType, error: ");
        printUnsigned(cast(uint)error);
        printLine("");
        return false;
    }
    
    g_ftInitialized = true;
    
    import anonymos.console : printLine;
    printLine("[freetype] FreeType initialized successfully");
    return true;
}

/// Load a TrueType font from a file path
bool loadTrueTypeFont(ref TrueTypeFont font, const(char)[] path, uint pixelSize = 16) @nogc nothrow
{
    import anonymos.console : print, printLine, printUnsigned;
    import anonymos.fs : readFile;
    
    if (!g_ftInitialized)
    {
        if (!initFreeType())
            return false;
    }
    
    // Copy path to font struct (null-terminated)
    size_t len = path.length < 255 ? path.length : 255;
    foreach (i; 0 .. len)
        font.path[i] = path[i];
    font.path[len] = '\0';
    
    // Read file from VFS
    // readFile expects null-terminated C string
    const(ubyte)[] data = readFile(font.path.ptr);
    
    if (data is null)
    {
        // Try stripping leading '/' if present (VFS might store without it)
        if (len > 1 && font.path[0] == '/')
        {
            data = readFile(font.path.ptr + 1);
        }
    }
    
    if (data is null)
    {
        print("[freetype] Failed to read font file: ");
        printLine(path);
        return false;
    }
    
    // Load from memory
    // Note: The data pointer from readFile points to persistent VMO memory, so it's safe to keep.
    return loadTrueTypeFontFromMemory(font, data, pixelSize);
}

/// Load a TrueType font from memory
bool loadTrueTypeFontFromMemory(ref TrueTypeFont font, const(ubyte)[] data, uint pixelSize = 16) @nogc nothrow
{
    import anonymos.console : print, printLine, printUnsigned;
    
    if (!g_ftInitialized)
    {
        if (!initFreeType())
            return false;
    }
    
    // Load the font face from memory
    FT_Error error = FT_New_Memory_Face(g_ftLibrary, data.ptr, cast(FT_Long)data.length, 0, &font.ftFace);
    if (error != 0)
    {
        print("[freetype] Failed to load font from memory, error: ");
        printUnsigned(cast(uint)error);
        printLine("");
        return false;
    }
    
    // Set pixel size
    error = FT_Set_Pixel_Sizes(font.ftFace, 0, pixelSize);
    if (error != 0)
    {
        print("[freetype] Failed to set pixel size: ");
        printUnsigned(pixelSize);
        printLine("");
        FT_Done_Face(font.ftFace);
        return false;
    }
    
    // Create HarfBuzz font from FreeType face
    font.hbFont = hb_ft_font_create_referenced(font.ftFace);
    if (font.hbFont is null)
    {
        printLine("[harfbuzz] Failed to create HarfBuzz font");
        FT_Done_Face(font.ftFace);
        return false;
    }
    
    font.pixelSize = pixelSize;
    font.available = true;
    
    printLine("[freetype] Loaded font from memory");
    return true;
}

/// Unload a TrueType font
void unloadTrueTypeFont(ref TrueTypeFont font) @nogc nothrow
{
    if (!font.available)
        return;
    
    if (font.hbFont !is null)
    {
        hb_font_destroy(font.hbFont);
        font.hbFont = null;
    }
    
    if (font.ftFace !is null)
    {
        FT_Done_Face(font.ftFace);
        font.ftFace = null;
    }
    
    font.available = false;
}

/// Render a single glyph to a bitmap
bool renderGlyph(ref TrueTypeFont font, dchar codepoint, ref ubyte[glyphWidth * glyphHeight] mask) @nogc nothrow
{
    if (!font.available)
        return false;
    
    // Get glyph index
    FT_UInt glyphIndex = FT_Get_Char_Index(font.ftFace, cast(FT_ULong)codepoint);
    if (glyphIndex == 0)
        return false;  // Glyph not found
    
    // Load and render the glyph
    FT_Error error = FT_Load_Glyph(font.ftFace, glyphIndex, FT_LOAD_RENDER | FT_LOAD_MONOCHROME);
    if (error != 0)
        return false;
    
    FT_GlyphSlot slot = font.ftFace.glyph;
    FT_Bitmap* bitmap = &slot.bitmap;
    
    // Clear the mask
    foreach (ref b; mask)
        b = 0;
    
    // Copy bitmap to mask (handle monochrome 1-bit bitmap)
    if (bitmap.pixel_mode == FT_Pixel_Mode.FT_PIXEL_MODE_MONO)
    {
        for (uint row = 0; row < bitmap.rows && row < glyphHeight; row++)
        {
            for (uint col = 0; col < bitmap.width && col < glyphWidth; col++)
            {
                uint byteIndex = row * bitmap.pitch + (col / 8);
                uint bitIndex = 7 - (col % 8);
                ubyte bit = (bitmap.buffer[byteIndex] >> bitIndex) & 1;
                mask[row * glyphWidth + col] = bit ? 0xFF : 0x00;
            }
        }
    }
    // Handle 8-bit grayscale
    else if (bitmap.pixel_mode == FT_Pixel_Mode.FT_PIXEL_MODE_GRAY)
    {
        for (uint row = 0; row < bitmap.rows && row < glyphHeight; row++)
        {
            for (uint col = 0; col < bitmap.width && col < glyphWidth; col++)
            {
                uint index = row * bitmap.pitch + col;
                mask[row * glyphWidth + col] = bitmap.buffer[index];
            }
        }
    }
    
    return true;
}

/// Shape text using HarfBuzz and return glyph info
struct ShapedText
{
    hb_glyph_info_t[256] glyphs;
    hb_glyph_position_t[256] positions;
    uint count;
}

bool shapeText(ref TrueTypeFont font, const(char)[] text, ref ShapedText result) @nogc nothrow
{
    if (!font.available || font.hbFont is null)
        return false;
    
    // Create HarfBuzz buffer
    hb_buffer_t* buffer = hb_buffer_create();
    if (buffer is null)
        return false;
    
    // Set buffer properties
    hb_buffer_set_direction(buffer, hb_direction_t.HB_DIRECTION_LTR);
    hb_buffer_set_script(buffer, HB_SCRIPT_LATIN);
    hb_buffer_set_language(buffer, hb_language_from_string("en".ptr, 2));
    
    // Add text to buffer
    hb_buffer_add_utf8(buffer, text.ptr, cast(int)text.length, 0, cast(int)text.length);
    
    // Shape the text
    hb_shape(font.hbFont, buffer, null, 0);
    
    // Get shaped glyphs
    uint length;
    hb_glyph_info_t* infos = hb_buffer_get_glyph_infos(buffer, &length);
    hb_glyph_position_t* positions = hb_buffer_get_glyph_positions(buffer, &length);
    
    // Copy results (limit to array size)
    result.count = length < 256 ? length : 256;
    foreach (i; 0 .. result.count)
    {
        result.glyphs[i] = infos[i];
        result.positions[i] = positions[i];
    }
    
    // Clean up
    hb_buffer_destroy(buffer);
    
    return true;
}
