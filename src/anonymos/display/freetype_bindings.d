module anonymos.display.freetype_bindings;

// Minimal FreeType bindings for kernel use
// Based on FreeType 2.x API

extern(C) @nogc nothrow:

import core.stdc.config;

// Opaque types
// Additional types
alias FT_String = char;

struct FT_Bitmap_Size
{
    FT_Short  height;
    FT_Short  width;
    FT_Pos    size;
    FT_Pos    x_ppem;
    FT_Pos    y_ppem;
}

struct FT_CharMapRec;
alias FT_CharMap = FT_CharMapRec*;

struct FT_Generic
{
    void*  data;
    void*  finalizer;
}

struct FT_BBox
{
    FT_Pos  xMin, yMin;
    FT_Pos  xMax, yMax;
}

struct FT_Outline
{
    short       n_contours;
    short       n_points;
    FT_Vector*  points;
    char*       tags;
    short*      contours;
    int         flags;
}

struct FT_SubGlyphRec;
alias FT_SubGlyph = FT_SubGlyphRec*;

// Struct definitions
struct FT_LibraryRec;
alias FT_Library = FT_LibraryRec*;

struct FT_FaceRec
{
    FT_Long           num_faces;
    FT_Long           face_index;

    FT_Long           face_flags;
    FT_Long           style_flags;

    FT_Long           num_glyphs;

    FT_String*        family_name;
    FT_String*        style_name;

    FT_Int            num_fixed_sizes;
    FT_Bitmap_Size*   available_sizes;

    FT_Int            num_charmaps;
    FT_CharMap*       charmaps;

    FT_Generic        generic;

    FT_BBox           bbox;

    FT_UShort         units_per_EM;
    FT_Short          ascender;
    FT_Short          descender;
    FT_Short          height;

    FT_Short          max_advance_width;
    FT_Short          max_advance_height;

    FT_Short          underline_position;
    FT_Short          underline_thickness;

    FT_GlyphSlot      glyph;
    FT_Size           size;
    FT_CharMap        charmap;

    /* private fields */
    void*             driver;
    void*             memory;
    void*             stream;

    void*             sizes_list_head;
    void*             sizes_list_tail;

    FT_Generic        autohint;
    void*             extensions;

    void*             internal;
}
alias FT_Face = FT_FaceRec*;

struct FT_GlyphSlotRec
{
    FT_Library        library;
    FT_Face           face;
    FT_GlyphSlot      next;
    FT_UInt           reserved;
    FT_Generic        generic;

    FT_Glyph_Metrics  metrics;
    FT_Fixed          linearHoriAdvance;
    FT_Fixed          linearVertAdvance;
    FT_Vector         advance;

    FT_Glyph_Format   format;

    FT_Bitmap         bitmap;
    FT_Int            bitmap_left;
    FT_Int            bitmap_top;

    FT_Outline        outline;

    FT_UInt           num_subglyphs;
    FT_SubGlyph       subglyphs;

    void*             control_data;
    c_long            control_len;

    FT_Pos            lsb_delta;
    FT_Pos            rsb_delta;

    void*             other;

    void*             internal;
}
alias FT_GlyphSlot = FT_GlyphSlotRec*;

struct FT_SizeRec;
alias FT_Size = FT_SizeRec*;

// Basic types
alias FT_Error = int;
alias FT_Long = c_long;
alias FT_ULong = c_ulong;
alias FT_Int = int;
alias FT_UInt = uint;
alias FT_Short = short;
alias FT_UShort = ushort;
alias FT_Byte = ubyte;
alias FT_Bool = ubyte;
alias FT_Fixed = c_long;
alias FT_Pos = c_long;

// Glyph formats
enum FT_Glyph_Format : uint
{
    FT_GLYPH_FORMAT_NONE      = 0,
    FT_GLYPH_FORMAT_COMPOSITE = 0x636F6D70,  // 'comp'
    FT_GLYPH_FORMAT_BITMAP    = 0x62697473,  // 'bits'
    FT_GLYPH_FORMAT_OUTLINE   = 0x6F75746C,  // 'outl'
    FT_GLYPH_FORMAT_PLOTTER   = 0x706C6F74   // 'plot'
}

// Pixel modes
enum FT_Pixel_Mode : ubyte
{
    FT_PIXEL_MODE_NONE = 0,
    FT_PIXEL_MODE_MONO,
    FT_PIXEL_MODE_GRAY,
    FT_PIXEL_MODE_GRAY2,
    FT_PIXEL_MODE_GRAY4,
    FT_PIXEL_MODE_LCD,
    FT_PIXEL_MODE_LCD_V,
    FT_PIXEL_MODE_BGRA
}

// Load flags
enum FT_LOAD_DEFAULT                  = 0x0;
enum FT_LOAD_NO_SCALE                 = 0x1;
enum FT_LOAD_NO_HINTING               = 0x2;
enum FT_LOAD_RENDER                   = 0x4;
enum FT_LOAD_NO_BITMAP                = 0x8;
enum FT_LOAD_VERTICAL_LAYOUT          = 0x10;
enum FT_LOAD_FORCE_AUTOHINT           = 0x20;
enum FT_LOAD_CROP_BITMAP              = 0x40;
enum FT_LOAD_PEDANTIC                 = 0x80;
enum FT_LOAD_IGNORE_GLOBAL_ADVANCE_WIDTH = 0x200;
enum FT_LOAD_NO_RECURSE               = 0x400;
enum FT_LOAD_IGNORE_TRANSFORM         = 0x800;
enum FT_LOAD_MONOCHROME               = 0x1000;
enum FT_LOAD_LINEAR_DESIGN            = 0x2000;
enum FT_LOAD_NO_AUTOHINT              = 0x8000;
enum FT_LOAD_COLOR                    = 0x100000;
enum FT_LOAD_COMPUTE_METRICS          = 0x200000;
enum FT_LOAD_BITMAP_METRICS_ONLY      = 0x400000;

// Render modes
enum FT_Render_Mode : uint
{
    FT_RENDER_MODE_NORMAL = 0,
    FT_RENDER_MODE_LIGHT,
    FT_RENDER_MODE_MONO,
    FT_RENDER_MODE_LCD,
    FT_RENDER_MODE_LCD_V
}

// Vector
struct FT_Vector
{
    FT_Pos x;
    FT_Pos y;
}

// Bitmap
struct FT_Bitmap
{
    uint rows;
    uint width;
    int pitch;
    ubyte* buffer;
    ushort num_grays;
    ubyte pixel_mode;
    ubyte palette_mode;
    void* palette;
}

// Glyph metrics
struct FT_Glyph_Metrics
{
    FT_Pos width;
    FT_Pos height;
    FT_Pos horiBearingX;
    FT_Pos horiBearingY;
    FT_Pos horiAdvance;
    FT_Pos vertBearingX;
    FT_Pos vertBearingY;
    FT_Pos vertAdvance;
}

// Size metrics
struct FT_Size_Metrics
{
    FT_UShort x_ppem;
    FT_UShort y_ppem;
    FT_Fixed x_scale;
    FT_Fixed y_scale;
    FT_Pos ascender;
    FT_Pos descender;
    FT_Pos height;
    FT_Pos max_advance;
}

// Core FreeType functions
FT_Error FT_Init_FreeType(FT_Library* alibrary);
FT_Error FT_Done_FreeType(FT_Library library);
FT_Error FT_New_Face(FT_Library library, const(char)* filepathname, FT_Long face_index, FT_Face* aface);
FT_Error FT_New_Memory_Face(FT_Library library, const(FT_Byte)* file_base, FT_Long file_size, FT_Long face_index, FT_Face* aface);
FT_Error FT_Done_Face(FT_Face face);
FT_Error FT_Set_Char_Size(FT_Face face, FT_Fixed char_width, FT_Fixed char_height, FT_UInt horz_resolution, FT_UInt vert_resolution);
FT_Error FT_Set_Pixel_Sizes(FT_Face face, FT_UInt pixel_width, FT_UInt pixel_height);
FT_UInt FT_Get_Char_Index(FT_Face face, FT_ULong charcode);
FT_Error FT_Load_Glyph(FT_Face face, FT_UInt glyph_index, FT_Int load_flags);
FT_Error FT_Load_Char(FT_Face face, FT_ULong char_code, FT_Int load_flags);
FT_Error FT_Render_Glyph(FT_GlyphSlot slot, FT_Render_Mode render_mode);

// Helper to convert 26.6 fixed point to pixels
pragma(inline, true)
FT_Pos FT_CEIL(FT_Pos x)
{
    return ((x + 63) & -64);
}

pragma(inline, true)
FT_Pos FT_FLOOR(FT_Pos x)
{
    return (x & -64);
}

pragma(inline, true)
FT_Pos FT_PIX_FLOOR(FT_Pos x)
{
    return (x >> 6);
}

pragma(inline, true)
FT_Pos FT_PIX_CEIL(FT_Pos x)
{
    return FT_PIX_FLOOR(x + 63);
}
