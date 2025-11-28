module anonymos.display.harfbuzz_bindings;

// Minimal HarfBuzz bindings for kernel use
// Based on HarfBuzz API

import anonymos.display.freetype_bindings : FT_Face;

extern(C) @nogc nothrow:

// Opaque types
struct hb_blob_t;
struct hb_face_t;
struct hb_font_t;
struct hb_buffer_t;
struct hb_feature_t;

// Basic types
alias hb_codepoint_t = uint;
alias hb_position_t = int;
alias hb_mask_t = uint;
alias hb_bool_t = int;
alias hb_tag_t = uint;

// Direction
enum hb_direction_t : uint
{
    HB_DIRECTION_INVALID = 0,
    HB_DIRECTION_LTR = 4,
    HB_DIRECTION_RTL,
    HB_DIRECTION_TTB,
    HB_DIRECTION_BTT
}

// Script
alias hb_script_t = uint;
enum : hb_script_t
{
    HB_SCRIPT_COMMON = 0x5A797979,  // 'Zyyy'
    HB_SCRIPT_LATIN  = 0x4C61746E,  // 'Latn'
}

// Language
struct hb_language_impl_t;
alias hb_language_t = const(hb_language_impl_t)*;

// Glyph info
struct hb_glyph_info_t
{
    hb_codepoint_t codepoint;
    hb_mask_t mask;
    uint cluster;
    uint var1;
    uint var2;
}

// Glyph position
struct hb_glyph_position_t
{
    hb_position_t x_advance;
    hb_position_t y_advance;
    hb_position_t x_offset;
    hb_position_t y_offset;
    uint var;
}

// Buffer content type
enum hb_buffer_content_type_t : uint
{
    HB_BUFFER_CONTENT_TYPE_INVALID = 0,
    HB_BUFFER_CONTENT_TYPE_UNICODE,
    HB_BUFFER_CONTENT_TYPE_GLYPHS
}

// Buffer cluster level
enum hb_buffer_cluster_level_t : uint
{
    HB_BUFFER_CLUSTER_LEVEL_MONOTONE_GRAPHEMES = 0,
    HB_BUFFER_CLUSTER_LEVEL_MONOTONE_CHARACTERS = 1,
    HB_BUFFER_CLUSTER_LEVEL_CHARACTERS = 2,
    HB_BUFFER_CLUSTER_LEVEL_DEFAULT = HB_BUFFER_CLUSTER_LEVEL_MONOTONE_GRAPHEMES
}

// Core HarfBuzz functions

// Buffer management
hb_buffer_t* hb_buffer_create();
void hb_buffer_destroy(hb_buffer_t* buffer);
void hb_buffer_reset(hb_buffer_t* buffer);
void hb_buffer_clear_contents(hb_buffer_t* buffer);
void hb_buffer_set_direction(hb_buffer_t* buffer, hb_direction_t direction);
hb_direction_t hb_buffer_get_direction(hb_buffer_t* buffer);
void hb_buffer_set_script(hb_buffer_t* buffer, hb_script_t script);
hb_script_t hb_buffer_get_script(hb_buffer_t* buffer);
void hb_buffer_set_language(hb_buffer_t* buffer, hb_language_t language);
hb_language_t hb_buffer_get_language(hb_buffer_t* buffer);
void hb_buffer_add_utf8(hb_buffer_t* buffer, const(char)* text, int text_length, uint item_offset, int item_length);
void hb_buffer_add_codepoints(hb_buffer_t* buffer, const(hb_codepoint_t)* text, int text_length, uint item_offset, int item_length);
uint hb_buffer_get_length(hb_buffer_t* buffer);
hb_glyph_info_t* hb_buffer_get_glyph_infos(hb_buffer_t* buffer, uint* length);
hb_glyph_position_t* hb_buffer_get_glyph_positions(hb_buffer_t* buffer, uint* length);

// Font/Face management
hb_face_t* hb_face_create(hb_blob_t* blob, uint index);
void hb_face_destroy(hb_face_t* face);
hb_font_t* hb_font_create(hb_face_t* face);
void hb_font_destroy(hb_font_t* font);
void hb_font_set_scale(hb_font_t* font, int x_scale, int y_scale);
void hb_font_set_ppem(hb_font_t* font, uint x_ppem, uint y_ppem);

// FreeType integration
hb_font_t* hb_ft_font_create(FT_Face ft_face, void* destroy);
hb_font_t* hb_ft_font_create_referenced(FT_Face ft_face);
void hb_ft_font_set_funcs(hb_font_t* font);
void hb_ft_font_set_load_flags(hb_font_t* font, int load_flags);
int hb_ft_font_get_load_flags(hb_font_t* font);

// Shaping
void hb_shape(hb_font_t* font, hb_buffer_t* buffer, const(hb_feature_t)* features, uint num_features);

// Language
hb_language_t hb_language_from_string(const(char)* str, int len);
const(char)* hb_language_to_string(hb_language_t language);
hb_language_t hb_language_get_default();

// Blob (for loading font data)
hb_blob_t* hb_blob_create(const(char)* data, uint length, int memory_mode, void* user_data, void* destroy);
void hb_blob_destroy(hb_blob_t* blob);

// Memory modes for blob
enum : int
{
    HB_MEMORY_MODE_DUPLICATE = 0,
    HB_MEMORY_MODE_READONLY,
    HB_MEMORY_MODE_WRITABLE,
    HB_MEMORY_MODE_READONLY_MAY_MAKE_WRITABLE
}
