/*
 * Minimal <librsvg/rsvg.h> for the HanonymOS librsvg stub.
 *
 * A full librsvg needs the Rust toolchain, which we cannot run in the cross
 * sysroot, so hyprgraphics/hyprcursor link against librsvg_stub.c instead.
 * This header declares exactly the subset of the librsvg API that those stubs
 * implement, with matching signatures, wrapped in extern "C" so the C++ callers
 * resolve the unmangled C symbols from the stub archive.
 */
#ifndef HOS_LIBRSVG_STUB_RSVG_H
#define HOS_LIBRSVG_STUB_RSVG_H

#include <glib-object.h>
#include <cairo.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _RsvgHandle RsvgHandle;

typedef struct _RsvgRectangle {
    double x;
    double y;
    double width;
    double height;
} RsvgRectangle;

typedef enum {
    RSVG_HANDLE_FLAGS_NONE = 0
} RsvgHandleFlags;

GType       rsvg_handle_get_type(void);
RsvgHandle* rsvg_handle_new_from_data(const unsigned char* data, unsigned long data_len, GError** error);
RsvgHandle* rsvg_handle_new_from_stream_sync(void* stream, void* base_file, RsvgHandleFlags flags, void* cancellable, GError** error);
int         rsvg_handle_render_document(RsvgHandle* handle, cairo_t* cr, const RsvgRectangle* viewport, GError** error);
void        rsvg_handle_get_intrinsic_dimensions(RsvgHandle* handle, void* out_has_width, void* out_width, void* out_has_height, void* out_height, void* out_has_viewbox, void* out_viewbox);
int         rsvg_handle_get_intrinsic_size_in_pixels(RsvgHandle* handle, double* out_width, double* out_height);

#ifdef __cplusplus
}
#endif

#endif /* HOS_LIBRSVG_STUB_RSVG_H */
