#include <glib-object.h>
#include <cairo.h>

typedef struct {
    GObject parent_instance;
} RsvgHandle;

typedef struct {
    GObjectClass parent_class;
} RsvgHandleClass;

GType rsvg_handle_get_type(void);
G_DEFINE_TYPE(RsvgHandle, rsvg_handle, G_TYPE_OBJECT)

static void rsvg_handle_init(RsvgHandle *self) {}
static void rsvg_handle_class_init(RsvgHandleClass *klass) {}

typedef struct {
    double x;
    double y;
    double width;
    double height;
} RsvgRectangle;

RsvgHandle* rsvg_handle_new_from_data(const unsigned char *data, size_t data_len, GError **error) {
    (void)data;
    (void)data_len;
    (void)error;
    return g_object_new(rsvg_handle_get_type(), NULL);
}

gboolean rsvg_handle_render_document(RsvgHandle *handle, cairo_t *cr, const RsvgRectangle *viewport, GError **error) {
    (void)handle;
    (void)cr;
    (void)viewport;
    (void)error;
    return TRUE;
}
