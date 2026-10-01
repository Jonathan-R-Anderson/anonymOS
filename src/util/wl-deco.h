// wl-deco.h — what was the shared client-side window-control buttons (minimize / maximize /
// close) for the EpinAnonymOS cairo-on-pixel-buffer Wayland clients; see below.
//
// These clients (wl-files, wl-domain-manager) render into a uint32 XRGB buffer
// (app->pixels). This header overlays the three window buttons at the top-right
// of that buffer and hit-tests pointer clicks against them — without disturbing
// the client's existing layout. The titlebar/drag is handled by the client (a
// press in its top header strip starts an xdg_toplevel_move grab).
//
// (wl-term has its own inline version because it is a raw-pixel + FreeType
// terminal with a full dedicated titlebar.)
#ifndef WL_DECO_H
#define WL_DECO_H
#include <stdint.h>

#define DECO_BTN_H 22          // button strip height (px), measured from the top edge

static inline void wl_deco_put(uint32_t *px, int stride, int W, int H, int x, int y, uint32_t c) {
    if (x < 0 || y < 0 || x >= W || y >= H) return;
    px[y * stride + x] = c;
}
static inline void wl_deco_fill(uint32_t *px, int stride, int W, int H,
                                int x0, int y0, int w, int h, uint32_t c) {
    for (int y = y0; y < y0 + h; y++)
        for (int x = x0; x < x0 + w; x++)
            wl_deco_put(px, stride, W, H, x, y, c);
}
// The window controls are the COMPOSITOR's now (2026-10-01): every window has a titlebar in its
// domain's colour with minimize / maximize / close (deps/hyprland CHosTitleBarDecoration), so a
// client drawing its own set would show two.  These stay as no-ops for the clients that call them:
// nothing is drawn (the returned x is the right edge), and no click is ever a control.
static inline int wl_deco_draw(uint32_t *px, int stride, int W, int H, uint32_t fg) {
    (void)px; (void)stride; (void)H; (void)fg;
    return W;
}
static inline int wl_deco_hit(double x, double y, int W) {
    (void)x; (void)y; (void)W;
    return 0;
}
#endif
