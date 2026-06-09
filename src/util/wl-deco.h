// wl-deco.h — shared client-side window-control buttons (minimize / maximize /
// close) for the EpinAnonymOS cairo-on-pixel-buffer Wayland clients.
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
// Draw minimize (—), maximize (□), close (✕) at the top-right. Returns the x of
// the leftmost (minimize) button so callers can keep their own chrome clear of it.
static inline int wl_deco_draw(uint32_t *px, int stride, int W, int H, uint32_t fg) {
    const int w = DECO_BTN_H, pad = DECO_BTN_H / 3;
    const int closex = W - w, maxx = W - 2 * w, minx = W - 3 * w;
    // minimize: a horizontal bar near the bottom
    wl_deco_fill(px, stride, W, H, minx + pad, DECO_BTN_H - pad - 2, w - 2 * pad, 2, fg);
    // maximize: a hollow square
    {
        int x0 = maxx + pad, y0 = pad, s = DECO_BTN_H - 2 * pad;
        wl_deco_fill(px, stride, W, H, x0, y0, s, 1, fg);
        wl_deco_fill(px, stride, W, H, x0, y0 + s - 1, s, 1, fg);
        wl_deco_fill(px, stride, W, H, x0, y0, 1, s, fg);
        wl_deco_fill(px, stride, W, H, x0 + s - 1, y0, 1, s, fg);
    }
    // close: an X (two diagonals)
    {
        int x0 = closex + pad, y0 = pad, s = DECO_BTN_H - 2 * pad;
        for (int i = 0; i < s; i++) {
            wl_deco_put(px, stride, W, H, x0 + i, y0 + i, fg);
            wl_deco_put(px, stride, W, H, x0 + s - 1 - i, y0 + i, fg);
        }
    }
    return minx;
}
// Hit-test a pointer (surface coords) against the button strip: 0=none, 2=min, 3=max, 4=close.
static inline int wl_deco_hit(double x, double y, int W) {
    if (y < 0 || y >= DECO_BTN_H) return 0;
    const int w = DECO_BTN_H;
    if (x >= W - w)     return 4;
    if (x >= W - 2 * w) return 3;
    if (x >= W - 3 * w) return 2;
    return 0;
}
#endif
