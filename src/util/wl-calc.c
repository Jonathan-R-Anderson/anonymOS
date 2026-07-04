/*
 * wl-calc.c -- a native Wayland calculator for EpinAnonymOS.
 *
 * Reuses the proven wl-wifi-menu machinery VERBATIM: xdg-shell surface/registry setup, the
 * double-buffered wl_shm pool (create_buffers / buffer_release / redraw_commit), the COMPLETE
 * v5 wl_pointer listener, the wl_keyboard listener, init_freetype(), draw_text(), fill_rect(),
 * and the poll() main loop.  Only the drawn CONTENT and the input handling are new.
 *
 * Draws its own CSD chrome (Weston has no server-side decorations): a titlebar strip with the
 * app name + a red close box top-right (click -> exit).  A right-aligned display, a 4-column
 * button grid, and a correct precedence-aware evaluator (* and / bind tighter than + and -).
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <wayland-client.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include "xdg-shell-client-protocol.h"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

enum { WIN_W = 260, WIN_H = 360,
       TITLE_H = 26, DISP_Y = 26, DISP_H = 64, GRID_Y = 96,
       PAD = 9, GAP = 6, BW = 56, BH = 44 };

/* button kinds -> tint */
enum { K_NUM, K_OP, K_EQ, K_CLR };

struct app {
    struct wl_display *display;
    struct wl_registry *registry;
    struct wl_compositor *compositor;
    struct wl_shm *shm;
    struct wl_seat *seat;
    struct wl_keyboard *keyboard;
    struct wl_pointer *pointer;
    struct xdg_wm_base *wm_base;
    struct wl_surface *surface;
    struct xdg_surface *xdg_surface;
    struct xdg_toplevel *toplevel;
    struct { struct wl_buffer *wl; uint32_t *px; int busy; } bufs[2];  // double-buffered
    int configured, dirty;         // dirty = a redraw was deferred because both buffers were busy
    uint32_t *pixels;              // the buffer draw_calc()/draw_text() currently target
    FT_Library ft;
    FT_Face face;
    unsigned char *font_data;
    size_t font_size, buffer_size;
    int width, height, stride;
    int font_ready, running;
    double pointer_x, pointer_y;

    char entry[160];               // the expression being typed / the last result
    int  entrylen;
    int  error;                    // last '=' produced an error -> show "Error"
    int  shift;
    int  hover;                    // hovered button index (-1 none)
};

static void log_line(const char *s){ fputs(s, stdout); fputc('\n', stdout); fflush(stdout); }
static int create_memfd(const char *name){ return (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC); }

static int load_file(const char *path, unsigned char **out, size_t *out_size){
    int fd = open(path, O_RDONLY); if (fd < 0) return -1;
    size_t cap = 8192, n = 0; unsigned char *b = malloc(cap);
    if (!b){ close(fd); return -1; }
    for (;;){ if (n + 4096 > cap){ cap *= 2; unsigned char *nb = realloc(b, cap); if (!nb){ free(b); close(fd); return -1; } b = nb; }
        ssize_t r = read(fd, b + n, 4096); if (r <= 0) break; n += (size_t)r; }
    close(fd); *out = b; *out_size = n; return 0;
}
static int init_freetype(struct app *app){
    const char *path = "/usr/share/fonts/noto/NotoSans-Regular.ttf";
    if (load_file(path, &app->font_data, &app->font_size) < 0) return -1;
    if (FT_Init_FreeType(&app->ft) != 0) return -1;
    if (FT_New_Memory_Face(app->ft, app->font_data, (FT_Long)app->font_size, 0, &app->face) != 0) return -1;
    app->font_ready = 1; return 0;
}
static uint32_t blend_xrgb(uint32_t dst, uint32_t src, unsigned int a){
    if (a >= 255) return src; if (a == 0) return dst; unsigned int inv = 255 - a;
    unsigned int sr=(src>>16)&0xff,sg=(src>>8)&0xff,sb=src&0xff, dr=(dst>>16)&0xff,dg=(dst>>8)&0xff,db=dst&0xff;
    return 0xff000000u | (((sr*a+dr*inv+127)/255)<<16) | (((sg*a+dg*inv+127)/255)<<8) | ((sb*a+db*inv+127)/255);
}
static void draw_text(struct app *app, const char *text, int x, int y, int max_w, int px, uint32_t color){
    if (!app->font_ready || !text || max_w <= 0) return;
    if (FT_Set_Pixel_Sizes(app->face, 0, (FT_UInt)px) != 0) return;
    int baseline = px;
    if (app->face->size && app->face->size->metrics.ascender > 0) baseline = (int)(app->face->size->metrics.ascender >> 6);
    int pen_x = x, pen_y = y + baseline;
    for (const unsigned char *p = (const unsigned char*)text; *p; ++p){
        unsigned char ch = *p; if (ch < 0x20 || ch >= 0x7f) ch = '?';
        if (FT_Load_Char(app->face, ch, FT_LOAD_RENDER|FT_LOAD_TARGET_NORMAL) != 0) continue;
        FT_GlyphSlot g = app->face->glyph; int advance = (int)(g->advance.x >> 6);
        if (pen_x + advance > x + max_w) break;
        FT_Bitmap *bm = &g->bitmap; int gx = pen_x + g->bitmap_left, gy = pen_y - g->bitmap_top;
        int pitch = bm->pitch; const unsigned char *base = bm->buffer;
        if (pitch < 0){ pitch = -pitch; base = bm->buffer - (int)(bm->rows-1)*pitch; }
        for (int row = 0; row < (int)bm->rows; row++){ int pyp = gy+row; if (pyp<0||pyp>=app->height) continue;
            const unsigned char *sr = base + row*pitch;
            for (int col = 0; col < (int)bm->width; col++){ int pxp = gx+col; if (pxp<0||pxp>=app->width) continue;
                unsigned int alpha = (bm->pixel_mode==FT_PIXEL_MODE_GRAY) ? sr[col]
                                   : ((sr[col>>3] & (0x80>>(col&7))) ? 255 : 0);
                uint32_t *d = &app->pixels[pyp*app->width+pxp]; *d = blend_xrgb(*d, color, alpha); } }
        pen_x += advance;
    }
}
static void fill_rect(struct app *app, int x, int y, int w, int h, uint32_t c){
    for (int j=y;j<y+h;j++){ if (j<0||j>=app->height) continue;
        for (int i=x;i<x+w;i++){ if (i<0||i>=app->width) continue; app->pixels[j*app->width+i]=c; } }
}
/* sum of glyph advances so the display can be right-aligned (mirrors draw_text's advance math). */
static int measure_text(struct app *app, const char *text, int px){
    if (!app->font_ready || !text) return 0;
    if (FT_Set_Pixel_Sizes(app->face, 0, (FT_UInt)px) != 0) return 0;
    int w = 0;
    for (const unsigned char *p = (const unsigned char*)text; *p; ++p){
        unsigned char ch = *p; if (ch < 0x20 || ch >= 0x7f) ch = '?';
        if (FT_Load_Char(app->face, ch, FT_LOAD_RENDER|FT_LOAD_TARGET_NORMAL) != 0) continue;
        w += (int)(app->face->glyph->advance.x >> 6);
    }
    return w;
}

/* raw evdev codes from wl_keyboard (no xkb keymap here) -> printable chars, unshifted + shifted. */
static const char EVDEV_CHAR[128] = {
    [2]='1',[3]='2',[4]='3',[5]='4',[6]='5',[7]='6',[8]='7',[9]='8',[10]='9',[11]='0',[12]='-',[13]='=',
    [16]='q',[17]='w',[18]='e',[19]='r',[20]='t',[21]='y',[22]='u',[23]='i',[24]='o',[25]='p',[26]='[',[27]=']',
    [30]='a',[31]='s',[32]='d',[33]='f',[34]='g',[35]='h',[36]='j',[37]='k',[38]='l',[39]=';',[40]='\'',[43]='\\',
    [44]='z',[45]='x',[46]='c',[47]='v',[48]='b',[49]='n',[50]='m',[51]=',',[52]='.',[53]='/',[57]=' ',
};
static const char EVDEV_SHIFT[128] = {
    [2]='!',[3]='@',[4]='#',[5]='$',[6]='%',[7]='^',[8]='&',[9]='*',[10]='(',[11]=')',[12]='_',[13]='+',
    [16]='Q',[17]='W',[18]='E',[19]='R',[20]='T',[21]='Y',[22]='U',[23]='I',[24]='O',[25]='P',[26]='{',[27]='}',
    [30]='A',[31]='S',[32]='D',[33]='F',[34]='G',[35]='H',[36]='J',[37]='K',[38]='L',[39]=':',[40]='"',[43]='|',
    [44]='Z',[45]='X',[46]='C',[47]='V',[48]='B',[49]='N',[50]='M',[51]='<',[52]='>',[53]='?',[57]=' ',
};

/* --- the button grid --- */
struct btn { const char *label; int col, row, span, kind; };
static const struct btn BTNS[] = {
    {"C",0,0,2,K_CLR}, {"<-",2,0,2,K_CLR},
    {"7",0,1,1,K_NUM}, {"8",1,1,1,K_NUM}, {"9",2,1,1,K_NUM}, {"/",3,1,1,K_OP},
    {"4",0,2,1,K_NUM}, {"5",1,2,1,K_NUM}, {"6",2,2,1,K_NUM}, {"*",3,2,1,K_OP},
    {"1",0,3,1,K_NUM}, {"2",1,3,1,K_NUM}, {"3",2,3,1,K_NUM}, {"-",3,3,1,K_OP},
    {"0",0,4,1,K_NUM}, {".",1,4,1,K_NUM}, {"=",2,4,1,K_EQ},  {"+",3,4,1,K_OP},
};
enum { N_BTNS = (int)(sizeof(BTNS)/sizeof(BTNS[0])) };

static void btn_rect(int i, int *bx, int *by, int *bw, int *bh){
    const struct btn *b = &BTNS[i];
    *bx = PAD + b->col*(BW+GAP);
    *by = GRID_Y + b->row*(BH+GAP);
    *bw = b->span*BW + (b->span-1)*GAP;
    *bh = BH;
}
static int button_at(struct app *app, double px, double py){
    (void)app;
    for (int i=0;i<N_BTNS;i++){ int bx,by,bw,bh; btn_rect(i,&bx,&by,&bw,&bh);
        if (px>=bx && px<bx+bw && py>=by && py<by+bh) return i; }
    return -1;
}

/* close box geometry (top-right of the titlebar) */
static int in_close_box(double x, double y){
    int cx = WIN_W-22, cy = 5, cw = 16, ch = 16;
    return (x>=cx && x<cx+cw && y>=cy && y<cy+ch);
}

/* --- evaluator: tokenize, then collapse * and / before + and - --- */
static int evaluate(const char *s, double *out){
    double nums[128]; char ops[128]; int nn=0, no=0; int expect_num=1;
    const char *p = s;
    while (*p){
        if (*p==' '){ p++; continue; }
        if (expect_num){
            char *end; double v = strtod(p, &end);   /* strtod consumes optional sign + digits + '.' */
            if (end == p) return -1;                  /* not a number where one was required */
            if (nn >= 128) return -1;
            nums[nn++] = v; p = end; expect_num = 0;
        } else {
            char c = *p;
            if (c=='+'||c=='-'||c=='*'||c=='/'){ if (no>=128) return -1; ops[no++]=c; p++; expect_num=1; }
            else return -1;                           /* garbage where an operator was required */
        }
    }
    if (expect_num) return -1;                        /* trailing operator, or empty */
    /* pass 1: * and / */
    for (int i=0;i<no;){
        if (ops[i]=='*' || ops[i]=='/'){
            double a=nums[i], b=nums[i+1], r;
            if (ops[i]=='/'){ if (b==0.0) return -2; r=a/b; } else r=a*b;
            nums[i]=r;
            for (int j=i+1;j<nn-1;j++) nums[j]=nums[j+1];
            for (int j=i;  j<no-1;j++) ops[j]=ops[j+1];
            nn--; no--;
        } else i++;
    }
    /* pass 2: + and - (left to right) */
    double acc = nums[0];
    for (int i=0;i<no;i++){ if (ops[i]=='+') acc += nums[i+1]; else acc -= nums[i+1]; }
    *out = acc; return 0;
}

/* --- entry mutation --- */
static void do_clear(struct app *a){ a->entry[0]=0; a->entrylen=0; a->error=0; }
static void input_char(struct app *a, char c){
    if (a->error) do_clear(a);
    if (a->entrylen < (int)sizeof(a->entry)-1){ a->entry[a->entrylen++]=c; a->entry[a->entrylen]=0; }
}
static void do_back(struct app *a){
    if (a->error){ do_clear(a); return; }
    if (a->entrylen>0) a->entry[--a->entrylen]=0;
}
static void do_eval(struct app *a){
    if (a->error || a->entrylen==0) return;
    double r; int rc = evaluate(a->entry, &r);
    if (rc != 0){ strcpy(a->entry, "Error"); a->entrylen=5; a->error=1; return; }
    char outb[64]; snprintf(outb, sizeof outb, "%.10g", r);
    strncpy(a->entry, outb, sizeof(a->entry)-1); a->entry[sizeof(a->entry)-1]=0;
    a->entrylen = (int)strlen(a->entry);
}

/* --- rendering --- */
static void draw_calc(struct app *app){
    const uint32_t BG=0xff1b1f27u, TITLE=0xff11141bu, DISP=0xff0d0f14u,
                   TXT=0xfff2f5fau, ACC=0xff4da3ffu,
                   BNUM=0xff2b313du, BNUMH=0xff353d4du, BOP=0xff394252u, BOPH=0xff455064u,
                   BEQ=0xff2f6d3au, BEQH=0xff3a8a49u, BCLR=0xff4a2b2bu, BCLRH=0xff5e3535u,
                   CLOSE=0xffd05050u;
    fill_rect(app, 0, 0, app->width, app->height, BG);

    /* titlebar + close box (our own chrome; Weston has no SSD) */
    fill_rect(app, 0, 0, app->width, TITLE_H, TITLE);
    draw_text(app, "Calculator", 10, 5, app->width-40, 15, TXT);
    fill_rect(app, app->width-22, 5, 16, 16, CLOSE);
    draw_text(app, "x", app->width-18, 4, 14, 14, 0xffffffffu);

    /* display strip, right-aligned */
    fill_rect(app, PAD, DISP_Y+6, app->width-2*PAD, DISP_H-12, DISP);
    const char *shown = app->error ? "Error" : (app->entrylen ? app->entry : "0");
    int px = 30;
    int tw = measure_text(app, shown, px);
    int avail = app->width - 2*PAD - 20;
    while (tw > avail && px > 12){ px -= 2; tw = measure_text(app, shown, px); }  /* shrink to fit */
    int tx = app->width - PAD - 10 - tw; if (tx < PAD+8) tx = PAD+8;
    int ty = DISP_Y + (DISP_H - px)/2;
    draw_text(app, shown, tx, ty, avail, px, app->error ? 0xffff6b6bu : TXT);

    /* button grid */
    for (int i=0;i<N_BTNS;i++){
        int bx,by,bw,bh; btn_rect(i,&bx,&by,&bw,&bh);
        int hov = (i==app->hover);
        uint32_t bc;
        switch (BTNS[i].kind){
            case K_OP:  bc = hov?BOPH:BOP;   break;
            case K_EQ:  bc = hov?BEQH:BEQ;   break;
            case K_CLR: bc = hov?BCLRH:BCLR; break;
            default:    bc = hov?BNUMH:BNUM; break;
        }
        fill_rect(app, bx, by, bw, bh, bc);
        int lpx = 22;
        int lw = measure_text(app, BTNS[i].label, lpx);
        uint32_t lc = (BTNS[i].kind==K_EQ) ? 0xffffffffu : (BTNS[i].kind==K_OP ? ACC : TXT);
        draw_text(app, BTNS[i].label, bx + (bw-lw)/2, by + (bh-lpx)/2, bw, lpx, lc);
    }
}

/* --- double-buffered wl_shm (one memfd, two slices) --- */
static void redraw_commit(struct app *app);   /* fwd */
static void buffer_release(void *d, struct wl_buffer *wl){ struct app *a = d;
    for (int i=0;i<2;i++) if (a->bufs[i].wl == wl) a->bufs[i].busy = 0;
    if (a->dirty){ a->dirty = 0; redraw_commit(a); }   /* a deferred redraw can now proceed */
}
static const struct wl_buffer_listener buffer_listener = { .release = buffer_release };

static int create_buffers(struct app *app){
    int fd = create_memfd("epin-calc"); if (fd < 0) return -1;
    size_t total = app->buffer_size * 2;
    if (ftruncate(fd, (off_t)total) < 0){ close(fd); return -1; }
    unsigned char *base = mmap(NULL, total, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED){ close(fd); return -1; }
    struct wl_shm_pool *pool = wl_shm_create_pool(app->shm, fd, (int)total);
    for (int i=0;i<2;i++){
        app->bufs[i].px = (uint32_t*)(base + (size_t)i*app->buffer_size);
        app->bufs[i].wl = wl_shm_pool_create_buffer(pool, (int)((size_t)i*app->buffer_size),
                                                    app->width, app->height, app->stride, WL_SHM_FORMAT_XRGB8888);
        if (!app->bufs[i].wl){ wl_shm_pool_destroy(pool); close(fd); return -1; }
        wl_buffer_add_listener(app->bufs[i].wl, &buffer_listener, app);
        app->bufs[i].busy = 0;
    }
    wl_shm_pool_destroy(pool); close(fd);
    return 0;
}
/* Draw into a FREE buffer and commit it; if both are in use, mark dirty and redraw on the next release
 * (never modify a buffer the compositor may still be reading -> that vanished the window on real HW). */
static void redraw_commit(struct app *app){
    if (!app->configured) return;
    int i = app->bufs[0].busy ? 1 : 0;
    if (app->bufs[i].busy){ app->dirty = 1; return; }
    app->pixels = app->bufs[i].px;
    draw_calc(app);
    app->bufs[i].busy = 1;
    wl_surface_attach(app->surface, app->bufs[i].wl, 0, 0);
    wl_surface_damage_buffer(app->surface, 0, 0, app->width, app->height);
    wl_surface_commit(app->surface);
    wl_display_flush(app->display);
}

/* --- input --- */
static void press_button(struct app *app, int i){
    if (i < 0 || i >= N_BTNS) return;
    const char *l = BTNS[i].label;
    if (!strcmp(l, "C"))       do_clear(app);
    else if (!strcmp(l, "<-")) do_back(app);
    else if (!strcmp(l, "="))  do_eval(app);
    else                       input_char(app, l[0]);
    redraw_commit(app);
}

static void pointer_enter(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)s;(void)sf; struct app*a=d; a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y); }
static void pointer_leave(void *d, struct wl_pointer *p, uint32_t s, struct wl_surface *sf){ (void)p;(void)s;(void)sf; struct app*a=d; if (a->hover!=-1){ a->hover=-1; redraw_commit(a); } }
static void pointer_motion(void *d, struct wl_pointer *p, uint32_t t, wl_fixed_t x, wl_fixed_t y){ (void)p;(void)t; struct app*a=d;
    a->pointer_x=wl_fixed_to_double(x); a->pointer_y=wl_fixed_to_double(y);
    int nh = button_at(a, a->pointer_x, a->pointer_y);
    if (nh != a->hover){ a->hover = nh; redraw_commit(a); } }
static void pointer_button(void *d, struct wl_pointer *p, uint32_t se, uint32_t t, uint32_t button, uint32_t state){ (void)p;(void)se;(void)t; struct app*a=d;
    if (button != 0x110 /*BTN_LEFT*/ || state != 1) return;
    if (in_close_box(a->pointer_x, a->pointer_y)){ log_line("CALC: close"); exit(0); }
    int i = button_at(a, a->pointer_x, a->pointer_y);
    if (i >= 0) press_button(a, i); }
static void pointer_axis(void *d, struct wl_pointer *p, uint32_t t, uint32_t ax, wl_fixed_t v){ (void)d;(void)p;(void)t;(void)ax;(void)v; }
/* wl_pointer >= v5 also emits frame/axis_source/axis_stop/axis_discrete — these listener slots MUST be
 * non-NULL or libwayland calls a NULL fn-ptr on the first real pointer 'frame' event and the client crashes. */
static void pointer_frame(void *d, struct wl_pointer *p){ (void)d;(void)p; }
static void pointer_axis_source(void *d, struct wl_pointer *p, uint32_t s){ (void)d;(void)p;(void)s; }
static void pointer_axis_stop(void *d, struct wl_pointer *p, uint32_t t, uint32_t a){ (void)d;(void)p;(void)t;(void)a; }
static void pointer_axis_discrete(void *d, struct wl_pointer *p, uint32_t a, int32_t dsc){ (void)d;(void)p;(void)a;(void)dsc; }
static const struct wl_pointer_listener pointer_listener = {
    .enter=pointer_enter,.leave=pointer_leave,.motion=pointer_motion,.button=pointer_button,.axis=pointer_axis,
    .frame=pointer_frame,.axis_source=pointer_axis_source,.axis_stop=pointer_axis_stop,.axis_discrete=pointer_axis_discrete };

static void kb_keymap(void *d, struct wl_keyboard *k, uint32_t f, int32_t fd, uint32_t sz){ (void)d;(void)k;(void)f;(void)sz; if (fd>=0) close(fd); }
static void kb_enter(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf, struct wl_array *ks){ (void)d;(void)k;(void)s;(void)sf;(void)ks; }
static void kb_leave(void *d, struct wl_keyboard *k, uint32_t s, struct wl_surface *sf){ (void)d;(void)k;(void)s;(void)sf; }
static void kb_key(void *d, struct wl_keyboard *k, uint32_t se, uint32_t t, uint32_t key, uint32_t state){ (void)k;(void)se;(void)t; struct app*a=d;
    if (key==42||key==54){ a->shift = (state==1); return; }
    if (state != 1) return;                          /* press only */
    if (key==1){ do_clear(a); redraw_commit(a); return; }               /* Esc -> clear */
    if (key==14){ do_back(a); redraw_commit(a); return; }               /* Backspace */
    if (key==28 || key==96){ do_eval(a); redraw_commit(a); return; }    /* Enter / KP-Enter */
    char c = 0;
    switch (key){                                    /* numeric keypad (not in the EVDEV tables) */
        case 71: case 72: case 73: c = (char)('7' + (key-71)); break;   /* KP7 KP8 KP9 */
        case 75: case 76: case 77: c = (char)('4' + (key-75)); break;   /* KP4 KP5 KP6 */
        case 79: case 80: case 81: c = (char)('1' + (key-79)); break;   /* KP1 KP2 KP3 */
        case 82: c = '0'; break;                                        /* KP0 */
        case 83: c = '.'; break;                                        /* KP. */
        case 55: c = '*'; break;                                        /* KP* */
        case 74: c = '-'; break;                                        /* KP- */
        case 78: c = '+'; break;                                        /* KP+ */
        case 98: c = '/'; break;                                        /* KP/ */
        default: if (key < 128) c = a->shift ? EVDEV_SHIFT[key] : EVDEV_CHAR[key]; break;
    }
    if (!c) return;
    if (c=='=')                do_eval(a);
    else if (c=='c'||c=='C')   do_clear(a);
    else if ((c>='0'&&c<='9')||c=='.'||c=='+'||c=='-'||c=='*'||c=='/') input_char(a, c);
    else return;
    redraw_commit(a); }
static void kb_modifiers(void *d, struct wl_keyboard *k, uint32_t se, uint32_t md, uint32_t ml, uint32_t lo, uint32_t g){ (void)d;(void)k;(void)se;(void)md;(void)ml;(void)lo;(void)g; }
static void kb_repeat(void *d, struct wl_keyboard *k, int32_t r, int32_t delay){ (void)d;(void)k;(void)r;(void)delay; }
static const struct wl_keyboard_listener keyboard_listener = {
    .keymap=kb_keymap,.enter=kb_enter,.leave=kb_leave,.key=kb_key,.modifiers=kb_modifiers,.repeat_info=kb_repeat };

static void seat_caps(void *d, struct wl_seat *seat, uint32_t caps){ struct app*a=d;
    if ((caps & WL_SEAT_CAPABILITY_KEYBOARD) && !a->keyboard){ a->keyboard = wl_seat_get_keyboard(seat); wl_keyboard_add_listener(a->keyboard,&keyboard_listener,a); }
    if ((caps & WL_SEAT_CAPABILITY_POINTER) && !a->pointer){ a->pointer = wl_seat_get_pointer(seat); wl_pointer_add_listener(a->pointer,&pointer_listener,a); } }
static void seat_name(void *d, struct wl_seat *s, const char *n){ (void)d;(void)s;(void)n; }
static const struct wl_seat_listener seat_listener = { .capabilities=seat_caps, .name=seat_name };

static void wm_base_ping(void *d, struct xdg_wm_base *b, uint32_t serial){ (void)d; xdg_wm_base_pong(b, serial); }
static const struct xdg_wm_base_listener wm_base_listener = { .ping=wm_base_ping };
static void toplevel_configure(void *d, struct xdg_toplevel *t, int32_t w, int32_t h, struct wl_array *s){ (void)d;(void)t;(void)w;(void)h;(void)s; }
static void toplevel_close(void *d, struct xdg_toplevel *t){ (void)t; struct app*a=d; a->running=0; }
static void toplevel_bounds(void *d, struct xdg_toplevel *t, int32_t w, int32_t h){ (void)d;(void)t;(void)w;(void)h; }
static void toplevel_wmcap(void *d, struct xdg_toplevel *t, struct wl_array *c){ (void)d;(void)t;(void)c; }
static const struct xdg_toplevel_listener toplevel_listener = {
    .configure=toplevel_configure,.close=toplevel_close,.configure_bounds=toplevel_bounds,.wm_capabilities=toplevel_wmcap };

static void xdg_surface_configure(void *d, struct xdg_surface *s, uint32_t serial){ struct app*a=d;
    xdg_surface_ack_configure(s, serial);
    a->configured = 1;
    redraw_commit(a); }
static const struct xdg_surface_listener xdg_surface_listener = { .configure=xdg_surface_configure };

static void registry_global(void *d, struct wl_registry *r, uint32_t name, const char *iface, uint32_t ver){ struct app*a=d;
    if (!strcmp(iface, wl_compositor_interface.name)) a->compositor = wl_registry_bind(r,name,&wl_compositor_interface, ver<4?ver:4);
    else if (!strcmp(iface, wl_shm_interface.name)) a->shm = wl_registry_bind(r,name,&wl_shm_interface,1);
    else if (!strcmp(iface, xdg_wm_base_interface.name)){ a->wm_base = wl_registry_bind(r,name,&xdg_wm_base_interface, ver<6?ver:6); xdg_wm_base_add_listener(a->wm_base,&wm_base_listener,a); }
    else if (!strcmp(iface, wl_seat_interface.name)){ a->seat = wl_registry_bind(r,name,&wl_seat_interface, ver<5?ver:5); wl_seat_add_listener(a->seat,&seat_listener,a); } }
static void registry_remove(void *d, struct wl_registry *r, uint32_t n){ (void)d;(void)r;(void)n; }
static const struct wl_registry_listener registry_listener = { .global=registry_global, .global_remove=registry_remove };

int main(void){
    static struct app app; memset(&app, 0, sizeof app);
    app.running = 1; app.hover = -1;
    app.width = WIN_W; app.height = WIN_H; app.stride = WIN_W*4; app.buffer_size = (size_t)app.stride*WIN_H;
    signal(SIGCHLD, SIG_IGN);
    init_freetype(&app);

    log_line("CALC: starting calculator");
    app.display = wl_display_connect(NULL);
    if (!app.display){ log_line("CALC: no wayland display"); return 1; }
    app.registry = wl_display_get_registry(app.display);
    wl_registry_add_listener(app.registry, &registry_listener, &app);
    wl_display_roundtrip(app.display);
    if (!app.compositor || !app.shm || !app.wm_base){ log_line("CALC: missing globals"); return 1; }
    if (create_buffers(&app) < 0){ log_line("CALC: buffer failed"); return 1; }

    app.surface = wl_compositor_create_surface(app.compositor);
    app.xdg_surface = xdg_wm_base_get_xdg_surface(app.wm_base, app.surface);
    xdg_surface_add_listener(app.xdg_surface, &xdg_surface_listener, &app);
    app.toplevel = xdg_surface_get_toplevel(app.xdg_surface);
    xdg_toplevel_add_listener(app.toplevel, &toplevel_listener, &app);
    xdg_toplevel_set_title(app.toplevel, "Calculator");
    xdg_toplevel_set_app_id(app.toplevel, "epin-calc");
    xdg_toplevel_set_min_size(app.toplevel, WIN_W, WIN_H);
    xdg_toplevel_set_max_size(app.toplevel, WIN_W, WIN_H);
    wl_surface_commit(app.surface);
    wl_display_flush(app.display);

    int wlfd = wl_display_get_fd(app.display);
    while (app.running){
        while (wl_display_prepare_read(app.display) != 0) wl_display_dispatch_pending(app.display);
        wl_display_flush(app.display);
        struct pollfd pfd = { .fd=wlfd, .events=POLLIN, .revents=0 };
        int pr = poll(&pfd, 1, 1000);
        if (pr > 0 && (pfd.revents & POLLIN)){ wl_display_read_events(app.display); wl_display_dispatch_pending(app.display); }
        else { wl_display_cancel_read(app.display); if (pr < 0){ if (errno==EINTR) continue; break; } }
    }
    return 0;
}
