module anonymos.display.loader;

import anonymos.display.canvas;
import anonymos.display.font_stack;
import anonymos.console : printLine;

// Colors from the web3 theme approximation
private enum uint COL_BG = 0xFF0F172A; // Slate 900
private enum uint COL_PRIMARY = 0xFF3B82F6; // Blue 500
private enum uint COL_SECONDARY = 0xFF8B5CF6; // Violet 500
private enum uint COL_TEXT = 0xFFF8FAFC; // Slate 50
private enum uint COL_TEXT_DIM = 0xFF94A3B8; // Slate 400

struct Particle
{
    float x, y;
    float vx, vy;
    float size;
}

struct LoaderState
{
    bool active;
    float progress;
    int timer;
    Particle[20] particles;
    bool initialized;
}

__gshared LoaderState g_loader;

public @nogc nothrow void initLoader(int width, int height)
{
    g_loader.active = true;
    g_loader.progress = 0.0f;
    g_loader.timer = 0;
    g_loader.initialized = true;
    
    // Initialize particles
    // Pseudo-random seeding since we don't have a full RNG
    uint seed = 12345;
    
    for (int i = 0; i < g_loader.particles.length; i++)
    {
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
        g_loader.particles[i].x = cast(float)(seed % width);
        
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
        g_loader.particles[i].y = cast(float)(seed % height);
        
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
        g_loader.particles[i].vx = (cast(float)(seed % 100) / 50.0f) - 1.0f; // -1 to 1
        
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
        g_loader.particles[i].vy = (cast(float)(seed % 100) / 50.0f) - 1.0f;
        
        g_loader.particles[i].size = 2.0f;
    }
}

public @nogc nothrow void updateLoader()
{
    if (!g_loader.active) return;
    
    g_loader.timer++;
    
    // Progress simulation - Correlate with steps
    // 0-20%: Initializing blockchain connection
    // 20-40%: Establishing peer connection
    // 40-60%: Fetching block headers
    // 60-80%: Verifying smart contracts
    // 80-95%: Loading decentralized content
    // 95-100%: Connection established
    
    float target = 0.0f;
    if (g_loader.timer < 120) target = 0.25f;       // 2s
    else if (g_loader.timer < 240) target = 0.45f;  // 4s
    else if (g_loader.timer < 360) target = 0.65f;  // 6s
    else if (g_loader.timer < 480) target = 0.85f;  // 8s
    else if (g_loader.timer < 600) target = 0.98f;  // 10s
    else target = 1.0f;
    
    // Smooth approach
    g_loader.progress += (target - g_loader.progress) * 0.05f;
    
    if (g_loader.progress >= 0.99f && g_loader.timer > 600)
    {
        g_loader.progress = 1.0f;
        g_loader.active = false;
    }
    
    // Update particles
    // We need screen dimensions, assume 1024x768 for update logic or pass them in.
    // For simplicity, we'll wrap at arbitrary bounds if we don't have them, 
    // but renderLoader has dimensions. Let's just update positions blindly here 
    // and wrap in render.
    for (int i = 0; i < g_loader.particles.length; i++)
    {
        g_loader.particles[i].x += g_loader.particles[i].vx;
        g_loader.particles[i].y += g_loader.particles[i].vy;
    }
}

public @nogc nothrow void renderLoader(Canvas* fbCanvas, int width, int height)
{
    import anonymos.kernel.physmem : allocFrame, freeFrame;
    import anonymos.kernel.memory : memset;
    
    // Allocate backbuffer for double buffering to prevent flickering
    // We need a contiguous buffer of size width*height*4.
    // allocFrame returns 4KB. That's not enough.
    // We need ~3MB for 1024x768.
    // Since we don't have a general purpose heap allocator exposed here easily (kmalloc was a guess),
    // we will use a static buffer in BSS if it fits, or just allocate multiple frames.
    // But allocating multiple contiguous frames is hard without a proper allocator.
    
    // ALTERNATIVE: Render directly to FB but minimize clearing.
    // OR: Use a smaller backbuffer and scale up? No, looks bad.
    // OR: Just accept we need a heap.
    // Wait, we are in kernel mode. We can just use a large static array?
    // 3MB is large for BSS but maybe okay.
    // Let's try a static array.
    
    // Actually, let's look at `src/anonymos/display/compositor.d`. It likely has surface allocation.
    // But for now, to fix the build error and get it working:
    // We will use a simplified approach:
    // 1. Clear only the dirty regions? Hard with particles.
    // 2. Use a static buffer.
    
    static uint[] backBuffer;
    
    if (backBuffer.length != width * height)
    {
        // We can't easily allocate 3MB contiguous physically without a proper allocator.
        // However, we are in identity mapped mode (mostly).
        // Let's try to grab a range of frames.
        // For now, let's just use the framebuffer directly but try to be smart?
        // No, flickering is due to clear + draw.
        
        // Let's use a smaller buffer for the "active" area? No, particles are full screen.
        
        // HACK: Use a fixed large static buffer.
        // __gshared uint[1024*768] g_loaderBuffer; 
        // This adds 3MB to the kernel image size. That's fine for a demo OS.
    }
    
    // Use the global static buffer defined below
    if (width * height > g_loaderBuffer.length) return; // Screen too big
    
    // Create canvas for backbuffer
    Canvas c = createBufferCanvas(g_loaderBuffer.ptr, width, height, width); // Pitch = width (pixels)
    
    // Clear background
    c.canvasRect(0, 0, width, height, COL_BG);
    
    // Render Particles & Connections
    for (int i = 0; i < g_loader.particles.length; i++)
    {
        // Wrap particles
        if (g_loader.particles[i].x < 0) g_loader.particles[i].x = width;
        if (g_loader.particles[i].x > width) g_loader.particles[i].x = 0;
        if (g_loader.particles[i].y < 0) g_loader.particles[i].y = height;
        if (g_loader.particles[i].y > height) g_loader.particles[i].y = 0;
        
        int px = cast(int)g_loader.particles[i].x;
        int py = cast(int)g_loader.particles[i].y;
        
        // Draw particle (filled circle with some transparency for glow effect simulation)
        // Core
        c.canvasCircle(px, py, 2, COL_PRIMARY | 0xFF000000, true);
        // Glow (faint larger circle)
        c.canvasCircle(px, py, 4, (COL_PRIMARY & 0x00FFFFFF) | 0x40000000, true);
        
        // Draw connections to nearby particles
        for (int j = i + 1; j < g_loader.particles.length; j++)
        {
            float dx = g_loader.particles[j].x - g_loader.particles[i].x;
            float dy = g_loader.particles[j].y - g_loader.particles[i].y;
            float distSq = dx*dx + dy*dy;
            
            if (distSq < 150*150) // Connection threshold
            {
                int px2 = cast(int)g_loader.particles[j].x;
                int py2 = cast(int)g_loader.particles[j].y;
                
                // Calculate opacity based on distance
                // Opacity: 1.0 at 0, 0.0 at 150
                // alpha = 255 * (1 - dist/150)
                
                int alpha = 0;
                if (distSq < 150*150)
                {
                    // Approximate sqrt or just linear falloff
                    // Let's use linear falloff based on distSq for speed
                    // alpha = 255 * (1 - distSq / (150*150))
                    float ratio = 1.0f - (distSq / (150.0f*150.0f));
                    alpha = cast(int)(128.0f * ratio); // Max alpha 128
                }
                
                if (alpha > 0)
                {
                    uint lineColor = (COL_SECONDARY & 0x00FFFFFF) | (alpha << 24);
                    c.canvasLine(px, py, px2, py2, lineColor);
                }
            }
        }
    }
    
    // Center Content
    int cx = width / 2;
    int cy = height / 2;
    
    // Logo (Hexagon Shape)
    int hexSize = 40;
    int hexY = cy - 50;
    
    // Draw Hexagon
    int h = cast(int)(hexSize * 0.866f);
    int r = hexSize;
    int r2 = r / 2;
    
    int[12] pts = [
        cx + r, hexY,
        cx + r2, hexY + h,
        cx - r2, hexY + h,
        cx - r, hexY,
        cx - r2, hexY - h,
        cx + r2, hexY - h
    ];
    
    uint hexColor = COL_PRIMARY;
    for (int i = 0; i < 6; i++)
    {
        int j = (i + 1) % 6;
        c.canvasLine(pts[i*2], pts[i*2+1], pts[j*2], pts[j*2+1], hexColor);
    }
    
    // Inner rotating element (simple triangle)
    // Rotate based on timer
    float angle = (g_loader.timer % 360) * 3.14159f / 180.0f;
    int ir = 20;
    int ix1 = cx + cast(int)(ir * cos(angle));
    int iy1 = hexY + cast(int)(ir * sin(angle));
    int ix2 = cx + cast(int)(ir * cos(angle + 2.09f)); // +120 deg
    int iy2 = hexY + cast(int)(ir * sin(angle + 2.09f));
    int ix3 = cx + cast(int)(ir * cos(angle + 4.18f)); // +240 deg
    int iy3 = hexY + cast(int)(ir * sin(angle + 4.18f));
    
    c.canvasLine(ix1, iy1, ix2, iy2, COL_SECONDARY);
    c.canvasLine(ix2, iy2, ix3, iy3, COL_SECONDARY);
    c.canvasLine(ix3, iy3, ix1, iy1, COL_SECONDARY);
    
    // Progress Text
    char[32] pctBuf;
    int pct = cast(int)(g_loader.progress * 100);
    int len = uintToStr(pct, pctBuf, 0);
    pctBuf[len] = '%';
    pctBuf[len+1] = 0;
    
    // Fix: Pass the correct slice length to drawString
    drawString(&c, cx - 15, cy + 20, pctBuf[0 .. len+1], COL_PRIMARY);
    
    // Status Text
    const(char)* status = "Initializing blockchain connection...";
    if (g_loader.progress > 0.2f) status = "Establishing peer connection...";
    if (g_loader.progress > 0.4f) status = "Fetching block headers...";
    if (g_loader.progress > 0.6f) status = "Verifying smart contracts...";
    if (g_loader.progress > 0.8f) status = "Loading decentralized content...";
    if (g_loader.progress >= 1.0f) status = "Connection established";
    
    // Centering text roughly (assuming 8px char width)
    int statusLen = 0;
    while (status[statusLen] != 0) statusLen++;
    int statusWidth = statusLen * 8;
    
    drawString(&c, cx - statusWidth/2, cy + 50, status, COL_TEXT_DIM);
    
    // Progress Bar
    int barW = 300;
    int barH = 4;
    c.canvasRect(cx - barW/2, cy + 80, barW, barH, 0xFF1E293B); // Background
    c.canvasRect(cx - barW/2, cy + 80, cast(int)(barW * g_loader.progress), barH, COL_PRIMARY); // Fill
    
    // Corner Decorations
    // Top Left
    c.canvasRect(20, 20, 2, 40, COL_PRIMARY);
    c.canvasRect(20, 20, 40, 2, COL_PRIMARY);
    
    // Bottom Right
    c.canvasRect(width - 22, height - 60, 2, 40, COL_SECONDARY);
    c.canvasRect(width - 62, height - 22, 40, 2, COL_SECONDARY);
    
    // Blit backbuffer to framebuffer
    if (fbCanvas.pixels !is null)
    {
        uint* dest = fbCanvas.pixels;
        uint* src = g_loaderBuffer.ptr;
        size_t count = width * height;
        
        // Simple copy
        for (size_t i = 0; i < count; i++)
        {
            dest[i] = src[i];
        }
    }
}

// Static buffer for double buffering (max 1920x1080)
private __gshared uint[1920*1080] g_loaderBuffer;

// Simple math helpers since we might not have std.math linked in kernel mode
private @nogc nothrow float cos(float x)
{
    // Taylor series approximation for cos(x)
    // cos(x) = 1 - x^2/2! + x^4/4! - ...
    // Good enough for small angles or normalized
    // Normalize to -PI..PI
    while (x > 3.14159f) x -= 6.28318f;
    while (x < -3.14159f) x += 6.28318f;
    
    float x2 = x*x;
    return 1.0f - x2/2.0f + (x2*x2)/24.0f - (x2*x2*x2)/720.0f;
}

private @nogc nothrow float sin(float x)
{
    // sin(x) = x - x^3/3! + x^5/5! - ...
    while (x > 3.14159f) x -= 6.28318f;
    while (x < -3.14159f) x += 6.28318f;
    
    float x2 = x*x;
    return x - (x*x2)/6.0f + (x2*x2*x)/120.0f;
}

private @nogc nothrow void drawString(Canvas* c, int x, int y, const(char)* s, uint color)
{
    import anonymos.display.canvas : canvasText;
    import anonymos.display.font_stack : activeFontStack;
    
    int len = 0;
    while (s[len] != 0) len++;
    
    if (len > 0)
    {
        (*c).canvasText(activeFontStack(), x, y, s[0..len], color, 0, false);
    }
}

private @nogc nothrow void drawString(Canvas* c, int x, int y, char[] s, uint color)
{
    import anonymos.display.canvas : canvasText;
    import anonymos.display.font_stack : activeFontStack;
    
    if (s.length > 0)
    {
        (*c).canvasText(activeFontStack(), x, y, s, color, 0, false);
    }
}

private @nogc nothrow int uintToStr(uint val, ref char[32] buf, int offset)
{
    if (val == 0) {
        buf[offset] = '0';
        return 1;
    }
    
    char[16] temp;
    int tempLen = 0;
    uint v = val;
    
    while (v > 0) {
        temp[tempLen++] = cast(char)('0' + (v % 10));
        v /= 10;
    }
    
    for (int i = 0; i < tempLen; i++) {
        buf[offset + i] = temp[tempLen - 1 - i];
    }
    
    return tempLen;
}
