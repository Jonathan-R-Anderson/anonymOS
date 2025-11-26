module anonymos.display.window_manager.manager;

import anonymos.display.framebuffer : framebufferAvailable;
import anonymos.display.canvas : Canvas;
import anonymos.display.input_pipeline : InputEvent, InputQueue, enqueue, dequeue;

nothrow:
@nogc:

private enum size_t INVALID_INDEX   = size_t.max;
private enum size_t MAX_WINDOWS     = 32;
private enum size_t MAX_DESKTOPS    = 4;
private enum size_t MAX_SHORTCUTS   = 16;
private enum uint  MIN_WINDOW_WIDTH = 96;
private enum uint  MIN_WINDOW_HEIGHT = 64;

public enum size_t WINDOW_MANAGER_CAPACITY = MAX_WINDOWS;

public enum LayoutMode
{
    floating,
    tiling,
}

public struct Rect
{
    int x, y;
    uint width, height;
}

public struct Damage
{
    Rect bounds;
    bool any;

    void add(int x, int y, uint w, uint h) @nogc nothrow
    {
        if (!any)
        {
            bounds = Rect(x, y, w, h);
            any = true;
            return;
        }

        // Union
        int minX = (x < bounds.x) ? x : bounds.x;
        int minY = (y < bounds.y) ? y : bounds.y;
        int maxX1 = x + cast(int)w;
        int maxY1 = y + cast(int)h;
        int maxX2 = bounds.x + cast(int)bounds.width;
        int maxY2 = bounds.y + cast(int)bounds.height;
        int maxX = (maxX1 > maxX2) ? maxX1 : maxX2;
        int maxY = (maxY1 > maxY2) ? maxY1 : maxY2;

        bounds.x = minX;
        bounds.y = minY;
        bounds.width = cast(uint)(maxX - minX);
        bounds.height = cast(uint)(maxY - minY);
    }
    
    void add(Rect r) @nogc nothrow
    {
        add(r.x, r.y, r.width, r.height);
    }
    
    void clear() @nogc nothrow
    {
        any = false;
        bounds = Rect(0,0,0,0);
    }
}

public struct Window
{
    size_t id;
    immutable(char)[] title;
    uint x;
    uint y;
    uint width;
    uint height;
    bool focused;
    bool minimized;
    bool maximized;
    bool floating;
    size_t desktop;
    size_t zOrder;
    size_t surfaceId;
    Canvas surfaceCanvas;
    
    Rect rect() const @nogc nothrow { return Rect(cast(int)x, cast(int)y, width, height); }
}

public struct ShortcutBinding
{
    immutable(char)[] name;
    immutable(char)[] action;
}

struct WindowManager
{
@nogc:
nothrow:
public:
    void reset()
    {
        foreach (i; 0 .. _windowCount)
        {
            releaseSurface(_windows[i].surfaceId);
        }
        _windowCount = 0;
        _nextId = 1;
        _nextZOrder = 0;
        _activeDesktop = 0;
        _desktopCount = 1;
        _configured = false;
        foreach (ref desktop; _layouts)
        {
            desktop = LayoutMode.tiling;
        }
        _shortcutCount = 0;
        _allocateSurface = null;
        _resizeSurface = null;
        _releaseSurface = null;
        foreach (ref queue; _inputQueues)
        {
            queue.head = 0;
            queue.tail = 0;
        }
    }

    void configure(uint screenWidth, uint screenHeight, uint taskbarHeight, size_t desktopCount)
    {
        _screenWidth = screenWidth;
        _screenHeight = screenHeight;
        _taskbarHeight = taskbarHeight;
        _desktopCount = (desktopCount == 0 || desktopCount > MAX_DESKTOPS) ? MAX_DESKTOPS : desktopCount;
        _configured = framebufferAvailable();
    }

    void configureSurfaceCallbacks(SurfaceAllocator allocator,
                                   SurfaceResizer resizer,
                                   SurfaceReleaser releaser)
    {
        _allocateSurface = allocator;
        _resizeSurface = resizer;
        _releaseSurface = releaser;
    }

    size_t createWindow(immutable(char)[] title, uint width, uint height, bool floating = false, size_t desktop = INVALID_INDEX, Damage* damage = null)
    {
        if (!_configured || !hasCapacity(_windowCount, _windows.length))
        {
            return INVALID_INDEX;
        }

        const targetDesktop = (desktop == INVALID_INDEX || desktop >= _desktopCount) ? _activeDesktop : desktop;

        auto w = &_windows[_windowCount++];
        w.id = _nextId++;
        w.title = title;
        w.width = width < MIN_WINDOW_WIDTH ? MIN_WINDOW_WIDTH : width;
        w.height = height < MIN_WINDOW_HEIGHT ? MIN_WINDOW_HEIGHT : height;
        w.x = (_screenWidth > w.width) ? (_screenWidth - w.width) / 4 : 0;
        w.y = (_screenHeight > _taskbarHeight + w.height) ? (_screenHeight - _taskbarHeight - w.height) / 4 : 0;
        w.focused = false;
        w.minimized = false;
        w.maximized = false;
        w.floating = floating;
        w.desktop = targetDesktop;
        w.zOrder = _nextZOrder++;
        w.surfaceId = INVALID_INDEX;

        _inputQueues[_windowCount - 1].head = 0;
        _inputQueues[_windowCount - 1].tail = 0;

        attachSurface(w);

        if (damage !is null && targetDesktop == _activeDesktop)
        {
            damage.add(w.rect());
        }

        focusWindow(w.id, damage);
        applyLayout(damage);
        return w.id;
    }

    bool destroyWindow(size_t id, Damage* damage = null)
    {
        const index = findIndex(id);
        if (index == INVALID_INDEX)
        {
            return false;
        }

        if (damage !is null && _windows[index].desktop == _activeDesktop && !_windows[index].minimized)
        {
            damage.add(_windows[index].rect());
        }

        const wasFocused = _windows[index].focused;
        releaseSurface(_windows[index].surfaceId);

        foreach (i; index .. _windowCount - 1)
        {
            _windows[i] = _windows[i + 1];
            _inputQueues[i] = _inputQueues[i + 1];
        }
        --_windowCount;

        if (wasFocused)
        {
            focusTopWindowOnDesktop(_activeDesktop, damage);
        }

        applyLayout(damage);
        return true;
    }

    bool focusWindow(size_t id, Damage* damage = null)
    {
        const index = findIndex(id);
        if (index == INVALID_INDEX)
        {
            return false;
        }

        const desktop = _windows[index].desktop;
        _activeDesktop = desktop;
        clearFocus(desktop, damage);
        _windows[index].focused = true;
        
        if (damage !is null && desktop == _activeDesktop && !_windows[index].minimized)
        {
            // Redraw title bar at least
            damage.add(_windows[index].x, _windows[index].y, _windows[index].width, 32); 
        }
        
        bringToFront(index);
        
        // Taskbar needs update on focus change
        if (damage !is null)
        {
             damage.add(0, _screenHeight - _taskbarHeight, _screenWidth, _taskbarHeight);
        }
        
        return true;
    }

    bool moveWindow(size_t id, int dx, int dy, Damage* damage = null)
    {
        const index = findIndex(id);
        if (index == INVALID_INDEX)
        {
            return false;
        }

        auto w = &_windows[index];
        if (w.minimized || w.maximized)
        {
            return false;
        }

        if (damage !is null) damage.add(w.rect());

        const newX = clampSigned(w.x, dx, _screenWidth, w.width);
        const newY = clampSigned(w.y, dy, _screenHeight - _taskbarHeight, w.height);
        w.x = newX;
        w.y = newY;
        
        if (damage !is null) damage.add(w.rect());
        
        return true;
    }

    bool resizeWindow(size_t id, int dw, int dh, Damage* damage = null)
    {
        const index = findIndex(id);
        if (index == INVALID_INDEX)
        {
            return false;
        }

        auto w = &_windows[index];
        if (w.minimized)
        {
            return false;
        }

        if (damage !is null) damage.add(w.rect());

        uint newWidth = clampSize(w.width, dw, _screenWidth, MIN_WINDOW_WIDTH);
        uint newHeight = clampSize(w.height, dh, _screenHeight - _taskbarHeight, MIN_WINDOW_HEIGHT);
        w.width = newWidth;
        w.height = newHeight;
        enforceBounds(w);

        if (damage !is null) damage.add(w.rect());

        if (_resizeSurface !is null && w.surfaceId != INVALID_INDEX)
        {
            Canvas resized;
            if (_resizeSurface(w.surfaceId, w.width, w.height, resized))
            {
                w.surfaceCanvas = resized;
            }
        }
        return true;
    }

    bool toggleFloating(size_t id, bool floating, Damage* damage = null)
    {
        const index = findIndex(id);
        if (index == INVALID_INDEX)
        {
            return false;
        }
        _windows[index].floating = floating;
        applyLayout(damage);
        return true;
    }

    bool minimizeWindow(size_t id, Damage* damage = null)
    {
        const index = findIndex(id);
        if (index == INVALID_INDEX)
        {
            return false;
        }
        
        if (damage !is null && _windows[index].desktop == _activeDesktop)
        {
            damage.add(_windows[index].rect());
        }
        
        _windows[index].minimized = true;
        if (_windows[index].focused)
        {
            focusTopWindowOnDesktop(_windows[index].desktop, damage);
        }
        return true;
    }

    bool maximizeWindow(size_t id, bool maximize, Damage* damage = null)
    {
        const index = findIndex(id);
        if (index == INVALID_INDEX)
        {
            return false;
        }

        auto w = &_windows[index];
        
        if (damage !is null) damage.add(w.rect());
        
        w.maximized = maximize;
        if (maximize)
        {
            w.x = 0;
            w.y = 0;
            w.width = _screenWidth;
            w.height = (_screenHeight > _taskbarHeight) ? _screenHeight - _taskbarHeight : _screenHeight;
            w.floating = false;
        }
        else
        {
            enforceBounds(w);
        }
        
        if (damage !is null) damage.add(w.rect());
        
        bringToFront(index);

        if (_resizeSurface !is null && w.surfaceId != INVALID_INDEX)
        {
            Canvas resized;
            if (_resizeSurface(w.surfaceId, w.width, w.height, resized))
            {
                w.surfaceCanvas = resized;
            }
        }
        return true;
    }

    bool switchDesktop(size_t desktop, Damage* damage = null)
    {
        if (desktop >= _desktopCount)
        {
            return false;
        }
        _activeDesktop = desktop;
        focusTopWindowOnDesktop(desktop, damage);
        applyLayout(damage);
        
        if (damage !is null)
        {
            // Full redraw on desktop switch
            damage.add(0, 0, _screenWidth, _screenHeight);
        }
        return true;
    }

    bool setLayout(size_t desktop, LayoutMode layout, Damage* damage = null)
    {
        if (desktop >= _desktopCount)
        {
            return false;
        }
        _layouts[desktop] = layout;
        if (desktop == _activeDesktop)
        {
            applyLayout(damage);
        }
        return true;
    }

    bool registerShortcut(immutable(char)[] name, immutable(char)[] action)
    {
        if (!hasCapacity(_shortcutCount, _shortcuts.length))
        {
            return false;
        }
        auto shortcut = &_shortcuts[_shortcutCount++];
        shortcut.name = name;
        shortcut.action = action;
        return true;
    }

    void applyLayout(Damage* damage = null)
    {
        if (!_configured)
        {
            return;
        }

        if (_layouts[_activeDesktop] == LayoutMode.tiling)
        {
            layoutTiled(damage);
        }
    }

    const(Window)[] windows() const
    {
        return _windows[0 .. _windowCount];
    }

    /// Enqueue an input event for the specified window
    bool queueInputForWindow(size_t id, InputEvent event)
    {
        const index = findIndex(id);
        if (index == INVALID_INDEX)
        {
            return false;
        }
        return enqueue(_inputQueues[index], event);
    }

    /// Inspect the pending input events for a window (read-only)
    const(InputQueue)* windowInputQueue(size_t id) const
    {
        const index = findIndex(id);
        if (index == INVALID_INDEX)
        {
            return null;
        }
        return &_inputQueues[index];
    }

    size_t activeDesktop() const { return _activeDesktop; }
    size_t desktopCount() const { return _desktopCount; }
    LayoutMode layoutForActiveDesktop() const { return _layouts[_activeDesktop]; }
    const(ShortcutBinding)[] shortcuts() const { return _shortcuts[0 .. _shortcutCount]; }

    size_t focusedWindowId() const
    {
        foreach (ref const window; _windows[0 .. _windowCount])
        {
            if (window.focused && window.desktop == _activeDesktop && !window.minimized)
            {
                return window.id;
            }
        }
        return INVALID_INDEX;
    }

private:
    Window[MAX_WINDOWS] _windows;
    ShortcutBinding[MAX_SHORTCUTS] _shortcuts;
    size_t _windowCount;
    size_t _shortcutCount;
    size_t _nextId;
    size_t _nextZOrder;
    size_t _activeDesktop;
    size_t _desktopCount;
    LayoutMode[MAX_DESKTOPS] _layouts;
    uint _screenWidth;
    uint _screenHeight;
    uint _taskbarHeight;
    bool _configured;
    SurfaceAllocator _allocateSurface;
    SurfaceResizer _resizeSurface;
    SurfaceReleaser _releaseSurface;
    InputQueue[MAX_WINDOWS] _inputQueues;

    size_t findIndex(size_t id) const
    {
        foreach (i; 0 .. _windowCount)
        {
            if (_windows[i].id == id)
            {
                return i;
            }
        }
        return INVALID_INDEX;
    }

    void bringToFront(size_t index)
    {
        if (index >= _windowCount)
        {
            return;
        }

        auto window = _windows[index];
        auto queue = _inputQueues[index];
        foreach (i; index .. _windowCount - 1)
        {
            _windows[i] = _windows[i + 1];
            _inputQueues[i] = _inputQueues[i + 1];
        }
        window.zOrder = _nextZOrder++;
        _windows[_windowCount - 1] = window;
        _inputQueues[_windowCount - 1] = queue;
    }

    void clearFocus(size_t desktop, Damage* damage = null)
    {
        foreach (ref window; _windows[0 .. _windowCount])
        {
            if (window.desktop == desktop)
            {
                if (window.focused && damage !is null && !window.minimized)
                {
                    // Redraw title bar of previously focused window
                    damage.add(window.x, window.y, window.width, 32);
                }
                window.focused = false;
            }
        }
    }

    void focusTopWindowOnDesktop(size_t desktop, Damage* damage = null)
    {
        size_t bestIndex = INVALID_INDEX;
        size_t bestZ = 0;
        foreach (i, ref window; _windows[0 .. _windowCount])
        {
            if (window.desktop == desktop && !window.minimized)
            {
                if (bestIndex == INVALID_INDEX || window.zOrder >= bestZ)
                {
                    bestIndex = i;
                    bestZ = window.zOrder;
                }
            }
        }

        clearFocus(desktop, damage);
        if (bestIndex != INVALID_INDEX)
        {
            _windows[bestIndex].focused = true;
            if (damage !is null)
            {
                damage.add(_windows[bestIndex].x, _windows[bestIndex].y, _windows[bestIndex].width, 32);
            }
        }
    }

    void layoutTiled(Damage* damage = null)
    {
        size_t tileCount = 0;
        foreach (ref window; _windows[0 .. _windowCount])
        {
            if (window.desktop == _activeDesktop && !window.floating && !window.minimized)
            {
                ++tileCount;
            }
        }

        if (tileCount == 0)
        {
            return;
        }

        const availableHeight = (_screenHeight > _taskbarHeight) ? _screenHeight - _taskbarHeight : _screenHeight;
        uint tileHeight = (tileCount > 0) ? (availableHeight / tileCount) : availableHeight;
        if (tileHeight < MIN_WINDOW_HEIGHT)
        {
            tileHeight = MIN_WINDOW_HEIGHT;
        }
        const tileWidth = _screenWidth;
        size_t placed = 0;
        foreach (ref window; _windows[0 .. _windowCount])
        {
            if (window.desktop != _activeDesktop || window.floating || window.minimized)
            {
                continue;
            }

            if (damage !is null) damage.add(window.rect());

            window.x = 0;
            window.y = cast(uint) (placed * tileHeight);
            window.width = tileWidth;
            window.height = tileHeight;
            
            if (damage !is null) damage.add(window.rect());
            
            ++placed;
        }
    }

    static bool hasCapacity(size_t count, size_t capacity)
    {
        return count < capacity;
    }

    static uint clampSigned(uint start, int delta, uint maxBound, uint extent)
    {
        int temp = cast(int) start + delta;
        if (temp < 0)
        {
            temp = 0;
        }
        const limit = (maxBound > extent) ? cast(int)(maxBound - extent) : 0;
        if (temp > limit)
        {
            temp = limit;
        }
        return cast(uint) temp;
    }

    static uint clampSize(uint value, int delta, uint limit, uint minimum)
    {
        int temp = cast(int) value + delta;
        if (temp < minimum)
        {
            temp = cast(int) minimum;
        }
        if (temp > limit)
        {
            temp = cast(int) limit;
        }
        return cast(uint) temp;
    }

    void enforceBounds(Window* window)
    {
        if (window is null)
        {
            return;
        }

        if (window.x + window.width > _screenWidth)
        {
            window.x = (_screenWidth > window.width) ? _screenWidth - window.width : 0;
        }
        const availableHeight = (_screenHeight > _taskbarHeight) ? _screenHeight - _taskbarHeight : _screenHeight;
        if (window.y + window.height > availableHeight)
        {
            window.y = (availableHeight > window.height) ? availableHeight - window.height : 0;
        }
    }

    void attachSurface(Window* window)
    {
        if (window is null || _allocateSurface is null)
        {
            return;
        }

        Canvas canvas;
        size_t id = INVALID_INDEX;
        if (_allocateSurface(window.width, window.height, id, canvas))
        {
            window.surfaceId = id;
            window.surfaceCanvas = canvas;
        }
    }

    void releaseSurface(size_t id)
    {
        if (_releaseSurface is null || id == INVALID_INDEX)
        {
            return;
        }
        _releaseSurface(id);
    }
}

alias SurfaceAllocator = bool function(uint width, uint height, out size_t id, out Canvas canvas) @nogc nothrow;
alias SurfaceResizer = bool function(size_t id, uint width, uint height, out Canvas canvas) @nogc nothrow;
alias SurfaceReleaser = void function(size_t id) @nogc nothrow;
