module minimal_os.display.window_manager.manager;

import minimal_os.display.framebuffer : framebufferAvailable;

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
        _windowCount = 0;
        _nextId = 1;
        _activeDesktop = 0;
        _desktopCount = 1;
        _configured = false;
        foreach (ref desktop; _layouts)
        {
            desktop = LayoutMode.tiling;
        }
        _shortcutCount = 0;
    }

    void configure(uint screenWidth, uint screenHeight, uint taskbarHeight, size_t desktopCount)
    {
        _screenWidth = screenWidth;
        _screenHeight = screenHeight;
        _taskbarHeight = taskbarHeight;
        _desktopCount = (desktopCount == 0 || desktopCount > MAX_DESKTOPS) ? MAX_DESKTOPS : desktopCount;
        _configured = framebufferAvailable();
    }

    size_t createWindow(immutable(char)[] title, uint width, uint height, bool floating = false, size_t desktop = INVALID_INDEX)
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

        focusWindow(w.id);
        applyLayout();
        return w.id;
    }

    bool destroyWindow(size_t id)
    {
        const index = findIndex(id);
        if (index == INVALID_INDEX)
        {
            return false;
        }

        const wasFocused = _windows[index].focused;

        foreach (i; index .. _windowCount - 1)
        {
            _windows[i] = _windows[i + 1];
        }
        --_windowCount;

        if (wasFocused)
        {
            focusTopWindowOnDesktop(_activeDesktop);
        }

        applyLayout();
        return true;
    }

    bool focusWindow(size_t id)
    {
        const index = findIndex(id);
        if (index == INVALID_INDEX)
        {
            return false;
        }

        const desktop = _windows[index].desktop;
        _activeDesktop = desktop;
        clearFocus(desktop);
        _windows[index].focused = true;
        bringToFront(index);
        return true;
    }

    bool moveWindow(size_t id, int dx, int dy)
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

        const newX = clampSigned(w.x, dx, _screenWidth, w.width);
        const newY = clampSigned(w.y, dy, _screenHeight - _taskbarHeight, w.height);
        w.x = newX;
        w.y = newY;
        return true;
    }

    bool resizeWindow(size_t id, int dw, int dh)
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

        uint newWidth = clampSize(w.width, dw, _screenWidth, MIN_WINDOW_WIDTH);
        uint newHeight = clampSize(w.height, dh, _screenHeight - _taskbarHeight, MIN_WINDOW_HEIGHT);
        w.width = newWidth;
        w.height = newHeight;
        enforceBounds(w);
        return true;
    }

    bool toggleFloating(size_t id, bool floating)
    {
        const index = findIndex(id);
        if (index == INVALID_INDEX)
        {
            return false;
        }
        _windows[index].floating = floating;
        applyLayout();
        return true;
    }

    bool minimizeWindow(size_t id)
    {
        const index = findIndex(id);
        if (index == INVALID_INDEX)
        {
            return false;
        }
        _windows[index].minimized = true;
        if (_windows[index].focused)
        {
            focusTopWindowOnDesktop(_windows[index].desktop);
        }
        return true;
    }

    bool maximizeWindow(size_t id, bool maximize)
    {
        const index = findIndex(id);
        if (index == INVALID_INDEX)
        {
            return false;
        }

        auto w = &_windows[index];
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
        bringToFront(index);
        return true;
    }

    bool switchDesktop(size_t desktop)
    {
        if (desktop >= _desktopCount)
        {
            return false;
        }
        _activeDesktop = desktop;
        focusTopWindowOnDesktop(desktop);
        applyLayout();
        return true;
    }

    bool setLayout(size_t desktop, LayoutMode layout)
    {
        if (desktop >= _desktopCount)
        {
            return false;
        }
        _layouts[desktop] = layout;
        if (desktop == _activeDesktop)
        {
            applyLayout();
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

    void applyLayout()
    {
        if (!_configured)
        {
            return;
        }

        if (_layouts[_activeDesktop] == LayoutMode.tiling)
        {
            layoutTiled();
        }
    }

    const(Window)[] windows() const
    {
        return _windows[0 .. _windowCount];
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
        foreach (i; index .. _windowCount - 1)
        {
            _windows[i] = _windows[i + 1];
        }
        window.zOrder = _nextZOrder++;
        _windows[_windowCount - 1] = window;
    }

    void clearFocus(size_t desktop)
    {
        foreach (ref window; _windows[0 .. _windowCount])
        {
            if (window.desktop == desktop)
            {
                window.focused = false;
            }
        }
    }

    void focusTopWindowOnDesktop(size_t desktop)
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

        clearFocus(desktop);
        if (bestIndex != INVALID_INDEX)
        {
            _windows[bestIndex].focused = true;
        }
    }

    void layoutTiled()
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

            window.x = 0;
            window.y = cast(uint) (placed * tileHeight);
            window.width = tileWidth;
            window.height = tileHeight;
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
}
