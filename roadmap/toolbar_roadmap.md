# Implement a GNOME-Style Top Bar and Quick Settings Overlay

Implement a complete desktop top bar for the operating system that closely matches the appearance, behavior, layout, and interaction model of Ubuntu’s GNOME Shell top bar while integrating with the existing Hyprland-style desktop environment.

The finished interface must be functional, not a static mockup.

## Primary Goal

Create a persistent top panel across the top of the screen with three main regions:

1. Activities and workspace controls on the left
2. Clock, calendar, and notifications in the center
3. System status indicators and an expandable Quick Settings panel on the right

The panel and all expanded menus must render as overlays above application windows and the desktop without changing window geometry, moving tiled windows, or reserving additional layout space beyond the height of the top bar.

The desktop beneath the panel should continue to behave like a Hyprland-style compositor with tiled windows, workspaces, smooth animations, rounded windows, blur, transparency, and keyboard-driven navigation.

---

# 1. Top Bar Layout

Create a top bar approximately 30 to 36 logical pixels tall.

It must:

* Span the full width of every monitor
* Remain fixed at the top
* Render above all regular windows
* Use the compositor’s highest normal shell layer
* Support transparent, translucent, blurred, or opaque backgrounds
* Never become part of the tiling layout
* Never push application windows downward when a menu opens
* Adapt correctly to display scaling
* Respect monitor-specific geometry
* Work correctly on multi-monitor setups

Suggested layout:

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Activities / Workspaces     Date and Time       Network Sound Power │
└─────────────────────────────────────────────────────────────────────┘
```

Use three logical containers:

```text
left_section
center_section
right_section
```

The center section must remain visually centered on the physical monitor, even when the left and right sections have different widths.

---

# 2. Left Side: Activities and Workspaces

The left side must include an Activities button or equivalent workspace-overview control.

Clicking Activities must open a full-screen or large-screen overview overlay containing:

* Current workspace thumbnails
* Open-window previews
* Search field
* Application launcher access
* Drag-and-drop movement of windows between workspaces
* Active workspace highlighting
* Smooth opening and closing animations
* Keyboard navigation
* Escape-to-close behavior
* Click-outside-to-close behavior

The overview must appear above the desktop and all regular application windows.

The left side may also display:

* Active application name
* Active window title
* Workspace indicator
* Workspace number
* Application icon

Support configurable display modes so these elements can be enabled or disabled.

Example configuration:

```toml
[top_bar.left]
show_activities = true
show_workspace_indicator = true
show_active_application = true
show_window_title = false
```

Workspace indicators must update immediately when:

* The active workspace changes
* A workspace is created
* A workspace is removed
* A window is moved to another workspace
* A monitor changes its active workspace

---

# 3. Center: Clock, Calendar, and Notifications

Display the current date and time in the center of the panel.

Example:

```text
Mon Jul 13 12:42 PM
```

The date and time format must be configurable.

Clicking the center clock must open a GNOME-style date, calendar, and notifications overlay.

The expanded panel must include:

* Current date
* Monthly calendar
* Previous-month button
* Next-month button
* Today button
* Selected-day highlighting
* Current-day highlighting
* Upcoming calendar events
* Notification history
* Notification grouping by application
* Dismiss-one action
* Dismiss-all action
* Do Not Disturb toggle
* Empty-state message when there are no notifications

The calendar and notification panel must:

* Open below the top bar
* Be centered relative to the monitor
* Appear above all normal windows
* Use rounded corners
* Use drop shadows
* Support optional background blur
* Animate when opening and closing
* Close when the user clicks outside
* Close when Escape is pressed
* Remain open while interacting with its contents
* Trap keyboard focus while open
* Restore focus to the previously focused window after closing

Suggested layout:

```text
┌──────────────────────────────────────────────┐
│ Monday, July 13                              │
├───────────────────────┬──────────────────────┤
│ Notifications         │ July 2026            │
│                       │ Su Mo Tu We Th Fr Sa │
│ App notification      │          1  2  3  4  │
│ App notification      │  5  6  7  8  9 10 11 │
│                       │ 12 13 14 15 16 17 18 │
│ Clear All             │ ...                  │
└───────────────────────┴──────────────────────┘
```

Integrate with the operating system’s notification service and calendar provider when available. Create abstraction interfaces when those services do not yet exist.

Suggested interfaces:

```text
NotificationService
CalendarService
ClockService
DoNotDisturbService
```

---

# 4. Right Side: System Status Area

The right side must contain compact status indicators for:

* Network connection
* Wi-Fi
* Wired Ethernet
* VPN
* Bluetooth
* Audio output
* Microphone status
* Battery level
* Charging state
* Power profile
* Screen brightness
* Night light
* Airplane mode
* Accessibility
* Keyboard layout
* Current user
* Power and session controls

Only show indicators that are relevant to the current device state.

Examples:

* Hide the battery icon on systems without a battery
* Hide Bluetooth controls when no Bluetooth adapter exists
* Show a muted microphone indicator only when the microphone is muted or actively used
* Show a VPN indicator only when connected or connecting
* Show a charging symbol when external power is connected

The entire right-side status group should behave as one clickable target, similar to GNOME Shell.

Clicking it must open the Quick Settings panel.

---

# 5. GNOME-Style Quick Settings Panel

Implement an expandable Quick Settings panel that opens from the upper-right corner directly below the top bar.

This panel must function as an overlay above the Hyprland-style desktop and all normal windows.

Do not implement it as a regular tiled application window.

The panel must use the compositor’s overlay or shell layer.

It must include:

## Primary Toggles

* Wi-Fi
* Bluetooth
* Airplane Mode
* Dark Mode
* Night Light
* Do Not Disturb
* VPN
* Mobile Broadband when available
* Power Mode
* Accessibility

Each primary toggle must support:

* Icon
* Label
* Current state
* Enabled and disabled styling
* Hover state
* Keyboard focus state
* Click action
* Optional secondary arrow or submenu button

Example tile:

```text
┌──────────────────────────┐
│  Wi-Fi             ▸     │
│  Connected Network       │
└──────────────────────────┘
```

Clicking the main body of a toggle should change the feature state.

Clicking the arrow should open a detailed submenu when applicable.

---

# 6. Wi-Fi Submenu

The Wi-Fi submenu must include:

* Current Wi-Fi state
* Current connected network
* Signal strength
* Available networks
* Secured-network indicator
* Connect action
* Disconnect action
* Forget network action
* Refresh action
* Open network settings action
* Loading state
* Error state
* No-networks state

Password-protected networks must display a secure password entry dialog.

Do not store plaintext Wi-Fi passwords in application configuration.

Use the platform network-management service such as NetworkManager through a clean backend abstraction.

Suggested interface:

```text
NetworkService
```

Example methods:

```text
get_wifi_state()
set_wifi_enabled(enabled)
list_access_points()
connect_to_network(ssid, credentials)
disconnect()
forget_network(id)
get_active_connection()
```

---

# 7. Bluetooth Submenu

The Bluetooth submenu must include:

* Bluetooth enabled state
* Adapter state
* Paired devices
* Connected devices
* Available nearby devices
* Pair action
* Connect action
* Disconnect action
* Remove device action
* Open Bluetooth settings action
* Device battery level when available

Use BlueZ or the platform Bluetooth service through an abstraction.

Suggested interface:

```text
BluetoothService
```

---

# 8. Audio Controls

Include a horizontal output-volume slider.

The audio area must provide:

* Current volume
* Mute button
* Output-device selector
* Current output device
* Input-volume control
* Microphone mute button
* Current input device
* Application-level volume controls where supported
* Real-time level updates
* Hardware-key synchronization

The speaker icon should change based on volume:

* Muted
* Low
* Medium
* High

The audio submenu should list available devices.

Example:

```text
Output
✓ Built-in Audio
  HDMI Display
  Bluetooth Headphones

Input
✓ Internal Microphone
  USB Microphone
```

Use PipeWire, WirePlumber, PulseAudio, or the platform audio service through an abstraction.

Suggested interface:

```text
AudioService
```

---

# 9. Brightness Controls

Include a horizontal display-brightness slider when supported.

The slider must:

* Update brightness continuously
* Reflect hardware-key changes
* Hide on systems where brightness control is unavailable
* Support multiple displays when possible
* Clamp values safely
* Avoid blocking the UI during hardware updates

Suggested interface:

```text
BrightnessService
```

---

# 10. Battery and Power

Display battery information including:

* Current percentage
* Charging status
* Estimated time remaining
* Estimated time until charged
* Battery health when available
* Current power source
* Current power profile

Support power profiles such as:

* Power Saver
* Balanced
* Performance

The power-profile submenu must update the platform service immediately.

Suggested interface:

```text
PowerService
```

---

# 11. Session and Power Buttons

At the bottom of the Quick Settings panel, include buttons for:

* Settings
* Lock
* Log Out
* Suspend
* Restart
* Shut Down

Potentially destructive actions must display a confirmation dialog.

The shutdown dialog should resemble:

```text
Power Off

The system will power off automatically in 60 seconds.

[Cancel] [Restart] [Power Off]
```

The confirmation dialog must be modal and rendered above the Quick Settings panel.

Locking the session must close all shell menus first.

Logging out, restarting, and shutting down must use the operating system’s session-management APIs rather than directly terminating arbitrary processes.

Suggested interface:

```text
SessionService
```

---

# 12. Overlay Behavior

All menus must behave like shell overlays.

Required rules:

* Only one major top-bar panel may be open at a time
* Opening Quick Settings closes the calendar panel
* Opening the calendar panel closes Quick Settings
* Opening Activities closes both
* Clicking the active button again closes its panel
* Clicking outside closes the panel
* Pressing Escape closes the panel
* Losing shell focus may close the panel when appropriate
* Opening a modal dialog keeps the parent panel open underneath
* Overlay panels must not alter tiled-window dimensions
* Overlay panels must not become part of the normal task switcher
* Overlay panels must not appear as regular applications
* Overlay panels must not receive normal workspace placement rules
* Panels must stay anchored to the correct monitor
* Panels must close or reposition safely when a monitor is disconnected

Create an overlay controller such as:

```text
ShellOverlayManager
```

It should manage states such as:

```text
CLOSED
QUICK_SETTINGS_OPEN
CALENDAR_OPEN
ACTIVITIES_OPEN
SUBMENU_OPEN
MODAL_OPEN
```

Use an explicit state machine rather than unrelated Boolean flags.

---

# 13. Hyprland-Style Desktop Integration

The desktop environment should retain Hyprland-like behavior underneath the GNOME-style shell.

Required compositor characteristics:

* Dynamic tiling
* Floating windows
* Workspaces
* Per-monitor workspaces
* Rounded corners
* Window gaps
* Blur effects
* Transparent surfaces
* Smooth workspace transitions
* Animated window opening and closing
* Keyboard-first window management
* Pointer and touch support
* Layer-shell-style shell surfaces
* Exclusive keyboard focus for shell overlays when required

The top bar must visually coexist with this environment.

Do not replace the compositor’s tiling system with GNOME Mutter behavior.

Instead, reproduce GNOME Shell’s top-panel user experience while preserving the existing compositor and window manager.

Use appropriate shell layers:

```text
background
bottom
normal
top
overlay
lockscreen
```

Suggested placement:

```text
desktop wallpaper        -> background
desktop widgets          -> bottom
application windows      -> normal
persistent top bar       -> top
expanded shell panels    -> overlay
modal confirmations      -> overlay-modal
lock screen              -> lockscreen
```

---

# 14. Animations

Implement smooth, interruptible animations.

Recommended durations:

```text
hover transition:       100–150 ms
panel open:             180–250 ms
panel close:            150–220 ms
submenu transition:     150–220 ms
workspace overview:     220–350 ms
toggle state change:    100–180 ms
```

Use easing functions similar to:

```text
easeOutCubic
easeInOutCubic
easeOutQuart
```

Quick Settings should animate from the top-right origin using a combination of:

* Opacity
* Slight vertical translation
* Slight scale change

Example:

```text
closed:
opacity = 0
translateY = -8
scale = 0.98

open:
opacity = 1
translateY = 0
scale = 1.0
```

Animations must:

* Be cancellable
* Avoid blocking input
* Respect reduced-motion accessibility settings
* Remain smooth during rapid opening and closing
* Avoid creating duplicate panel instances

---

# 15. Visual Design

Closely follow modern GNOME Shell visual principles.

Use:

* Rounded panel corners
* Consistent spacing
* Compact top-bar indicators
* Large, touch-friendly Quick Settings tiles
* Subtle shadows
* Optional blur
* High-contrast active states
* Clear hover states
* Consistent icon sizes
* Minimal visual clutter

Suggested dimensions:

```text
top bar height:             32 px
top bar horizontal padding: 8–12 px
indicator spacing:          6–10 px
quick settings width:       360–430 px
quick settings padding:     16–20 px
tile height:                48–64 px
tile corner radius:         12–18 px
panel corner radius:        16–24 px
```

The panel should be positioned approximately:

```text
top = top_bar_height + 6 to 10 px
right = 8 to 16 px
```

Add support for:

* Light theme
* Dark theme
* Automatic theme switching
* Accent color
* High-contrast theme
* Reduced transparency
* Reduced motion

Do not hardcode colors throughout individual components.

Use design tokens.

Example:

```text
--shell-bg
--shell-panel-bg
--shell-panel-border
--shell-text
--shell-text-secondary
--shell-hover
--shell-active
--shell-accent
--shell-warning
--shell-danger
--shell-shadow
--shell-radius
```

---

# 16. Icons

Use symbolic icons similar to GNOME’s icon system.

Required icons include:

* Wi-Fi signal levels
* Wired network
* VPN
* Bluetooth
* Volume levels
* Microphone
* Battery levels
* Battery charging
* Brightness
* Night light
* Airplane mode
* Accessibility
* Lock
* Settings
* Log out
* Suspend
* Restart
* Power off
* Previous
* Next
* Expand
* Collapse
* Checkmark

Icons must:

* Scale correctly
* Follow foreground color
* Support high-DPI displays
* Have accessible labels
* Avoid emoji as interface icons

Prefer SVG or a symbolic icon theme.

---

# 17. Input Support

Support:

* Mouse
* Touchpad
* Touchscreen
* Keyboard
* Accessibility input tools

Keyboard requirements:

```text
Super                  Open Activities overview
Super+A                Open application grid
Super+V                Open notification panel
Escape                 Close active shell overlay
Tab                    Move focus
Shift+Tab              Move focus backward
Arrow keys             Navigate menus and grids
Enter or Space         Activate focused control
```

Allow keybindings to be configured.

The top-right panel must also be accessible through a configurable shortcut, for example:

```text
Super+Q
```

Do not steal shortcuts already assigned to window-management commands without checking for conflicts.

---

# 18. Accessibility

All controls must expose:

* Accessible name
* Accessible description
* Role
* State
* Keyboard focus
* Focus order
* Value information for sliders
* Toggle state
* Expanded or collapsed state

Support:

* Screen readers
* High contrast
* Large text
* Reduced motion
* Sticky keys
* Slow keys
* On-screen keyboard
* Keyboard-only navigation

Focus must be clearly visible.

Do not rely only on color to communicate state.

---

# 19. Backend Architecture

Separate presentation code from system control logic.

Recommended architecture:

```text
Shell
├── TopBar
│   ├── LeftSection
│   ├── ClockSection
│   └── StatusSection
├── OverlayManager
├── ActivitiesOverview
├── CalendarNotificationPanel
├── QuickSettingsPanel
│   ├── ToggleGrid
│   ├── AudioControls
│   ├── BrightnessControls
│   ├── PowerControls
│   └── SessionControls
├── Services
│   ├── NetworkService
│   ├── BluetoothService
│   ├── AudioService
│   ├── BrightnessService
│   ├── PowerService
│   ├── NotificationService
│   ├── CalendarService
│   ├── SessionService
│   └── CompositorService
└── Theme
```

Each backend service should publish reactive state changes.

The interface must update immediately when system state changes externally.

Examples:

* Wi-Fi disabled using a command-line tool
* Volume changed using keyboard buttons
* Bluetooth device connected elsewhere
* Battery begins charging
* VPN connection drops
* Workspace changes through a compositor shortcut

Use event subscriptions, IPC, D-Bus, sockets, or compositor events instead of constant high-frequency polling.

Polling may be used only as a safe fallback.

---

# 20. Compositor IPC

Create a compositor integration layer that can:

* Read monitor geometry
* Read scale factor
* Read active workspace
* Read workspace list
* Read open windows
* Read focused window
* Switch workspaces
* Move windows between workspaces
* Focus windows
* Close windows
* Open the application launcher
* Request lock screen
* Register shell surfaces
* Assign shell surface layers
* Apply blur and shadow metadata
* Handle monitor hot-plugging

Suggested interface:

```text
CompositorService
```

Do not scatter compositor-specific commands throughout UI components.

All compositor communication must pass through this service.

---

# 21. Error Handling

Every system control must handle:

* Service unavailable
* Permission denied
* Hardware unavailable
* Operation timed out
* Invalid state
* Device disconnected
* Backend crash
* Unsupported feature

The UI must never crash because one subsystem is unavailable.

Examples:

* Hide brightness controls when no supported display exists
* Disable Bluetooth controls when BlueZ is unavailable
* Show “Network service unavailable” instead of leaving an empty panel
* Reconnect to backend services when they restart
* Preserve the rest of the panel when one component fails

Log meaningful diagnostic errors.

Do not expose stack traces directly to normal users.

---

# 22. Security Requirements

Do not execute shell commands by concatenating untrusted strings.

Use structured APIs or properly escaped argument arrays.

Validate:

* Network names
* Bluetooth device names
* Calendar data
* Notification text
* Application names
* Icon paths
* External URLs

Do not allow notifications to inject markup or executable content.

Do not store credentials in plaintext.

Use the operating system’s secrets service for saved credentials.

Power and session actions must respect user permissions.

---

# 23. Configuration

Create a configuration system for panel behavior and styling.

Example:

```toml
[top_bar]
height = 32
position = "top"
blur = true
opacity = 0.92
show_on_all_monitors = true

[top_bar.clock]
format = "%a %b %d %I:%M %p"
show_seconds = false
show_date = true

[top_bar.quick_settings]
width = 400
animation_duration_ms = 220
close_on_outside_click = true
close_on_escape = true

[top_bar.modules]
activities = true
workspace_indicator = true
active_window = false
clock = true
notifications = true
network = true
bluetooth = true
audio = true
battery = true
power = true
```

Configuration changes should reload without restarting the entire desktop when practical.

---

# 24. Persistence

Persist appropriate user preferences, including:

* Selected power profile
* Do Not Disturb state
* Dark-mode preference
* Night-light preference
* Clock format
* Visible modules
* Panel opacity
* Quick Settings tile order

Do not persist temporary UI state such as an open menu across reboot.

---

# 25. Testing Requirements

Add automated tests for:

* Opening and closing each panel
* Mutual exclusion between major overlays
* Outside-click behavior
* Escape-key behavior
* Keyboard focus trapping
* Monitor hot-plugging
* Multi-monitor panel placement
* Scale-factor changes
* Wi-Fi toggle state
* Bluetooth toggle state
* Volume slider behavior
* Brightness slider behavior
* Battery-state updates
* Power-profile changes
* Notification dismissal
* Calendar month navigation
* Lock, logout, restart, and shutdown confirmation
* Missing backend services
* Backend reconnection
* Reduced-motion mode

Add integration tests with mocked backend services.

Add screenshot or visual-regression tests for:

* Light theme
* Dark theme
* High contrast
* 100%, 125%, 150%, and 200% scaling
* Narrow and wide displays
* Quick Settings open
* Calendar panel open
* Activities overview open

---

# 26. Acceptance Criteria

The implementation is complete only when all of the following are true:

1. A GNOME-style bar is visible across the top of the desktop.
2. The bar is not managed as a normal tiled window.
3. Clicking the top-right system indicators opens a working Quick Settings panel.
4. The Quick Settings panel appears above all normal desktop windows.
5. Opening the panel does not resize or reposition tiled windows.
6. Wi-Fi, Bluetooth, sound, brightness, battery, and power controls reflect real system state.
7. The clock opens a calendar and notification panel.
8. Activities opens a workspace and window overview.
9. Only one major shell overlay is open at a time.
10. Escape and clicking outside close active overlays.
11. Keyboard navigation works throughout.
12. Multi-monitor positioning is correct.
13. The system remains functional when an optional backend service is unavailable.
14. Animations are smooth and respect reduced-motion preferences.
15. The interface closely resembles GNOME Shell while the underlying desktop continues to function like Hyprland.
16. All system actions use proper backend APIs and are not merely visual placeholders.
17. The implementation is modular, testable, and documented.

---

# 27. Development Process

Before modifying code:

1. Inspect the existing repository structure.
2. Identify the GUI toolkit, compositor architecture, event loop, IPC system, theme system, and current panel implementation.
3. Reuse existing framework components where possible.
4. Identify the exact files that need to be changed.
5. Produce a concise implementation plan.
6. Implement the feature in incremental, buildable stages.
7. Run compilation, linting, and tests after each major stage.
8. Fix all introduced errors before finishing.
9. Do not remove existing desktop functionality.
10. Do not replace working compositor code unnecessarily.

Suggested implementation order:

```text
Phase 1: Shell surface and top-bar layout
Phase 2: Overlay manager and panel state machine
Phase 3: Quick Settings visual layout
Phase 4: Network, Bluetooth, and audio backends
Phase 5: Brightness, battery, and power backends
Phase 6: Calendar and notifications
Phase 7: Activities and workspace overview
Phase 8: Accessibility and keyboard navigation
Phase 9: Multi-monitor and scaling support
Phase 10: Testing, documentation, and refinement
```

At completion, provide:

* Summary of the architecture
* List of files changed
* Backend services implemented
* Keyboard shortcuts
* Configuration options
* Build and run instructions
* Tests performed
* Known limitations
* Screenshots or a clear description of the completed interface

Do not stop after generating a visual prototype. Implement the full functional shell behavior.
