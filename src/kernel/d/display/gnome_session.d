module display.gnome_session;

// --------------------------------------------------------------------------
// GNOME desktop session bootstrap
//
// This module prepares a Wayland-centric GNOME environment and probes a small
// desktop chain:
//
//   1. /sbin/dbus-daemon --system
//   2. /sbin/NetworkManager --no-daemon
//   3. /sbin/dbus-daemon --session
//   4. /sbin/dconf-service
//   5. /sbin/pipewire
//   6. /sbin/wireplumber
//   7. /sbin/pipewire-pulse
//   8. /sbin/logind
//   9. /sbin/gnome-settings-daemon
//   10. /sbin/mutter
//   11. /sbin/gnome-shell --wayland --display-server
//   12. /sbin/gdm
//   13. keep the compatibility greeter onscreen if the GNOME launcher chain
//       cannot be completed
//
// The D-Bus, NetworkManager, dconf, PipeWire, GDM, and GNOME Shell entrypoints
// exported by the build are compatibility modules that keep the desktop
// middleware surface coherent. Mutter is the real compositor payload.
// --------------------------------------------------------------------------

import userland.shell.console : printLine, print, printUnsigned;
import core.syscalls.posix : spawnRegisteredProcess, pid_t;

@nogc nothrow:

private __gshared pid_t  g_gnomePid     = 0;
private __gshared pid_t  g_systemBusPid = 0;
private __gshared pid_t  g_networkManagerPid = 0;
private __gshared pid_t  g_sessionBusPid = 0;
private __gshared pid_t  g_dconfPid     = 0;
private __gshared pid_t  g_pipewirePid  = 0;
private __gshared pid_t  g_wirePlumberPid = 0;
private __gshared pid_t  g_pipewirePulsePid = 0;
private __gshared pid_t  g_logindPid    = 0;
private __gshared pid_t  g_gnomeSettingsDaemonPid = 0;
private __gshared bool   g_gnomeActive  = false;

private void logSpawnSuccess(const(char)[] label, pid_t pid) @nogc nothrow
{
    print("[gnome] ");
    print(label);
    print(" spawned pid=");
    printUnsigned(cast(uint) pid);
    printLine("");
}

private bool trySpawnSystemBus() @nogc nothrow
{
    const(char)*[4] args;
    args[0] = "/sbin/dbus-daemon\0".ptr;
    args[1] = "--system\0".ptr;
    args[2] = "--nofork\0".ptr;
    args[3] = null;

    g_systemBusPid = spawnRegisteredProcess(args[0], args.ptr, null);
    if (g_systemBusPid <= 0)
    {
        return false;
    }

    logSpawnSuccess("dbus system bus", g_systemBusPid);
    return true;
}

private bool trySpawnSessionBus(const(char*)* envp) @nogc nothrow
{
    const(char)*[5] args;
    args[0] = "/sbin/dbus-daemon\0".ptr;
    args[1] = "--session\0".ptr;
    args[2] = "--nofork\0".ptr;
    args[3] = "--address=unix:path=/run/user/1000/bus\0".ptr;
    args[4] = null;

    g_sessionBusPid = spawnRegisteredProcess(args[0], args.ptr, envp);
    if (g_sessionBusPid <= 0)
    {
        return false;
    }

    logSpawnSuccess("dbus session bus", g_sessionBusPid);
    return true;
}

private bool trySpawnNetworkManager(const(char*)* envp) @nogc nothrow
{
    const(char)*[3] args;
    args[0] = "/sbin/NetworkManager\0".ptr;
    args[1] = "--no-daemon\0".ptr;
    args[2] = null;

    g_networkManagerPid = spawnRegisteredProcess(args[0], args.ptr, envp);
    if (g_networkManagerPid <= 0)
    {
        return false;
    }

    logSpawnSuccess("NetworkManager", g_networkManagerPid);
    return true;
}

private bool trySpawnDconfService(const(char*)* envp) @nogc nothrow
{
    const(char)*[2] args;
    args[0] = "/sbin/dconf-service\0".ptr;
    args[1] = null;

    g_dconfPid = spawnRegisteredProcess(args[0], args.ptr, envp);
    if (g_dconfPid <= 0)
    {
        return false;
    }

    logSpawnSuccess("dconf settings service", g_dconfPid);
    return true;
}

private bool trySpawnPipeWire(const(char*)* envp) @nogc nothrow
{
    const(char)*[4] args;
    args[0] = "/sbin/pipewire\0".ptr;
    args[1] = "-c\0".ptr;
    args[2] = "/etc/pipewire/pipewire.conf\0".ptr;
    args[3] = null;

    g_pipewirePid = spawnRegisteredProcess(args[0], args.ptr, envp);
    if (g_pipewirePid <= 0)
    {
        return false;
    }

    logSpawnSuccess("pipewire", g_pipewirePid);
    return true;
}

private bool trySpawnWirePlumber(const(char*)* envp) @nogc nothrow
{
    const(char)*[4] args;
    args[0] = "/sbin/wireplumber\0".ptr;
    args[1] = "-c\0".ptr;
    args[2] = "/etc/wireplumber/wireplumber.conf\0".ptr;
    args[3] = null;

    g_wirePlumberPid = spawnRegisteredProcess(args[0], args.ptr, envp);
    if (g_wirePlumberPid <= 0)
    {
        return false;
    }

    logSpawnSuccess("wireplumber", g_wirePlumberPid);
    return true;
}

private bool trySpawnPipeWirePulse(const(char*)* envp) @nogc nothrow
{
    const(char)*[4] args;
    args[0] = "/sbin/pipewire-pulse\0".ptr;
    args[1] = "-c\0".ptr;
    args[2] = "/etc/pipewire/pipewire-pulse.conf\0".ptr;
    args[3] = null;

    g_pipewirePulsePid = spawnRegisteredProcess(args[0], args.ptr, envp);
    if (g_pipewirePulsePid <= 0)
    {
        return false;
    }

    logSpawnSuccess("pipewire-pulse", g_pipewirePulsePid);
    return true;
}

private bool trySpawnLogind() @nogc nothrow
{
    const(char)*[2] args;
    args[0] = "/sbin/logind\0".ptr;
    args[1] = null;

    g_logindPid = spawnRegisteredProcess(args[0], args.ptr, null);
    if (g_logindPid <= 0)
    {
        return false;
    }

    logSpawnSuccess("logind", g_logindPid);
    return true;
}

private bool trySpawnGnomeSettingsDaemon(const(char*)* envp) @nogc nothrow
{
    const(char)*[2] args;
    args[0] = "/sbin/gnome-settings-daemon\0".ptr;
    args[1] = null;

    g_gnomeSettingsDaemonPid = spawnRegisteredProcess(args[0], args.ptr, envp);
    if (g_gnomeSettingsDaemonPid <= 0)
    {
        return false;
    }

    logSpawnSuccess("gnome-settings-daemon", g_gnomeSettingsDaemonPid);
    return true;
}

private bool trySpawnGdm(const(char*)* envp) @nogc nothrow
{
    const(char)*[2] args;
    args[0] = "/sbin/gdm\0".ptr;
    args[1] = null;

    g_gnomePid = spawnRegisteredProcess(args[0], args.ptr, envp);
    if (g_gnomePid <= 0)
    {
        return false;
    }

    g_gnomeActive = true;
    logSpawnSuccess("gdm", g_gnomePid);
    return true;
}

private bool trySpawnGnomeShell(const(char*)* envp) @nogc nothrow
{
    const(char)*[4] args;
    args[0] = "/sbin/gnome-shell\0".ptr;
    args[1] = "--wayland\0".ptr;
    args[2] = "--display-server\0".ptr;
    args[3] = null;

    g_gnomePid = spawnRegisteredProcess(args[0], args.ptr, envp);
    if (g_gnomePid <= 0)
    {
        return false;
    }

    g_gnomeActive = true;
    logSpawnSuccess("gnome-shell", g_gnomePid);
    return true;
}

private bool trySpawnMutter(const(char*)* envp) @nogc nothrow
{
    const(char)*[2] args;
    args[0] = "/sbin/mutter\0".ptr;
    args[1] = null;

    g_gnomePid = spawnRegisteredProcess(args[0], args.ptr, envp);
    if (g_gnomePid <= 0)
    {
        return false;
    }

    g_gnomeActive = true;
    logSpawnSuccess("mutter compositor", g_gnomePid);
    return true;
}

/// Start a GNOME desktop Wayland session through the real Mutter compositor
/// first, then compatibility launchers if needed.
/// Returns true if a desktop process was successfully spawned; false if the
/// compatibility greeter should remain onscreen.
bool startGnomeSession() @nogc nothrow
{
    if (g_gnomePid > 0) return g_gnomeActive;

    printLine("[gnome] Starting GNOME desktop Wayland session...");
    print  ("[gnome]   WAYLAND_DISPLAY=wayland-0");  printLine("");
    print  ("[gnome]   XDG_RUNTIME_DIR=/run/user/1000"); printLine("");
    print  ("[gnome]   GDK_BACKEND=wayland"); printLine("");
    print  ("[gnome]   GDMSESSION=gnome"); printLine("");
    print  ("[gnome]   DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket"); printLine("");
    print  ("[gnome]   NetworkManager=enabled"); printLine("");
    print  ("[gnome]   DCONF_PROFILE=user"); printLine("");
    print  ("[gnome]   GSETTINGS_BACKEND=dconf"); printLine("");
    print  ("[gnome]   PIPEWIRE_REMOTE=pipewire-0"); printLine("");
    print  ("[gnome]   PULSE_SERVER=unix:/run/user/1000/pulse/native"); printLine("");

    const(char)*[26] env;
    env[0] = "WAYLAND_DISPLAY=wayland-0\0".ptr;
    env[1] = "XDG_RUNTIME_DIR=/run/user/1000\0".ptr;
    env[2] = "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus\0".ptr;
    env[3] = "GDK_BACKEND=wayland\0".ptr;
    env[4] = "CLUTTER_BACKEND=wayland\0".ptr;
    env[5] = "XDG_SESSION_TYPE=wayland\0".ptr;
    env[6] = "XDG_CURRENT_DESKTOP=GNOME\0".ptr;
    env[7] = "XDG_SESSION_DESKTOP=gnome\0".ptr;
    env[8] = "DESKTOP_SESSION=gnome\0".ptr;
    env[9] = "MUTTER_DEBUG_DUMMY_MODE_SPECS=1920x1080\0".ptr;
    env[10] = "GDMSESSION=gnome\0".ptr;
    env[11] = "XDG_SEAT=seat0\0".ptr;
    env[12] = "XDG_VTNR=1\0".ptr;
    env[13] = "DBUS_SYSTEM_BUS_ADDRESS=unix:path=/run/dbus/system_bus_socket\0".ptr;
    env[14] = "PIPEWIRE_RUNTIME_DIR=/run/user/1000\0".ptr;
    env[15] = "PIPEWIRE_REMOTE=pipewire-0\0".ptr;
    env[16] = "PULSE_SERVER=unix:/run/user/1000/pulse/native\0".ptr;
    env[17] = "DCONF_PROFILE=user\0".ptr;
    env[18] = "GSETTINGS_BACKEND=dconf\0".ptr;
    env[19] = "GSETTINGS_SCHEMA_DIR=/usr/share/glib-2.0/schemas\0".ptr;
    env[20] = "XDG_DATA_DIRS=/usr/share\0".ptr;
    env[21] = "XDG_CONFIG_DIRS=/etc\0".ptr;
    env[22] = "HOME=/root\0".ptr;
    env[23] = "PATH=/usr/bin:/bin:/usr/local/bin:/sbin:/usr/sbin\0".ptr;
    env[24] = "DISPLAY=\0".ptr;
    env[25] = null;

    if (trySpawnSystemBus())
    {
        printLine("[gnome] system bus ready");
    }
    else
    {
        printLine("[gnome] system bus unavailable, continuing without system D-Bus");
    }

    if (trySpawnNetworkManager(env.ptr))
    {
        printLine("[gnome] NetworkManager ready");
    }
    else
    {
        printLine("[gnome] NetworkManager unavailable, GNOME network stack will remain inert");
    }

    if (trySpawnSessionBus(env.ptr))
    {
        printLine("[gnome] session bus ready");
    }
    else
    {
        printLine("[gnome] session bus unavailable, continuing without session D-Bus");
    }

    if (trySpawnDconfService(env.ptr))
    {
        printLine("[gnome] dconf settings service ready");
    }
    else
    {
        printLine("[gnome] dconf service unavailable, GSettings writes will be best-effort only");
    }

    if (trySpawnPipeWire(env.ptr))
    {
        printLine("[gnome] pipewire core ready");
    }
    else
    {
        printLine("[gnome] pipewire unavailable, continuing without media graph daemon");
    }

    if (trySpawnWirePlumber(env.ptr))
    {
        printLine("[gnome] wireplumber ready");
    }
    else
    {
        printLine("[gnome] wireplumber unavailable, continuing without session policy");
    }

    if (trySpawnPipeWirePulse(env.ptr))
    {
        printLine("[gnome] pipewire-pulse ready");
    }
    else
    {
        printLine("[gnome] pipewire-pulse unavailable, PulseAudio compatibility disabled");
    }

    if (trySpawnLogind())
    {
        printLine("[gnome] logind ready");
    }
    else
    {
        printLine("[gnome] logind unavailable, continuing without login1 daemon");
    }

    if (trySpawnGnomeSettingsDaemon(env.ptr))
    {
        printLine("[gnome] gnome-settings-daemon ready");
    }
    else
    {
        printLine("[gnome] gnome-settings-daemon unavailable, GNOME settings services disabled");
    }

    if (trySpawnMutter(env.ptr))
    {
        return true;
    }

    printLine("[gnome] mutter unavailable, trying /sbin/gnome-shell");
    if (trySpawnGnomeShell(env.ptr))
    {
        return true;
    }

    printLine("[gnome] gnome-shell unavailable, trying /sbin/gdm");
    if (trySpawnGdm(env.ptr))
    {
        return true;
    }

    printLine("[gnome] GNOME launchers unavailable; keeping compatibility greeter onscreen");
    return false;
}

/// Returns true if the preferred desktop compositor/session was started.
bool gnomeSessionActive() @nogc nothrow
{
    return g_gnomeActive;
}

/// PID of the spawned desktop compositor or launcher process.
pid_t gnomeSessionPid() @nogc nothrow
{
    return g_gnomePid;
}
