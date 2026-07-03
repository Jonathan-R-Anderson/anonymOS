/*
 * hos-wifiterm.c -- TEMPORARY (WiFi/M3 debugging) lightweight terminal launcher (static-musl).
 *
 * Autostart execs a bare path with no env, and wl-term defaults to a full login zsh (compinit +
 * oh-my-zsh + powerlevel10k) whose startup fork-storm — combined with the task-slot leak — exhausts
 * the task table and stalls the desktop/installer.  This wrapper sets EPIN_SHELL=light so wl-term
 * runs `zsh -f -i` (no rc files, no compinit) instead: an instant, lightweight terminal in which the
 * user can run `/hos-nmcli-test`.  Remove the `autostart = /hos-wifiterm` line in desktop.conf to revert.
 */
#include <unistd.h>
#include <stdlib.h>

extern char **environ;

int main(void)
{
    setenv("EPIN_SHELL", "light", 1);
    char *argv[] = { "/wl-term", 0 };
    execve("/wl-term", argv, environ);
    return 1;
}
