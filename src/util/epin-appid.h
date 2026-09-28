// epin-appid.h — domain-qualified Wayland app_id for anonymOS GUI clients (2026-09-27).
//
// Returns "<base>@<EPIN_DOMAIN>" (e.g. "epin-calc@Work") when the app was spawned INTO a domain,
// else just "<base>" (unqualified — e.g. launched from a global keybind with no domain).  This lets
// a PER-DOMAIN Hyprland window rule route the SAME app differently depending on which domain launched
// it: the Domain Manager's per-app "Overlay" toggle (on a given domain's Applications tab) writes a
// rule matching "<base>@<domain>" to float that app's window onto the special:overlay plane, so the
// same app can be an overlay program in one domain and a normal tiled window in another.
//
// SECURITY NOTE: this only changes the Wayland app_id (a window-management hint).  The trusted,
// unspoofable domain-COLOR identity border is drawn by the kernel from the owning task's pid/identity
// (posix.d hosIdentityColor), NOT from the app_id, so it is unaffected by this qualification.
#ifndef EPIN_APPID_H
#define EPIN_APPID_H
#include <stdio.h>
#include <stdlib.h>

static inline const char *epin_domain_appid(const char *base) {
    static char epin__appid_buf[96];
    const char *dom = getenv("EPIN_DOMAIN");
    if (dom && dom[0]) {
        snprintf(epin__appid_buf, sizeof epin__appid_buf, "%s@%s", base, dom);
        return epin__appid_buf;
    }
    return base;
}

#endif /* EPIN_APPID_H */
