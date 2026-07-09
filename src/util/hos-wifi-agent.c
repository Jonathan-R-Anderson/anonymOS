/*
 * hos-wifi-agent.c -- M6: the D-Bus engine behind the top-right Wi-Fi menu.
 *
 * Talks to the real NetworkManager over the system bus (libdbus) and bridges its Wi-Fi state to two
 * plain files so the Wayland menu (wl-wifi-menu) stays a pure file-driven renderer, exactly like
 * wl-domain-manager reads /config/domains.json:
 *
 *   READ  -> /run/wifi/networks : one line per access point "SSID\tSTRENGTH\tSECURITY\tACTIVE\tPATH"
 *            + a header line "#dev\t<devpath>\t<state>" (state = NM device state int).
 *   WRITE <- /run/wifi/connect  : "SSID\nPASSWORD\n" (PASSWORD empty for open); the agent calls
 *            NM.AddAndActivateConnection then unlinks the file.
 *
 * Runs under LD_PRELOAD=/libnshim.so (inherits the routed sockets) + DBUS_SYSTEM_BUS_ADDRESS so its
 * libdbus reaches our dbus-daemon.  Polls every few seconds and requests a fresh scan each cycle.
 */
#include <dbus/dbus.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>

#define NM_DEST  "org.freedesktop.NetworkManager"
#define NM_PATH  "/org/freedesktop/NetworkManager"
#define NM_IFACE "org.freedesktop.NetworkManager"
#define DEV_IFACE   "org.freedesktop.NetworkManager.Device"
#define WIFI_IFACE  "org.freedesktop.NetworkManager.Device.Wireless"
#define AP_IFACE    "org.freedesktop.NetworkManager.AccessPoint"
#define PROP_IFACE  "org.freedesktop.DBus.Properties"

static void napms(long ms){ struct timespec t = { ms/1000, (ms%1000)*1000000L }; nanosleep(&t, 0); }

/* --- Properties.Get helpers (blocking) --- */

/* Get a UINT32 property; returns 0 on error (with *ok=0). */
static dbus_uint32_t get_u32(DBusConnection *c, const char *path, const char *iface,
                             const char *prop, int *ok){
    *ok = 0;
    DBusMessage *m = dbus_message_new_method_call(NM_DEST, path, PROP_IFACE, "Get");
    if (!m) return 0;
    dbus_message_append_args(m, DBUS_TYPE_STRING, &iface, DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);
    DBusError e; dbus_error_init(&e);
    DBusMessage *r = dbus_connection_send_with_reply_and_block(c, m, 5000, &e);
    dbus_message_unref(m);
    if (!r) { dbus_error_free(&e); return 0; }
    DBusMessageIter it, var; dbus_uint32_t v = 0;
    if (dbus_message_iter_init(r, &it) && dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_VARIANT) {
        dbus_message_iter_recurse(&it, &var);
        int t = dbus_message_iter_get_arg_type(&var);
        if (t == DBUS_TYPE_UINT32 || t == DBUS_TYPE_INT32) { dbus_message_iter_get_basic(&var, &v); *ok = 1; }
        else if (t == DBUS_TYPE_BYTE) { unsigned char b=0; dbus_message_iter_get_basic(&var,&b); v=b; *ok=1; }
    }
    dbus_message_unref(r);
    return v;
}

/* Get a STRING property into out (caller buffer); returns 1 on success. */
static int get_str(DBusConnection *c, const char *path, const char *iface,
                   const char *prop, char *out, int outlen){
    out[0]=0;
    DBusMessage *m = dbus_message_new_method_call(NM_DEST, path, PROP_IFACE, "Get");
    if (!m) return 0;
    dbus_message_append_args(m, DBUS_TYPE_STRING, &iface, DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);
    DBusError e; dbus_error_init(&e);
    DBusMessage *r = dbus_connection_send_with_reply_and_block(c, m, 5000, &e);
    dbus_message_unref(m);
    if (!r) { dbus_error_free(&e); return 0; }
    DBusMessageIter it, var; int rc = 0;
    if (dbus_message_iter_init(r, &it) && dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_VARIANT) {
        dbus_message_iter_recurse(&it, &var);
        if (dbus_message_iter_get_arg_type(&var) == DBUS_TYPE_STRING) {
            const char *s=0; dbus_message_iter_get_basic(&var, &s);
            if (s) { strncpy(out, s, outlen-1); out[outlen-1]=0; rc = 1; }
        }
    }
    dbus_message_unref(r);
    return rc;
}

/* Get the AccessPoint Ssid (a variant holding ay) into out; returns SSID length (0 if none/hidden). */
static int get_ssid(DBusConnection *c, const char *ap, char *out, int outlen){
    out[0]=0;
    const char *iface = AP_IFACE, *prop = "Ssid";
    DBusMessage *m = dbus_message_new_method_call(NM_DEST, ap, PROP_IFACE, "Get");
    if (!m) return 0;
    dbus_message_append_args(m, DBUS_TYPE_STRING, &iface, DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);
    DBusError e; dbus_error_init(&e);
    DBusMessage *r = dbus_connection_send_with_reply_and_block(c, m, 5000, &e);
    dbus_message_unref(m);
    if (!r) { dbus_error_free(&e); return 0; }
    DBusMessageIter it, var, arr; int n = 0;
    if (dbus_message_iter_init(r, &it) && dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_VARIANT) {
        dbus_message_iter_recurse(&it, &var);
        if (dbus_message_iter_get_arg_type(&var) == DBUS_TYPE_ARRAY) {
            dbus_message_iter_recurse(&var, &arr);
            while (dbus_message_iter_get_arg_type(&arr) == DBUS_TYPE_BYTE && n < outlen-1) {
                unsigned char b=0; dbus_message_iter_get_basic(&arr, &b);
                out[n++] = (char)b; dbus_message_iter_next(&arr);
            }
        }
    }
    out[n]=0;
    dbus_message_unref(r);
    return n;
}

/* Call a method returning a single ARRAY of OBJECT_PATH (o).  Fills paths[] (each up to 255), returns count. */
static int call_paths(DBusConnection *c, const char *path, const char *iface, const char *method,
                      char paths[][256], int maxpaths){
    DBusMessage *m = dbus_message_new_method_call(NM_DEST, path, iface, method);
    if (!m) return 0;
    DBusError e; dbus_error_init(&e);
    DBusMessage *r = dbus_connection_send_with_reply_and_block(c, m, 8000, &e);
    dbus_message_unref(m);
    if (!r) {
        static int elog = 0;
        if (elog++ < 6) fprintf(stderr, "[wifi-agent] %s.%s FAILED: %s\n", iface, method,
                                dbus_error_is_set(&e)?e.message:"(null reply)");
        dbus_error_free(&e);
        return 0;
    }
    DBusMessageIter it, arr; int n = 0;
    if (dbus_message_iter_init(r, &it) && dbus_message_iter_get_arg_type(&it) == DBUS_TYPE_ARRAY) {
        dbus_message_iter_recurse(&it, &arr);
        while (dbus_message_iter_get_arg_type(&arr) == DBUS_TYPE_OBJECT_PATH && n < maxpaths) {
            const char *p=0; dbus_message_iter_get_basic(&arr, &p);
            if (p) { strncpy(paths[n], p, 255); paths[n][255]=0; n++; }
            dbus_message_iter_next(&arr);
        }
    }
    dbus_message_unref(r);
    return n;
}

/* Find the first Wi-Fi device (DeviceType==2); returns 1 + fills devpath/iface, else 0. */
static int find_wifi_device(DBusConnection *c, char *devpath, int dplen, char *ifname, int iflen,
                            dbus_uint32_t *state){
    char devs[32][256];
    int nd = call_paths(c, NM_PATH, NM_IFACE, "GetDevices", devs, 32);
    for (int i=0;i<nd;i++){
        int ok=0; dbus_uint32_t dt = get_u32(c, devs[i], DEV_IFACE, "DeviceType", &ok);
        if (ok && dt == 2 /*NM_DEVICE_TYPE_WIFI*/){
            strncpy(devpath, devs[i], dplen-1); devpath[dplen-1]=0;
            get_str(c, devs[i], DEV_IFACE, "Interface", ifname, iflen);
            int sok=0; *state = get_u32(c, devs[i], DEV_IFACE, "State", &sok);
            return 1;
        }
    }
    return 0;
}

/* Ask NM to (re)scan, best-effort. */
static void request_scan(DBusConnection *c, const char *devpath){
    DBusMessage *m = dbus_message_new_method_call(NM_DEST, devpath, WIFI_IFACE, "RequestScan");
    if (!m) return;
    DBusMessageIter it, arr;
    dbus_message_iter_init_append(m, &it);
    /* empty a{sv} options */
    dbus_message_iter_open_container(&it, DBUS_TYPE_ARRAY, "{sv}", &arr);
    dbus_message_iter_close_container(&it, &arr);
    DBusError e; dbus_error_init(&e);
    DBusMessage *r = dbus_connection_send_with_reply_and_block(c, m, 5000, &e);
    dbus_message_unref(m);
    if (r) dbus_message_unref(r); else dbus_error_free(&e);
}

/* security label from AP flags */
static const char *sec_label(dbus_uint32_t flags, dbus_uint32_t wpa, dbus_uint32_t rsn){
    if (rsn) return "wpa2";
    if (wpa) return "wpa";
    if (flags & 0x1 /*NM_802_11_AP_FLAGS_PRIVACY*/) return "wep";
    return "open";
}

/* --- demo fallback ---------------------------------------------------------
 * When NetworkManager is unreachable / has no wifi device for ~3 poll cycles
 * (e.g. QEMU with no wireless hardware, or NM still booting), publish a small
 * canned network list so the Wi-Fi drop-down is populated and the whole
 * select -> password -> connect -> checkmark UX stays exercisable.  A demo
 * "connect" simply marks that SSID active.  The moment a REAL wifi device
 * appears, the miss counter resets and the next poll overwrites the file with
 * real data — the demo can never mask real networks. */
static int  g_nm_misses = 0;
static char g_demo_active[128] = "";
/* The canned demo list is OFF by default (it once looked like real networks and
 * confused the user).  Real WiFi comes from either NetworkManager or, in QEMU, the
 * host WiFi bridge (WIFI=1 makes the kernel COM2 bridge own the /run/wifi files and
 * this agent is not even spawned).  Set HOS_WIFI_DEMO=1 to re-enable the demo. */
static int  g_demo_enabled = 0;

static void write_demo_networks(void){
    char tmp[1024];
    static int announced = 0;
    if (!announced){ announced = 1; fprintf(stderr, "[wifi-agent] NM absent; publishing demo network list\n"); }
    int fd = open("/run/wifi/networks.tmp", O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0){ fprintf(stderr, "[wifi-agent] demo: open networks.tmp failed\n"); return; }
    int connected = g_demo_active[0] != 0;
    int n = snprintf(tmp, sizeof tmp,
        "#dev\t/demo\twlan0\t%d\n"
        "EpinAnonymOS-Demo\t82\twpa2\t%d\t/demo/ap0\n"
        "CoffeeShop-Guest\t61\topen\t%d\t/demo/ap1\n"
        "Neighbor-5G\t34\twpa2\t%d\t/demo/ap2\n",
        connected ? 100 : 30,
        strcmp(g_demo_active, "EpinAnonymOS-Demo") == 0,
        strcmp(g_demo_active, "CoffeeShop-Guest") == 0,
        strcmp(g_demo_active, "Neighbor-5G") == 0);
    (void)!write(fd, tmp, n);
    close(fd);
    rename("/run/wifi/networks.tmp", "/run/wifi/networks");
    fprintf(stderr, "[wifi-agent] demo list written\n");
}

/* --- write the networks file --- */
static void write_networks(DBusConnection *c){
    char devpath[256]="", ifname[64]="", tmp[8192]; dbus_uint32_t state=0;
    int have = find_wifi_device(c, devpath, sizeof devpath, ifname, sizeof ifname, &state);
    if (!have){
        if (++g_nm_misses >= 3 && g_demo_enabled){ write_demo_networks(); return; }
    } else {
        g_nm_misses = 0;
        g_demo_active[0] = 0;
    }
    /* External udhcpc obtained a lease (its script touched /run/wifi/dhcp-ok) -> present the device as
     * ACTIVATED(100) so hos-log-upload (wifi_activated: #dev state>=100) proceeds and the menu shows
     * "connected", even though NM itself sits in ip-config forever waiting on its own stalled client. */
    if (have && state < 100 && access("/run/wifi/dhcp-ok", F_OK) == 0) state = 100;
    int fd = open("/run/wifi/networks.tmp", O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fd < 0) return;
    int n = snprintf(tmp, sizeof tmp, "#dev\t%s\t%s\t%u\n", have?devpath:"", ifname, (unsigned)state);
    (void)!write(fd, tmp, n);
    int napcount = 0;
    if (have){
        char aps[128][256];
        int na = call_paths(c, devpath, WIFI_IFACE, "GetAllAccessPoints", aps, 128);
        napcount = na;
        /* active AP (for the checkmark) */
        char active[256]=""; get_str(c, devpath, WIFI_IFACE, "ActiveAccessPoint", active, sizeof active);
        for (int i=0;i<na;i++){
            char ssid[128]; int sl = get_ssid(c, aps[i], ssid, sizeof ssid);
            if (sl == 0) continue;                  /* skip hidden */
            int ok=0;
            dbus_uint32_t str = get_u32(c, aps[i], AP_IFACE, "Strength", &ok);
            dbus_uint32_t fl  = get_u32(c, aps[i], AP_IFACE, "Flags", &ok);
            dbus_uint32_t wpa = get_u32(c, aps[i], AP_IFACE, "WpaFlags", &ok);
            dbus_uint32_t rsn = get_u32(c, aps[i], AP_IFACE, "RsnFlags", &ok);
            int isact = (strcmp(active, aps[i]) == 0);
            /* sanitize SSID: strip tabs/newlines */
            for (char *p=ssid; *p; p++) if (*p=='\t'||*p=='\n') *p=' ';
            n = snprintf(tmp, sizeof tmp, "%s\t%u\t%s\t%d\t%s\n",
                         ssid, (unsigned)str, sec_label(fl,wpa,rsn), isact, aps[i]);
            (void)!write(fd, tmp, n);
        }
    }
    close(fd);
    rename("/run/wifi/networks.tmp", "/run/wifi/networks");
    (void)napcount;
}

/* --- connect path --- */

/* append a {sv} string entry to a dict iter */
static void dict_str(DBusMessageIter *dict, const char *key, const char *val){
    DBusMessageIter e, v;
    dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, 0, &e);
    dbus_message_iter_append_basic(&e, DBUS_TYPE_STRING, &key);
    dbus_message_iter_open_container(&e, DBUS_TYPE_VARIANT, "s", &v);
    dbus_message_iter_append_basic(&v, DBUS_TYPE_STRING, &val);
    dbus_message_iter_close_container(&e, &v);
    dbus_message_iter_close_container(dict, &e);
}
/* append a {s -> ay} entry (byte array variant, e.g. ssid) */
static void dict_ay(DBusMessageIter *dict, const char *key, const unsigned char *bytes, int len){
    DBusMessageIter e, v, arr;
    dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, 0, &e);
    dbus_message_iter_append_basic(&e, DBUS_TYPE_STRING, &key);
    dbus_message_iter_open_container(&e, DBUS_TYPE_VARIANT, "ay", &v);
    dbus_message_iter_open_container(&v, DBUS_TYPE_ARRAY, "y", &arr);
    dbus_message_iter_append_fixed_array(&arr, DBUS_TYPE_BYTE, &bytes, len);
    dbus_message_iter_close_container(&v, &arr);
    dbus_message_iter_close_container(&e, &v);
    dbus_message_iter_close_container(dict, &e);
}
/* open a setting sub-dict "key" -> a{sv}; caller fills *sub then must close both */
static void open_setting(DBusMessageIter *conn, const char *key, DBusMessageIter *entry, DBusMessageIter *sub){
    dbus_message_iter_open_container(conn, DBUS_TYPE_DICT_ENTRY, 0, entry);
    dbus_message_iter_append_basic(entry, DBUS_TYPE_STRING, &key);
    dbus_message_iter_open_container(entry, DBUS_TYPE_ARRAY, "{sv}", sub);
}
static void close_setting(DBusMessageIter *conn, DBusMessageIter *entry, DBusMessageIter *sub){
    dbus_message_iter_close_container(entry, sub);
    dbus_message_iter_close_container(conn, entry);
}

static void do_connect(DBusConnection *c, const char *ssid, const char *psk){
    char devpath[256]="", ifname[64]=""; dbus_uint32_t state=0;
    if (!find_wifi_device(c, devpath, sizeof devpath, ifname, sizeof ifname, &state)){
        /* demo mode (no real wifi device): "connect" = mark the SSID active so the
         * menu's checkmark + the bar's signal glyph respond; refresh immediately. */
        if (g_nm_misses >= 3 && g_demo_enabled){
            snprintf(g_demo_active, sizeof g_demo_active, "%s", ssid);
            fprintf(stderr, "[wifi-agent] demo connect '%s'\n", ssid);
            write_demo_networks();
        }
        return;
    }

    DBusMessage *m = dbus_message_new_method_call(NM_DEST, NM_PATH, NM_IFACE, "AddAndActivateConnection");
    if (!m) return;
    DBusMessageIter args, conn, e, sub;
    dbus_message_iter_init_append(m, &args);
    /* a{sa{sv}} connection settings */
    dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY, "{sa{sv}}", &conn);

    open_setting(&conn, "connection", &e, &sub);
        dict_str(&sub, "type", "802-11-wireless");
        dict_str(&sub, "id", ssid);
    close_setting(&conn, &e, &sub);

    open_setting(&conn, "802-11-wireless", &e, &sub);
        dict_ay(&sub, "ssid", (const unsigned char*)ssid, (int)strlen(ssid));
        dict_str(&sub, "mode", "infrastructure");
    close_setting(&conn, &e, &sub);

    if (psk && psk[0]) {
        open_setting(&conn, "802-11-wireless-security", &e, &sub);
            dict_str(&sub, "key-mgmt", "wpa-psk");
            dict_str(&sub, "psk", psk);
        close_setting(&conn, &e, &sub);
    }
    open_setting(&conn, "ipv4", &e, &sub); dict_str(&sub, "method", "auto"); close_setting(&conn, &e, &sub);
    open_setting(&conn, "ipv6", &e, &sub); dict_str(&sub, "method", "auto"); close_setting(&conn, &e, &sub);

    dbus_message_iter_close_container(&args, &conn);

    /* device object path + specific-object ("/" = let NM pick the AP) */
    const char *dp = devpath; const char *spec = "/";
    dbus_message_iter_append_basic(&args, DBUS_TYPE_OBJECT_PATH, &dp);
    dbus_message_iter_append_basic(&args, DBUS_TYPE_OBJECT_PATH, &spec);

    DBusError err; dbus_error_init(&err);
    DBusMessage *r = dbus_connection_send_with_reply_and_block(c, m, 15000, &err);
    dbus_message_unref(m);
    if (r) { fprintf(stderr, "[wifi-agent] AddAndActivateConnection('%s') OK\n", ssid); dbus_message_unref(r); }
    else   { fprintf(stderr, "[wifi-agent] AddAndActivateConnection('%s') FAILED: %s\n", ssid, err.message?err.message:"?"); dbus_error_free(&err); }
}

/* poll /run/wifi/connect ("SSID\nPASSWORD\n"); returns 1 if a request was handled. */
static int check_connect(DBusConnection *c){
    int fd = open("/run/wifi/connect", O_RDONLY);
    if (fd < 0) return 0;
    char buf[512]; int n = (int)read(fd, buf, sizeof buf - 1); close(fd);
    unlink("/run/wifi/connect");
    if (n <= 0) return 0;
    buf[n]=0;
    char ssid[128]="", psk[128]="";
    char *nl = strchr(buf, '\n');
    if (nl){ *nl=0; strncpy(ssid, buf, sizeof ssid-1);
             char *p = nl+1; char *nl2 = strchr(p, '\n'); if (nl2) *nl2=0; strncpy(psk, p, sizeof psk-1); }
    else strncpy(ssid, buf, sizeof ssid-1);
    if (ssid[0]) do_connect(c, ssid, psk);
    return 1;
}

/* --- boot auto-connect -----------------------------------------------------
 * The Wi-Fi connection is meant to be AUTOMATIC: NM's launcher installs an
 * autoconnect keyfile profile from /epin-debug-net.conf (wifi_ssid/wifi_psk).
 * In practice NM's own autoconnect never fires here — the device sits in
 * DISCONNECTED(30) scanning forever and never associates (so the box never
 * gets an IP and the debug-log scp fails "Network unreachable").
 *
 * So we drive the association ourselves: read the SAME creds and, whenever the
 * radio is idle, call do_connect() -> NM.AddAndActivateConnection.  That passes
 * the whole connection INLINE over D-Bus, so it starts the association even if
 * NM never loaded the keyfile profile (i.e. it's robust to the keyfile-plugin
 * discovery being the root cause).  /etc is a fresh ramfs each boot, so at most
 * a couple of duplicate profiles can appear within one session. */
static char g_auto_ssid[128] = "";
static char g_auto_psk[128]  = "";
static int  g_auto_attempts   = 0;
static int  g_auto_last_cycle = 0;

static char *trim_ws(char *s){
    while (*s==' '||*s=='\t'||*s=='\r'||*s=='\n') s++;
    char *e = s + strlen(s);
    while (e>s && (e[-1]==' '||e[-1]=='\t'||e[-1]=='\r'||e[-1]=='\n')) *--e = 0;
    return s;
}
/* read a key=value line from /epin-debug-net.conf (same file/format NM's launcher uses) */
static int conf_value(const char *key, char *out, int outlen){
    out[0]=0;
    int fd = open("/epin-debug-net.conf", O_RDONLY);
    if (fd < 0) return 0;
    char buf[4096]; int n = (int)read(fd, buf, sizeof buf - 1); close(fd);
    if (n <= 0) return 0;
    buf[n]=0;
    for (char *line = buf; line && *line; ){
        char *next = strchr(line, '\n');
        if (next) *next++ = 0;
        char *p = trim_ws(line);
        if (*p && *p != '#'){
            char *eq = strchr(p, '=');
            if (eq){ *eq = 0;
                if (strcmp(trim_ws(p), key) == 0){
                    char *v = trim_ws(eq+1);
                    strncpy(out, v, outlen-1); out[outlen-1]=0;
                    return out[0] != 0;
                }
            }
        }
        line = next;
    }
    return 0;
}
static void load_auto_creds(void){
    if (!conf_value("wifi_ssid", g_auto_ssid, sizeof g_auto_ssid)) g_auto_ssid[0]=0;
    if (!conf_value("wifi_psk",  g_auto_psk,  sizeof g_auto_psk))  g_auto_psk[0]=0;
    if (g_auto_ssid[0])
        fprintf(stderr, "[wifi-agent] boot auto-connect target from /epin-debug-net.conf: '%s'\n", g_auto_ssid);
    else
        fprintf(stderr, "[wifi-agent] no wifi_ssid in /epin-debug-net.conf; boot auto-connect disabled\n");
}

/* Kick off the association from the boot creds when the radio is idle.  Throttled
 * (~15s between tries) and bounded so a persistently-failing PSK can't pile up
 * profiles; re-arms once the device actually connects. */
static void auto_connect_tick(DBusConnection *c, int have, dbus_uint32_t st, int cycle){
    if (!have || !g_auto_ssid[0]) return;
    if (st == 100 /*NM_DEVICE_STATE_ACTIVATED*/){ g_auto_attempts = 0; return; }
    if (st != 30 /*DISCONNECTED*/ && st != 120 /*FAILED*/) return;  /* busy connecting */
    if (g_auto_attempts >= 8) return;
    if (g_auto_attempts != 0 && (cycle - g_auto_last_cycle) < 3) return;
    g_auto_attempts++;
    g_auto_last_cycle = cycle;
    fprintf(stderr, "[wifi-agent] boot auto-connect attempt %d -> '%s' (dev state %u)\n",
            g_auto_attempts, g_auto_ssid, (unsigned)st);
    do_connect(c, g_auto_ssid, g_auto_psk);
}

/* --- external DHCP client ---------------------------------------------------
 * NM's in-process n-dhcp4 stalls before it ever sends a DISCOVER (its nested epoll+timerfd never fires
 * on this OS), so the lease is obtained by a STANDALONE busybox udhcpc under LD_PRELOAD=/libnshim.so
 * (its AF_PACKET/rtnetlink are interposed by the shim and routed to the LKL-owned AX210, exactly like
 * wpa).  That udhcpc is launched by the KERNEL (hos-udhcpc-launch) rather than forked from here — fork()
 * out of this dbus-connected agent produced a dead child.  /udhcpc-script applies the lease (IP + route)
 * and touches /run/wifi/dhcp-ok, which write_networks() turns into a state=100 so the uploader + menu
 * see the link as up. */

int main(void){
    mkdir("/run", 0755);
    mkdir("/run/wifi", 0755);
    g_demo_enabled = (getenv("HOS_WIFI_DEMO") != NULL);   /* off by default */
    load_auto_creds();                                    /* boot auto-connect target (/epin-debug-net.conf) */
    /* Point libdbus at OUR dbus-daemon (a kernel-spawned process gets a fixed minimal env, so
     * DBUS_SYSTEM_BUS_ADDRESS isn't inherited), then use the STANDARD shared-connection path
     * dbus_bus_get(DBUS_BUS_SYSTEM) — the same one dbus-send uses successfully.  (An earlier
     * dbus_connection_open_private + dbus_bus_register connected + Hello'd fine but the bus reported
     * NM's name "not provided" on that private connection; the shared path resolves names correctly.) */
    setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/run/dbus/system_bus_socket", 1);
    DBusError e; dbus_error_init(&e);
    DBusConnection *c = 0;
    for (int i=0;i<90 && !c;i++){
        c = dbus_bus_get(DBUS_BUS_SYSTEM, &e);
        if (!c){ dbus_error_free(&e); dbus_error_init(&e); napms(1000); }
    }
    if (!c){
        if (!g_demo_enabled){
            fprintf(stderr, "[wifi-agent] no system bus; exiting (set HOS_WIFI_DEMO=1 for the test list)\n");
            return 1;
        }
        /* HOS_WIFI_DEMO: no system bus — run the demo loop so the Wi-Fi drop-down
         * still lists (fake) networks and select/connect works end-to-end for UI tests. */
        fprintf(stderr, "[wifi-agent] no system bus; entering demo mode\n");
        g_nm_misses = 3;
        for (;;){
            int fd = open("/run/wifi/connect", O_RDONLY);
            if (fd >= 0){
                char buf[512]; int n = (int)read(fd, buf, sizeof buf - 1); close(fd);
                unlink("/run/wifi/connect");
                if (n > 0){
                    buf[n] = 0;
                    char *nl = strchr(buf, '\n'); if (nl) *nl = 0;
                    snprintf(g_demo_active, sizeof g_demo_active, "%s", buf);
                    fprintf(stderr, "[wifi-agent] demo connect '%s'\n", buf);
                }
            }
            write_demo_networks();
            napms(1000);
        }
    }
    dbus_connection_set_exit_on_disconnect(c, FALSE);
    fprintf(stderr, "[wifi-agent] connected to NM system bus; polling APs\n");

    char devpath[256]="", ifname[64]=""; dbus_uint32_t st=0;
    int cycle = 0;
    for (;;){
        /* handle a pending (menu) connect request promptly */
        if (check_connect(c)) { write_networks(c); }
        int have = find_wifi_device(c, devpath, sizeof devpath, ifname, sizeof ifname, &st);
        if (have) request_scan(c, devpath);
        /* automatic connection: start the association ourselves from the boot creds
         * when the radio is idle (NM's own autoconnect never fires here). */
        auto_connect_tick(c, have, st, cycle);
        /* The external udhcpc is launched by the KERNEL (hos-udhcpc-launch), not from here: fork() out
         * of this dbus-connected agent produced a dead child, whereas the kernel-spawned launcher
         * execve()s udhcpc directly and reliably.  We only surface its result — write_networks() reads
         * /run/wifi/dhcp-ok and promotes the device to state=100 once the lease lands. */
        write_networks(c);
        for (int k=0;k<25;k++){ if (check_connect(c)) write_networks(c); napms(200); }  /* ~5s, responsive to connect */
        cycle++;
    }
    return 0;
}
