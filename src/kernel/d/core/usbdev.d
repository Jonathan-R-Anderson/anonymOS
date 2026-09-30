/**
 * core/usbdev.d -- the USB devices the kernel knows about, and which domains may use each one.
 *
 * A domain's Permissions have a USB class switch (DEVCLASS_USB: /dev/bus/usb/*).  This adds the
 * per-DEVICE decision on top: every device the USB stack enumerates is registered here (vendor,
 * product, class, a name), and the Domain Manager can assign it to domains -- "usbon/usboff
 * <domain> <vid:pid>".  Until a device has been assigned, the class switch alone decides (a
 * domain with USB access may use it); once assigned, only the listed domains may, and only while
 * they also hold the class.  /config/usb.json lists the devices with their domains.
 *
 * Sources today: the native xHCI enumeration (drivers/input/usb_hid.d).  Devices driven by the
 * LKL (usb-storage, USB=1 images) are not reported here yet.
 */
module core.usbdev;

import core.io : klog, klog_hex;

@nogc nothrow:

enum int USB_MAX_DEVS = 16;
enum int USB_MAX_DOMS = 8;

private struct UsbDev {
    bool     used;
    ubyte    bus, addr, cls;
    ushort   vid, pid;
    char[40] name = 0;
    bool     assigned;               // a per-device list exists (else: the class switch decides)
    uint[USB_MAX_DOMS] dom;
    int      ndom;
}

private __gshared UsbDev[USB_MAX_DEVS] g_usb;

private size_t cstrLen(const(char)* s, size_t max) { size_t n = 0; while (n < max && s[n]) ++n; return n; }

/// The USB stack found a device (idempotent per bus/address).
public void usbDevRegister(ubyte bus, ubyte addr, ushort vid, ushort pid, ubyte cls, const(char)* name) {
    int slot = -1;
    foreach (i; 0 .. USB_MAX_DEVS) {
        if (g_usb[i].used && g_usb[i].bus == bus && g_usb[i].addr == addr) { slot = cast(int)i; break; }
        if (slot < 0 && !g_usb[i].used) slot = cast(int)i;
    }
    if (slot < 0) return;
    auto d = &g_usb[slot];
    const bool fresh = !d.used;
    d.used = true; d.bus = bus; d.addr = addr; d.vid = vid; d.pid = pid; d.cls = cls;
    const size_t n = name is null ? 0 : cstrLen(name, d.name.length - 1);
    foreach (i; 0 .. n) d.name[i] = name[i];
    d.name[n] = 0;
    if (fresh) {
        klog("[usb] device "); klog_hex(vid); klog(":"); klog_hex(pid); klog(" ");
        klog(d.name.ptr); klog(" registered\n");
    }
}

public void usbDevUnregister(ubyte bus, ubyte addr) {
    foreach (ref d; g_usb) if (d.used && d.bus == bus && d.addr == addr) d.used = false;
}

private UsbDev* byId(ushort vid, ushort pid) {
    foreach (ref d; g_usb) if (d.used && d.vid == vid && d.pid == pid) return &d;
    return null;
}
private UsbDev* byBusAddr(ubyte bus, ubyte addr) {
    foreach (ref d; g_usb) if (d.used && d.bus == bus && d.addr == addr) return &d;
    return null;
}

private bool classAllowed(uint dom) {
    import core.domain : domainById;
    import core.identity : DEVCLASS_USB;
    auto r = domainById(dom);
    return r !is null && (r.allowedDevices & DEVCLASS_USB) != 0;
}

private bool listed(const(UsbDev)* d, uint dom) {
    foreach (i; 0 .. d.ndom) if (d.dom[i] == dom) return true;
    return false;
}

/// May domain `dom` use device (vid, pid)?  The class switch always applies; an assigned device
/// is additionally restricted to its domains.
public bool usbDevAllowed(uint dom, ushort vid, ushort pid) {
    if (!classAllowed(dom)) return false;
    auto d = byId(vid, pid);
    return d is null || !d.assigned || listed(d, dom);
}
/// The same for a /dev/bus/usb/BBB/DDD node.
public bool usbDevAllowedAt(uint dom, ubyte bus, ubyte addr) {
    if (!classAllowed(dom)) return false;
    auto d = byBusAddr(bus, addr);
    return d is null || !d.assigned || listed(d, dom);
}

/// "vvvv:pppp" (hex) -> (vid, pid).
private bool parseId(const(char)* s, out ushort vid, out ushort pid) {
    uint v = 0, p = 0; int k = 0, digits = 0;
    for (; s[k] && s[k] != ':' && k < 8; ++k) {
        const char c = s[k];
        const int h = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
        if (h < 0) return false;
        v = v * 16 + h; ++digits;
    }
    if (s[k] != ':' || digits == 0) return false;
    ++k; digits = 0;
    for (; s[k] && k < 16; ++k) {
        const char c = s[k];
        const int h = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
        if (h < 0) return false;
        p = p * 16 + h; ++digits;
    }
    if (digits == 0 || v > 0xFFFF || p > 0xFFFF) return false;
    vid = cast(ushort)v; pid = cast(ushort)p;
    return true;
}

/// `usbon/usboff <domain> <vid:pid>`: give or take one device from one domain.  The first change
/// to a device starts its list from "every domain that currently has USB access", so turning it
/// off for one domain does not silently take it away from the others.
public bool usbDevSet(uint dom, const(char)* id, bool on) {
    import core.domain : g_domains;
    ushort vid, pid;
    if (dom == 0 || !parseId(id, vid, pid)) return false;
    auto d = byId(vid, pid);
    if (d is null) return false;
    if (!d.assigned) {
        d.assigned = true;
        d.ndom = 0;
        foreach (ref e; g_domains)
            if (e.inUse && !e.isTemplate && classAllowed(e.objId) && d.ndom < USB_MAX_DOMS) d.dom[d.ndom++] = e.objId;
    }
    if (on) {
        if (!listed(d, dom) && d.ndom < USB_MAX_DOMS) d.dom[d.ndom++] = dom;
    } else {
        foreach (i; 0 .. d.ndom)
            if (d.dom[i] == dom) { d.dom[i] = d.dom[d.ndom - 1]; --d.ndom; break; }
    }
    klog("[usb] "); klog(on ? "gave " : "took "); klog_hex(vid); klog(":"); klog_hex(pid);
    klog(on ? " to domain 0x" : " from domain 0x"); klog_hex(dom); klog("\n");
    return true;
}

/// /config/usb.json: [{"id":"vvvv:pppp","name":..,"class":N,"bus":B,"addr":A,"assigned":bool,
/// "domains":[names allowed now]}].
public size_t usbDevRenderJson(char* buf, size_t cap) {
    import core.domain : g_domains, domainNameOf;
    size_t n = 0;
    void s(const(char)* t) { while (*t && n + 1 < cap) buf[n++] = *t++; }
    void hex4(uint v) { foreach_reverse (sh; [12, 8, 4, 0]) { const uint h = (v >> sh) & 15; if (n + 1 < cap) buf[n++] = cast(char)(h < 10 ? '0' + h : 'a' + h - 10); } }
    void dec(uint v) { char[12] t; int k = 0; do { t[k++] = cast(char)('0' + v % 10); v /= 10; } while (v); while (k) if (n + 1 < cap) buf[n++] = t[--k]; else --k; }
    s("[");
    bool first = true;
    foreach (ref d; g_usb) {
        if (!d.used) continue;
        if (!first) s(",");
        first = false;
        s("\n  {\"id\":\""); hex4(d.vid); s(":"); hex4(d.pid); s("\",\"name\":\""); s(d.name.ptr);
        s("\",\"class\":"); dec(d.cls); s(",\"bus\":"); dec(d.bus); s(",\"addr\":"); dec(d.addr);
        s(",\"assigned\":"); s(d.assigned ? "true" : "false"); s(",\"domains\":[");
        bool f2 = true;
        foreach (ref e; g_domains) {
            if (!e.inUse || e.isTemplate || !usbDevAllowed(e.objId, d.vid, d.pid)) continue;
            if (!f2) s(",");
            f2 = false;
            s("\""); s(e.name.ptr); s("\"");
        }
        s("]}");
    }
    s("\n]\n");
    if (n < cap) buf[n] = 0;
    return n;
}
