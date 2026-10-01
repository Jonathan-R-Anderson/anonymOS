// The PC's battery-backed real-time clock (MC146818-compatible CMOS RTC, ports 0x70/0x71).
//
// It is how the kernel knows the date without asking the network.  Until it was read, the wall
// clock started at the Unix epoch on every boot and only an SNTP reply could correct it -- and
// SNTP is suppressed on live media (no network fingerprint), so a live session spent its whole
// life in January 1970: every TLS certificate was "not yet valid" and Firefox refused every HTTPS
// site with "Your Computer Clock is Wrong".
//
// The RTC is taken to hold UTC, as Linux and every Unix keep it.  (A machine whose RTC keeps local
// time -- Windows dual-boot, VirtualBox without --rtc-use-utc -- reads off by its UTC offset, which
// certificates tolerate; SNTP corrects it where it runs.)
module drivers.rtc;

import core.io : inb, outb;

@nogc nothrow:

private enum ushort RTC_INDEX = 0x70;
private enum ushort RTC_DATA  = 0x71;

private ubyte rtcReg(ubyte reg) {
    outb(RTC_INDEX, reg);
    return inb(RTC_DATA);
}

private struct RtcTime { ubyte sec, min, hour, day, mon, year; }

private bool rtcUpdating() { return (rtcReg(0x0A) & 0x80) != 0; }

private RtcTime rtcRaw() {
    RtcTime t;
    t.sec  = rtcReg(0x00);
    t.min  = rtcReg(0x02);
    t.hour = rtcReg(0x04);
    t.day  = rtcReg(0x07);
    t.mon  = rtcReg(0x08);
    t.year = rtcReg(0x09);
    return t;
}

private bool rtcSame(ref const RtcTime a, ref const RtcTime b) {
    return a.sec == b.sec && a.min == b.min && a.hour == b.hour && a.day == b.day && a.mon == b.mon && a.year == b.year;
}

private ubyte fromBcd(ubyte v) { return cast(ubyte)((v & 0x0F) + (v >> 4) * 10); }

// Days from 1970-01-01 to y-m-d (proleptic Gregorian; Howard Hinnant's days_from_civil).
private long daysFromCivil(long y, uint m, uint d) {
    if (m <= 2) y -= 1;
    const long era = (y >= 0 ? y : y - 399) / 400;
    const uint yoe = cast(uint)(y - era * 400);
    const uint doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const uint doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146_097 + cast(long)doe - 719_468;
}

/// The RTC's time as Unix epoch seconds.  false if there is no believable clock (absent, or a
/// date outside 2020..2099 -- a dead battery reads as 2000 or garbage, and a wrong date presented
/// as right is worse than none).
public bool rtcReadUnix(out ulong unixSec) {
    unixSec = 0;
    // A read that straddles the once-a-second update can mix two seconds' fields: wait out an
    // update in progress, then read until two consecutive reads agree.
    RtcTime a, b;
    foreach (attempt; 0 .. 8) {
        foreach (spin; 0 .. 100_000) if (!rtcUpdating()) break;
        a = rtcRaw();
        foreach (spin; 0 .. 100_000) if (!rtcUpdating()) break;
        b = rtcRaw();
        if (rtcSame(a, b)) break;
        if (attempt == 7) return false;
    }

    const ubyte regB = rtcReg(0x0B);
    const bool binary = (regB & 0x04) != 0;
    const bool h24    = (regB & 0x02) != 0;
    const bool pm     = (b.hour & 0x80) != 0;
    ubyte hour = cast(ubyte)(b.hour & 0x7F);
    ubyte sec = b.sec, min = b.min, day = b.day, mon = b.mon, yy = b.year;
    if (!binary) {
        sec = fromBcd(sec); min = fromBcd(min); hour = fromBcd(hour);
        day = fromBcd(day); mon = fromBcd(mon); yy = fromBcd(yy);
    }
    if (!h24) {                       // 12-hour mode: 12 AM is 0, 12 PM is 12
        if (hour == 12) hour = 0;
        if (pm) hour = cast(ubyte)(hour + 12);
    }
    const uint year = 2000 + yy;      // two-digit year; this kernel postdates 2000
    if (year < 2020 || mon < 1 || mon > 12 || day < 1 || day > 31 || hour > 23 || min > 59 || sec > 59)
        return false;

    const long days = daysFromCivil(year, mon, day);
    unixSec = cast(ulong)(days * 86_400 + hour * 3600 + min * 60 + sec);
    return true;
}
