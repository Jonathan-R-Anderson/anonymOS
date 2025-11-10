// renice.d
module renice;

version (OSX) {} // placeholder for _DARWIN_C_SOURCE equivalent if needed

import core.stdc.stdio : printf, fprintf, perror, stderr;
import core.stdc.stdlib : exit;
import core.stdc.string : strerror;
import core.stdc.errno : errno, ERANGE;
import core.sys.posix.sys.resource : getpriority, setpriority,
    PRIO_PROCESS, PRIO_PGRP, PRIO_USER;
import core.sys.posix.pwd : passwd, getpwnam;
import std.string : toStringz;
import std.conv : to, ConvException;
// import std.typecons : nullable; // (unused)
// import std.algorithm : startsWith; // (unused)

// Not all platforms expose PRIO_MIN/PRIO_MAX via bindings; define sane defaults.
enum PRIO_MIN = -20; // typical on Linux/Unix
enum PRIO_MAX =  20; // Linux accepts up to +19; we allow 20 for bound check like original

// ---------------- Option state ----------------
__gshared int niceMode = PRIO_PROCESS; // default: -p (process IDs)
__gshared int niceIncrement = 0;       // if 0, just print priorities

// ---------------- Helpers ----------------
/** Parse an integer from a string; returns (ok, value). */
bool tryParseInt(string s, out int v)
{
    try { v = to!int(s); return true; }
    catch (ConvException) { return false; }
}

int getPrioritySafe(int which, int who, out bool ok)
{
    // getpriority may legitimately return -1; use errno to detect errors
    errno = 0;
    int val = getpriority(which, who);
    if (val == -1 && errno != 0) {
        ok = false;
        return -1;
    }
    ok = true;
    return val;
}

bool setPrioritySafe(int which, int who, int prio, out int err)
{
    int rc = setpriority(which, who, prio);
    if (rc < 0) {
        err = errno;
        return false;
    }
    err = 0;
    return true;
}

bool resolveUserOrNumber(string token, out int id)
{
    // For -u: allow username or numeric uid
    passwd* pw = getpwnam(token.toStringz);
    if (pw !is null) {
        id = cast(int) pw.pw_uid;
        return true;
    }
    // else try numeric
    return tryParseInt(token, id);
}

// ---------------- Core actor ----------------
int reniceActor(string operand)
{
    int target = 0;
    bool haveTarget = false;

    if (niceMode == PRIO_USER) {
        haveTarget = resolveUserOrNumber(operand, target);
        if (!haveTarget) {
            perror(operand.toStringz); // mimic original perror on failure to parse/resolve
            return 1;
        }
    } else {
        haveTarget = tryParseInt(operand, target);
        if (!haveTarget) {
            perror(operand.toStringz);
            return 1;
        }
    }

    bool ok = false;
    int oldPrio = getPrioritySafe(niceMode, target, ok);
    if (!ok) {
        fprintf(stderr, "getpriority(%s): %s\n".toStringz,
                operand.toStringz, strerror(errno));
        return 1;
    }

    int newPrio = oldPrio;
    if (niceIncrement != 0) {
        // Original note: "Linux renice interprets 'increment' as absolute value"
        // but the code actually *adds* the increment, so we mirror that behavior.
        newPrio = oldPrio + niceIncrement;

        int err = 0;
        if (!setPrioritySafe(niceMode, target, newPrio, err)) {
            fprintf(stderr, "setpriority(%s -> %d): %s\n".toStringz,
                    operand.toStringz, newPrio, strerror(err));
            return 1;
        }

        // Re-read to show the effective new priority
        bool ok2 = false;
        int check = getPrioritySafe(niceMode, target, ok2);
        if (!ok2) {
            fprintf(stderr, "getpriority 2(%s): %s\n".toStringz,
                    operand.toStringz, strerror(errno));
            return 1;
        }
        newPrio = check;
    }

    // Match the original's (non-POSIX) but informative output line
    printf("%s: old priority %d, new priority %d\n".toStringz,
           operand.toStringz, oldPrio, newPrio);
    return 0;
}

// ---------------- Option parsing ----------------
/*
 * Supported:
 *   -p  interpret operands as PIDs (default)
 *   -g  interpret operands as process group IDs
 *   -u  interpret operands as users (name or uid)
 *   -n <increment>  add increment to current nice value
 *   --  end of options
 */
int parseOptions(ref size_t idx, string[] args)
{
    idx = 1;
    while (idx < args.length) {
        auto a = args[idx];
        if (a == "--") { ++idx; break; }
        if (a.length >= 2 && a[0] == '-' && a != "-") {
            // Handle -n which takes a value; support -nVALUE or "-n VALUE"
            if (a[1] == 'n') {
                string valStr;
                if (a.length > 2) {
                    valStr = a[2 .. $]; // -nVALUE
                } else {
                    // next token
                    if (idx + 1 >= args.length) {
                        fprintf(stderr, "renice: option -n requires an argument\n".toStringz);
                        return 2;
                    }
                    valStr = args[++idx];
                }
                int tmp = 0;
                if (!tryParseInt(valStr, tmp) || tmp < PRIO_MIN || tmp > PRIO_MAX) {
                    // Mirror original's ARGP_ERR_UNKNOWN-like behavior with error exit
                    fprintf(stderr, "renice: invalid increment '%s' (must be between %d and %d)\n".toStringz,
                            valStr.toStringz, PRIO_MIN, PRIO_MAX);
                    return 2;
                }
                niceIncrement = tmp;
                ++idx;
                continue;
            }

            // Single-letter flags can be grouped; handle each char after '-'
            foreach (ch; a[1 .. $]) {
                // NOTE: use regular switch, not final switch (exhaustiveness unknown for runtime char)
                switch (ch) {
                    case 'p': niceMode = PRIO_PROCESS; break;
                    case 'g': niceMode = PRIO_PGRP;    break;
                    case 'u': niceMode = PRIO_USER;    break;
                    default:
                        fprintf(stderr, "renice: unknown option -%c\n".toStringz, ch);
                        return 2;
                }
            }
            ++idx;
        } else {
            break; // first operand
        }
    }
    return 0;
}

// ---------------- Main ----------------
int main(string[] args)
{
    if (args.length < 2) {
        // Show terse help like argp doc
        fprintf(stderr, "renice - alter priority of running processes\n".toStringz);
        fprintf(stderr, "usage: %s [-p|-g|-u] [-n increment] ID...\n".toStringz,
                args[0].toStringz);
        return 2;
    }

    size_t idx = 0;
    int prc = parseOptions(idx, args);
    if (prc != 0) return prc;

    if (idx >= args.length) {
        fprintf(stderr, "renice: missing IDs\n".toStringz);
        return 2;
    }

    int rc = 0;
    for (; idx < args.length; ++idx) {
        rc |= reniceActor(args[idx]);
    }
    return rc;
}
