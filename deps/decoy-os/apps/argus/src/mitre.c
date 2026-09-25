#include <stdio.h>
#include <string.h>
#include "mitre.h"

/*
 * Static lookup tables indexed directly by event_type_t value.
 * NULL entries indicate events with no ATT&CK mapping.
 */

static const char * const g_mitre_ids[EVENT_TYPE_MAX] = {
    /* EVENT_EXEC         0 */ "T1059",
    /* EVENT_OPEN         1 */ "T1083",
    /* EVENT_EXIT         2 */ NULL,
    /* EVENT_CONNECT      3 */ "T1071",
    /* EVENT_UNLINK       4 */ "T1070.004",
    /* EVENT_RENAME       5 */ "T1036",
    /* EVENT_CHMOD        6 */ "T1222",
    /* EVENT_BIND         7 */ "T1571",
    /* EVENT_PTRACE       8 */ "T1055.008",
    /* EVENT_DNS          9 */ "T1071.004",
    /* EVENT_SEND        10 */ "T1041",
    /* EVENT_WRITE_CLOSE 11 */ "T1565",
    /* EVENT_PRIVESC     12 */ "T1548",
    /* EVENT_MEMEXEC     13 */ "T1055",
    /* EVENT_KMOD_LOAD   14 */ "T1547.006",
    /* EVENT_NET_CORR    15 */ "T1071",
    /* EVENT_RATE_LIMIT  16 */ NULL,
    /* EVENT_THREAT_INTEL17 */ "T1071",
    /* EVENT_TLS_SNI     18 */ "T1573",
    /* EVENT_PROC_SCRAPE 19 */ "T1057",
    /* EVENT_NS_ESCAPE   20 */ "T1611",
};

static const char * const g_mitre_names[EVENT_TYPE_MAX] = {
    /* EVENT_EXEC         0 */ "Command and Scripting Interpreter",
    /* EVENT_OPEN         1 */ "File and Directory Discovery",
    /* EVENT_EXIT         2 */ NULL,
    /* EVENT_CONNECT      3 */ "Application Layer Protocol",
    /* EVENT_UNLINK       4 */ "File Deletion",
    /* EVENT_RENAME       5 */ "Masquerading",
    /* EVENT_CHMOD        6 */ "File and Directory Permissions Modification",
    /* EVENT_BIND         7 */ "Non-Standard Port",
    /* EVENT_PTRACE       8 */ "Ptrace System Calls",
    /* EVENT_DNS          9 */ "DNS",
    /* EVENT_SEND        10 */ "Exfiltration Over C2 Channel",
    /* EVENT_WRITE_CLOSE 11 */ "Data Manipulation",
    /* EVENT_PRIVESC     12 */ "Abuse Elevation Control Mechanism",
    /* EVENT_MEMEXEC     13 */ "Process Injection",
    /* EVENT_KMOD_LOAD   14 */ "Kernel Modules and Extensions",
    /* EVENT_NET_CORR    15 */ "Application Layer Protocol",
    /* EVENT_RATE_LIMIT  16 */ NULL,
    /* EVENT_THREAT_INTEL17 */ "Application Layer Protocol",
    /* EVENT_TLS_SNI     18 */ "Encrypted Channel",
    /* EVENT_PROC_SCRAPE 19 */ "Process Discovery",
    /* EVENT_NS_ESCAPE   20 */ "Escape to Host",
};

static const char * const g_mitre_tactics[EVENT_TYPE_MAX] = {
    /* EVENT_EXEC         0 */ "execution",
    /* EVENT_OPEN         1 */ "discovery",
    /* EVENT_EXIT         2 */ NULL,
    /* EVENT_CONNECT      3 */ "command-and-control",
    /* EVENT_UNLINK       4 */ "defense-evasion",
    /* EVENT_RENAME       5 */ "defense-evasion",
    /* EVENT_CHMOD        6 */ "defense-evasion",
    /* EVENT_BIND         7 */ "command-and-control",
    /* EVENT_PTRACE       8 */ "privilege-escalation",
    /* EVENT_DNS          9 */ "command-and-control",
    /* EVENT_SEND        10 */ "exfiltration",
    /* EVENT_WRITE_CLOSE 11 */ "impact",
    /* EVENT_PRIVESC     12 */ "privilege-escalation",
    /* EVENT_MEMEXEC     13 */ "privilege-escalation",
    /* EVENT_KMOD_LOAD   14 */ "persistence",
    /* EVENT_NET_CORR    15 */ "command-and-control",
    /* EVENT_RATE_LIMIT  16 */ NULL,
    /* EVENT_THREAT_INTEL17 */ "command-and-control",
    /* EVENT_TLS_SNI     18 */ "command-and-control",
    /* EVENT_PROC_SCRAPE 19 */ "discovery",
    /* EVENT_NS_ESCAPE   20 */ "privilege-escalation",
};

const char *mitre_id(event_type_t type)
{
    if ((unsigned)type >= EVENT_TYPE_MAX)
        return NULL;
    return g_mitre_ids[type];
}

const char *mitre_name(event_type_t type)
{
    if ((unsigned)type >= EVENT_TYPE_MAX)
        return NULL;
    return g_mitre_names[type];
}

const char *mitre_tactic(event_type_t type)
{
    if ((unsigned)type >= EVENT_TYPE_MAX)
        return NULL;
    return g_mitre_tactics[type];
}

void mitre_append_json(event_type_t type, char *buf, size_t bufsz)
{
    const char *id     = mitre_id(type);
    const char *name   = mitre_name(type);
    const char *tactic = mitre_tactic(type);

    if (!id || !name || !tactic)
        return;

    size_t used = strlen(buf);
    if (used >= bufsz)
        return;

    snprintf(buf + used, bufsz - used,
             ",\"mitre_id\":\"%s\",\"mitre_name\":\"%s\",\"mitre_tactic\":\"%s\"",
             id, name, tactic);
}
