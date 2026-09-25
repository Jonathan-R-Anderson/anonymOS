#ifndef __MITRE_H
#define __MITRE_H

#include <stddef.h>
#include "argus.h"

/*
 * MITRE ATT&CK tagging.
 *
 * Maps each event_type_t to its closest ATT&CK technique.  Events with no
 * meaningful technique mapping (EVENT_EXIT, EVENT_RATE_LIMIT) return NULL
 * from all lookup functions.
 *
 * mitre_append_json() is intended for use inside JSON log formatters: it
 * appends three key-value pairs to an existing partial JSON object string
 * (the caller must ensure the buffer is large enough for the remainder of
 * the object and its closing brace).
 */

/* Returns the ATT&CK technique ID string (e.g. "T1059") or NULL. */
const char *mitre_id(event_type_t type);

/* Returns the ATT&CK technique name string or NULL. */
const char *mitre_name(event_type_t type);

/* Returns the ATT&CK tactic name string (lower-case) or NULL. */
const char *mitre_tactic(event_type_t type);

/*
 * Appends ,"mitre_id":"...","mitre_name":"...","mitre_tactic":"..."
 * to buf (which must already contain a partial JSON object).
 * Does nothing if there is no mapping for the given type.
 * bufsz is the total capacity of buf; the function will not write past it.
 */
void mitre_append_json(event_type_t type, char *buf, size_t bufsz);

#endif /* __MITRE_H */
