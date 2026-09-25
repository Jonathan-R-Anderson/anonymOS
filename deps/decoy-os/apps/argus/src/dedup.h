#ifndef __DEDUP_H
#define __DEDUP_H

/*
 * Alert deduplication — suppress identical alerts within a time window.
 *
 * A "key" is a short string that uniquely identifies an alert (typically
 * built from rule name + comm + filename).  The first occurrence within
 * the window is allowed through; subsequent identical keys are suppressed
 * and counted.  When the window expires the suppression counter is reset.
 */

/* Initialise with the given dedup window in seconds (0 = disabled). */
void dedup_init(int window_secs);

/*
 * Check whether the alert identified by 'key' should be suppressed.
 * Records the current time on first sight.
 * Returns 1 → suppress (already seen within window),
 *         0 → allow (new or window expired; key is now recorded).
 */
int dedup_check(const char *key);

/* Return how many alerts have been suppressed so far. */
long dedup_suppressed(void);

#endif /* __DEDUP_H */
