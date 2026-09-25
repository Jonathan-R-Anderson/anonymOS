#ifndef __THREATINTEL_H
#define __THREATINTEL_H

#include <stdint.h>

/*
 * Threat intelligence CIDR blocklist loader.
 *
 * Parses a text file containing one IPv4 or IPv6 CIDR per line (comments
 * starting with '#' and blank lines are ignored), and populates BPF LPM-trie
 * maps for in-kernel lookup.  Also maintains a userspace sorted list for
 * testing / offline queries.
 */

/* Load CIDR blocklist from file.
 * If map_fd_v4 >= 0, IPv4 CIDRs are inserted into that BPF LPM_TRIE map.
 * If map_fd_v6 >= 0, IPv6 CIDRs are inserted into that BPF LPM_TRIE map.
 * Returns number of entries loaded (>= 0), or -1 on file open error. */
int  threatintel_load(const char *path, int map_fd_v4, int map_fd_v6);

/* Userspace check: returns 1 if IPv4 addr (host byte order) matches
 * any loaded CIDR, 0 otherwise.  Useful for testing without BPF. */
int  threatintel_check_ipv4(uint32_t addr);

/* Free all userspace blocklist state. */
void threatintel_free(void);

#endif /* __THREATINTEL_H */
