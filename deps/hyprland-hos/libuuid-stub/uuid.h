/*
 * Minimal <uuid/uuid.h> compatible with util-linux libuuid, for the HanonymOS
 * sysroot. util-linux does not cross-compile cleanly against musl, and Hyprland
 * only needs the small libuuid API below (v4 random UUIDs + (un)parse helpers).
 */
#ifndef HOS_LIBUUID_UUID_H
#define HOS_LIBUUID_UUID_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char uuid_t[16];

void uuid_generate(uuid_t out);
void uuid_generate_random(uuid_t out);
void uuid_generate_time(uuid_t out);
int  uuid_generate_time_safe(uuid_t out);

void uuid_clear(uuid_t uu);
void uuid_copy(uuid_t dst, const uuid_t src);
int  uuid_compare(const uuid_t uu1, const uuid_t uu2);
int  uuid_is_null(const uuid_t uu);

int  uuid_parse(const char *in, uuid_t uu);
void uuid_unparse(const uuid_t uu, char *out);
void uuid_unparse_lower(const uuid_t uu, char *out);
void uuid_unparse_upper(const uuid_t uu, char *out);

#ifdef __cplusplus
}
#endif

#endif /* HOS_LIBUUID_UUID_H */
