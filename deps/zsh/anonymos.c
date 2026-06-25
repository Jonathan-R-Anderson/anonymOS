/*
 * anonymos.c - AnonymOS native object-model builtins (Z4c.4)
 *
 * In-process native-ABI builtins (obj/id/ns/svc/sys) that issue HOS_SYS_QUERY
 * directly from the zsh process, replacing the /hos-sh helper-spawn of Z4c.1
 * (a "fuller-integration" refinement: no subprocess per object command).
 *
 * Safe by personality: the native ABI is gated (HOS_SYS_QUERY is ENOSYS unless
 * the calling task holds the N0 native-ABI grant, set only on /hos-zsh exec), so
 * these builtins are functional only inside native zsh; in a Linux-personality
 * zsh the same syscall returns -ENOSYS and the builtin reports it as unavailable.
 */

#include "anonymos.mdh"
#include "anonymos.pro"

#include <unistd.h>

#define HOS_SYS_QUERY   0x4000L
#define HOSQ_OBJECTS    1L
#define HOSQ_IDENTITIES 2L
#define HOSQ_NAMESPACES 3L
#define HOSQ_SERVICES   4L
#define HOSQ_SYS        5L

static char hosbuf[16384];

/* Run one native enumeration query and print its text result in-process. */
static int
run_hosq(char *nam, long op, const char *header)
{
    long n = syscall(HOS_SYS_QUERY, op, 0L, (long)hosbuf, (long)(sizeof(hosbuf) - 1));
    if (n < 0) {
	zwarnnam(nam, "native object ABI unavailable (errno %d) - not a native shell?",
		 (int)-n);
	return 1;
    }
    hosbuf[n] = '\0';
    if (header)
	fputs(header, stdout);
    fwrite(hosbuf, 1, (size_t)n, stdout);
    fflush(stdout);
    return 0;
}

/**/
static int
bin_obj(char *nam, UNUSED(char **args), UNUSED(Options ops), UNUSED(int func))
{ return run_hosq(nam, HOSQ_OBJECTS, "TYPE                COUNT\n"); }

/**/
static int
bin_id(char *nam, UNUSED(char **args), UNUSED(Options ops), UNUSED(int func))
{ return run_hosq(nam, HOSQ_IDENTITIES, "IDENTITY DOMAINS\n"); }

/**/
static int
bin_ns(char *nam, UNUSED(char **args), UNUSED(Options ops), UNUSED(int func))
{ return run_hosq(nam, HOSQ_NAMESPACES, "NAMESPACES\n"); }

/**/
static int
bin_svc(char *nam, UNUSED(char **args), UNUSED(Options ops), UNUSED(int func))
{ return run_hosq(nam, HOSQ_SERVICES, "SERVICES\n"); }

/**/
static int
bin_sys(char *nam, UNUSED(char **args), UNUSED(Options ops), UNUSED(int func))
{ return run_hosq(nam, HOSQ_SYS, NULL); }

/* The builtin table — sorted by name, as zsh expects. */
static struct builtin bintab[] = {
    BUILTIN("id",  0, bin_id,  0, -1, 0, NULL, NULL),
    BUILTIN("ns",  0, bin_ns,  0, -1, 0, NULL, NULL),
    BUILTIN("obj", 0, bin_obj, 0, -1, 0, NULL, NULL),
    BUILTIN("svc", 0, bin_svc, 0, -1, 0, NULL, NULL),
    BUILTIN("sys", 0, bin_sys, 0, -1, 0, NULL, NULL),
};

static struct features module_features = {
    bintab, sizeof(bintab)/sizeof(*bintab),
    NULL, 0,
    NULL, 0,
    NULL, 0,
    0
};

/**/
int
setup_(UNUSED(Module m))
{ return 0; }

/**/
int
features_(Module m, char ***features)
{ *features = featuresarray(m, &module_features); return 0; }

/**/
int
enables_(Module m, int **enables)
{ return handlefeatures(m, &module_features, enables); }

/**/
int
boot_(UNUSED(Module m))
{ return 0; }

/**/
int
cleanup_(Module m)
{ return setfeatureenables(m, &module_features, NULL); }

/**/
int
finish_(UNUSED(Module m))
{ return 0; }
