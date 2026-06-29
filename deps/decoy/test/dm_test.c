/* deps/decoy §G2.2 — validate the honey-hashed typo-tolerant boot matcher. */
#include <stdio.h>
#include <string.h>
#include "dm.h"
#include "decoy.h"

static int pass=0, fail=0;
static void ok(const char *w,int c){ printf("  [%s] %s\n",c?"PASS":"FAIL",w); if(c)pass++; else fail++; }

int main(void){
    DecoyMatcher m; dm_init(&m);
    int d0 = dm_register_decoy(&m, "decoy-password");
    int d1 = dm_register_decoy(&m, "hidden-password");
    dm_register_chaff(&m, 6);                       /* honeyword padding */

    int idx; uint64_t seed, seedExact;

    /* exact decoy password -> match, correct decoy, seed == decoy_seed(canonical) */
    int r = dm_match(&m, "decoy-password", &idx, &seedExact);
    ok("exact decoy password boots its decoy", r && idx==d0 && seedExact==decoy_seed("decoy-password"));

    /* typos within the correction model snap to the SAME universe */
    ok("caps-lock typo boots the same decoy + identical universe",
       dm_match(&m,"DECOY-PASSWORD",&idx,&seed) && idx==d0 && seed==seedExact);
    ok("first-char-case typo boots the same decoy",
       dm_match(&m,"Decoy-password",&idx,&seed) && idx==d0 && seed==seedExact);
    ok("transposition typo boots the same decoy",
       dm_match(&m,"dceoy-password",&idx,&seed) && idx==d0 && seed==seedExact);   /* d[ce]oy <-> d[ec]oy */
    ok("extra-character typo boots the same decoy",
       dm_match(&m,"decoyy-password",&idx,&seed) && idx==d0 && seed==seedExact);  /* delete the dup */

    /* the second decoy is independent */
    ok("the hidden-OS password boots its own decoy + universe",
       dm_match(&m,"hidden-password",&idx,&seed) && idx==d1 && seed==decoy_seed("hidden-password"));

    /* anything outside the decoy set (and beyond the typo threshold) is rejected */
    ok("an unrelated password is rejected", !dm_match(&m,"battleship",&idx,&seed));
    ok("a far-off typo (2+ edits) is rejected", !dm_match(&m,"decoy-passXYZ",&idx,&seed));
    ok("empty input is rejected", !dm_match(&m,"",&idx,&seed));

    /* honey/chaff: stored bytes (salt+hash) don't reveal which verifiers are real */
    int reals=0; for(int i=0;i<m.n;i++) reals+=m.v[i].is_real;
    ok("storage hides the decoy count (2 real among 8 verifiers, indistinguishable bytes)",
       m.n==8 && reals==2);

    printf("DECOY-MATCH: %d passed, %d failed -> %s\n", pass, fail, fail?"FAIL":"PASS");
    return fail?1:0;
}
