#!/usr/bin/env bash
# The commit-verification block in update-from-github.sh (§18.14).
#
#   bash scripts/verify-commit-signing.test.sh
#
# Exercised against a real git repository and real ssh-keygen signatures. No
# mocks: the thing under test is git's own verify-commit and the exact flags the
# updater passes it, and a fake would be testing the fake.
#
# The fourth case is the one worth having. `gpg.ssh.allowedSignersFile` can be
# set in a repository's OWN config, so a mirror that was allowed to supply its
# verification policy would be verifying itself -- the updater passes the policy
# per-invocation with -c for exactly that reason, and this proves repo config
# cannot override it.
set -uo pipefail
W=$(mktemp -d); cd "$W"
pass=0; fail=0
ok(){ echo "  PASS $1"; pass=$((pass+1)); }
no(){ echo "  FAIL $1"; fail=$((fail+1)); }

ssh-keygen -q -t ed25519 -N '' -C good@axon -f good
ssh-keygen -q -t ed25519 -N '' -C evil@axon -f evil
echo "good@axon namespaces=\"git\" $(cat good.pub)" > allowed

git init -q repo && cd repo
git config user.email good@axon; git config user.name good
git config gpg.format ssh; git config user.signingkey "$W/good.pub"
echo one > f; git add f; git commit -qS -m "signed by the good key"
GOOD=$(git rev-parse HEAD)

verify() { # $1=sha  $2=signers
  git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$2" verify-commit "$1" >/dev/null 2>&1
}

verify "$GOOD" "$W/allowed" && ok "a signed commit verifies" || no "a signed commit verifies"

echo two > f; git add f; git commit -q --no-gpg-sign -m "unsigned"
UNSIGNED=$(git rev-parse HEAD)
verify "$UNSIGNED" "$W/allowed" && no "an UNSIGNED commit is refused" || ok "an UNSIGNED commit is refused"

git config user.signingkey "$W/evil.pub"; git config user.email evil@axon
echo three > f; git add f; git commit -qS -m "signed by the wrong key"
EVIL=$(git rev-parse HEAD)
verify "$EVIL" "$W/allowed" && no "a commit signed by an UNPINNED key is refused" || ok "a commit signed by an UNPINNED key is refused"

# The attack the per-invocation -c flags exist for: a repo that sets its own
# verification policy would be verifying itself.
git config gpg.ssh.allowedSignersFile "$W/evil-allowed"
echo "evil@axon namespaces=\"git\" $(cat "$W/evil.pub")" > "$W/evil-allowed"
verify "$EVIL" "$W/allowed" && no "repo config cannot override the pinned signers" || ok "repo config cannot override the pinned signers"

echo; echo "  $pass passed, $fail failed"
cd /; rm -rf "$W"
exit $fail
