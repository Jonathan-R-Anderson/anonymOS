#!/bin/sh
set -e

assert_contains() {
    haystack="$1"
    needle="$2"
    if ! printf '%s\n' "$haystack" | grep -Fq "$needle"; then
        echo "  [FAIL] Expected output to contain: $needle"
        echo "  Full output was:"
        printf '%s\n' "$haystack"
        exit 1
    fi
}

assert_not_contains() {
    haystack="$1"
    needle="$2"
    if printf '%s\n' "$haystack" | grep -Fq "$needle"; then
        echo "  [FAIL] Expected output to NOT contain: $needle"
        echo "  Full output was:"
        printf '%s\n' "$haystack"
        exit 1
    fi
}

echo "Running test: jobs shows running background job"
output=$(cat <<'SCRIPT' | ./lfe-sh
sleep 0.5 &
sleep 0.05
jobs
SCRIPT
)
assert_contains "$output" "Running"
assert_contains "$output" "SimpleCommand(sleep, 0.5))"
echo "  [PASS]"

echo "Running test: jobs reports completed background job"
output=$(cat <<'SCRIPT' | ./lfe-sh
sleep 0.1 &
sleep 0.3
jobs
SCRIPT
)
assert_contains "$output" "Completed"
assert_contains "$output" "SimpleCommand(sleep, 0.1))"
echo "  [PASS]"

echo "Running test: fg removes completed jobs"
output=$(cat <<'SCRIPT' | ./lfe-sh
sleep 0.1 &
fg %1
jobs
SCRIPT
)
assert_not_contains "$output" "Sequence("
echo "  [PASS]"

echo "\nJob listing and fg tests passed!"
