#!/bin/bash

set -e

batch=1
count=0

git ls-files --others --exclude-standard > /tmp/untracked.txt

total=$(wc -l < /tmp/untracked.txt)

echo "Found $total untracked files"

while read -r file; do
    [ -z "$file" ] && continue

    git add "$file"

    count=$((count + 1))

    if [ $count -eq 15 ]; then
        echo "Creating batch commit $batch"

        git commit -m "Batch commit $batch"

        batch=$((batch + 1))
        count=0
    fi
done < /tmp/untracked.txt

if [ $count -gt 0 ]; then
    git commit -m "Batch commit $batch"
fi

echo "Finished batching commits."
echo "Push when ready:"
echo "git push -u origin main"