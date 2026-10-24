#!/usr/bin/env bash
# Clone netbird at the pinned commit and apply our patches into ./.netbird-src
set -euo pipefail
cd "$(dirname "$0")/.."
NETBIRD_REF="${NETBIRD_REF:-c051ca8f8767617091ce8fdb23edccd83487cba0}"
rm -rf .netbird-src
git init -q .netbird-src
git -C .netbird-src remote add origin https://github.com/netbirdio/netbird.git
GIT_LFS_SKIP_SMUDGE=1 git -C .netbird-src fetch -q --depth 1 origin "$NETBIRD_REF"
git -C .netbird-src checkout -q FETCH_HEAD
for p in patches/*.patch; do
  git -C .netbird-src apply --index "../$p"
done
echo "netbird $NETBIRD_REF patched"
