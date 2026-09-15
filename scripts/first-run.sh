#!/usr/bin/env bash
#
# first-run.sh — the First User Test for ASM.
#
# This script does exactly what a first-time user does, in the same order, with
# nothing prepared in advance: it downloads the newest published release from
# GitHub, verifies the checksum, extracts it, starts the binary, and waits for
# the dashboard to answer. It writes only inside a throwaway directory under
# /tmp and it never needs root.
#
# Run it on a clean Ubuntu machine:
#
#     bash scripts/first-run.sh
#
# It prints PASS only if a first user would have a working dashboard in front
# of them, and it fails if that took longer than the budget below.
#
# Requirements: bash, curl, tar, sha256sum, python3 — all present on a stock
# Ubuntu Server install.

set -euo pipefail

REPO="attack-surface-monitor"
PRODUCT="ASM"
PORT="${FIRST_RUN_PORT:-8423}"   # override only when the default port is taken
HEALTH_PATH="/"
BUDGET_SECONDS=900          # 15 minutes — the promise the product makes
API="https://api.github.com/repos/nizartuanku/${REPO}/releases/latest"

START=$(date +%s)
WORKDIR=$(mktemp -d "/tmp/${REPO}-first-run.XXXXXX")
SERVER_PID=""

elapsed() { echo $(( $(date +%s) - START )); }
step()    { printf '\n[%3ss] Step %s/7 — %s\n' "$(elapsed)" "$1" "$2"; }
fail()    { printf '\n[%3ss] FAIL — %s\n' "$(elapsed)" "$1" >&2; exit 1; }

cleanup() {
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

for tool in curl tar sha256sum python3; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not installed"
done

# A port that is already taken makes the binary exit one second after it
# starts, which reads like a broken product when it is really a busy machine.
# Say which it is before spending a download on it.
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q ":${PORT} "; then
  fail "port ${PORT} is already in use on this machine. The First User Test wants a clean machine; free the port, or re-run with FIRST_RUN_PORT=<free port>."
fi

echo "First User Test — ${PRODUCT} (${REPO})"
echo "Working directory: ${WORKDIR}"
echo "Budget: ${BUDGET_SECONDS}s"

# ---------------------------------------------------------------- 1. resolve
step 1 "resolve the newest published release"
RELEASE_JSON="${WORKDIR}/release.json"
curl -fsSL "$API" -o "$RELEASE_JSON" || fail "cannot reach ${API}"

read -r TAG ASSET ARCHIVE_COUNT <<EOF
$(python3 - "$RELEASE_JSON" <<'PY'
import json, sys
release = json.load(open(sys.argv[1]))
names = [a["name"] for a in release.get("assets", [])]
archives = [n for n in names if n.endswith((".tar.gz", ".zip"))]
linux = [n for n in archives if "linux" in n and ("amd64" in n or "x86_64" in n)]
# A single-platform release names no platform at all; fall back to the one archive.
picked = linux[0] if linux else (archives[0] if len(archives) == 1 else "")
print(release.get("tag_name", ""), picked, len(archives))
PY
)
EOF

[ -n "$TAG" ]   || fail "the release has no tag"
[ -n "$ASSET" ] || fail "no linux-amd64 archive in release ${TAG}"
echo "  release ${TAG}, asset ${ASSET} (${ARCHIVE_COUNT} archive(s) in this release)"

BASE="https://github.com/nizartuanku/${REPO}/releases/download/${TAG}"

# --------------------------------------------------------------- 2. download
step 2 "download the asset and SHA256SUMS"
cd "$WORKDIR"
curl -fsSL -O "${BASE}/${ASSET}"     || fail "cannot download ${ASSET}"
curl -fsSL -O "${BASE}/SHA256SUMS"   || fail "cannot download SHA256SUMS"
echo "  $(stat -c '%s' "$ASSET") bytes"

# ----------------------------------------------------------------- 3. verify
# A release that publishes one archive is checked plainly. A release that
# publishes several is checked by selecting this asset's line, because a plain
# run would look for the archives for other platforms that were never
# downloaded. Both forms exit 0 on success and neither uses --ignore-missing,
# which would hide a missing file instead of reporting it.
step 3 "verify the checksum"
if [ "$ARCHIVE_COUNT" -gt 1 ]; then
  echo "  grep '${ASSET}' SHA256SUMS | sha256sum -c -"
  grep "$ASSET" SHA256SUMS | sha256sum -c - || fail "checksum does not match"
else
  echo "  sha256sum -c SHA256SUMS"
  sha256sum -c SHA256SUMS || fail "checksum does not match"
fi

# ---------------------------------------------------------------- 4. extract
step 4 "extract"
tar xzf "$ASSET" || fail "cannot extract ${ASSET}"

BINARY=$(find "$WORKDIR" -maxdepth 2 -type f -perm -u+x \
           ! -name '*.tar.gz' ! -name '*.sh' ! -name 'SHA256SUMS' | head -1)
[ -n "$BINARY" ] || fail "no executable found in the archive"
echo "  binary: ${BINARY#$WORKDIR/}"

# --------------------------------------------------------------------- 5. run
# Started from the directory it was extracted into, exactly as the install
# guide tells the reader to, so that anything the binary expects to find
# beside itself is where it expects it.
step 5 "start it"
cd "$(dirname "$BINARY")"
LISTEN_ARGS=()
[ -n "${FIRST_RUN_PORT:-}" ] && LISTEN_ARGS=(-listen "127.0.0.1:${PORT}")
"./$(basename "$BINARY")" "${LISTEN_ARGS[@]+"${LISTEN_ARGS[@]}"}" > "${WORKDIR}/server.log" 2>&1 &
SERVER_PID=$!
sleep 1
kill -0 "$SERVER_PID" 2>/dev/null || {
  echo "--- server log ---"; cat "${WORKDIR}/server.log"; echo "------------------"
  fail "the binary exited immediately"
}
echo "  pid ${SERVER_PID}, log ${WORKDIR}/server.log"

# ------------------------------------------------------------ 6. first result
step 6 "wait for the first result"
URL="http://127.0.0.1:${PORT}${HEALTH_PATH}"
CODE=""
while [ "$(elapsed)" -lt "$BUDGET_SECONDS" ]; do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$URL" || true)
  [ "$CODE" = "200" ] && break
  sleep 2
done
if [ "$CODE" != "200" ]; then
  echo "--- server log ---"; tail -30 "${WORKDIR}/server.log"; echo "------------------"
  fail "${URL} did not answer 200 within the budget (last code: ${CODE:-none})"
fi
echo "  ${URL} → 200"

# ------------------------------------------------------------------ 7. verdict
step 7 "verdict"
TOTAL=$(elapsed)
if [ "$TOTAL" -gt "$BUDGET_SECONDS" ]; then
  fail "first result took ${TOTAL}s, over the ${BUDGET_SECONDS}s budget"
fi
printf '\nPASS — %s %s: a first user reaches a working dashboard in %ss (budget %ss).\n' \
  "$PRODUCT" "$TAG" "$TOTAL" "$BUDGET_SECONDS"
