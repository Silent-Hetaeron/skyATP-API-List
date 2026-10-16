#!/usr/bin/env bash
#
# MIT License
#
# Copyright (c) 2026 Silent Hetaeron
# Copyright (c) 2026 MGi
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Authors: Silent Hetaeron and MGi, with assistance from Claude (Anthropic).
#
# One-off helper (not part of the cron job): find which URL entries Sky ATP
# rejects (the main script already does this automatically on every run; use this
# to get the full list in one go). It uploads the cleaned URL list to a SCRATCH feed called
# Quarantine_ValidationTest, reads the "Validation error: <entry>" message, removes
# that entry, and tries again until Sky ATP accepts the list. The scratch feed
# is deleted at the end. The real Quarantine_Blacklist* feeds are never touched.
#
# Usage: ./find-rejected-entries.sh
# Result: /var/lib/update-quarantine-blocklist/findbad/rejected.txt (entries Sky ATP refused)
#         /var/lib/update-quarantine-blocklist/findbad/accepted.txt (what remains)

set -uo pipefail

API="${API:-https://threat-api.sky.junipersecurity.net/v2/cloudfeeds/blacklist}"
FEED="${FEED:-Quarantine_ValidationTest}"
SRC="${SRC:-/var/lib/update-quarantine-blocklist/quarantine_urls.txt}"
WORK="${WORK:-/var/lib/update-quarantine-blocklist/findbad}"
PAUSE="${PAUSE:-2}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-100}"

if [ -z "${SKYATP_API_TOKEN:-}" ] && [ -f "${HOME}/.config/skyatp/tokens" ]; then
    # shellcheck source=/dev/null
    source "${HOME}/.config/skyatp/tokens"
fi
[ -n "${SKYATP_API_TOKEN:-}" ] || { echo "ERROR: SKYATP_API_TOKEN is not set" >&2; exit 1; }
[ -s "$SRC" ] || { echo "ERROR: $SRC is missing or empty - run the main script with --fetch first" >&2; exit 1; }
command -v jq >/dev/null || { echo "ERROR: jq not found" >&2; exit 1; }

mkdir -p "$WORK"
cp "$SRC" "$WORK/accepted.txt"
: > "$WORK/rejected.txt"

api() { curl -sS --connect-timeout 10 --max-time 120 -H "Authorization: Bearer ${SKYATP_API_TOKEN}" "$@"; }

delete_feed() { api -o /dev/null -X DELETE -F server='*' "${API}/param/url/${FEED}" || true; }

wait_gone() {
    local code
    for _ in $(seq 1 30); do
        code=$(api -o /dev/null -w '%{http_code}' "${API}/file/url/${FEED}") || code=000
        [ "$code" = "404" ] && return 0
        sleep "$PAUSE"
    done
    return 1
}

trap 'delete_feed' EXIT

echo "Testing $(wc -l < "$WORK/accepted.txt") entries against scratch feed '${FEED}'"
attempt=0
while [ "$attempt" -lt "$MAX_ATTEMPTS" ]; do
    attempt=$((attempt + 1))
    delete_feed
    wait_gone || { echo "ERROR: scratch feed would not delete" >&2; exit 1; }

    code=$(api -o /dev/null -w '%{http_code}' -X POST -F "file=@${WORK}/accepted.txt" "${API}/file/url/${FEED}") || code=000
    [ "$code" = "202" ] || { echo "ERROR: upload returned HTTP $code" >&2; exit 1; }

    result=""; msg=""
    for _ in $(seq 1 40); do
        msg=$(api "${API}/file/url/${FEED}" | jq -r '.message // empty') || msg=""
        case "$msg" in
            *"processing complete"*) result="ok"; break ;;
            *"Validation error:"*)   result="bad"; break ;;
        esac
        sleep "$PAUSE"
    done

    if [ "$result" = "ok" ]; then
        echo "Attempt $attempt: ACCEPTED by Sky ATP ($(wc -l < "$WORK/accepted.txt") entries)"
        break
    elif [ "$result" = "bad" ]; then
        entry="${msg##*Validation error: }"
        if grep -qxF -- "$entry" "$WORK/accepted.txt"; then
            grep -vxF -- "$entry" "$WORK/accepted.txt" > "$WORK/accepted.new" || true
            mv "$WORK/accepted.new" "$WORK/accepted.txt"
            printf '%s\n' "$entry" >> "$WORK/rejected.txt"
            echo "Attempt $attempt: rejected -> $entry"
        else
            echo "ERROR: Sky ATP's message does not match an entry in the list:" >&2
            echo "       $msg" >&2
            exit 1
        fi
    else
        echo "ERROR: gave up waiting. Last message: '$msg'" >&2
        exit 1
    fi
done

echo ""
echo "Rejected entries: $(wc -l < "$WORK/rejected.txt")  (saved in $WORK/rejected.txt)"
cat "$WORK/rejected.txt"
echo "Accepted entries: $(wc -l < "$WORK/accepted.txt")"
