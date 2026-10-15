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
# Not affiliated with or endorsed by Juniper Networks. "Juniper", "Sky ATP" and
# "ATP Cloud" are trademarks of Juniper Networks, Inc.
#
# This script downloads the quarantine URL and IP lists and publishes them to
# Sky ATP as blacklist feeds via the Open API. Lists longer than CHUNK_SIZE
# are split across several feeds (<prefix>IP1, <prefix>IP2, ...).
#
# Usage:
#   ./update-quarantine-blocklist.sh [--check|--fetch|--plan|--selftest|--selftest-delete|--update|--delete]
#
#   --check    Print the settings the script sees and exit. Calls nothing.
#   --fetch    Download and clean both lists, print counts, and stop.
#              Nothing is sent to Sky ATP.
#   --plan     Like --fetch, then split the lists into feed-sized files and
#              show which feeds would be pushed. Nothing is sent to Sky ATP.
#   --selftest Upload a tiny throwaway feed (<prefix>Test01, two reserved example
#              addresses) to Sky ATP and wait until it reports it processed.
#   --selftest-delete
#              Delete the throwaway <prefix>Test01 feed again and wait until Sky ATP
#              confirms it is gone.
#   --update   Download both lists and publish them to Sky ATP, replacing the
#              existing feeds (default if omitted - this is what cron runs).
#   --delete   Delete all <prefix>URL* and <prefix>IP* feeds from Sky ATP
#              without re-uploading.
#
# When --update or --delete runs without a terminal (e.g. from cron) all output
# goes to LOG_FILE, and only one run can be active at a time.
#
# Token:
#   Option 1 - token file (recommended for cron):
#     echo 'SKYATP_API_TOKEN="<your_token>"' > ~/.config/skyatp/tokens
#     chmod 600 ~/.config/skyatp/tokens
#
#   Option 2 - environment variable:
#     export SKYATP_API_TOKEN="<your_token>"
#
set -euo pipefail
umask 077

# === ARGUMENTS === #
MODE="update"
case "${1:-}" in
    --check)  MODE="check" ;;
    --fetch)  MODE="fetch" ;;
    --plan)   MODE="plan" ;;
    --selftest) MODE="selftest" ;;
    --selftest-delete) MODE="selftest-delete" ;;
    --delete) MODE="delete" ;;
    --update|"") MODE="update" ;;
    *) echo "Usage: $0 [--check|--fetch|--plan|--selftest|--selftest-delete|--update|--delete]" >&2; exit 1 ;;
esac

# === CONFIGURATION === #

# API token: environment variable first, then the token file.
# Generated in the Sky ATP portal; it expires and must be refreshed.
if [ -z "${SKYATP_API_TOKEN:-}" ]; then
    TOKEN_FILE="${HOME}/.config/skyatp/tokens"
    if [ -f "$TOKEN_FILE" ]; then
        # shellcheck source=/dev/null
        source "$TOKEN_FILE"
    fi
fi
if [ -z "${SKYATP_API_TOKEN:-}" ]; then
    echo "ERROR: SKYATP_API_TOKEN is not set." >&2
    echo "       Option 1 - token file: echo 'SKYATP_API_TOKEN=\"<token>\"' > ~/.config/skyatp/tokens && chmod 600 ~/.config/skyatp/tokens" >&2
    echo "       Option 2 - environment: export SKYATP_API_TOKEN=\"<your_token>\"" >&2
    exit 1
fi

# Curl timeouts for the source server (seconds)
CURL_CONNECT_TIMEOUT=5    # max time to establish connection
CURL_MAX_TIME=30          # max total transfer time

# Feed names are <prefix>IP1, <prefix>IP2, ... and <prefix>URL1, <prefix>URL2, ...
# Sky ATP allows only letters, numbers and underscores, 8-64 characters.
FEED_PREFIX="${FEED_PREFIX:-Quarantine_Blacklist}"

# Maximum entries per feed. Sky ATP accepts at most 10000 per push.
CHUNK_SIZE="${CHUNK_SIZE:-9000}"

# Maximum length of one URL entry. Sky ATP rejects longer ones; they are cut to
# this length (Sky ATP matches the start of a URL, so the original still matches).
URL_MAX_LEN="${URL_MAX_LEN:-128}"

# Where the two source lists are downloaded from. Set at least one of them.
# One entry per line: IPv4 addresses (optionally with /mask) for the IP list,
# hostnames or URLs for the URL list. Leave one empty to skip that list.
QUARANTINE_URLS_URL="${QUARANTINE_URLS_URL:-}"
QUARANTINE_IPS_URL="${QUARANTINE_IPS_URL:-}"

# TLS certificates of the source server are verified. Set SOURCE_INSECURE_TLS=1
# only if it uses a self-signed certificate you cannot add to the trust store.
SOURCE_INSECURE_TLS="${SOURCE_INSECURE_TLS:-0}"
SOURCE_TLS_OPT=""
if [ "$SOURCE_INSECURE_TLS" = "1" ]; then SOURCE_TLS_OPT="-k"; fi

# Working folder. Keep it root-owned (not /tmp): it holds the downloaded lists,
# the feed-sized pieces, the lock file and the per-feed checksums.
STATE_DIR="${STATE_DIR:-/var/lib/update-quarantine-blocklist}"
URLS_FILE="${URLS_FILE:-${STATE_DIR}/quarantine_urls.txt}"
IPS_FILE="${IPS_FILE:-${STATE_DIR}/quarantine_ips.txt}"

# Folder where the feed-sized pieces are written (cleared on every run)
CHUNK_DIR="${CHUNK_DIR:-${STATE_DIR}/chunks}"

# Sky ATP API timeouts and status polling (seconds)
API_CONNECT_TIMEOUT="${API_CONNECT_TIMEOUT:-10}"
API_MAX_TIME="${API_MAX_TIME:-120}"
STATUS_INTERVAL="${STATUS_INTERVAL:-5}"     # wait between status checks
STATUS_MAX_WAIT="${STATUS_MAX_WAIT:-120}"   # give up waiting after this long

# Log file used when run without a terminal (set LOG_FILE="" to disable), and
# the lock file that stops two runs overlapping.
LOG_FILE="${LOG_FILE-/var/log/update-quarantine-blocklist.log}"
LOCK_FILE="${LOCK_FILE:-${STATE_DIR}/update.lock}"

# The script remembers a checksum of every feed it has published (in STATE_DIR).
# A feed whose content has not changed (and still exists in Sky ATP) is left
# alone instead of being deleted and uploaded again. FORCE=1 republishes all.
FORCE="${FORCE:-0}"

# If Sky ATP rejects a single entry ("Validation error: <entry>") the script
# removes that entry and uploads the feed again, up to this many times per feed.
MAX_REJECTED="${MAX_REJECTED:-25}"

# The source lists are rewritten by another system and can be empty or only
# partly written for a few seconds. A download that is empty, or that is less
# than MIN_PERCENT % of the previous list, is tried again FETCH_ATTEMPTS times
# (FETCH_RETRY_WAIT seconds apart) and then refused. ALLOW_SHRINK=1 accepts a
# genuinely much smaller list.
FETCH_ATTEMPTS="${FETCH_ATTEMPTS:-3}"
FETCH_RETRY_WAIT="${FETCH_RETRY_WAIT:-15}"
MIN_PERCENT="${MIN_PERCENT:-50}"
ALLOW_SHRINK="${ALLOW_SHRINK:-0}"

# Sky ATP Threat Intelligence Open API (blacklist cloud feeds).
SKYATP_API="${SKYATP_API:-https://threat-api.sky.junipersecurity.net/v2/cloudfeeds/blacklist}"

# --- Helper ---
die() {
    echo "NOT OK" >&2
    echo "ERROR: $*" >&2
    exit 1
}

# === SANITY CHECKS === #
for tool in curl jq split sort awk sed tr flock sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || die "Required tool not found: $tool"
done

[[ "$CHUNK_SIZE" =~ ^[0-9]+$ ]] || die "CHUNK_SIZE must be a whole number (got '$CHUNK_SIZE')"
{ [ "$CHUNK_SIZE" -ge 1 ] && [ "$CHUNK_SIZE" -le 10000 ]; } || die "CHUNK_SIZE must be between 1 and 10000 (got $CHUNK_SIZE)"
[[ "$URL_MAX_LEN" =~ ^[0-9]+$ ]] && [ "$URL_MAX_LEN" -ge 1 ] || die "URL_MAX_LEN must be a whole number of at least 1 (got '$URL_MAX_LEN')"
[[ "$FETCH_ATTEMPTS" =~ ^[0-9]+$ && "$FETCH_RETRY_WAIT" =~ ^[0-9]+$ && "$MIN_PERCENT" =~ ^[0-9]+$ ]] || die "FETCH_ATTEMPTS, FETCH_RETRY_WAIT and MIN_PERCENT must be whole numbers"
[ "$FETCH_ATTEMPTS" -ge 1 ] || die "FETCH_ATTEMPTS must be at least 1"
[[ "$FEED_PREFIX" =~ ^[A-Za-z0-9_]+$ ]] || die "FEED_PREFIX may only contain letters, numbers and underscores (got '$FEED_PREFIX')"
[[ "$CHUNK_DIR" == /?* ]] || die "CHUNK_DIR must be an absolute path other than / (got '$CHUNK_DIR')"

if [ "$MODE" = "fetch" ] || [ "$MODE" = "plan" ] || [ "$MODE" = "update" ]; then
    if [ -z "$QUARANTINE_URLS_URL" ] && [ -z "$QUARANTINE_IPS_URL" ]; then
        die "Set QUARANTINE_IPS_URL and/or QUARANTINE_URLS_URL (where to download the lists from)"
    fi
fi

# Create the working folder (and tighten its permissions).
ensure_state_dir() {
    mkdir -p "$STATE_DIR" || die "Cannot create working folder $STATE_DIR (set STATE_DIR to a folder you can write to)"
}

# === DOWNLOAD AND CLEAN === #

# Download one list from the source server and clean it.
#   $1 = label used in messages ("URL" or "IP")
#   $2 = source address
#   $3 = local file the cleaned list is written to
#   $4 = kind: "url" or "ip"
# The previous local copy is kept as <file>.bak and is left untouched if the
# download fails or the cleaned list comes out empty or much smaller.
# Returns 0 on success and 2 if the source gave an empty or too-small list
# (fetch_list below then tries again); any other problem stops the script.
fetch_list_once() {
    local label="$1" src="$2" file="$3" kind="$4"
    local raw="${file}.raw" tmp="${file}.tmp" bak="${file}.bak"
    local code url_skipped="" url_long="" old new

    echo -n "Checking if the quarantine ${label} server is reachable... "
    # shellcheck disable=SC2086  # SOURCE_TLS_OPT is empty or a single option
    code=$(curl $SOURCE_TLS_OPT -I -s -w '%{http_code}' -o /dev/null \
        --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
        "$src") \
        || die "curl failed reaching $src"
    [ "$code" = "200" ] || die "Server returned HTTP $code for ${label} list"
    echo "OK"

    if [ -f "$file" ]; then
        echo -n "Backing up existing ${label} list... "
        cp "$file" "$bak" || die "Failed to create backup"
        echo "OK"
    fi

    echo -n "Downloading ${label} list... "
    # shellcheck disable=SC2086
    curl $SOURCE_TLS_OPT -s -f \
        --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
        -o "$raw" "$src" \
        || { rm -f "$raw"; die "Download failed for ${label} list"; }
    echo "OK ($(wc -l < "$raw") raw lines)"

    echo -n "Cleaning ${label} list... "
    if [ "$kind" = "ip" ]; then
        # Keep IPv4 addresses with an optional /mask (e.g. 198.51.100.0/24).
        # Drop anything with an octet above 255 or a mask above 32. De-duplicate.
        tr -d '\r' < "$raw" \
            | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' \
            | awk -F'[./]' '$1<=255 && $2<=255 && $3<=255 && $4<=255 && (NF==4 || $5<=32)' \
            | sort -u > "$tmp" || true
    else
        # Sky ATP accepts bare hostnames/paths only. So:
        #   - remove invisible characters (zero-width space/joiner, word joiner, BOM ...)
        #   - trim whitespace, drop comment and blank lines
        #   - undo "defanging": "[.]" and "(.)" become ".", "hxxp" becomes "http"
        #   - cut a trailing "..." (the ellipsis character) where the source list was shortened
        #   - strip a leading "http://", "https://" etc. (also the typo "https//")
        #   - strip a leading "*" / "*." and a trailing "/*" / "*"
        #   - skip entries that cannot be valid: spaces, non-ASCII characters, or a
        #     host part (up to the first / ? #) with no dot or with characters
        #     other than letters, digits and . _ - : @
        #   - cut entries longer than URL_MAX_LEN (Sky ATP rejects them)
        #   - de-duplicate (cleaning can make two entries identical)
        tr -d '\r' < "$raw" \
            | LC_ALL=C sed -e 's/\xe2\x80[\x8b-\x8f]//g' -e 's/\xe2\x80[\xaa-\xae]//g' \
                           -e 's/\xe2\x81[\xa0-\xa4]//g' -e 's/\xe2\x81[\xa6-\xa9]//g' \
                           -e 's/\xef\xbb\xbf//g' -e 's/\xc2\xad//g' \
                           -e 's/\xe2\x80\xa6.*$//' \
            | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
            | grep -v '^#' \
            | grep -v '^$' \
            | sed -E -e 's#\[\.\]#.#g' -e 's#\(\.\)#.#g' -e 's#^hxxp(s?)://#http\1://#I' \
                     -e 's#^[A-Za-z][A-Za-z0-9+.-]*://##' -e 's#^(https?|ftp)//##I' \
                     -e 's#^\*+\.?##' \
                     -e 's#/?\*+$##' \
            | grep -v '^$' > "${tmp}.norm" || true
        : > "${tmp}.good"; : > "${tmp}.bad"
        LC_ALL=C awk -v good="${tmp}.good" -v bad="${tmp}.bad" '
            { host = $0; sub(/[\/?#].*$/, "", host)
              if ($0 !~ /[^!-~]/ && host ~ /\./ && host ~ /^[A-Za-z0-9._:@-]+$/) print > good
              else print > bad }' "${tmp}.norm"
        url_skipped=$(cat "${tmp}.bad")
        url_long=$(awk -v max="$URL_MAX_LEN" 'length($0) > max' "${tmp}.good" || true)
        cut -c1-"$URL_MAX_LEN" "${tmp}.good" \
            | sort -u > "$tmp" || true
        rm -f "${tmp}.norm" "${tmp}.good" "${tmp}.bad"
    fi
    rm -f "$raw"

    if [ ! -s "$tmp" ]; then
        rm -f "$tmp"
        echo "NOT OK (no valid ${label} entries - the source may be empty or being rewritten)"
        return 2
    fi
    if [ "$ALLOW_SHRINK" != "1" ] && [ -f "$bak" ]; then
        old=$(wc -l < "$bak")
        new=$(wc -l < "$tmp")
        if [ "$old" -ge 20 ] && [ $(( new * 100 )) -lt $(( old * MIN_PERCENT )) ]; then
            rm -f "$tmp"
            echo "NOT OK (list shrank from ${old} to ${new} entries, below ${MIN_PERCENT}% - the source may be incomplete)"
            return 2
        fi
    fi

    mv "$tmp" "$file"
    if [ "$kind" = "ip" ]; then
        echo "OK ($(wc -l < "$file") unique entries, $(grep -c '/' "$file" || true) of them with a /mask)"
    else
        echo "OK ($(wc -l < "$file") unique entries)"
        if [ -n "$url_skipped" ]; then
            echo "  Skipped $(echo "$url_skipped" | wc -l) entry/entries that cannot be valid URLs (spaces, odd characters or no proper hostname):"
            echo "$url_skipped" | head -10 | cut -c1-100 | sed 's/^/    /'
        fi
        if [ -n "$url_long" ]; then
            echo "  Shortened $(echo "$url_long" | wc -l) entry/entries longer than ${URL_MAX_LEN} characters (the start of the URL still matches the original)"
        fi
    fi
}

# Download and clean one list (same arguments as fetch_list_once). If the
# source gives an empty or much smaller list it may be mid-rewrite, so wait and
# try again; after FETCH_ATTEMPTS tries stop without touching anything.
fetch_list() {
    local attempt=1 rc

    while true; do
        rc=0
        fetch_list_once "$@" || rc=$?
        if [ "$rc" -eq 0 ]; then return 0; fi
        if [ "$attempt" -ge "$FETCH_ATTEMPTS" ]; then
            die "$1 list is still empty or incomplete after ${FETCH_ATTEMPTS} attempts - existing local list left untouched"
        fi
        attempt=$((attempt + 1))
        echo "  Waiting ${FETCH_RETRY_WAIT}s, then trying again (attempt ${attempt} of ${FETCH_ATTEMPTS})..."
        sleep "$FETCH_RETRY_WAIT"
    done
}

# === SPLIT INTO FEED-SIZED PIECES === #

# Split a cleaned list into pieces of at most CHUNK_SIZE lines. Piece N is
# written to ${CHUNK_DIR}/<prefix><KIND><N>.txt, which is also the Sky ATP feed
# name (e.g. Quarantine_BlacklistIP1.txt -> feed Quarantine_BlacklistIP1).
#   $1 = kind label: "IP" or "URL"
#   $2 = cleaned list file
# Prints one table row per piece and sets CHUNK_COUNT to the number of pieces.
CHUNK_COUNT=0
split_list() {
    local kind="$1" file="$2"
    local part n=0 name

    split -l "$CHUNK_SIZE" "$file" "${CHUNK_DIR}/part_${kind}_"
    for part in "${CHUNK_DIR}/part_${kind}_"*; do
        n=$((n + 1))
        name="${FEED_PREFIX}${kind}${n}"
        mv "$part" "${CHUNK_DIR}/${name}.txt"
        printf '  %-28s %7d entries   %s\n' "$name" "$(wc -l < "${CHUNK_DIR}/${name}.txt")" "${CHUNK_DIR}/${name}.txt"
    done
    CHUNK_COUNT=$n
}

# Empty the chunk folder of files from a previous run.
prepare_chunk_dir() {
    mkdir -p "$CHUNK_DIR" || die "Cannot create $CHUNK_DIR"
    find "$CHUNK_DIR" -maxdepth 1 -type f -name '*.txt' -delete
    find "$CHUNK_DIR" -maxdepth 1 -type f -name 'part_*' -delete
    find "$CHUNK_DIR" -maxdepth 1 -type f -name '*.try' -delete
}

# === SKY ATP API CALLS === #

# Print a response body as formatted JSON if possible, otherwise as it is.
show_body() {
    echo "$1" | jq -c . 2>/dev/null || echo "$1"
}

# Upload a file of entries as a new feed. Sky ATP answers 202 when it accepts it.
#   $1 = feed name   $2 = "ip" or "url"   $3 = file to upload
feed_upload() {
    local feed_name="$1" feed_type="$2" feed_file="$3"
    local response http_code body

    echo -n "Uploading '${feed_name}' (${feed_type}) to Sky ATP... "
    response=$(curl -s -w '\n%{http_code}' \
        --connect-timeout "$API_CONNECT_TIMEOUT" --max-time "$API_MAX_TIME" \
        -X POST \
        -H "Authorization: Bearer $SKYATP_API_TOKEN" \
        -F "file=@${feed_file}" \
        "${SKYATP_API}/file/${feed_type}/${feed_name}") \
        || die "curl failed on POST request for ${feed_name}"

    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" -lt 200 ] || [ "$http_code" -ge 300 ]; then
        echo "NOT OK (HTTP $http_code)"
        show_body "$body" >&2
        return 1
    fi
    echo "OK (HTTP $http_code)"
    show_body "$body"
}

# Ask Sky ATP for the processing status of a feed.
# Sets FEED_STATUS_CODE (HTTP status) and FEED_STATUS_MSG (its message text).
FEED_STATUS_CODE=""
FEED_STATUS_MSG=""
feed_status() {
    local feed_name="$1" feed_type="$2"
    local response body

    response=$(curl -s -w '\n%{http_code}' \
        --connect-timeout "$API_CONNECT_TIMEOUT" --max-time "$API_MAX_TIME" \
        -X GET \
        -H "Authorization: Bearer $SKYATP_API_TOKEN" \
        "${SKYATP_API}/file/${feed_type}/${feed_name}") \
        || die "curl failed on GET request for ${feed_name}"

    FEED_STATUS_CODE=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')
    FEED_STATUS_MSG=$(echo "$body" | jq -r '.message // empty' 2>/dev/null || true)
    [ -n "$FEED_STATUS_MSG" ] || FEED_STATUS_MSG="$body"
}

# Poll the status of a feed until Sky ATP says processing is complete.
# Returns 0 when complete, 1 on an error status or if it takes too long.
#   $1 = feed name   $2 = "ip" or "url"
wait_for_feed() {
    local feed_name="$1" feed_type="$2"
    local waited=0

    echo "Waiting for Sky ATP to finish processing '${feed_name}'..."
    while true; do
        feed_status "$feed_name" "$feed_type"
        echo "  [${waited}s] HTTP ${FEED_STATUS_CODE}: ${FEED_STATUS_MSG:-<no message>}"

        if [ "$FEED_STATUS_CODE" -lt 200 ] || [ "$FEED_STATUS_CODE" -ge 300 ]; then
            return 1
        fi
        if echo "$FEED_STATUS_MSG" | grep -qiE 'error|fail|invalid'; then
            return 1
        fi
        if echo "$FEED_STATUS_MSG" | grep -qi 'complete'; then
            return 0
        fi
        if [ "$waited" -ge "$STATUS_MAX_WAIT" ]; then
            echo "Gave up waiting after ${waited}s."
            return 1
        fi
        sleep "$STATUS_INTERVAL"
        waited=$((waited + STATUS_INTERVAL))
    done
}

# Delete a whole feed. Returns 0 if it was deleted or did not exist.
# Sets FEED_DELETE_RESULT to "deleted" or "absent".
#   $1 = feed name   $2 = "ip" or "url"
FEED_DELETE_RESULT=""
feed_delete() {
    local feed_name="$1" feed_type="$2"
    local response http_code body

    echo -n "Deleting Sky ATP feed '${feed_name}' (${feed_type})... "
    response=$(curl -s -w '\n%{http_code}' \
        --connect-timeout "$API_CONNECT_TIMEOUT" --max-time "$API_MAX_TIME" \
        -X DELETE \
        -H "Authorization: Bearer $SKYATP_API_TOKEN" \
        -F server='*' \
        "${SKYATP_API}/param/${feed_type}/${feed_name}") \
        || die "curl failed on DELETE request for ${feed_name}"

    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" -eq 404 ]; then
        FEED_DELETE_RESULT="absent"
        echo "OK (feed did not exist)"
        return 0
    fi
    if [ "$http_code" -lt 200 ] || [ "$http_code" -ge 300 ]; then
        echo "NOT OK (HTTP $http_code)"
        show_body "$body" >&2
        return 1
    fi
    FEED_DELETE_RESULT="deleted"
    echo "OK (HTTP $http_code)"
    show_body "$body"
}

# Poll until Sky ATP no longer knows the feed (status check answers 404).
# Returns 0 when the feed is gone, 1 if it is still there after STATUS_MAX_WAIT.
#   $1 = feed name   $2 = "ip" or "url"
wait_for_feed_gone() {
    local feed_name="$1" feed_type="$2"
    local waited=0

    echo "Waiting for Sky ATP to remove '${feed_name}'..."
    while true; do
        feed_status "$feed_name" "$feed_type"
        if [ "$FEED_STATUS_CODE" = "404" ]; then
            echo "  [${waited}s] gone (HTTP 404)"
            return 0
        fi
        echo "  [${waited}s] HTTP ${FEED_STATUS_CODE}: ${FEED_STATUS_MSG:-<no message>}"
        if [ "$waited" -ge "$STATUS_MAX_WAIT" ]; then
            echo "Gave up waiting after ${waited}s."
            return 1
        fi
        sleep "$STATUS_INTERVAL"
        waited=$((waited + STATUS_INTERVAL))
    done
}

# === PUBLISHING === #

# Is this feed already published with exactly this content? True only if the
# checksum saved after the last successful upload matches the new content AND
# Sky ATP still reports the feed as complete (so a feed deleted by hand, or one
# that ended in an error, is published again). FORCE=1 always returns false.
#   $1 = feed name   $2 = "ip" or "url"   $3 = file with the new entries
#   $4 = checksum file for this feed
feed_is_current() {
    local feed_name="$1" feed_type="$2" feed_file="$3" sum_file="$4"
    local now

    if [ "$FORCE" = "1" ]; then return 1; fi
    if [ ! -f "$sum_file" ]; then return 1; fi
    now=$(sha256sum "$feed_file" | cut -d' ' -f1)
    if [ "$now" != "$(cat "$sum_file")" ]; then return 1; fi

    feed_status "$feed_name" "$feed_type"
    if [ "$FEED_STATUS_CODE" != "200" ]; then return 1; fi
    if echo "$FEED_STATUS_MSG" | grep -qiE 'error|fail|invalid'; then return 1; fi
    echo "$FEED_STATUS_MSG" | grep -qi 'complete'
}

# Replace one feed: delete the old one, wait until it is gone, upload the new
# content, then wait until Sky ATP has processed it. A feed that is unchanged
# is skipped (see feed_is_current).
#   $1 = feed name   $2 = "ip" or "url"   $3 = file with the new entries
feed_replace() {
    local feed_name="$1" feed_type="$2" feed_file="$3"
    local sum_file="${STATE_DIR}/${feed_name}.sha256"
    local try_file="${feed_file}.try" want_sum entry rejected=0

    if feed_is_current "$feed_name" "$feed_type" "$feed_file" "$sum_file"; then
        echo "Feed '${feed_name}' is unchanged and already in Sky ATP - skipped"
        return 0
    fi

    # The checksum saved on success is that of the wanted content, even if
    # Sky ATP made us leave out a few entries, so the next run can skip it.
    want_sum=$(sha256sum "$feed_file" | cut -d' ' -f1)
    rm -f "$sum_file"    # forget the old checksum until the new upload succeeds
    cp "$feed_file" "$try_file" || return 1

    while true; do
        feed_delete "$feed_name" "$feed_type" || { rm -f "$try_file"; return 1; }
        wait_for_feed_gone "$feed_name" "$feed_type" || { rm -f "$try_file"; return 1; }
        feed_upload "$feed_name" "$feed_type" "$try_file" || { rm -f "$try_file"; return 1; }
        if wait_for_feed "$feed_name" "$feed_type"; then
            break
        fi

        # Sky ATP names the entry it refuses: "... Validation error: <entry>".
        # Leave that one entry out and upload again instead of losing the feed.
        entry="${FEED_STATUS_MSG##*Validation error: }"
        if [[ "$FEED_STATUS_MSG" != *"Validation error: "* ]] || ! grep -qxF -- "$entry" "$try_file"; then
            rm -f "$try_file"
            return 1
        fi
        rejected=$((rejected + 1))
        REJECTED_TOTAL=$((REJECTED_TOTAL + 1))
        if [ "$rejected" -gt "$MAX_REJECTED" ]; then
            echo "Sky ATP rejected more than ${MAX_REJECTED} entries in '${feed_name}' - giving up."
            rm -f "$try_file"
            return 1
        fi
        echo "Sky ATP rejected this entry - leaving it out and trying again: $(echo "$entry" | cut -c1-100)"
        grep -vxF -- "$entry" "$try_file" > "${try_file}.new" || true
        mv "${try_file}.new" "$try_file"
        if [ ! -s "$try_file" ]; then
            echo "Nothing left to upload for '${feed_name}'."
            rm -f "$try_file"
            return 1
        fi
    done

    rm -f "$try_file"
    echo "$want_sum" > "$sum_file"
    UPDATED_FEEDS=$((UPDATED_FEEDS + 1))
}

# Delete feeds <prefix><KIND><first>, <first+1>, ... until one does not exist.
#   $1 = kind label "URL" or "IP"   $2 = "url" or "ip"   $3 = first number
delete_feeds_from() {
    local kind="$1" feed_type="$2" idx="$3"

    while true; do
        feed_delete "${FEED_PREFIX}${kind}${idx}" "$feed_type" || return 1
        [ "$FEED_DELETE_RESULT" = "deleted" ] || return 0
        idx=$((idx + 1))
    done
}

# Publish one cleaned list: split it into feed-sized pieces, replace one feed
# per piece, then remove leftover feeds from an earlier, longer list.
#   $1 = kind label "URL" or "IP"   $2 = "url" or "ip"   $3 = cleaned list file
PUBLISHED_FEEDS=0
UPDATED_FEEDS=0
REJECTED_TOTAL=0
publish_list() {
    local kind="$1" feed_type="$2" file="$3"
    local pieces n name

    split_list "$kind" "$file"
    pieces=$CHUNK_COUNT
    for ((n = 1; n <= pieces; n++)); do
        name="${FEED_PREFIX}${kind}${n}"
        feed_replace "$name" "$feed_type" "${CHUNK_DIR}/${name}.txt" || return 1
    done
    delete_feeds_from "$kind" "$feed_type" $((pieces + 1)) || return 1
    PUBLISHED_FEEDS=$((PUBLISHED_FEEDS + pieces))
}

# === --check: show settings and stop === #
if [ "$MODE" = "check" ]; then
    echo "Running as:    $(id -un)  (HOME=${HOME})"
    echo "Token:         loaded (${#SKYATP_API_TOKEN} characters)"
    echo "Feed names:    ${FEED_PREFIX}IP1, ${FEED_PREFIX}IP2, ...   ${FEED_PREFIX}URL1, ${FEED_PREFIX}URL2, ..."
    echo "Chunk size:    ${CHUNK_SIZE}"
    echo "URL max length: ${URL_MAX_LEN}"
    echo "API base:      ${SKYATP_API}"
    echo "IP source:     ${QUARANTINE_IPS_URL:-<not set - IP list skipped>}"
    echo "URL source:    ${QUARANTINE_URLS_URL:-<not set - URL list skipped>}"
    echo "Source TLS:    $([ "$SOURCE_INSECURE_TLS" = "1" ] && echo "certificate NOT verified" || echo "certificate verified")"
    echo "Working files: ${IPS_FILE}  ${URLS_FILE}"
    echo "Chunk folder:  ${CHUNK_DIR}"
    echo "Log file:      ${LOG_FILE:-<disabled>}"
    echo "Lock file:     ${LOCK_FILE}"
    echo "State folder:  ${STATE_DIR}   (FORCE=${FORCE}, MAX_REJECTED=${MAX_REJECTED})"
    echo "Source checks: ${FETCH_ATTEMPTS} attempts, ${FETCH_RETRY_WAIT}s apart; refuse a list under ${MIN_PERCENT}% of the last one (ALLOW_SHRINK=${ALLOW_SHRINK})"
    echo "Tools:         curl, jq, split, sort, awk, sed, tr, flock all found"
    echo "OK - nothing was sent anywhere."
    exit 0
fi

# === --fetch: download and clean, then stop === #
if [ "$MODE" = "fetch" ]; then
    ensure_state_dir
    if [ -n "$QUARANTINE_URLS_URL" ]; then
        echo ""
        echo "=== Quarantine URLs ==="
        fetch_list "URL" "$QUARANTINE_URLS_URL" "$URLS_FILE" "url"
        echo "Cleaned URL list: ${URLS_FILE} ($(wc -l < "$URLS_FILE") entries)"
    fi
    if [ -n "$QUARANTINE_IPS_URL" ]; then
        echo ""
        echo "=== Quarantine IPs ==="
        fetch_list "IP" "$QUARANTINE_IPS_URL" "$IPS_FILE" "ip"
        echo "Cleaned IP list: ${IPS_FILE} ($(wc -l < "$IPS_FILE") entries)"
    fi
    echo ""
    echo "OK - nothing was sent to Sky ATP."
    exit 0
fi

# === --plan: fetch, split, show what would be pushed, then stop === #
if [ "$MODE" = "plan" ]; then
    ensure_state_dir
    if [ -n "$QUARANTINE_URLS_URL" ]; then
        echo ""
        echo "=== Quarantine URLs ==="
        fetch_list "URL" "$QUARANTINE_URLS_URL" "$URLS_FILE" "url"
    fi
    if [ -n "$QUARANTINE_IPS_URL" ]; then
        echo ""
        echo "=== Quarantine IPs ==="
        fetch_list "IP" "$QUARANTINE_IPS_URL" "$IPS_FILE" "ip"
    fi

    prepare_chunk_dir
    echo ""
    echo "=== Feeds that would be pushed (chunk size ${CHUNK_SIZE}) ==="
    url_feeds=0
    ip_feeds=0
    if [ -n "$QUARANTINE_URLS_URL" ]; then split_list "URL" "$URLS_FILE"; url_feeds=$CHUNK_COUNT; fi
    if [ -n "$QUARANTINE_IPS_URL" ]; then split_list "IP" "$IPS_FILE"; ip_feeds=$CHUNK_COUNT; fi
    echo ""
    echo "Total: $((url_feeds + ip_feeds)) feeds ($url_feeds URL, $ip_feeds IP)"
    echo "OK - nothing was sent to Sky ATP."
    exit 0
fi

# === --selftest: upload a throwaway feed, wait for it, then stop === #
if [ "$MODE" = "selftest" ]; then
    TEST_FEED="${FEED_PREFIX}Test01"
    TEST_FILE=$(mktemp) || die "Cannot create temp file"
    # 192.0.2.0/24 is reserved for documentation, so nothing real is blocked.
    printf '192.0.2.1\n192.0.2.2\n' > "$TEST_FILE"

    echo ""
    echo "=== Self-test: IP feed '${TEST_FEED}' with 2 example addresses ==="
    feed_upload "$TEST_FEED" "ip" "$TEST_FILE" || { rm -f "$TEST_FILE"; exit 1; }
    rm -f "$TEST_FILE"
    wait_for_feed "$TEST_FEED" "ip" || die "Sky ATP did not report '${TEST_FEED}' as processed"
    echo ""
    echo "OK - test feed '${TEST_FEED}' uploaded and processed. Remove it again with"
    echo "     --selftest-delete."
    exit 0
fi

# === --selftest-delete: remove the throwaway feed again, then stop === #
if [ "$MODE" = "selftest-delete" ]; then
    TEST_FEED="${FEED_PREFIX}Test01"
    echo ""
    echo "=== Self-test delete: IP feed '${TEST_FEED}' ==="
    feed_delete "$TEST_FEED" "ip" || exit 1
    wait_for_feed_gone "$TEST_FEED" "ip" || die "Sky ATP still lists '${TEST_FEED}'"
    echo ""
    echo "OK - test feed '${TEST_FEED}' deleted and confirmed gone."
    exit 0
fi

# === LOGGING, LOCK AND EXIT MESSAGE (--update and --delete only) === #
if [ "$MODE" = "update" ] || [ "$MODE" = "delete" ]; then
    ensure_state_dir
    # Without a terminal (cron), write everything to the log file. Rotate it
    # to <file>.1 when it passes 5 MB.
    if [ ! -t 1 ] && [ -n "$LOG_FILE" ]; then
        { : >> "$LOG_FILE"; } 2>/dev/null || die "Cannot write to log file $LOG_FILE"
        if [ "$(stat -c %s "$LOG_FILE")" -gt 5242880 ]; then
            mv -f "$LOG_FILE" "${LOG_FILE}.1"
        fi
        exec >> "$LOG_FILE" 2>&1
    fi
    echo ""
    echo "===== $(date '+%Y-%m-%d %H:%M:%S') ${0##*/} --${MODE} started ====="
    trap 'rc=$?; echo "===== $(date "+%Y-%m-%d %H:%M:%S") finished, exit code ${rc} ====="' EXIT

    # Only one run at a time.
    exec 9> "$LOCK_FILE" || die "Cannot open lock file $LOCK_FILE"
    if ! flock -n 9; then
        echo "Another run is still in progress - exiting without doing anything."
        exit 0
    fi
fi

# === --update: fetch both lists, then publish them === #
if [ "$MODE" = "update" ]; then
    START_TIME=$(date +%s)

    # Fetch and clean ALL lists first, so that if a source is down nothing in
    # Sky ATP is touched.
    if [ -n "$QUARANTINE_URLS_URL" ]; then
        echo ""
        echo "=== Quarantine URLs ==="
        fetch_list "URL" "$QUARANTINE_URLS_URL" "$URLS_FILE" "url"
    fi
    if [ -n "$QUARANTINE_IPS_URL" ]; then
        echo ""
        echo "=== Quarantine IPs ==="
        fetch_list "IP" "$QUARANTINE_IPS_URL" "$IPS_FILE" "ip"
    fi

    prepare_chunk_dir
    if [ -n "$QUARANTINE_URLS_URL" ]; then
        echo ""
        echo "=== Publishing URL feeds (chunk size ${CHUNK_SIZE}) ==="
        publish_list "URL" "url" "$URLS_FILE" || die "Publishing the URL feeds failed"
    fi
    if [ -n "$QUARANTINE_IPS_URL" ]; then
        echo ""
        echo "=== Publishing IP feeds (chunk size ${CHUNK_SIZE}) ==="
        publish_list "IP" "ip" "$IPS_FILE" || die "Publishing the IP feeds failed"
    fi

    echo ""
    echo "Done: ${PUBLISHED_FEEDS} feeds up to date (${UPDATED_FEEDS} republished, $(( PUBLISHED_FEEDS - UPDATED_FEEDS )) unchanged) in $(( $(date +%s) - START_TIME ))s."
    if [ "$REJECTED_TOTAL" -gt 0 ]; then
        echo "WARNING: Sky ATP rejected ${REJECTED_TOTAL} entry/entries, which were left out of the feeds (see above)."
    fi
    exit 0
fi

# === --delete: remove all feeds this script manages === #
if [ "$MODE" = "delete" ]; then
    echo ""
    echo "=== Deleting all ${FEED_PREFIX}URL* and ${FEED_PREFIX}IP* feeds ==="
    delete_feeds_from "URL" "url" 1 || die "Deleting the URL feeds failed"
    delete_feeds_from "IP" "ip" 1 || die "Deleting the IP feeds failed"
    echo ""
    echo "Done."
    exit 0
fi

