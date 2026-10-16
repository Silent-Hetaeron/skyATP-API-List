#!/usr/bin/env bash
#
# Test suite for update-quarantine-blocklist.sh
#
# Runs the script against a fake source server and a fake Sky ATP Open API (see
# bin/curl), so nothing touches the network and no token or account is needed.
#
#   ./tests/run-tests.sh
#
# Requires: bash, curl-compatible stub (included), jq, flock, coreutils, awk, sed.
# shellcheck disable=SC2015,SC2129  # "A && ok || fail" is deliberate: ok never fails
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${SCRIPT:-$HERE/../update-quarantine-blocklist.sh}"
PASS=0; FAIL=0

ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/       /'; }
check() { # check "name" command...   (passes if command succeeds)
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then ok "$name"; else fail "$name"; fi
}

new_env() { # fresh sandbox: $T/{state,api,src}
    T="$(mktemp -d)"; mkdir -p "$T/api" "$T/src"
    : > "$T/api/calls.log"
    export STUB_SRC="$T/src" STUB_API="$T/api"
    unset STUB_BAD STUB_EMPTY_FIRST STUB_SOURCE_DOWN
}
run() { # run the script with a clean, test-only environment; output in $OUT, exit code in $RC
    OUT="$(env -i PATH="$HERE/bin:$PATH" HOME="$T" \
        SKYATP_API_TOKEN="test-token" \
        SKYATP_API="https://api.example/v2/cloudfeeds/blacklist" \
        STATE_DIR="$T/state" LOG_FILE="" \
        STATUS_INTERVAL=0 STATUS_MAX_WAIT=5 FETCH_RETRY_WAIT=0 \
        STUB_SRC="$STUB_SRC" STUB_API="$STUB_API" STUB_BAD="${STUB_BAD:-}" \
        STUB_EMPTY_FIRST="${STUB_EMPTY_FIRST:-}" STUB_SOURCE_DOWN="${STUB_SOURCE_DOWN:-}" \
        "$@" 2>&1)"
    RC=$?
}
S="$SCRIPT"
URLS_SRC="https://source.example/urls.txt"
IPS_SRC="https://source.example/ips.txt"
calls() { grep -c "^$1 " "$T/api/calls.log" || true; }
feed()  { echo "$T/api/feed_$1"; }

write_sources() {
    printf '%s\n' '# a comment' 'Example.org/path' 'https://www.example.com/a/b' 'hxxp://evil[.]example.net' \
        '*.wild.example.org/*' 'https//typo.example.org' 'https%3A%2F%2Fenc.example.org' 'nodot' \
        'has space.example.org' 'dup.example.org' 'dup.example.org' '' > "$T/src/urls.txt"
    printf 'crlf.example.org\r\n' >> "$T/src/urls.txt"
    printf '\xe2\x80\x8bzerowidth.example.org\n\xc3\xbcnicode.example.org\n' >> "$T/src/urls.txt"
    printf 'www.canva.com/design/ABC123/\xe2\x80\xa6\n' >> "$T/src/urls.txt"
    printf 'long.example.org/%s\n' "$(head -c 200 /dev/zero | tr '\0' a)" >> "$T/src/urls.txt"
    printf '%s\n' '# ips' '198.51.100.7' '198.51.100.7' '203.0.113.0/24' '10.0.0.256' '192.0.2.1/33' 'junk' '192.0.2.9 trailing text' > "$T/src/ips.txt"
}

echo "== settings and argument handling"
new_env
run "$S" --check
[ $RC -eq 0 ] && grep -q 'not set - IP list skipped' <<<"$OUT" && ok "--check works with no sources set" || fail "--check works with no sources set" "$OUT"
run "$S" --bogus
[ $RC -ne 0 ] && grep -q Usage <<<"$OUT" && ok "unknown option is refused" || fail "unknown option is refused" "$OUT"
run "$S" --update
[ $RC -ne 0 ] && grep -q 'Set QUARANTINE_IPS_URL' <<<"$OUT" && ok "--update with no source is refused" || fail "--update with no source is refused" "$OUT"
run env -u SKYATP_API_TOKEN HOME="$T" "$S" --check
[ $RC -ne 0 ] && grep -q 'SKYATP_API_TOKEN is not set' <<<"$OUT" && ok "missing token is refused" || fail "missing token is refused" "$OUT"
run env FEED_PREFIX='bad-prefix!' "$S" --check
[ $RC -ne 0 ] && ok "invalid FEED_PREFIX is refused" || fail "invalid FEED_PREFIX is refused" "$OUT"
run env CHUNK_SIZE=10001 "$S" --check
[ $RC -ne 0 ] && ok "CHUNK_SIZE above 10000 is refused" || fail "CHUNK_SIZE above 10000 is refused" "$OUT"
run env SOURCE_INSECURE_TLS=1 "$S" --check
grep -q 'NOT verified' <<<"$OUT" && ok "--check reports disabled TLS verification" || fail "--check reports disabled TLS verification" "$OUT"
run env SOURCE_INSECURE_TLS=0 "$S" --check
grep -q 'certificate verified' <<<"$OUT" && ok "TLS verification is on by default" || fail "TLS verification is on by default" "$OUT"
rm -rf "$T"

echo "== cleaning"
new_env; write_sources
run env QUARANTINE_URLS_URL=$URLS_SRC QUARANTINE_IPS_URL=$IPS_SRC "$S" --fetch
[ $RC -eq 0 ] || fail "--fetch succeeds" "$OUT"
cat > "$T/expected_urls" <<'EOT'
Example.org/path
crlf.example.org
dup.example.org
evil.example.net
@@LONG@@
typo.example.org
wild.example.org
www.canva.com/design/ABC123/
www.example.com/a/b
zerowidth.example.org
EOT
sed -i "s#@@LONG@@#$(printf 'long.example.org/%s' "$(head -c 200 /dev/zero | tr '\0' a)" | cut -c1-128)#" "$T/expected_urls"
sort -o "$T/expected_urls" "$T/expected_urls"
diff <(sort "$T/state/quarantine_urls.txt") "$T/expected_urls" >"$T/diff" 2>&1 \
    && ok "URL list cleaned as expected" || fail "URL list cleaned as expected" "$(cat "$T/diff")"
printf '192.0.2.9\n198.51.100.7\n203.0.113.0/24\n' | sort > "$T/expected_ips"
diff <(sort "$T/state/quarantine_ips.txt") "$T/expected_ips" >"$T/diff" 2>&1 \
    && ok "IP list cleaned as expected" || fail "IP list cleaned as expected" "$(cat "$T/diff")"
[ "$(awk '{ if (length($0) > 128) n++ } END { print n+0 }' "$T/state/quarantine_urls.txt")" = 0 ] \
    && ok "no URL entry is longer than 128 characters" || fail "no URL entry is longer than 128 characters"
[ "$(calls POST)$(calls DELETE)" = "00" ] && ok "--fetch sends nothing to the API" || fail "--fetch sends nothing to the API"
[ -z "$(find "$T" -path "$T/state" -prune -o -path "$T/src" -prune -o -path "$T/api" -prune -o -type f -name '*.txt' -print)" ] \
    && ok "working files stay under STATE_DIR" || fail "working files stay under STATE_DIR"
[ "$(stat -c %a "$T/state")" = 700 ] && ok "STATE_DIR is private (700)" || fail "STATE_DIR is private (700)" "$(stat -c %a "$T/state")"
rm -rf "$T"

echo "== publish, skip, change"
new_env; write_sources
printf '192.0.2.9\n198.51.100.7\n203.0.113.0/24\n' | sort > "$T/expected_ips"
run env QUARANTINE_URLS_URL=$URLS_SRC QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ $RC -eq 0 ] && grep -q 'Done: 2 feeds up to date (2 republished, 0 unchanged)' <<<"$OUT" && ok "first run publishes both feeds" || fail "first run publishes both feeds" "$OUT"
[ -f "$(feed Quarantine_BlacklistURL1)" ] && [ -f "$(feed Quarantine_BlacklistIP1)" ] && ok "feeds named <prefix>URL1 and <prefix>IP1" || fail "feeds named <prefix>URL1 and <prefix>IP1"
diff <(sort "$(feed Quarantine_BlacklistIP1)") "$T/expected_ips" >/dev/null && ok "published IP feed content is the cleaned list" || fail "published IP feed content is the cleaned list"
: > "$T/api/calls.log"
run env QUARANTINE_URLS_URL=$URLS_SRC QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ $RC -eq 0 ] && grep -q '0 republished, 2 unchanged' <<<"$OUT" && [ "$(calls POST)" = 0 ] && ! grep -q "^DELETE Quarantine_Blacklist\(URL\|IP\)1\$" "$T/api/calls.log" \
    && ok "second run changes nothing (no upload, no replace)" || fail "second run changes nothing" "$OUT"
echo '203.0.113.99' >> "$T/src/ips.txt"; : > "$T/api/calls.log"
run env QUARANTINE_URLS_URL=$URLS_SRC QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ $RC -eq 0 ] && grep -q '1 republished, 1 unchanged' <<<"$OUT" && grep -q 203.0.113.99 "$(feed Quarantine_BlacklistIP1)" \
    && ok "a changed list republishes only that feed" || fail "a changed list republishes only that feed" "$OUT"
: > "$T/api/calls.log"
run env FORCE=1 QUARANTINE_URLS_URL=$URLS_SRC QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
grep -q '2 republished, 0 unchanged' <<<"$OUT" && ok "FORCE=1 republishes everything" || fail "FORCE=1 republishes everything" "$OUT"
rm -f "$(feed Quarantine_BlacklistURL1)"; : > "$T/api/calls.log"
run env QUARANTINE_URLS_URL=$URLS_SRC QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ -f "$(feed Quarantine_BlacklistURL1)" ] && grep -q '1 republished, 1 unchanged' <<<"$OUT" \
    && ok "a feed missing in Sky ATP is recreated even if unchanged locally" || fail "a feed missing in Sky ATP is recreated" "$OUT"
rm -rf "$T"

echo "== chunking"
new_env; write_sources
seq 1 25 | sed 's#^#198.51.100.#' > "$T/src/ips.txt"
run env CHUNK_SIZE=10 QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ $RC -eq 0 ] && [ -f "$(feed Quarantine_BlacklistIP1)" ] && [ -f "$(feed Quarantine_BlacklistIP3)" ] && [ ! -f "$(feed Quarantine_BlacklistIP4)" ] \
    && [ "$(wc -l < "$(feed Quarantine_BlacklistIP1)")" = 10 ] && [ "$(wc -l < "$(feed Quarantine_BlacklistIP3)")" = 5 ] \
    && ok "25 entries at CHUNK_SIZE=10 give feeds of 10/10/5" || fail "25 entries at CHUNK_SIZE=10 give feeds of 10/10/5" "$OUT"
[ ! -e "$(feed Quarantine_BlacklistURL1)" ] && ok "only-IP configuration publishes no URL feeds" || fail "only-IP configuration publishes no URL feeds"
seq 1 8 | sed 's#^#198.51.100.#' > "$T/src/ips.txt"
run env CHUNK_SIZE=10 ALLOW_SHRINK=1 QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ ! -f "$(feed Quarantine_BlacklistIP2)" ] && [ ! -f "$(feed Quarantine_BlacklistIP3)" ] && [ -f "$(feed Quarantine_BlacklistIP1)" ] \
    && ok "leftover feeds from an earlier, longer list are deleted" || fail "leftover feeds from an earlier, longer list are deleted" "$OUT"
rm -rf "$T"

new_env; write_sources
run env QUARANTINE_URLS_URL=$URLS_SRC "$S" --update
[ $RC -eq 0 ] && [ -f "$(feed Quarantine_BlacklistURL1)" ] && [ ! -e "$(feed Quarantine_BlacklistIP1)" ] \
    && ok "only-URL configuration publishes no IP feeds" || fail "only-URL configuration publishes no IP feeds" "$OUT"
run env QUARANTINE_URLS_URL=$URLS_SRC QUARANTINE_IPS_URL=$IPS_SRC "$S" --plan
[ $RC -eq 0 ] && grep -q 'Total: 2 feeds (1 URL, 1 IP)' <<<"$OUT" && ok "--plan reports the feeds it would push" || fail "--plan reports the feeds it would push" "$OUT"
rm -rf "$T"

echo "== custom prefix"
new_env; write_sources
run env FEED_PREFIX=My_Feed QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ -f "$(feed My_FeedIP1)" ] && ok "FEED_PREFIX changes feed names" || fail "FEED_PREFIX changes feed names" "$OUT"
rm -rf "$T"

echo "== rejected entries"
new_env; write_sources
printf '198.51.100.7\n' > "$T/bad"   # pretend Sky ATP dislikes this one
export STUB_BAD="$T/bad"
run env QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ $RC -eq 0 ] && ! grep -qx '198.51.100.7' "$(feed Quarantine_BlacklistIP1)" && grep -qx '203.0.113.0/24' "$(feed Quarantine_BlacklistIP1)" \
    && grep -q 'WARNING: Sky ATP rejected 1' <<<"$OUT" && ok "a rejected entry is dropped and the feed is uploaded again" || fail "a rejected entry is dropped and the feed is uploaded again" "$OUT"
: > "$T/api/calls.log"
run env QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ "$(calls POST)" = 0 ] && ok "after a rejection the next run still sees the feed as unchanged" || fail "after a rejection the next run still sees the feed as unchanged" "$OUT"
rm -rf "$T"
new_env; write_sources
seq 1 6 | sed 's#^#198.51.100.#' > "$T/src/ips.txt"; cp "$T/src/ips.txt" "$T/bad"
export STUB_BAD="$T/bad"
run env MAX_REJECTED=3 QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ $RC -ne 0 ] && grep -qi 'reject' <<<"$OUT" && ok "MAX_REJECTED stops a feed that keeps failing" || fail "MAX_REJECTED stops a feed that keeps failing" "$OUT"
rm -rf "$T"

echo "== source problems"
new_env; write_sources
run env QUARANTINE_URLS_URL=$URLS_SRC QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
cp "$T/state/quarantine_ips.txt" "$T/ips_before"; : > "$T/api/calls.log"
: > "$T/src/ips.txt"
run env QUARANTINE_URLS_URL=$URLS_SRC QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ $RC -ne 0 ] && cmp -s "$T/ips_before" "$T/state/quarantine_ips.txt" && [ "$(calls POST)$(calls DELETE)" = "00" ] \
    && ok "an empty source is refused; local list and Sky ATP untouched" || fail "an empty source is refused" "$OUT"
write_sources; : > "$T/api/calls.log"; echo 0 > "$T/api/empty_count"
export STUB_EMPTY_FIRST=2
run env QUARANTINE_URLS_URL=$URLS_SRC QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ $RC -eq 0 ] && grep -q 'trying again' <<<"$OUT" && ok "a source that is empty twice then recovers is retried" || fail "a source that is empty twice then recovers is retried" "$OUT"
unset STUB_EMPTY_FIRST
seq 1 100 | sed 's#^#198.51.100.#' > "$T/src/ips.txt"
run env QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
seq 1 10 | sed 's#^#198.51.100.#' > "$T/src/ips.txt"
run env QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ $RC -ne 0 ] && [ "$(wc -l < "$(feed Quarantine_BlacklistIP1)")" = 100 ] && ok "a list that shrinks below MIN_PERCENT is refused" || fail "a list that shrinks below MIN_PERCENT is refused" "$OUT"
run env ALLOW_SHRINK=1 QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ $RC -eq 0 ] && [ "$(wc -l < "$(feed Quarantine_BlacklistIP1)")" = 10 ] && ok "ALLOW_SHRINK=1 accepts the smaller list" || fail "ALLOW_SHRINK=1 accepts the smaller list" "$OUT"
export STUB_SOURCE_DOWN=1
run env QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ $RC -ne 0 ] && ok "an unreachable source stops the run" || fail "an unreachable source stops the run" "$OUT"
rm -rf "$T"

echo "== TLS option"
new_env; write_sources
run env SOURCE_INSECURE_TLS=1 QUARANTINE_IPS_URL=$IPS_SRC "$S" --fetch
grep -q INSECURE "$T/api/calls.log" && ok "SOURCE_INSECURE_TLS=1 passes -k to curl" || fail "SOURCE_INSECURE_TLS=1 passes -k to curl"
: > "$T/api/calls.log"
run env QUARANTINE_IPS_URL=$IPS_SRC "$S" --fetch
! grep -q INSECURE "$T/api/calls.log" && ok "-k is not used by default" || fail "-k is not used by default"
rm -rf "$T"

echo "== lock and logging"
new_env; write_sources
mkdir -p "$T/state"
( exec 9> "$T/state/update.lock"; flock -n 9; run env QUARANTINE_IPS_URL=$IPS_SRC "$S" --update; echo "$RC" > "$T/rc"; echo "$OUT" > "$T/out" )
grep -q 'Another run is still in progress' "$T/out" && [ "$(cat "$T/rc")" = 0 ] && ok "a second run exits quietly while the lock is held" || fail "a second run exits quietly while the lock is held" "$(cat "$T/out")"
run env LOG_FILE="$T/test.log" QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
[ -z "$OUT" ] && grep -q 'finished, exit code 0' "$T/test.log" && [ "$(stat -c %a "$T/test.log")" = 600 ] \
    && ok "without a terminal, output goes to the private log file" || fail "without a terminal, output goes to the private log file" "$OUT"
rm -rf "$T"

echo "== delete"
new_env; write_sources
run env QUARANTINE_URLS_URL=$URLS_SRC QUARANTINE_IPS_URL=$IPS_SRC "$S" --update
run env "$S" --delete
[ $RC -eq 0 ] && [ -z "$(ls "$T"/api/feed_* 2>/dev/null)" ] && ok "--delete removes every managed feed" || fail "--delete removes every managed feed" "$OUT"
run env "$S" --selftest
[ $RC -eq 0 ] && [ -f "$(feed Quarantine_BlacklistTest01)" ] && ok "--selftest uploads the throwaway feed" || fail "--selftest uploads the throwaway feed" "$OUT"
run env "$S" --selftest-delete
[ $RC -eq 0 ] && [ ! -f "$(feed Quarantine_BlacklistTest01)" ] && ok "--selftest-delete removes it again" || fail "--selftest-delete removes it again" "$OUT"
rm -rf "$T"

echo
echo "Passed: $PASS   Failed: $FAIL"
[ "$FAIL" -eq 0 ]
