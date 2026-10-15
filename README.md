# update-quarantine-blocklist

Keep a Juniper **Sky ATP / ATP Cloud** blacklist in step with a quarantine list of
IP addresses and URLs that lives on one of your own servers.

The script downloads two plain-text lists (IPs and URLs/hostnames), cleans them up so
Sky ATP will accept them, splits them into feeds of at most 9,000 entries, and publishes
them through the Sky ATP **Threat Intelligence Open API**. It is meant to run from cron,
every ten minutes or so, and to be boring: if nothing changed it does nothing, and if
something looks wrong it stops *before* touching what is already published.

> **Not affiliated with Juniper Networks.** "Juniper", "Sky ATP" and "ATP Cloud" are
> trademarks of Juniper Networks, Inc. This is an independent, community script.
> Use it at your own risk and test it on a non-production feed first (`--selftest`).

Authors: **Silent Hetaeron** and **MGi**, with assistance from **Claude** (Anthropic).
Licensed under the [MIT licence](LICENSE).

---

## What it does

```
your server                      this script                         Sky ATP
quarantine-ips.txt   ──►  download ─► clean ─► split ─► compare ─►   <prefix>IP1, IP2 ...
quarantine-urls.txt  ──►  (retry if empty/short)   (9,000 per feed)   <prefix>URL1, URL2 ...
                                                                        │
                                              SRX / ATP Cloud policy ◄──┘  (you wire this up)
```

* **IP list** – IPv4 addresses, optionally with a `/mask`. Anything else on the line is
  ignored; octets above 255 and masks above 32 are dropped; duplicates removed.
* **URL list** – hostnames or URLs, one per line. See [Cleaning](#cleaning-the-url-list).
* **Feeds** are named `<prefix>IP1`, `<prefix>IP2`, … and `<prefix>URL1`, `<prefix>URL2`, …
  (default prefix `Quarantine_Blacklist`). If the list shrinks, feeds that are no longer
  needed are deleted.
* **Change detection** – a SHA-256 of each feed is stored locally. A feed whose content has not
  changed *and* still exists in Sky ATP is skipped, so the job normally does nothing and
  the log says so.
* **Replacing a feed** is delete → wait until gone → upload → wait until processed. The API
  does not offer an in-place update that we could rely on, so this is the safe order.

This script only gets the lists **into** Sky ATP. Making an SRX (or any other enforcement
point) actually use them is a separate step – see [After the feeds are published](#after-the-feeds-are-published).

## Requirements

* Linux with `bash` 4+, `curl`, `jq`, `flock` (util-linux), `split`, `sort`, `awk`, `sed`,
  `tr`, `sha256sum` (all standard). The script checks for them on start.
* A Sky ATP / ATP Cloud **Open API token** for the realm that owns the feeds.
* Outbound HTTPS to `threat-api.sky.junipersecurity.net` and to your list server.
* Run as `root` (or any user that can write to the working folder and log file – see below).

## Install

```bash
sudo install -m 755 update-quarantine-blocklist.sh /usr/local/sbin/

# token (never commit this file)
mkdir -p ~/.config/skyatp && chmod 700 ~/.config/skyatp
cp examples/tokens.example ~/.config/skyatp/tokens
chmod 600 ~/.config/skyatp/tokens
$EDITOR ~/.config/skyatp/tokens          # paste the token
```

The token can also be exported as `SKYATP_API_TOKEN`. The token file is read as shell,
so it may also hold any of the settings below (for example `QUARANTINE_IPS_URL=...`).

## Try it – one safe step at a time

Nothing below touches your real feeds until step 5.

```bash
export QUARANTINE_IPS_URL=https://lists.example.net/quarantine-ips.txt
export QUARANTINE_URLS_URL=https://lists.example.net/quarantine-urls.txt

update-quarantine-blocklist.sh --check          # 1. show settings, call nothing
update-quarantine-blocklist.sh --fetch          # 2. download + clean, print counts, send nothing
update-quarantine-blocklist.sh --plan           # 3. ...and show which feeds would be pushed
update-quarantine-blocklist.sh --selftest       # 4. upload a throwaway 2-address feed (192.0.2.x)
update-quarantine-blocklist.sh --selftest-delete   #    ...and remove it again
update-quarantine-blocklist.sh --update         # 5. publish the real feeds
```

Either source may be left unset: with only `QUARANTINE_IPS_URL` set, no URL feeds are
touched, and vice versa. At least one is required.

When `--update` or `--delete` runs **without a terminal** (cron) everything is appended to
`/var/log/update-quarantine-blocklist.log`, which rotates itself at 5 MB, and a lock stops two
runs overlapping. From a terminal you see the output live.

## Run it from cron

See [`examples/crontab.example`](examples/crontab.example):

```cron
QUARANTINE_URLS_URL=https://lists.example.net/quarantine-urls.txt
QUARANTINE_IPS_URL=https://lists.example.net/quarantine-ips.txt

3-59/10 * * * * /usr/local/sbin/update-quarantine-blocklist.sh
```

The `3-59/10` offset is deliberate: if another system rewrites the source lists on the
hour or on :10/:20…, running a few minutes later avoids catching a half-written file. (The
script also copes with that – see [Safeguards](#safeguards).)

Cron will not e-mail you about failures because the script logs to a file. A simple health
check for your monitoring:

```bash
grep 'finished, exit code' /var/log/update-quarantine-blocklist.log | tail -n 1 | grep -q 'exit code 0'
```

A normal quiet run ends with
`Done: 2 feeds up to date (0 republished, 2 unchanged) in 3s.`
and a run that had to drop entries ends with a `WARNING: Sky ATP rejected N entry/entries …` line.

## Settings

All settings are environment variables (or lines in the token file). Defaults are in the
script header.

| Variable | Default | Meaning |
|---|---|---|
| `SKYATP_API_TOKEN` | – (required) | Open API bearer token |
| `QUARANTINE_IPS_URL` | – | where to download the IP list; empty = skip IPs |
| `QUARANTINE_URLS_URL` | – | where to download the URL list; empty = skip URLs |
| `SOURCE_INSECURE_TLS` | `0` | `1` = do not verify the list server's certificate (self-signed). Verified by default |
| `FEED_PREFIX` | `Quarantine_Blacklist` | feed names are `<prefix>IP1…`, `<prefix>URL1…`; letters, digits, `_` only |
| `CHUNK_SIZE` | `9000` | entries per feed (Sky ATP accepts at most 10,000 per push) |
| `URL_MAX_LEN` | `128` | longer URL entries are cut to this length |
| `STATE_DIR` | `/var/lib/update-quarantine-blocklist` | downloaded lists, chunks, lock file, per-feed checksums. Keep it root-owned and **not** in `/tmp` |
| `LOG_FILE` | `/var/log/update-quarantine-blocklist.log` | log used when there is no terminal; `""` disables |
| `FORCE` | `0` | `1` = republish every feed even if unchanged |
| `MAX_REJECTED` | `25` | per feed, how many entries Sky ATP may reject before the script gives up |
| `FETCH_ATTEMPTS` / `FETCH_RETRY_WAIT` | `3` / `15` | retries (and seconds between them) when a source list is empty or too short |
| `MIN_PERCENT` / `ALLOW_SHRINK` | `50` / `0` | refuse a list smaller than this % of the previous one; `ALLOW_SHRINK=1` accepts a genuine large drop once |
| `SKYATP_API` | `https://threat-api.sky.junipersecurity.net/v2/cloudfeeds/blacklist` | API base URL |
| `STATUS_INTERVAL` / `STATUS_MAX_WAIT` | `5` / `120` | polling of feed processing status (seconds) |

## Safeguards

These exist because each one bit us, or nearly did, while building it.

* **Fetch first, change later.** Both lists are downloaded and cleaned before anything in
  Sky ATP is touched, so a down source server changes nothing.
* **Empty or truncated source.** If the list server is rewriting its file while you download, you
  can get an empty or partial file. An empty result, or one below `MIN_PERCENT` of the previous
  list, is retried `FETCH_ATTEMPTS` times and then refused. The previous list and the published
  feeds stay as they were.
* **Unchanged feeds are left alone**, so there is no needless delete/re-upload churn every
  ten minutes.
* **Rejected entries do not take the feed down.** Sky ATP validates a feed after upload and
  reports only the *first* bad entry (`Validation error: <entry>`). The script removes that
  entry, uploads again, and repeats (up to `MAX_REJECTED`), then lists what it dropped. Without
  this, one odd line in the source would leave the feed deleted and empty.
* **One run at a time** (`flock`), a private (`umask 077`) working folder owned by the running
  user, and an exit line (`finished, exit code N`) in the log for every run.
* Token is never printed; TLS to the source server is verified unless you opt out.

## Cleaning the URL list

Real-world quarantine lists contain things Sky ATP will not take. Before upload the script:

* removes invisible characters (zero-width space/joiner, word joiner, BOM, soft hyphen …)
  and carriage returns;
* trims whitespace and drops blank and `#` comment lines;
* "refangs" defanged entries: `example[.]com`, `example(.)com`, `hxxp://` → normal form;
* strips a leading scheme (`http://`, `https://`, `ftp://`, and the typo `https//`);
* strips leading `*` / `*.` and trailing `/*` / `*`;
* drops a trailing ellipsis character (and whatever follows) where the source list was shortened;
* **skips** (and reports) entries that cannot be valid: embedded spaces, non-ASCII characters,
  or a host part with no dot or with illegal characters (this catches things like
  percent-encoded schemes and bare fragments);
* cuts entries longer than 128 characters (Sky ATP matches the start of a URL, so the
  shortened entry still matches the original);
* removes duplicates that cleaning created.

What was skipped or shortened is printed in the log on every run, so you can fix the source.

### A note on what is documented and what is observed

The rules above come from **testing against the live service, not from vendor documentation**,
and may change. What we observed:

* Juniper's documentation says wildcards and protocols are not valid entries in a URL feed
  and that Sky ATP adds wildcards at the start and end itself, so a host or path prefix matches.
* Entries over 128 characters were rejected.
* The host part must look like a hostname; fragments with no dot, percent-encoded schemes,
  a leading invisible character and `[.]` were rejected.
* After upload, Sky ATP reports only the **first** invalid entry per attempt, which is why the
  script loops.
* Feed names must match `^[a-zA-Z0-9_]{8,64}$`; one push may hold at most 10,000 entries.

If a future Sky ATP release is stricter or looser, `tools/find-rejected-entries.sh` (below)
will show you what it now refuses.

## After the feeds are published

Open API feeds appear on an SRX under the **`Blacklist`** security-intelligence category
(`show services security-intelligence category summary`), after the SRX next downloads feed
updates – in our testing within about 12 minutes with a 3600 s update interval. A feed that is
present there is **not enforced** until a security-intelligence profile and policy refer to the
`Blacklist` category. Wiring that up depends on your Junos version and design; follow Juniper's
documentation or your support contact. This repository deliberately does not cover it.

Old or test feeds with other names are not touched by this script – it only manages
`<prefix>IP*` and `<prefix>URL*`.

## Other tools

* `./update-quarantine-blocklist.sh --delete` – delete every `<prefix>IP*` and `<prefix>URL*`
  feed from Sky ATP.
* `tools/find-rejected-entries.sh` – one-off helper that uploads the cleaned URL list to a scratch
  feed (`Quarantine_ValidationTest`), collects *every* entry Sky ATP refuses, and deletes the
  scratch feed again. The real feeds are not touched.

## Tests

```bash
./tests/run-tests.sh
```

The suite runs the script against a fake source server and a fake Sky ATP API (`tests/bin/curl`),
so it needs no network, token or account. It covers cleaning, chunking, change detection,
rejected entries, empty/shrinking sources, TLS option, locking, logging, and delete.
The fake API reproduces the behaviour we observed; it cannot prove the real service still
behaves that way, so run `--selftest` against your own realm too.

## Troubleshooting

| You see | Likely cause |
|---|---|
| `SKYATP_API_TOKEN is not set` | no token file / variable for the user cron runs as |
| HTTP 401 / 403 from the API | token expired or for another realm – generate a new one |
| `Server returned HTTP … for … list` | the list server is down or the URL is wrong; nothing was changed |
| `no valid … entries - the source may be empty` after retries | source empty/rewriting, or the format is not what the cleaner expects; run `--fetch` and look at the working files in `STATE_DIR` |
| `Another run is still in progress` | the previous run (or a `--delete`) is still going; normal if a run is slow |
| `WARNING: Sky ATP rejected N entries` | the listed entries are invalid for Sky ATP; fix them at the source (the rest was published) |

## Contributing

Issues and pull requests are welcome. Please run `shellcheck` and `./tests/run-tests.sh`
before sending a change, and **never include real tokens, internal addresses or customer data**
in issues, logs or tests.
