# Automation Scripts

A small collection of Bash and Python scripts for everyday network and security tasks:
sweeping and pinging hosts, hashing data, analysing SSH auth logs for failed and brute-force logins,
and enriching Indicators of Compromise with threat intelligence.

---

## Contents

```
.
├── bash/
│   ├── hash_input.sh
│   ├── ping_ip_list.sh
│   └── ping_sweep.sh
└── python/
    ├── brute_force_detector.py
    ├── failed_login_counter.py
    ├── ioc_enricher.py
    ├── sample_auth_small.log
    ├── sample_phishing_email.txt
    └── tests/
        └── test_ioc_enricher.py
```

## Bash

The Bash scripts define shell functions. Source a file to load its functions into your current shell:

```bash
source bash/ping_sweep.sh
```

To have them available in every session, add the `source` lines to your `~/.bashrc` or `~/.zshrc`.

### `ping_sweep.sh`

| Function | Description | Example |
|---|---|---|
| `ping_sweep <subnet_prefix>` | Pings `.1` to `.10` of a subnet in parallel and prints the hosts that respond. | `ping_sweep 10.0.0` |
| `check_host <host>` | Pings a single host once and reports whether it is up or down. | `check_host 10.0.0.1` |
| `rot13 <text>` | Encodes/decodes text with ROT13. | `rot13 "hello"` |

### `ping_ip_list.sh`

| Function | Description | Example |
|---|---|---|
| `ping_ip_list <filename>` | Extracts every IPv4 address from a file, pings each one in parallel, and writes the results to `alive_hosts.txt`. | `ping_ip_list ips.txt` |

### `hash_input.sh`

| Function | Description | Example |
|---|---|---|
| `hash_input <algo> <string_or_file> [...]` | Hashes each argument and prints one hash per line. Files are hashed by content, anything else is hashed as a string. Supports any algorithm in Python's `hashlib` (`md5`, `sha1`, `sha256`, `sha512`, `shake_128`, ...). | `hash_input sha256 notes.txt` |
| `<cmd> \| hash_input [algo]` | Hashes data piped in from another command. The algorithm defaults to `sha256`. | `echo -n "hello" \| hash_input md5` |

Requires `python3`.

## Python

The two log analysis scripts read `sample_auth_small.log` (an example SSH auth log) from the `python/` folder and can be run from any directory. Report files are written to the current directory.

```bash
python3 python/failed_login_counter.py
python3 python/brute_force_detector.py
```

To analyse a different log, change the `LOGFILE` value at the top of the script.

### `failed_login_counter.py`

Counts `Failed password` attempts per IP address.

- Prints the top 5 IPs by failed attempts, the number of lines read, the number of unique IPs, and the run time.
- Writes every IP and its count to `failed_counts.txt` (CSV format).

### `brute_force_detector.py`

Finds likely brute-force attacks: IPs with 5 or more failed logins within a 10-minute window. Overlapping windows are merged into one incident covering the whole attack, and separate attacks from the same IP are reported separately.

- Prints each incident with its attempt count, time window and duration.
- Writes `bruteforce_incidents.txt` (details of each incident).
- Writes `summary_report.txt` (all IPs ranked by total failed attempts).
- Saves a bar chart of the top attackers to `top_attackers.png` if `matplotlib` is installed (`pip install matplotlib`), otherwise skips it.

Syslog timestamps don't include a year, so the most recent year that gives a valid, non-future date is used.

Functions:

| Function | Description |
|---|---|
| `parse_auth_line(line)` | Returns `(timestamp, ip, event_type)` for a log line, where `event_type` is `failed`, `accepted` or `other`. |
| `parse_syslog_timestamp(ts_str)` | Parses a year-less syslog timestamp such as `Mar 10 13:58:01`. |
| `detect_brute_force(per_ip_timestamps, max_minutes=10, threshold=5)` | Sliding-window check that returns a list of incidents. |
| `save_incidents_to_file(incidents, filename)` | Writes the incident report. |
| `create_summary_report(per_ip_timestamps, filename)` | Writes the summary report. |
| `plot_attackers_chart(per_ip_timestamps, top_n=10)` | Plots the top `n` attacking IPs. |

### `ioc_enricher.py`

Pulls Indicators of Compromise out of raw text (a phishing email, ticket description or log dump), looks them up in threat intelligence sources, and writes a scored report you can paste into a ticket. Defanged input (`hxxp://evil[.]com`, `1.2.3[.]4`) is handled, and indicators in the reports are defanged so they can't be clicked by accident.

```bash
python3 python/ioc_enricher.py python/sample_phishing_email.txt    # read a file
pbpaste | python3 python/ioc_enricher.py                           # read stdin (paste a ticket)
python3 python/ioc_enricher.py suspicious.txt --json               # also write a JSON report
python3 python/ioc_enricher.py suspicious.txt --offline            # extract only, no API calls
```

| Option | Meaning |
|---|---|
| `--json` | Also write `ioc_report_<timestamp>.json`. |
| `--no-md` | Don't write the Markdown report. |
| `--offline` | Extract and filter only; no network calls. |
| `--no-cache` | Don't read or write the result cache (`~/.cache/ioc_enricher/cache.json`, 24 h). |
| `--vt-rate N` | VirusTotal requests per minute (default 4, the free-tier limit). |

**What it extracts:** IPv4/IPv6 addresses, domains, URLs, MD5/SHA-1/SHA-256 hashes and CVE IDs. Private, reserved and documentation IPs, internal names (`.local`, `.corp`, ...) and a small allowlist of well-known domains are listed as skipped rather than looked up. Filenames like `invoice.pdf` are ignored.

**Sources and API keys:** keys are read from environment variables. A source without a key is skipped with a warning; the Shodan sources need no key, so the script is useful even with none set.

| Source | Checks | Key |
|---|---|---|
| [VirusTotal](https://www.virustotal.com/) | IPs, domains, URLs, hashes | `VT_API_KEY` (free account) |
| [AbuseIPDB](https://www.abuseipdb.com/) | IPs | `ABUSEIPDB_API_KEY` (free account) |
| [Shodan InternetDB](https://internetdb.shodan.io/) | IPs: open ports, CVEs, tags | none |
| [Shodan CVEDB](https://cvedb.shodan.io/) | CVEs: CVSS, EPSS, CISA KEV | none |

```bash
export VT_API_KEY=...
export ABUSEIPDB_API_KEY=...
```

**Scoring:** each source gives a 0-100 score, an indicator's score is the highest of its sources, and the overall score is the highest indicator score. Every score comes with its reason (e.g. `VT 14/94 engines · AbuseIPDB 87% (312 reports)`).

| Source | Rule |
|---|---|
| VirusTotal | 0 detections → 0, otherwise `20 + 8 × malicious + 4 × suspicious`, max 100 |
| AbuseIPDB | Abuse confidence score as-is |
| Shodan InternetDB | +10 per CVE (max 40), +10 per risky open port such as Telnet/SMB/RDP/Redis (max 30), capped at 50 (exposure is not maliciousness). Tagged `compromised`/`malware` → 80, `tor` → 40 |
| Shodan CVEDB | CVSS × 10; on CISA KEV → at least 90; EPSS ≥ 0.5 → +10 |

Verdicts: **Clean** 0-9 · **Low** 10-39 · **Medium** 40-69 · **High** 70-89 · **Critical** 90-100 · **Unknown** when no source returned data (never treated as Clean). Shodan InternetDB only measures exposure, so it can raise an IP's score but can't mark it Clean on its own: an IP needs VirusTotal or AbuseIPDB data to be Clean.

**Exit codes** (for use in scripts or SOAR playbooks):

| Code | Meaning |
|---|---|
| 0 | Clean, Low or Unknown (always 0 with `--offline`) |
| 1 | Medium |
| 2 | High or Critical |
| 3 | Could not run (e.g. unreadable input file) |

**Tests** (offline, standard library only):

```bash
python3 -m unittest discover -s python/tests -v
```
