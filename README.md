# Automation Scripts

A small collection of Bash and Python scripts for everyday network and security tasks:
sweeping and pinging hosts, hashing data, and analysing SSH auth logs for failed and brute-force logins.

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
    └── sample_auth_small.log
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

Both Python scripts read `sample_auth_small.log` (an example SSH auth log) from the `python/` folder and can be run from any directory. Report files are written to the current directory.

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
