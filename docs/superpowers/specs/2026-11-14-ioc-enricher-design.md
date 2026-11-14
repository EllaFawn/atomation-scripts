# Multi-Source IoC Enrichment Pipeline — Design

**Date:** 2026-11-14
**Script:** `python/ioc_enricher.py`
**Status:** Approved design, pending implementation plan

## Purpose

A SOC triage helper. It takes raw unstructured text (a phishing email body,
ticket description, or log dump), extracts Indicators of Compromise, enriches
them against threat intelligence sources, and produces a scored, explainable
report an analyst can paste straight into a ticket.

It works out of the box with a bundled sample and no API keys, handles
defanged input, rate limits, caching and API failures, and integrates with
automation via JSON output and exit codes.

## Constraints

- **Python standard library only** (`urllib`, `json`, `re`, `ipaddress`,
  `concurrent.futures`, `argparse`, `unittest`, ...). No `pip install` needed.
- Follows existing repo conventions: single script in `python/`, module
  docstring, `pathlib`, reports written to the current directory, README section.
- API keys from environment variables only, never in code.
- Coloured terminal output only when stdout is a TTY; plain text otherwise.

## Usage

```bash
python3 python/ioc_enricher.py suspicious_email.txt      # read a file
pbpaste | python3 python/ioc_enricher.py                 # read stdin
python3 python/ioc_enricher.py sample.txt --json         # also write JSON report
python3 python/ioc_enricher.py sample.txt --offline      # extract only, no API calls
```

| Option | Default | Meaning |
|---|---|---|
| `input` (positional) | stdin | File to analyse. Reads stdin if omitted. |
| `--json` | off | Also write `ioc_report_<timestamp>.json`. |
| `--no-md` | off | Do not write the Markdown report. |
| `--offline` | off | Extract and filter only; no network calls. |
| `--no-cache` | off | Ignore and do not write the cache. |
| `--vt-rate` | 4 | VirusTotal requests per minute (raise for premium keys). |

Environment variables: `VT_API_KEY`, `ABUSEIPDB_API_KEY`. A missing key prints
one warning and that source is skipped. Shodan InternetDB and CVEDB are keyless.

## Architecture

One file, organised into independent units with clear interfaces:

1. **Extraction** — `refang(text) -> str`, `extract_iocs(text) -> ExtractionResult`
2. **Sources** — one function per source, each `(ioc) -> SourceResult`
3. **Lookup orchestration** — rate limiting, threading, caching
4. **Scoring** — `score_ioc(source_results) -> (score, verdict, reason)`
5. **Reporting** — terminal, Markdown and JSON renderers from one results dict
6. **CLI** — `main()` wires the above together and sets the exit code

Data flow: `input text → refang → extract + filter → lookups (cached, rate
limited) → per-source scores → per-IoC score → overall score → reports`.

## 1. Extraction

1. **Refang** before extracting: `hxxp`/`hXXp` → `http`, `[.]` `(.)` `{.}` →
   `.`, `[:]` → `:`, `[@]` → `@`.
2. **Extract**, each type de-duplicated with first-seen order preserved:
   - IPv4 and IPv6 — candidates validated with `ipaddress`.
   - URLs — `http(s)://...`, trailing punctuation stripped.
   - Domains — standalone and the host part of extracted URLs.
   - Hashes — hex strings of length 32 (MD5), 40 (SHA-1), 64 (SHA-256) on word
     boundaries; lower-cased.
   - CVEs — `CVE-\d{4}-\d{4,}`, case-insensitive, normalised to upper case.
3. **Filter**, recording each skipped indicator with a reason:
   - IPs that are private, loopback, link-local, multicast, reserved,
     unspecified, or in documentation ranges → `skipped: non-routable`.
   - Domains whose final label is a common file extension (`pdf`, `exe`,
     `docx`, `xlsx`, `zip`, `js`, `png`, `jpg`, `txt`, `log`, ...) → dropped as
     filename false positives (not reported).
   - Domains in an editable `ALLOWLIST` constant (`google.com`,
     `microsoft.com`, ...; matches subdomains too) → `skipped: allowlisted`.
     URLs whose host is allowlisted are skipped too.

## 2. Sources

| IoC type | VirusTotal v3 | AbuseIPDB v2 | Shodan InternetDB | Shodan CVEDB |
|---|---|---|---|---|
| IP | `/ip_addresses/{ip}` | `/check?ipAddress=` | `internetdb.shodan.io/{ip}` | |
| Domain | `/domains/{d}` | | | |
| URL | `/urls/{base64url id}` | | | |
| Hash | `/files/{hash}` | | | |
| CVE | | | | `cvedb.shodan.io/cve/{id}` |

Each source returns a `SourceResult` dict:

```python
{"source": "virustotal", "status": "ok" | "not_found" | "error" | "skipped",
 "score": int | None, "reason": str, "data": {...key fields...}, "link": str}
```

## 3. Lookup orchestration

- **VirusTotal** requests run sequentially through a rate limiter that spaces
  calls by `60 / --vt-rate` seconds. Before starting, print the estimated
  wait (e.g. "14 VT lookups, ~3.5 min"). Cached results don't count.
- **Other sources** run concurrently in a `ThreadPoolExecutor` (max 8 workers).
- **Cache**: `~/.cache/ioc_enricher/cache.json`, keyed by
  `source:ioc_type:value`, 24 h TTL. Only `ok` and `not_found` results are
  cached. `--no-cache` disables reads and writes.
- **HTTP**: `urllib.request`, 15 s timeout, descriptive `User-Agent`
  (`ioc-enricher/1.0`).

### Error handling

| Condition | Behaviour |
|---|---|
| 404 | `not_found` — a meaningful result, shown in report, **not** treated as clean. |
| 401 / 403 | Disable that source for the rest of the run; warn once. |
| 429 | Back off (respect `Retry-After`, else 60 s for VT / 5 s others), retry once, then `error`. |
| Timeout / network / bad JSON | `error` with message; run continues. |

No single lookup failure aborts the run.

## 4. Scoring

Per-source score (0–100):

| Source | Rule |
|---|---|
| VirusTotal | 0 detections → 0. Otherwise `min(100, 20 + 8·malicious + 4·suspicious)`. |
| AbuseIPDB | `abuseConfidenceScore` as-is. |
| InternetDB | Tags `compromised` or `malware` → 80. Tag `tor` → 40. Otherwise `min(40, 10·len(vulns)) + min(30, 10·risky_ports)`, **capped at 50**. Risky ports: 21, 23, 445, 1433, 3306, 3389, 5900, 6379, 9200, 11211, 27017. Final score is the max of the applicable rules. |
| CVEDB | `round(cvss · 10)`; KEV → `max(score, 90)`; EPSS ≥ 0.5 → `+10`; capped at 100. |

- **Per-IoC score** = max of its sources' scores (sources with `status` other
  than `ok` contribute no score).
- **Verdict bands**: Clean 0–9 · Low 10–39 · Medium 40–69 · High 70–89 ·
  Critical 90–100 · **Unknown** if no source returned `ok`.
- **Clean requires a reputation source** (VirusTotal, AbuseIPDB or CVEDB). If
  only Shodan InternetDB returned data and the score is under 10, the verdict is
  Unknown with reason suffix `(no reputation data)`.
- **Overall score** = highest per-IoC score; overall verdict from the same
  bands (Unknown only if every IoC is Unknown, or no IoCs found).
- Every score carries a human-readable reason, e.g.
  `VT 14/94 engines · AbuseIPDB 87% (312 reports)`.

## 5. Reporting

All three outputs render from one results dict (which *is* the JSON output).

**Indicators are defanged in all outputs** (`hxxp://evil[.]com`,
`1.2.3[.]4`) so pasted reports don't create live links. The JSON report also
keeps the raw value in a separate `value` field for machine use.

Report contents:

1. **Header** — timestamp, input source (filename or `stdin`), SHA-256 of the
   input text, overall verdict and score.
2. **Summary table** — all enriched IoCs sorted by score descending: type,
   indicator, verdict, score, reason.
3. **Details per type** — key fields per source (e.g. AbuseIPDB ISP, country,
   usage type, total reports; InternetDB ports/vulns/tags; CVE CVSS/EPSS/KEV)
   plus links to the VT / AbuseIPDB / Shodan pages.
4. **Coverage** — counts found/enriched/skipped, skipped list with reasons,
   lookup errors, Unknown verdicts called out explicitly.

Terminal output shows the header, summary table and coverage counts, and
the report file paths. Markdown/JSON written to
`ioc_report_<YYYYmmdd_HHMMSS>.md` / `.json` in the current directory.

## 6. Exit codes

| Code | Meaning |
|---|---|
| 0 | Overall Clean, Low or Unknown (or `--offline`) |
| 1 | Overall Medium |
| 2 | Overall High or Critical |
| 3 | Runtime failure (unreadable input, etc.) |

## Repo changes

- `python/ioc_enricher.py` — the script.
- `python/tests/test_ioc_enricher.py` — `unittest` tests (no network).
- `python/sample_phishing_email.txt` — demo input containing defanged URLs and
  domains, the EICAR test file hashes (MD5 `44d88612fea8a8f36de82e1278abb02f`,
  SHA-256 `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`),
  a documentation IP and a private IP (to show skipping), well-known public IPs
  (`8.8.8.8`, `1.1.1.1`) for real lookups, a filename false positive
  (`invoice.pdf`), and a public KEV CVE (`CVE-2021-44228`).
- `.gitignore` — add `ioc_report_*.md` and `ioc_report_*.json`.
- `README.md` — new section: usage, API keys, scoring table, exit codes.

## Testing

All tests run offline with `python3 -m unittest discover python/tests`.

- **Refang/extraction**: each defang form; each IoC type; IPv6; hash lengths;
  CVE case normalisation; de-duplication order; URL trailing punctuation.
- **Filtering**: private/reserved/documentation IPs skipped; filename
  false positives dropped; allowlist incl. subdomains.
- **Scoring**: each source rule with boundary values; InternetDB cap; KEV floor;
  max aggregation; verdict band edges; Unknown when no `ok` source.
- **Sources**: parsing of canned API JSON responses into `SourceResult`;
  404/401/429 handling via a mocked HTTP layer (`unittest.mock`).
- **Cache**: TTL expiry; errors not cached.
- **Reporting**: defanging; exit code mapping; Markdown contains summary rows.

## Out of scope

- Full Shodan API (paid host lookups), additional TI sources, email header
  parsing, attachment handling, HTML report output.
