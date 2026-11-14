# IoC Enrichment Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `python/ioc_enricher.py`, a stdlib-only CLI that extracts IoCs from raw text, enriches them via VirusTotal, AbuseIPDB, Shodan InternetDB and Shodan CVEDB, and writes a scored terminal/Markdown/JSON report.

**Architecture:** One script organised into independent sections (extraction → HTTP/cache → sources → orchestration → scoring → reporting → CLI). Every network call goes through one injectable `http` callable so all tests run offline with canned responses.

**Tech Stack:** Python 3 standard library only (`re`, `ipaddress`, `urllib.request`, `json`, `concurrent.futures`, `argparse`, `hashlib`, `unittest`, `unittest.mock`).

**Spec:** `docs/superpowers/specs/2026-11-14-ioc-enricher-design.md`

## Global Constraints

- Standard library only. No `requirements.txt`, no third-party imports.
- API keys only from env vars `VT_API_KEY`, `ABUSEIPDB_API_KEY`.
- HTTP: 15 s timeout, `User-Agent: ioc-enricher/1.0`.
- Cache: `~/.cache/ioc_enricher/cache.json`, 24 h TTL, only `ok`/`not_found` cached.
- Verdict bands: Clean 0–9 · Low 10–39 · Medium 40–69 · High 70–89 · Critical 90–100 · Unknown = no `ok` source.
- Exit codes: 0 Clean/Low/Unknown/offline · 1 Medium · 2 High/Critical · 3 runtime failure.
- Indicators defanged in every human-readable output.
- Repo style: module docstring, `pathlib`, reports written to the current directory.
- Work on branch `feature/ioc-enricher`. Commit locally. **Never `git push`** — the user pushes.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Test command (from repo root): `python3 -m unittest discover -s python/tests -v`

## Review Focus

1. **Empty input / no IoCs found** — report still written, overall verdict `Unknown`, exit 0, no crash. (Task 7)
2. **Non-UTF-8 bytes in input file** (raw log dumps) — decoded with `errors="replace"`, extraction still works. (Task 7)
3. **Corrupt or unreadable cache file** — treated as empty cache with no traceback; overwritten on save. (Task 3)
4. **Hex substrings** — a SHA-256 must not also yield an MD5/SHA-1 from inside it, and hex inside a longer hex run (>64) yields nothing. (Task 1)
5. **URLs wrapped in punctuation** — `(see hxxp://evil[.]com/a).` extracts `http://evil.com/a` without `)` or `.`. (Task 1)

---

## File Structure

| File | Responsibility |
|---|---|
| `python/ioc_enricher.py` | The script (all sections). |
| `python/tests/test_ioc_enricher.py` | All unit tests. Starts with `sys.path.insert(0, str(Path(__file__).resolve().parents[1]))` then `import ioc_enricher as ie`. Test imports: `hashlib, io, json, os, sys, tempfile, unittest, urllib.error`, `from unittest import mock`, `from pathlib import Path`. |
| `python/sample_phishing_email.txt` | Demo input. |
| `.gitignore`, `README.md` | Updated in Task 7. |

### Shared data shapes (used across tasks)

```python
IoC          = {"type": "ip"|"domain"|"url"|"hash"|"cve", "value": str}
Skipped      = {"type": str, "value": str, "reason": str}       # reason: "non-routable" | "allowlisted"
SourceResult = {"source": "virustotal"|"abuseipdb"|"internetdb"|"cvedb",
                "status": "ok"|"not_found"|"error"|"skipped",
                "score": int | None, "reason": str, "data": dict, "link": str}
IoCResult    = IoC | {"score": int|None, "verdict": str, "reason": str, "sources": [SourceResult]}
```

---

### Task 1: Refang and IoC extraction

**Files:**
- Create: `python/ioc_enricher.py` (module docstring, imports, constants `ALLOWLIST`, `FILE_EXTENSIONS`, extraction functions)
- Create: `python/tests/test_ioc_enricher.py`

**Interfaces:**
- Produces: `refang(text: str) -> str`; `extract_iocs(text: str) -> dict` returning `{"iocs": [IoC], "skipped": [Skipped]}`; `is_allowlisted(domain: str) -> bool`.

- [ ] **Step 1: Write failing tests** (`class TestExtraction(unittest.TestCase)`)

```python
def test_refang_forms(self):
    self.assertEqual(ie.refang("hxxps://evil[.]com hXXp://a(.)b{.}c x[@]y.com 1.2.3[:]80"),
                     "https://evil.com http://a.b.c x@y.com 1.2.3:80")

def _vals(self, text, t):
    return [i["value"] for i in ie.extract_iocs(text)["iocs"] if i["type"] == t]

def test_ipv4_and_ipv6(self):
    self.assertEqual(self._vals("hit 8.8.8.8 and 2606:4700:4700::1111", "ip"),
                     ["8.8.8.8", "2606:4700:4700::1111"])

def test_invalid_ipv4_ignored(self):
    self.assertEqual(self._vals("ver 10.0.19041.1 and 999.1.1.1", "ip"), [])

def test_non_routable_ips_skipped(self):
    r = ie.extract_iocs("10.0.0.5 127.0.0.1 192.0.2.10 169.254.1.1 8.8.8.8")
    self.assertEqual([i["value"] for i in r["iocs"]], ["8.8.8.8"])
    self.assertEqual({s["value"] for s in r["skipped"]}, {"10.0.0.5", "127.0.0.1", "192.0.2.10", "169.254.1.1"})
    self.assertTrue(all(s["reason"] == "non-routable" for s in r["skipped"]))

def test_url_and_its_domain(self):
    self.assertEqual(self._vals("(see hxxp://evil[.]com/a).", "url"), ["http://evil.com/a"])
    self.assertEqual(self._vals("(see hxxp://evil[.]com/a).", "domain"), ["evil.com"])

def test_filename_not_domain(self):
    self.assertEqual(self._vals("open invoice.pdf and setup.exe on bad-site.net", "domain"), ["bad-site.net"])

def test_allowlist_includes_subdomains_and_urls(self):
    r = ie.extract_iocs("https://login.microsoft.com/x google.com")
    self.assertEqual(r["iocs"], [])
    self.assertEqual({s["reason"] for s in r["skipped"]}, {"allowlisted"})

def test_hash_lengths_lowercased(self):
    md5, sha1, sha256 = "A"*32, "b"*40, "c"*64
    self.assertEqual(self._vals(f"{md5} {sha1} {sha256}", "hash"), ["a"*32, "b"*40, "c"*64])

def test_no_hash_substrings(self):
    self.assertEqual(self._vals("d"*64, "hash"), ["d"*64])
    self.assertEqual(self._vals("e"*70, "hash"), [])

def test_cve_normalised(self):
    self.assertEqual(self._vals("cve-2021-44228 and CVE-2023-123456", "cve"), ["CVE-2021-44228", "CVE-2023-123456"])

def test_dedup_preserves_order(self):
    self.assertEqual(self._vals("1.1.1.1 8.8.8.8 1.1.1.1", "ip"), ["1.1.1.1", "8.8.8.8"])

def test_domain_from_email(self):
    self.assertIn("evil-mail.org", self._vals("from: bob[@]evil-mail[.]org", "domain"))
```

- [ ] **Step 2: Run tests, verify they fail**

Run: `python3 -m unittest discover -s python/tests -v`
Expected: FAIL / ImportError (`ioc_enricher` or attributes missing).

- [ ] **Step 3: Implement extraction in `python/ioc_enricher.py`**

- `refang`: ordered regex replacements, case-insensitive `hxxp`.
- Hashes: `(?<![0-9a-fA-F])[0-9a-fA-F]{N}(?![0-9a-fA-F])` for N in 64, 40, 32 — the hex-boundary lookarounds give Review Focus #4.
- URLs: `https?://[^\s<>"'\]]+`, then `rstrip(".,;:!?)'\"")`; the host (via `urllib.parse.urlsplit`) is added as a domain or IP.
- Domains: labels `[a-z0-9-]+` joined by dots, TLD `[a-z]{2,}`, lower-cased; drop if the TLD is in `FILE_EXTENSIONS = {"pdf","exe","docx","doc","xlsx","xls","zip","rar","js","png","jpg","jpeg","gif","txt","log","csv","html","htm","dll","bat","ps1","sh","py","msi","iso","img","php","asp","aspx","jsp"}` (so `reset.php` in a URL path is not a domain).
- `ALLOWLIST = {"google.com","microsoft.com","office.com","live.com","outlook.com","apple.com","amazon.com","github.com","cloudflare.com","linkedin.com"}`; `is_allowlisted` matches the exact name or a `.`-suffix.
- IPv4 candidates: `\b(?:\d{1,3}\.){3}\d{1,3}\b`; IPv6 candidates: runs of `[0-9A-Fa-f:]` containing at least two `:`; every candidate is validated with `ipaddress.ip_address` and invalid ones are dropped (so `13:58:01` timestamps are ignored).
- IPs: an IP is non-routable when `not ipaddress.ip_address(v).is_global` (this covers the documentation ranges).
- Output order inside `iocs`: grouped by type in order ip, domain, url, hash, cve; first-seen order within each type.

- [ ] **Step 4: Run tests, verify they pass**

Run: `python3 -m unittest discover -s python/tests -v` — Expected: all OK.

- [ ] **Step 5: Commit** — `git add python/ioc_enricher.py python/tests/ && git commit -m "Add IoC extraction and refanging for ioc_enricher"`

---

### Task 2: Scoring

**Files:** Modify `python/ioc_enricher.py`; Test `python/tests/test_ioc_enricher.py`

**Interfaces:**
- Produces: `vt_score(malicious: int, suspicious: int) -> int`; `internetdb_score(ports: list[int], vulns: list[str], tags: list[str]) -> int`; `cve_score(cvss: float|None, kev: bool, epss: float|None) -> int`; `verdict_for(score: int|None) -> str`; `score_ioc(sources: list[SourceResult]) -> tuple[int|None, str, str]` (score, verdict, reason); `overall_verdict(iocs: list[IoCResult]) -> tuple[int|None, str]`; constant `RISKY_PORTS`.

- [ ] **Step 1: Write failing tests** (`class TestScoring`)

```python
def test_vt_score(self):
    self.assertEqual(ie.vt_score(0, 0), 0)
    self.assertEqual(ie.vt_score(1, 0), 28)
    self.assertEqual(ie.vt_score(5, 0), 60)
    self.assertEqual(ie.vt_score(0, 2), 28)
    self.assertEqual(ie.vt_score(10, 0), 100)
    self.assertEqual(ie.vt_score(30, 5), 100)

def test_internetdb_score(self):
    self.assertEqual(ie.internetdb_score([443], [], []), 0)
    self.assertEqual(ie.internetdb_score([23, 3389], ["CVE-1"], []), 30)
    self.assertEqual(ie.internetdb_score([21, 23, 445, 3389], ["a", "b", "c", "d", "e"], []), 50)  # cap
    self.assertEqual(ie.internetdb_score([], [], ["tor"]), 40)
    self.assertEqual(ie.internetdb_score([], [], ["compromised"]), 80)
    self.assertEqual(ie.internetdb_score([23], [], ["malware", "tor"]), 80)

def test_cve_score(self):
    self.assertEqual(ie.cve_score(5.0, False, None), 50)
    self.assertEqual(ie.cve_score(5.0, True, None), 90)
    self.assertEqual(ie.cve_score(9.8, False, 0.6), 100)
    self.assertEqual(ie.cve_score(7.5, False, 0.5), 85)
    self.assertEqual(ie.cve_score(None, False, None), 0)

def test_verdict_bands(self):
    for s, v in [(None, "Unknown"), (0, "Clean"), (9, "Clean"), (10, "Low"), (39, "Low"),
                 (40, "Medium"), (69, "Medium"), (70, "High"), (89, "High"), (90, "Critical"), (100, "Critical")]:
        self.assertEqual(ie.verdict_for(s), v)

def _src(self, name, status, score, reason="r"):
    return {"source": name, "status": status, "score": score, "reason": reason, "data": {}, "link": ""}

def test_score_ioc_max_and_reason(self):
    score, verdict, reason = ie.score_ioc([self._src("virustotal", "ok", 28, "VT 1/90 engines"),
                                           self._src("abuseipdb", "ok", 87, "AbuseIPDB 87%")])
    self.assertEqual((score, verdict), (87, "High"))
    self.assertEqual(reason, "VT 1/90 engines · AbuseIPDB 87%")

def test_score_ioc_unknown_without_ok(self):
    self.assertEqual(ie.score_ioc([self._src("virustotal", "not_found", None),
                                   self._src("abuseipdb", "error", None)])[:2], (None, "Unknown"))

def test_overall(self):
    self.assertEqual(ie.overall_verdict([{"score": None}, {"score": 45}, {"score": 12}]), (45, "Medium"))
    self.assertEqual(ie.overall_verdict([{"score": None}]), (None, "Unknown"))
    self.assertEqual(ie.overall_verdict([]), (None, "Unknown"))
```

- [ ] **Step 2: Run, verify fail.** Same command; expected AttributeError failures in `TestScoring`.
- [ ] **Step 3: Implement** using the spec's §4 formulas exactly. `RISKY_PORTS = {21, 23, 445, 1433, 3306, 3389, 5900, 6379, 9200, 11211, 27017}`. `score_ioc` joins the `reason` of every `ok` source with `" · "`; when nothing is `ok`, reason is `"No source returned data"`.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `"Add risk scoring for ioc_enricher"`

---

### Task 3: HTTP layer and cache

**Files:** Modify `python/ioc_enricher.py`; Test `python/tests/test_ioc_enricher.py`

**Interfaces:**
- Produces:
  - `fetch_json(url: str, headers: dict|None = None, timeout: int = 15) -> tuple[int, dict|None, dict]` — returns (HTTP status, parsed JSON or None, response headers). Network errors, timeouts and invalid JSON raise `FetchError(Exception)`. HTTP error codes are **returned**, not raised (catch `urllib.error.HTTPError` and return its `.code`).
  - `class Cache(path: Path, ttl: int = 86400, enabled: bool = True, now=time.time)` with `.get(key: str) -> SourceResult|None`, `.set(key: str, result: SourceResult) -> None` (ignores any status other than `ok`/`not_found`), `.save() -> None` (creates parent dirs).
  - `cache_key(source: str, ioc: IoC) -> str` → `f"{source}:{ioc['type']}:{ioc['value']}"`.
  - `DEFAULT_CACHE_PATH = Path.home() / ".cache" / "ioc_enricher" / "cache.json"`.

- [ ] **Step 1: Write failing tests** (`class TestHttpAndCache`, using `tempfile.TemporaryDirectory`)

```python
def test_cache_roundtrip_and_ttl(self):
    t = [1000.0]
    c = ie.Cache(self.path, ttl=10, now=lambda: t[0])
    c.set("k", {"status": "ok", "score": 5}); c.save()
    c2 = ie.Cache(self.path, ttl=10, now=lambda: t[0])
    self.assertEqual(c2.get("k")["score"], 5)
    t[0] = 1011.0
    self.assertIsNone(c2.get("k"))

def test_errors_not_cached(self):
    c = ie.Cache(self.path)
    c.set("k", {"status": "error"})
    self.assertIsNone(c.get("k"))

def test_disabled_cache(self):
    c = ie.Cache(self.path, enabled=False)
    c.set("k", {"status": "ok"}); c.save()
    self.assertIsNone(c.get("k")); self.assertFalse(self.path.exists())

def test_corrupt_cache_file(self):          # Review Focus #3
    self.path.write_text("{not json")
    c = ie.Cache(self.path)
    self.assertIsNone(c.get("k"))
    c.set("k", {"status": "ok"}); c.save()
    self.assertEqual(json.loads(self.path.read_text())["k"]["result"]["status"], "ok")

def test_fetch_json_returns_http_error_code(self):
    err = urllib.error.HTTPError("u", 404, "nf", {}, io.BytesIO(b"{}"))
    with mock.patch("urllib.request.urlopen", side_effect=err):
        self.assertEqual(ie.fetch_json("http://x")[0], 404)

def test_fetch_json_network_error_raises(self):
    with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
        with self.assertRaises(ie.FetchError):
            ie.fetch_json("http://x")
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement.** The cache file format is `{key: {"ts": float, "result": SourceResult}}`. Any `OSError`/`json.JSONDecodeError` on load gives an empty dict.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `"Add HTTP helper and result cache for ioc_enricher"`

---

### Task 4: Source lookups

**Files:** Modify `python/ioc_enricher.py`; Test `python/tests/test_ioc_enricher.py`

**Interfaces:**
- Consumes: `fetch_json`, `FetchError` (Task 3); `vt_score`, `internetdb_score`, `cve_score` (Task 2).
- Produces:
  - `class AuthError(Exception)` — raised on 401/403 so the orchestrator can disable that source.
  - `lookup_virustotal(ioc: IoC, api_key: str, http=fetch_json, sleep=time.sleep) -> SourceResult`
  - `lookup_abuseipdb(ioc: IoC, api_key: str, http=fetch_json, sleep=time.sleep) -> SourceResult`
  - `lookup_internetdb(ioc: IoC, http=fetch_json, sleep=time.sleep) -> SourceResult`
  - `lookup_cvedb(ioc: IoC, http=fetch_json, sleep=time.sleep) -> SourceResult`
  - `SOURCES_FOR_TYPE = {"ip": ["virustotal","abuseipdb","internetdb"], "domain": ["virustotal"], "url": ["virustotal"], "hash": ["virustotal"], "cve": ["cvedb"]}`

Endpoints and fields:

| Source | URL / headers | Fields kept in `data` | `reason` format | `link` |
|---|---|---|---|---|
| VT | `https://www.virustotal.com/api/v3/{ip_addresses\|domains\|urls\|files}/{id}`, header `x-apikey`. URL id = `base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")` | `malicious`, `suspicious`, `harmless`, `undetected` from `data.attributes.last_analysis_stats`; `total` = sum of the four | `VT {malicious}/{total} engines` | `https://www.virustotal.com/gui/{ip-address\|domain\|url\|file}/{id}` |
| AbuseIPDB | `https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90`, headers `Key`, `Accept: application/json` | `abuseConfidenceScore`, `totalReports`, `countryCode`, `isp`, `usageType` from `data` | `AbuseIPDB {score}% ({totalReports} reports)` | `https://www.abuseipdb.com/check/{ip}` |
| InternetDB | `https://internetdb.shodan.io/{ip}` | `ports`, `vulns`, `tags`, `hostnames` | `Shodan: {n} ports, {m} CVEs` + `, tags: a,b` if any | `https://www.shodan.io/host/{ip}` |
| CVEDB | `https://cvedb.shodan.io/cve/{id}` | `cvss` (prefer `cvss_v3`, else `cvss`), `epss`, `kev`, `summary` (first 200 chars) | `CVSS {cvss}` + `, KEV` if kev + `, EPSS {epss:.2f}` if present | `https://nvd.nist.gov/vuln/detail/{id}` |

Status handling (shared helper `_request(source, url, headers, http, sleep) -> tuple[str, dict|None, str]` returning (status, json, error_msg)):
200 → `ok`; 404 → `not_found` (score None, reason `"{Source}: not found"`); 401/403 → raise `AuthError(source)`; 429 → sleep `int(Retry-After)` if present, else 60 s for VT / 5 s for others, retry once, then `error` with reason `"rate limited"`; `FetchError` or other codes → `error` with the message. Note: InternetDB returns 404 for IPs it has no data on, which is normal.

- [ ] **Step 1: Write failing tests** (`class TestSources`). Build a fake: `def fake(*responses): it = iter(responses); return lambda url, headers=None, timeout=15: next(it)`.

```python
def test_vt_ok(self):
    body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 0, "harmless": 60, "undetected": 25}}}}
    r = ie.lookup_virustotal({"type": "hash", "value": "a"*32}, "k", http=fake((200, body, {})))
    self.assertEqual((r["status"], r["score"], r["reason"]), ("ok", 60, "VT 5/90 engines"))
    self.assertEqual(r["link"], "https://www.virustotal.com/gui/file/" + "a"*32)

def test_vt_url_id_is_base64url(self):
    seen = []
    def http(url, headers=None, timeout=15):
        seen.append(url); return (404, None, {})
    ie.lookup_virustotal({"type": "url", "value": "http://evil.com/a"}, "k", http=http)
    self.assertTrue(seen[0].endswith("/urls/aHR0cDovL2V2aWwuY29tL2E"))

def test_not_found(self):
    r = ie.lookup_virustotal({"type": "domain", "value": "x.com"}, "k", http=fake((404, None, {})))
    self.assertEqual((r["status"], r["score"]), ("not_found", None))

def test_auth_error_raises(self):
    with self.assertRaises(ie.AuthError):
        ie.lookup_abuseipdb({"type": "ip", "value": "8.8.8.8"}, "bad", http=fake((401, None, {})))

def test_429_retries_once_with_retry_after(self):
    sleeps = []
    body = {"data": {"abuseConfidenceScore": 87, "totalReports": 312, "countryCode": "NL", "isp": "X", "usageType": "Data Center"}}
    r = ie.lookup_abuseipdb({"type": "ip", "value": "8.8.8.8"}, "k",
                            http=fake((429, None, {"Retry-After": "2"}), (200, body, {})), sleep=sleeps.append)
    self.assertEqual(sleeps, [2]); self.assertEqual((r["score"], r["reason"]), (87, "AbuseIPDB 87% (312 reports)"))

def test_429_twice_is_error(self):
    r = ie.lookup_internetdb({"type": "ip", "value": "8.8.8.8"}, http=fake((429, None, {}), (429, None, {})), sleep=lambda s: None)
    self.assertEqual(r["status"], "error")

def test_network_error(self):
    def boom(*a, **k): raise ie.FetchError("timed out")
    r = ie.lookup_cvedb({"type": "cve", "value": "CVE-2021-44228"}, http=boom)
    self.assertEqual(r["status"], "error"); self.assertIn("timed out", r["reason"])

def test_internetdb_ok(self):
    body = {"ports": [23, 443], "vulns": ["CVE-2020-1"], "tags": [], "hostnames": []}
    r = ie.lookup_internetdb({"type": "ip", "value": "8.8.8.8"}, http=fake((200, body, {})))
    self.assertEqual((r["score"], r["reason"]), (20, "Shodan: 2 ports, 1 CVEs"))

def test_cvedb_kev(self):
    body = {"cvss_v3": 10.0, "epss": 0.97, "kev": True, "summary": "Log4Shell"}
    r = ie.lookup_cvedb({"type": "cve", "value": "CVE-2021-44228"}, http=fake((200, body, {})))
    self.assertEqual((r["score"], r["reason"]), (100, "CVSS 10.0, KEV, EPSS 0.97"))
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the four lookups and `_request` as specified above.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `"Add VirusTotal, AbuseIPDB and Shodan lookups for ioc_enricher"`

---

### Task 5: Orchestration (rate limiting, threading, cache, disabled sources)

**Files:** Modify `python/ioc_enricher.py`; Test `python/tests/test_ioc_enricher.py`

**Interfaces:**
- Consumes: lookups, `AuthError`, `SOURCES_FOR_TYPE` (Task 4); `Cache`, `cache_key` (Task 3); `score_ioc` (Task 2).
- Produces:
  - `class RateLimiter(per_minute: float, clock=time.monotonic, sleep=time.sleep)` with `.wait() -> None` — the first call returns immediately; later calls sleep until `60/per_minute` s after the previous call.
  - `enrich(iocs: list[IoC], keys: dict, cache: Cache, vt_rate: float = 4, lookups: dict|None = None, sleep=time.sleep, clock=time.monotonic, log=print) -> list[IoCResult]` — `keys = {"virustotal": str|None, "abuseipdb": str|None}`; `lookups` maps source name → callable `(ioc) -> SourceResult` (the passed dict is merged over defaults that wrap the real lookups with keys bound). Results keep the input order, and each IoC's `sources` follow `SOURCES_FOR_TYPE` order.

Behaviour:
- A source with a missing key → `skipped` result, reason `"No API key"`. One warning per source goes to `log`.
- Cache hits skip the network and do not consume VT rate.
- Before VT lookups, log `f"{n} VirusTotal lookups, ~{minutes:.1f} min at {vt_rate}/min"` when n > 0 (n excludes cache hits; minutes = `(n-1) * 60 / vt_rate / 60`).
- Non-VT lookups run in `ThreadPoolExecutor(max_workers=8)`; VT lookups run sequentially, each preceded by `RateLimiter.wait()`.
- `AuthError` → that source goes into a disabled set; this and all later lookups for it become `skipped` with reason `"Invalid API key"`; one warning is logged.

- [ ] **Step 1: Write failing tests** (`class TestEnrich`)

```python
def test_rate_limiter_spacing(self):
    t, slept = [0.0], []
    rl = ie.RateLimiter(4, clock=lambda: t[0], sleep=lambda s: (slept.append(s), t.__setitem__(0, t[0] + s)))
    rl.wait(); rl.wait(); rl.wait()
    self.assertEqual(slept, [15.0, 15.0])

def _ok(self, name, score):
    return lambda ioc: {"source": name, "status": "ok", "score": score, "reason": name, "data": {}, "link": ""}

def test_enrich_scores_and_order(self):
    lookups = {"virustotal": self._ok("virustotal", 60), "abuseipdb": self._ok("abuseipdb", 10),
               "internetdb": self._ok("internetdb", 0), "cvedb": self._ok("cvedb", 90)}
    res = ie.enrich([{"type": "ip", "value": "8.8.8.8"}, {"type": "cve", "value": "CVE-2021-44228"}],
                    {"virustotal": "k", "abuseipdb": "k"}, ie.Cache(self.path, enabled=False),
                    lookups=lookups, sleep=lambda s: None, log=lambda *a: None)
    self.assertEqual([r["value"] for r in res], ["8.8.8.8", "CVE-2021-44228"])
    self.assertEqual([s["source"] for s in res[0]["sources"]], ["virustotal", "abuseipdb", "internetdb"])
    self.assertEqual((res[0]["score"], res[0]["verdict"]), (60, "Medium"))
    self.assertEqual(res[1]["verdict"], "Critical")

def test_missing_key_skipped(self):
    res = ie.enrich([{"type": "hash", "value": "a"*32}], {"virustotal": None, "abuseipdb": None},
                    ie.Cache(self.path, enabled=False), lookups={}, log=lambda *a: None)
    self.assertEqual(res[0]["sources"][0]["status"], "skipped"); self.assertEqual(res[0]["verdict"], "Unknown")

def test_auth_error_disables_source(self):
    calls = []
    def bad(ioc): calls.append(ioc); raise ie.AuthError("virustotal")
    iocs = [{"type": "hash", "value": c*32} for c in "ab"]
    res = ie.enrich(iocs, {"virustotal": "bad", "abuseipdb": None}, ie.Cache(self.path, enabled=False),
                    lookups={"virustotal": bad}, sleep=lambda s: None, log=lambda *a: None)
    self.assertEqual(len(calls), 1)
    self.assertEqual([r["sources"][0]["reason"] for r in res], ["Invalid API key"] * 2)

def test_cache_hit_skips_lookup(self):
    cache = ie.Cache(self.path)
    cache.set("cvedb:cve:CVE-1-1", {"source": "cvedb", "status": "ok", "score": 50, "reason": "c", "data": {}, "link": ""})
    res = ie.enrich([{"type": "cve", "value": "CVE-1-1"}], {}, cache,
                    lookups={"cvedb": lambda i: self.fail("should use cache")}, log=lambda *a: None)
    self.assertEqual(res[0]["score"], 50)
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `RateLimiter` and `enrich` per the behaviour list. Cache writes (`cache.set`) happen for every fresh result; the caller calls `cache.save()`.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `"Add rate-limited, cached enrichment orchestration"`

---

### Task 6: Reporting

**Files:** Modify `python/ioc_enricher.py`; Test `python/tests/test_ioc_enricher.py`

**Interfaces:**
- Consumes: `overall_verdict` (Task 2); `IoCResult`, `Skipped` shapes.
- Produces:
  - `defang(value: str) -> str` — `http`→`hxxp` (scheme only) and the **last** `.` → `[.]` in the host/IP part (e.g. `hxxp://evil[.]com/a.php`, `1.2.3[.]4`, `sub.evil[.]com`); `:` → `[:]` for IPv6; hashes and CVEs unchanged.
  - `build_results(source_name: str, text: str, iocs: list[IoCResult], skipped: list[Skipped], offline: bool) -> dict` — the spec §5 results dict: `{"generated": ISO-8601 str, "input": {"source", "sha256"}, "offline": bool, "overall": {"score", "verdict"}, "counts": {"found", "enriched", "skipped"}, "iocs": [... + "defanged"], "skipped": [... + "defanged"], "errors": [{"ioc": defanged, "source", "reason"}]}`. `iocs` are sorted by score descending (None last). `found = enriched + skipped`.
  - `render_markdown(results: dict) -> str`, `render_terminal(results: dict, color: bool) -> str`.
  - `exit_code(verdict: str) -> int` — mapping from the Global Constraints.
  - `write_reports(results: dict, outdir: Path, md: bool, js: bool) -> list[Path]` — filenames `ioc_report_<YYYYmmdd_HHMMSS>.md/.json`.

Markdown layout (exact headings): `# IoC Enrichment Report`, the header bullets (Generated, Input, Input SHA-256, **Overall: {verdict} ({score}/100)**), `## Summary` table `| Type | Indicator | Verdict | Score | Reason |`, `## Details` with `### {defanged}` per IoC listing each source's status, key `data` fields and link, `## Coverage` with counts, the skipped list with reasons, errors, and an Unknown call-out line: `> **{n} indicator(s) returned no data — verdict Unknown, not Clean.**` when n > 0. Score shows `–` when None. Source `link`s are rendered as-is (they point at TI sites, not at the indicator). In offline mode the summary lists the extracted IoCs with verdict `Not checked`.

Terminal: overall line (coloured by verdict when `color=True`: Critical/High red, Medium yellow, Low/Clean green, Unknown grey, via ANSI codes), the summary table as aligned text columns, the counts line. No ANSI codes when `color=False`.

- [ ] **Step 1: Write failing tests** (`class TestReporting`)

```python
def test_defang(self):
    self.assertEqual(ie.defang("http://evil.com/a.php"), "hxxp://evil[.]com/a.php")
    self.assertEqual(ie.defang("https://sub.evil.com"), "hxxps://sub.evil[.]com")
    self.assertEqual(ie.defang("1.2.3.4"), "1.2.3[.]4")
    self.assertEqual(ie.defang("evil.com"), "evil[.]com")
    self.assertEqual(ie.defang("2606:4700::1"), "2606[:]4700[:][:]1")
    self.assertEqual(ie.defang("CVE-2021-44228"), "CVE-2021-44228")

def test_exit_codes(self):
    for v, c in [("Clean", 0), ("Low", 0), ("Unknown", 0), ("Medium", 1), ("High", 2), ("Critical", 2)]:
        self.assertEqual(ie.exit_code(v), c)

def _results(self):
    iocs = [{"type": "ip", "value": "8.8.8.8", "score": 87, "verdict": "High", "reason": "AbuseIPDB 87%",
             "sources": [{"source": "abuseipdb", "status": "ok", "score": 87, "reason": "AbuseIPDB 87%", "data": {"isp": "X"}, "link": "L"}]},
            {"type": "domain", "value": "x.com", "score": None, "verdict": "Unknown", "reason": "No source returned data",
             "sources": [{"source": "virustotal", "status": "error", "score": None, "reason": "timed out", "data": {}, "link": ""}]}]
    return ie.build_results("email.txt", "hello", iocs, [{"type": "ip", "value": "10.0.0.1", "reason": "non-routable"}], False)

def test_build_results(self):
    r = self._results()
    self.assertEqual(r["overall"], {"score": 87, "verdict": "High"})
    self.assertEqual(r["counts"], {"found": 3, "enriched": 2, "skipped": 1})
    self.assertEqual(r["input"]["sha256"], hashlib.sha256(b"hello").hexdigest())
    self.assertEqual(r["errors"], [{"ioc": "x[.]com", "source": "virustotal", "reason": "timed out"}])
    json.dumps(r)  # serialisable

def test_markdown_defanged_and_coverage(self):
    md = ie.render_markdown(self._results())
    self.assertIn("**Overall: High (87/100)**", md)
    self.assertIn("| ip | 8.8.8[.]8 | High | 87 | AbuseIPDB 87% |", md)
    self.assertNotIn("8.8.8.8", md)
    self.assertIn("10.0.0[.]1", md)
    self.assertIn("1 indicator(s) returned no data", md)

def test_terminal_color_toggle(self):
    self.assertNotIn("\x1b[", ie.render_terminal(self._results(), color=False))
    self.assertIn("\x1b[", ie.render_terminal(self._results(), color=True))
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the functions above.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `"Add terminal, Markdown and JSON reporting for ioc_enricher"`

---

### Task 7: CLI, sample input, docs

**Files:**
- Modify: `python/ioc_enricher.py` (add `main(argv: list[str]|None = None) -> int` and `if __name__ == "__main__": sys.exit(main())`)
- Create: `python/sample_phishing_email.txt`
- Modify: `.gitignore` (append `ioc_report_*.md` and `ioc_report_*.json` under "Files generated by the scripts"), `README.md`
- Test: `python/tests/test_ioc_enricher.py`

**Interfaces:**
- Consumes: everything above.
- Produces: `main(argv) -> int` (exit code). The args are those in spec §Usage (`input`, `--json`, `--no-md`, `--offline`, `--no-cache`, `--vt-rate`).

Flow: read the input (file read as bytes and decoded `utf-8`, `errors="replace"`; stdin uses `sys.stdin.read()`; unreadable file → message to stderr, return 3) → `extract_iocs` → if `--offline`, skip `enrich` (IoCs get `score=None`, `verdict="Not checked"`, `sources=[]`) → else `enrich(..., keys from os.environ, Cache(DEFAULT_CACHE_PATH, enabled=not args.no_cache))`, then `cache.save()` → `build_results` → print `render_terminal(color=sys.stdout.isatty())` → `write_reports(Path.cwd(), md=not args.no_md, js=args.json)`, print the paths → return `0` if offline else `exit_code(overall verdict)`.

- [ ] **Step 1: Write failing tests** (`class TestCli`, running inside a temp dir via `os.chdir` in setUp/tearDown, `--offline` or patched `enrich` so no network)

```python
def test_offline_sample(self):
    sample = Path(__file__).resolve().parents[1] / "sample_phishing_email.txt"
    code = ie.main([str(sample), "--offline", "--json"])
    self.assertEqual(code, 0)
    data = json.loads(next(Path.cwd().glob("ioc_report_*.json")).read_text())
    values = {i["value"] for i in data["iocs"]}
    self.assertTrue({"8.8.8.8", "1.1.1.1", "44d88612fea8a8f36de82e1278abb02f",
                     "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "CVE-2021-44228"} <= values)
    self.assertNotIn("invoice.pdf", values)
    self.assertTrue({"192.0.2.15", "10.1.2.3"} <= {s["value"] for s in data["skipped"]})
    self.assertTrue(list(Path.cwd().glob("ioc_report_*.md")))

def test_empty_input(self):                 # Review Focus #1
    Path("empty.txt").write_text("nothing to see here")
    with mock.patch.object(ie, "enrich", return_value=[]):
        self.assertEqual(ie.main(["empty.txt"]), 0)
    self.assertIn("Unknown", next(Path.cwd().glob("ioc_report_*.md")).read_text())

def test_non_utf8_input(self):              # Review Focus #2
    Path("raw.log").write_bytes(b"\xff\xfe junk 8.8.8.8 \x80")
    self.assertEqual(ie.main(["raw.log", "--offline", "--no-md"]), 0)

def test_missing_file_returns_3(self):
    self.assertEqual(ie.main(["does_not_exist.txt"]), 3)

def test_exit_code_follows_verdict(self):
    Path("in.txt").write_text("8.8.8.8")
    high = [{"type": "ip", "value": "8.8.8.8", "score": 95, "verdict": "Critical", "reason": "r", "sources": []}]
    with mock.patch.object(ie, "enrich", return_value=high):
        self.assertEqual(ie.main(["in.txt", "--no-md", "--no-cache"]), 2)
```

- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Write `python/sample_phishing_email.txt`** — a realistic phishing email ("Your Microsoft 365 password expires today") whose body contains: the defanged `hxxp://secure-login-verify[.]xyz/reset.php`, the domain `account-update-portal[.]top`, the sender `it-support[@]secure-login-verify[.]xyz`, a link to `https://login.microsoft.com/` (allowlisted), the attachment name `invoice.pdf`, the EICAR MD5 `44d88612fea8a8f36de82e1278abb02f` and SHA-256 `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`, "Received: from 192.0.2.15", an internal relay `10.1.2.3`, DNS references `8.8.8.8` and `1.1.1.1`, and "patch for CVE-2021-44228".
- [ ] **Step 4: Implement `main`** per the flow above.
- [ ] **Step 5: Run, verify pass.** Full suite, all OK.
- [ ] **Step 6: Manual smoke test.** Run `python3 python/ioc_enricher.py python/sample_phishing_email.txt --offline` from a scratch directory. Expected: the terminal table lists the IoCs defanged, counts show the skipped IPs/allowlisted URL, and a `.md` is written. Then run without `--offline` and with no keys set. Expected: VT/AbuseIPDB "No API key" warnings, InternetDB and CVEDB return live data, `CVE-2021-44228` is Critical, exit code 2 (check with `echo $?`).
- [ ] **Step 7: Update `.gitignore` and `README.md`.** Add `ioc_enricher.py` to the README Contents tree, plus a `### ioc_enricher.py` section after `brute_force_detector.py`: one-paragraph purpose, usage block (the 4 commands from the spec), API key env vars with where to get free keys, a sources table, the scoring table from spec §4, the exit codes table, and the test command.
- [ ] **Step 8: Commit** — `git add python/ .gitignore README.md && git commit -m "Add ioc_enricher CLI, sample input and docs"`. **Do not push.**
