"""
ioc_enricher.py

Extracts Indicators of Compromise (IPs, domains, URLs, file hashes and CVEs)
from raw text such as a phishing email, ticket or log dump, enriches them
against threat intelligence sources (VirusTotal, AbuseIPDB, Shodan InternetDB
and Shodan CVEDB) and writes a scored, explainable report.

Standard library only. API keys are read from the VT_API_KEY and
ABUSEIPDB_API_KEY environment variables; sources without a key are skipped.
"""
import base64
import hashlib
import ipaddress
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

# Well-known domains that are not worth spending API quota on.
# Matches the domain itself and any subdomain (login.microsoft.com).
ALLOWLIST = {
    "google.com", "microsoft.com", "office.com", "live.com", "outlook.com",
    "apple.com", "amazon.com", "github.com", "cloudflare.com", "linkedin.com",
}

# "Domains" ending in these are almost always filenames (invoice.pdf).
FILE_EXTENSIONS = {
    "pdf", "exe", "docx", "doc", "xlsx", "xls", "zip", "rar", "js", "png",
    "jpg", "jpeg", "gif", "txt", "log", "csv", "html", "htm", "dll", "bat",
    "ps1", "sh", "py", "msi", "iso", "img", "php", "asp", "aspx", "jsp",
}

IOC_TYPES = ("ip", "domain", "url", "hash", "cve")

_REFANG_RULES = [
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]"), "@"),
]

_URL_RE = re.compile(r"https?://[^\s<>\"'\]]+", re.IGNORECASE)
_URL_TRAILING = ".,;:!?)'\""
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f:]{2,}(?![0-9A-Fa-f:])")
_DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w-])",
    re.IGNORECASE,
)
# Exactly 64 (SHA-256), 40 (SHA-1) or 32 (MD5) hex chars, not part of a longer hex run.
_HASH_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])"
)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def refang(text):
    """Undo common defanging: hxxp -> http, [.] (.) {.} -> ., [:] -> :, [@] -> @."""
    for pattern, replacement in _REFANG_RULES:
        text = pattern.sub(replacement, text)
    return text


def is_allowlisted(domain):
    """True if domain is in ALLOWLIST or is a subdomain of an allowlisted domain."""
    domain = domain.lower().rstrip(".")
    return any(domain == a or domain.endswith("." + a) for a in ALLOWLIST)


def _valid_ip(candidate):
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def extract_iocs(text):
    """
    Refang the text and extract IoCs.

    Returns {"iocs": [{"type", "value"}], "skipped": [{"type", "value", "reason"}]}.
    IoCs are grouped by type (ip, domain, url, hash, cve), each in first-seen
    order with duplicates removed. Non-routable IPs and allowlisted domains/URLs
    are moved to "skipped"; filename-like domains are dropped silently.
    """
    text = refang(text)
    found = {t: [] for t in IOC_TYPES}

    def add(ioc_type, value):
        if value not in found[ioc_type]:
            found[ioc_type].append(value)

    # URLs first, then blank them out so their paths don't produce fake domains.
    url_hosts = []
    for match in _URL_RE.finditer(text):
        url = match.group(0).rstrip(_URL_TRAILING)
        add("url", url)
        host = urlsplit(url).hostname
        if host:
            url_hosts.append(host.lower())
    text_without_urls = _URL_RE.sub(" ", text)

    for match in _IPV4_RE.finditer(text):
        ip = _valid_ip(match.group(0))
        if ip:
            add("ip", ip)
    for match in _IPV6_RE.finditer(text):
        if match.group(0).count(":") >= 2:
            ip = _valid_ip(match.group(0))
            if ip:
                add("ip", ip)

    domains = [m.group(0).lower() for m in _DOMAIN_RE.finditer(text_without_urls)]
    for host in domains + url_hosts:
        if _valid_ip(host.strip("[]")):
            add("ip", _valid_ip(host.strip("[]")))
        elif host.rsplit(".", 1)[-1] not in FILE_EXTENSIONS and "." in host:
            add("domain", host)

    for match in _HASH_RE.finditer(text):
        add("hash", match.group(0).lower())

    for match in _CVE_RE.finditer(text):
        add("cve", match.group(0).upper())

    iocs, skipped = [], []
    for ioc_type in IOC_TYPES:
        for value in found[ioc_type]:
            reason = None
            if ioc_type == "ip" and not ipaddress.ip_address(value).is_global:
                reason = "non-routable"
            elif ioc_type == "domain" and is_allowlisted(value):
                reason = "allowlisted"
            elif ioc_type == "url" and is_allowlisted(urlsplit(value).hostname or ""):
                reason = "allowlisted"
            if reason:
                skipped.append({"type": ioc_type, "value": value, "reason": reason})
            else:
                iocs.append({"type": ioc_type, "value": value})
    return {"iocs": iocs, "skipped": skipped}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

# Exposed services that are commonly abused or should rarely face the internet.
RISKY_PORTS = {21, 23, 445, 1433, 3306, 3389, 5900, 6379, 9200, 11211, 27017}

VERDICT_BANDS = [(90, "Critical"), (70, "High"), (40, "Medium"), (10, "Low"), (0, "Clean")]


def vt_score(malicious, suspicious):
    """Engine-count based: 1-2 detections are often false positives, 10+ rarely are."""
    if malicious == 0 and suspicious == 0:
        return 0
    return min(100, 20 + 8 * malicious + 4 * suspicious)


def internetdb_score(ports, vulns, tags):
    """
    Exposure is not maliciousness, so plain exposure is capped at 50.
    Only Shodan's 'compromised'/'malware' tags push an IP above that.
    """
    candidates = [min(50, min(40, 10 * len(vulns)) + min(30, 10 * len(set(ports) & RISKY_PORTS)))]
    if "compromised" in tags or "malware" in tags:
        candidates.append(80)
    if "tor" in tags:
        candidates.append(40)
    return max(candidates)


def cve_score(cvss, kev, epss):
    """CVSS x 10, floored at 90 if on CISA KEV, +10 if EPSS >= 0.5, capped at 100."""
    score = round((cvss or 0) * 10)
    if kev:
        score = max(score, 90)
    if epss is not None and epss >= 0.5:
        score += 10
    return min(100, score)


def verdict_for(score):
    """Map a 0-100 score to a verdict band; None means no data -> Unknown."""
    if score is None:
        return "Unknown"
    for floor, verdict in VERDICT_BANDS:
        if score >= floor:
            return verdict
    return "Clean"


def score_ioc(sources):
    """Per-IoC score = highest score among sources that returned data."""
    ok = [s for s in sources if s["status"] == "ok"]
    if not ok:
        return None, "Unknown", "No source returned data"
    score = max(s["score"] for s in ok)
    return score, verdict_for(score), " · ".join(s["reason"] for s in ok)


def overall_verdict(iocs):
    """Overall score = highest IoC score; Unknown if no IoC has a score."""
    scores = [i["score"] for i in iocs if i.get("score") is not None]
    if not scores:
        return None, "Unknown"
    return max(scores), verdict_for(max(scores))


# ---------------------------------------------------------------------------
# HTTP and cache
# ---------------------------------------------------------------------------

USER_AGENT = "ioc-enricher/1.0"
DEFAULT_CACHE_PATH = Path.home() / ".cache" / "ioc_enricher" / "cache.json"
CACHEABLE_STATUSES = {"ok", "not_found"}


class FetchError(Exception):
    """Network failure, timeout or unparseable response."""


def fetch_json(url, headers=None, timeout=15):
    """
    GET a URL and parse the JSON body.

    Returns (status_code, parsed_json_or_None, response_headers). HTTP error
    codes are returned, not raised. Network errors, timeouts and invalid JSON
    on a 200 raise FetchError.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status, body, resp_headers = response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as err:
        return err.code, None, dict(err.headers or {})
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        raise FetchError(f"network error: {getattr(err, 'reason', err)}") from err
    try:
        return status, json.loads(body), resp_headers
    except ValueError as err:
        raise FetchError("invalid JSON in response") from err


def cache_key(source, ioc):
    return f"{source}:{ioc['type']}:{ioc['value']}"


class Cache:
    """JSON file cache of source results with a TTL. Errors are never cached."""

    def __init__(self, path, ttl=86400, enabled=True, now=time.time):
        self.path, self.ttl, self.enabled, self.now = Path(path), ttl, enabled, now
        self.entries = {}
        if enabled:
            try:
                loaded = json.loads(self.path.read_text())
                self.entries = loaded if isinstance(loaded, dict) else {}
            except (OSError, ValueError):
                self.entries = {}  # missing or corrupt cache: start fresh

    def get(self, key):
        if not self.enabled:
            return None
        entry = self.entries.get(key)
        if not isinstance(entry, dict) or self.now() - entry.get("ts", 0) > self.ttl:
            return None
        return entry.get("result")

    def set(self, key, result):
        if self.enabled and result.get("status") in CACHEABLE_STATUSES:
            self.entries[key] = {"ts": self.now(), "result": result}

    def save(self):
        if not self.enabled:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.entries))
        except OSError:
            pass  # a cache we can't write is not worth failing the run over


# ---------------------------------------------------------------------------
# Threat intelligence sources
# ---------------------------------------------------------------------------

SOURCES_FOR_TYPE = {
    "ip": ["virustotal", "abuseipdb", "internetdb"],
    "domain": ["virustotal"],
    "url": ["virustotal"],
    "hash": ["virustotal"],
    "cve": ["cvedb"],
}
SOURCE_LABELS = {"virustotal": "VT", "abuseipdb": "AbuseIPDB", "internetdb": "Shodan", "cvedb": "CVEDB"}
DEFAULT_BACKOFF = {"virustotal": 60}  # seconds to wait after a 429 without Retry-After
OTHER_BACKOFF = 5

_VT_API = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "hash": "files"}
_VT_GUI = {"ip": "ip-address", "domain": "domain", "url": "url", "hash": "file"}


class AuthError(Exception):
    """A source rejected our API key (401/403). The orchestrator disables it."""


def _result(source, status, score=None, reason="", data=None, link=""):
    return {"source": source, "status": status, "score": score, "reason": reason,
            "data": data or {}, "link": link}


def _request(source, url, headers, http, sleep):
    """
    Shared status handling. Returns (status, json, error_message):
    200 -> ok, 404 -> not_found, 401/403 -> AuthError, 429 -> wait and retry once.
    """
    for attempt in range(2):
        try:
            code, body, resp_headers = http(url, headers=headers)
        except FetchError as err:
            return "error", None, str(err)
        if code == 200:
            return "ok", body, ""
        if code == 404:
            return "not_found", None, ""
        if code in (401, 403):
            raise AuthError(source)
        if code == 429:
            if attempt == 0:
                try:
                    wait = int(resp_headers.get("Retry-After"))
                except (TypeError, ValueError):
                    wait = DEFAULT_BACKOFF.get(source, OTHER_BACKOFF)
                sleep(wait)
                continue
            return "error", None, "rate limited"
        return "error", None, f"HTTP {code}"
    return "error", None, "rate limited"


def _non_ok(source, status, message, link):
    if status == "not_found":
        return _result(source, "not_found", reason=f"{SOURCE_LABELS[source]}: not found", link=link)
    return _result(source, "error", reason=message, link=link)


def lookup_virustotal(ioc, api_key, http=fetch_json, sleep=time.sleep):
    value = ioc["value"]
    if ioc["type"] == "url":
        vt_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        gui_id = hashlib.sha256(value.encode()).hexdigest()  # the VT web UI uses the URL's SHA-256
    else:
        vt_id = gui_id = value
    url = f"https://www.virustotal.com/api/v3/{_VT_API[ioc['type']]}/{vt_id}"
    link = f"https://www.virustotal.com/gui/{_VT_GUI[ioc['type']]}/{gui_id}"
    status, body, message = _request("virustotal", url, {"x-apikey": api_key}, http, sleep)
    if status != "ok":
        return _non_ok("virustotal", status, message, link)
    stats = (body.get("data") or {}).get("attributes", {}).get("last_analysis_stats", {})
    data = {k: int(stats.get(k, 0)) for k in ("malicious", "suspicious", "harmless", "undetected")}
    data["total"] = sum(data.values())
    return _result("virustotal", "ok", vt_score(data["malicious"], data["suspicious"]),
                   f"VT {data['malicious']}/{data['total']} engines", data, link)


def lookup_abuseipdb(ioc, api_key, http=fetch_json, sleep=time.sleep):
    ip = ioc["value"]
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    link = f"https://www.abuseipdb.com/check/{ip}"
    headers = {"Key": api_key, "Accept": "application/json"}
    status, body, message = _request("abuseipdb", url, headers, http, sleep)
    if status != "ok":
        return _non_ok("abuseipdb", status, message, link)
    raw = body.get("data") or {}
    data = {k: raw.get(k) for k in ("abuseConfidenceScore", "totalReports", "countryCode", "isp", "usageType")}
    score = int(data["abuseConfidenceScore"] or 0)
    return _result("abuseipdb", "ok", score,
                   f"AbuseIPDB {score}% ({data['totalReports'] or 0} reports)", data, link)


def lookup_internetdb(ioc, http=fetch_json, sleep=time.sleep):
    ip = ioc["value"]
    link = f"https://www.shodan.io/host/{ip}"
    status, body, message = _request("internetdb", f"https://internetdb.shodan.io/{ip}", None, http, sleep)
    if status != "ok":
        return _non_ok("internetdb", status, message, link)
    data = {k: body.get(k) or [] for k in ("ports", "vulns", "tags", "hostnames")}
    reason = f"Shodan: {len(data['ports'])} ports, {len(data['vulns'])} CVEs"
    if data["tags"]:
        reason += ", tags: " + ",".join(data["tags"])
    return _result("internetdb", "ok", internetdb_score(data["ports"], data["vulns"], data["tags"]),
                   reason, data, link)


def lookup_cvedb(ioc, http=fetch_json, sleep=time.sleep):
    cve = ioc["value"]
    link = f"https://nvd.nist.gov/vuln/detail/{cve}"
    status, body, message = _request("cvedb", f"https://cvedb.shodan.io/cve/{cve}", None, http, sleep)
    if status != "ok":
        return _non_ok("cvedb", status, message, link)
    cvss = body.get("cvss_v3") if body.get("cvss_v3") is not None else body.get("cvss")
    data = {"cvss": cvss, "epss": body.get("epss"), "kev": bool(body.get("kev")),
            "summary": (body.get("summary") or "")[:200]}
    reason = f"CVSS {cvss if cvss is not None else 'n/a'}"
    if data["kev"]:
        reason += ", KEV"
    if data["epss"] is not None:
        reason += f", EPSS {data['epss']:.2f}"
    return _result("cvedb", "ok", cve_score(cvss, data["kev"], data["epss"]), reason, data, link)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

KEY_ENV_VARS = {"virustotal": "VT_API_KEY", "abuseipdb": "ABUSEIPDB_API_KEY"}


class RateLimiter:
    """Spaces calls at least 60/per_minute seconds apart. The first call never waits."""

    def __init__(self, per_minute, clock=time.monotonic, sleep=time.sleep):
        self.interval = 60.0 / per_minute
        self.clock, self.sleep = clock, sleep
        self.last = None

    def wait(self):
        if self.last is not None:
            remaining = self.interval - (self.clock() - self.last)
            if remaining > 0:
                self.sleep(remaining)
        self.last = self.clock()


def _default_lookups(keys, sleep):
    return {
        "virustotal": lambda ioc: lookup_virustotal(ioc, keys.get("virustotal"), sleep=sleep),
        "abuseipdb": lambda ioc: lookup_abuseipdb(ioc, keys.get("abuseipdb"), sleep=sleep),
        "internetdb": lambda ioc: lookup_internetdb(ioc, sleep=sleep),
        "cvedb": lambda ioc: lookup_cvedb(ioc, sleep=sleep),
    }


def enrich(iocs, keys, cache, vt_rate=4, lookups=None, sleep=time.sleep, clock=time.monotonic, log=print):
    """
    Look up every IoC in its applicable sources and score it.

    VirusTotal lookups run one at a time behind a RateLimiter; other sources run
    in a thread pool. Cached results are reused. A source whose key is missing is
    skipped; one whose key is rejected is disabled for the rest of the run.
    Returns IoC dicts (input order) with score, verdict, reason and sources.
    """
    funcs = {**_default_lookups(keys, sleep), **(lookups or {})}
    results = {}          # (ioc index, source) -> SourceResult
    disabled = set()
    lock = threading.Lock()
    vt_jobs, other_jobs = [], []

    for idx, ioc in enumerate(iocs):
        for source in SOURCES_FOR_TYPE[ioc["type"]]:
            if source in KEY_ENV_VARS and not keys.get(source):
                if source not in disabled:
                    disabled.add(source)
                    log(f"Warning: {KEY_ENV_VARS[source]} not set, skipping {SOURCE_LABELS[source]}")
                results[idx, source] = _result(source, "skipped", reason="No API key")
                continue
            cached = cache.get(cache_key(source, ioc))
            if cached is not None:
                results[idx, source] = cached
            elif source == "virustotal":
                vt_jobs.append((idx, ioc, source))
            else:
                other_jobs.append((idx, ioc, source))

    def run(job):
        idx, ioc, source = job
        with lock:
            if source in disabled:
                results[idx, source] = _result(source, "skipped", reason="Invalid API key")
                return
        try:
            result = funcs[source](ioc)
        except AuthError:
            with lock:
                if source not in disabled:
                    disabled.add(source)
                    log(f"Warning: {SOURCE_LABELS[source]} rejected the API key, disabling it")
            result = _result(source, "skipped", reason="Invalid API key")
        with lock:
            results[idx, source] = result
            cache.set(cache_key(source, ioc), result)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(run, job) for job in other_jobs]
        if vt_jobs:
            minutes = (len(vt_jobs) - 1) * 60 / vt_rate / 60
            log(f"{len(vt_jobs)} VirusTotal lookups, ~{minutes:.1f} min at {vt_rate:g}/min")
            limiter = RateLimiter(vt_rate, clock=clock, sleep=sleep)
            for job in vt_jobs:
                if "virustotal" not in disabled:
                    limiter.wait()
                run(job)
        for future in futures:
            future.result()

    enriched = []
    for idx, ioc in enumerate(iocs):
        sources = [results[idx, s] for s in SOURCES_FOR_TYPE[ioc["type"]]]
        score, verdict, reason = score_ioc(sources)
        enriched.append({**ioc, "score": score, "verdict": verdict, "reason": reason, "sources": sources})
    return enriched
