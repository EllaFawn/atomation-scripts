"""
ioc_enricher.py

Extracts Indicators of Compromise (IPs, domains, URLs, file hashes and CVEs)
from raw text such as a phishing email, ticket or log dump, enriches them
against threat intelligence sources (VirusTotal, AbuseIPDB, Shodan InternetDB
and Shodan CVEDB) and writes a scored, explainable report.

Standard library only. API keys are read from the VT_API_KEY and
ABUSEIPDB_API_KEY environment variables; sources without a key are skipped.
"""
import ipaddress
import json
import re
import time
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
