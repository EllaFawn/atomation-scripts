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
import re
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
