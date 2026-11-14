"""Unit tests for ioc_enricher.py. All tests run offline.

Run from the repo root:  python3 -m unittest discover -s python/tests -v
"""
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ioc_enricher as ie  # noqa: E402


class TestExtraction(unittest.TestCase):
    def _vals(self, text, t):
        return [i["value"] for i in ie.extract_iocs(text)["iocs"] if i["type"] == t]

    def test_refang_forms(self):
        self.assertEqual(ie.refang("hxxps://evil[.]com hXXp://a(.)b{.}c x[@]y.com 1.2.3[:]80"),
                         "https://evil.com http://a.b.c x@y.com 1.2.3:80")

    def test_ipv4_and_ipv6(self):
        self.assertEqual(self._vals("hit 8.8.8.8 and 2606:4700:4700::1111", "ip"),
                         ["8.8.8.8", "2606:4700:4700::1111"])

    def test_invalid_ipv4_ignored(self):
        self.assertEqual(self._vals("ver 10.0.19041.1 and 999.1.1.1", "ip"), [])

    def test_timestamps_not_ipv6(self):
        self.assertEqual(self._vals("Mar 10 13:58:01 host sshd", "ip"), [])

    def test_non_routable_ips_skipped(self):
        r = ie.extract_iocs("10.0.0.5 127.0.0.1 192.0.2.10 169.254.1.1 8.8.8.8")
        self.assertEqual([i["value"] for i in r["iocs"]], ["8.8.8.8"])
        self.assertEqual({s["value"] for s in r["skipped"]},
                         {"10.0.0.5", "127.0.0.1", "192.0.2.10", "169.254.1.1"})
        self.assertTrue(all(s["reason"] == "non-routable" for s in r["skipped"]))

    def test_url_and_its_domain(self):  # Review Focus #5
        self.assertEqual(self._vals("(see hxxp://evil[.]com/a).", "url"), ["http://evil.com/a"])
        self.assertEqual(self._vals("(see hxxp://evil[.]com/a).", "domain"), ["evil.com"])

    def test_url_path_file_not_domain(self):
        self.assertEqual(self._vals("hxxp://evil[.]com/reset.php", "domain"), ["evil.com"])

    def test_filename_not_domain(self):
        self.assertEqual(self._vals("open invoice.pdf and setup.exe on bad-site.net", "domain"),
                         ["bad-site.net"])

    def test_allowlist_includes_subdomains_and_urls(self):
        r = ie.extract_iocs("https://login.microsoft.com/x google.com")
        self.assertEqual(r["iocs"], [])
        self.assertEqual({s["reason"] for s in r["skipped"]}, {"allowlisted"})

    def test_hash_lengths_lowercased(self):
        md5, sha1, sha256 = "A" * 32, "b" * 40, "c" * 64
        self.assertEqual(self._vals(f"{md5} {sha1} {sha256}", "hash"), ["a" * 32, "b" * 40, "c" * 64])

    def test_no_hash_substrings(self):  # Review Focus #4
        self.assertEqual(self._vals("d" * 64, "hash"), ["d" * 64])
        self.assertEqual(self._vals("e" * 70, "hash"), [])

    def test_cve_normalised(self):
        self.assertEqual(self._vals("cve-2021-44228 and CVE-2023-123456", "cve"),
                         ["CVE-2021-44228", "CVE-2023-123456"])

    def test_dedup_preserves_order(self):
        self.assertEqual(self._vals("1.1.1.1 8.8.8.8 1.1.1.1", "ip"), ["1.1.1.1", "8.8.8.8"])

    def test_domain_from_email(self):
        self.assertIn("evil-mail.org", self._vals("from: bob[@]evil-mail[.]org", "domain"))


class TestScoring(unittest.TestCase):
    def _src(self, name, status, score, reason="r"):
        return {"source": name, "status": status, "score": score, "reason": reason, "data": {}, "link": ""}

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
        self.assertEqual(ie.internetdb_score([21, 23, 445, 3389], ["a", "b", "c", "d", "e"], []), 50)
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
                     (40, "Medium"), (69, "Medium"), (70, "High"), (89, "High"),
                     (90, "Critical"), (100, "Critical")]:
            self.assertEqual(ie.verdict_for(s), v)

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


class TestHttpAndCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "sub" / "cache.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_cache_key(self):
        self.assertEqual(ie.cache_key("cvedb", {"type": "cve", "value": "CVE-1-1"}), "cvedb:cve:CVE-1-1")

    def test_cache_roundtrip_and_ttl(self):
        t = [1000.0]
        c = ie.Cache(self.path, ttl=10, now=lambda: t[0])
        c.set("k", {"status": "ok", "score": 5})
        c.save()
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
        c.set("k", {"status": "ok"})
        c.save()
        self.assertIsNone(c.get("k"))
        self.assertFalse(self.path.exists())

    def test_corrupt_cache_file(self):  # Review Focus #3
        self.path.parent.mkdir(parents=True)
        self.path.write_text("{not json")
        c = ie.Cache(self.path)
        self.assertIsNone(c.get("k"))
        c.set("k", {"status": "ok"})
        c.save()
        self.assertEqual(json.loads(self.path.read_text())["k"]["result"]["status"], "ok")

    def test_fetch_json_ok(self):
        resp = mock.MagicMock()
        resp.__enter__.return_value = resp
        resp.status = 200
        resp.read.return_value = b'{"a": 1}'
        resp.headers = {"X": "y"}
        with mock.patch("urllib.request.urlopen", return_value=resp) as uo:
            self.assertEqual(ie.fetch_json("http://x", {"k": "v"}), (200, {"a": 1}, {"X": "y"}))
        req = uo.call_args[0][0]
        self.assertEqual(req.get_header("User-agent"), "ioc-enricher/1.0")
        self.assertEqual(uo.call_args[1]["timeout"], 15)

    def test_fetch_json_returns_http_error_code(self):
        err = urllib.error.HTTPError("u", 404, "nf", {}, io.BytesIO(b"{}"))
        with mock.patch("urllib.request.urlopen", side_effect=err):
            self.assertEqual(ie.fetch_json("http://x")[0], 404)

    def test_fetch_json_network_error_raises(self):
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            with self.assertRaises(ie.FetchError):
                ie.fetch_json("http://x")

    def test_fetch_json_bad_json_raises(self):
        resp = mock.MagicMock()
        resp.__enter__.return_value = resp
        resp.status = 200
        resp.read.return_value = b"<html>"
        resp.headers = {}
        with mock.patch("urllib.request.urlopen", return_value=resp):
            with self.assertRaises(ie.FetchError):
                ie.fetch_json("http://x")


if __name__ == "__main__":
    unittest.main()
