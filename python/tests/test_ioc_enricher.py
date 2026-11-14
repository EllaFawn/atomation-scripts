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


if __name__ == "__main__":
    unittest.main()
