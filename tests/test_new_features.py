"""
Unit tests for the new reconflow modules: takeover, scope, github_leaks,
cve_correlate. Append these test classes into tests/test_reconflow.py
(or keep as a separate tests/test_new_features.py — unittest discover
picks up both).
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reconflow.scope import filter_in_scope, load_scope
from reconflow.takeover import TAKEOVER_FINGERPRINTS, detect_subdomain_takeovers


class TestScope(unittest.TestCase):
    def test_load_scope_plain_text(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scope_file = Path(tmpdir) / "scope.txt"
            scope_file.write_text("example.com\n*.example.com\n!internal.example.com\n# comment\n")
            scope = load_scope(str(scope_file))
            self.assertIn("example.com", scope["in_scope"])
            self.assertIn("internal.example.com", scope["out_of_scope"])

    def test_load_scope_hackerone_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scope_file = Path(tmpdir) / "scope.json"
            scope_file.write_text(json.dumps([
                {"asset_identifier": "*.example.com", "asset_type": "WILDCARD",
                 "eligible_for_submission": True},
                {"asset_identifier": "internal.example.com", "asset_type": "URL",
                 "eligible_for_submission": False},
                {"asset_identifier": "com.example.app", "asset_type": "GOOGLE_PLAY_APP_ID",
                 "eligible_for_submission": True},
            ]))
            scope = load_scope(str(scope_file))
            self.assertIn("*.example.com", scope["in_scope"])
            self.assertIn("internal.example.com", scope["out_of_scope"])
            # Mobile app IDs should be skipped, not treated as domains
            self.assertNotIn("com.example.app", scope["in_scope"])

    def test_filter_in_scope(self):
        scope = {"in_scope": ["example.com"], "out_of_scope": ["internal.example.com"]}
        subs = ["api.example.com", "internal.example.com", "other.com"]
        kept, dropped = filter_in_scope(subs, scope)
        self.assertIn("api.example.com", kept)
        self.assertIn("internal.example.com", dropped)
        self.assertIn("other.com", dropped)

    def test_filter_prevents_domain_collision_and_substring_leak(self):
        """CRITICAL: Ensure substrings like evil-example.com are NEVER treated as in-scope."""
        scope = {"in_scope": ["example.com"], "out_of_scope": []}
        candidates = [
            "example.com",                  # apex -> kept
            "api.example.com",              # sub -> kept
            "deep.sub.dev.example.com",     # deep sub -> kept
            "notexample.com",               # prefix collision -> MUST DROP
            "evil-example.com",             # hyphen collision -> MUST DROP
            "example.com.attacker.com",     # suffix extension -> MUST DROP
            "example.community",            # TLD collision -> MUST DROP
            "fakeexample.com",              # substring match -> MUST DROP
        ]
        kept, dropped = filter_in_scope(candidates, scope)
        expected = ["api.example.com", "deep.sub.dev.example.com", "example.com"]
        self.assertEqual(sorted(kept), expected)
        self.assertIn("notexample.com", dropped)
        self.assertIn("evil-example.com", dropped)
        self.assertIn("example.com.attacker.com", dropped)
        self.assertIn("example.community", dropped)
        self.assertIn("fakeexample.com", dropped)

    def test_filter_cidr_and_ip_matching(self):
        scope = {"in_scope": ["192.168.1.0/24", "10.0.0.1"], "out_of_scope": ["192.168.1.99"]}
        candidates = [
            "192.168.1.50",
            "192.168.1.99",
            "192.168.2.1",
            "10.0.0.1",
            "10.0.0.2",
        ]
        kept, dropped = filter_in_scope(candidates, scope)
        self.assertIn("192.168.1.50", kept)
        self.assertIn("10.0.0.1", kept)
        self.assertIn("192.168.1.99", dropped)  # out of scope wins
        self.assertIn("192.168.2.1", dropped)   # not in CIDR
        self.assertIn("10.0.0.2", dropped)

    def test_filter_handles_schemes_ports_paths(self):
        scope = {"in_scope": ["example.com"], "out_of_scope": ["admin.example.com"]}
        candidates = [
            "https://api.example.com:8443/graphql",
            "http://admin.example.com:80/console",
            "http://example.com/",
        ]
        kept, dropped = filter_in_scope(candidates, scope)
        self.assertIn("https://api.example.com:8443/graphql", kept)
        self.assertIn("http://example.com/", kept)
        self.assertIn("http://admin.example.com:80/console", dropped)

    def test_wildcard_excludes_apex(self):
        """*.example.com covers subdomains at any depth, but not the apex itself."""
        scope = {"in_scope": ["*.example.com"], "out_of_scope": []}
        kept, dropped = filter_in_scope(
            ["example.com", "api.example.com", "a.b.example.com", "evilexample.com"], scope
        )
        self.assertEqual(kept, ["api.example.com", "a.b.example.com"])
        self.assertIn("example.com", dropped)
        self.assertIn("evilexample.com", dropped)

    def test_inner_wildcard_stays_within_one_label(self):
        scope = {"in_scope": ["dev-*.example.com"], "out_of_scope": []}
        kept, dropped = filter_in_scope(
            ["dev-a.example.com", "dev-a.b.example.com", "prod.dev-a.example.com"], scope
        )
        self.assertEqual(kept, ["dev-a.example.com"])
        self.assertIn("dev-a.b.example.com", dropped)
        self.assertIn("prod.dev-a.example.com", dropped)

    def test_question_mark_matches_single_character(self):
        scope = {"in_scope": ["api?.example.com"], "out_of_scope": []}
        kept, _ = filter_in_scope(
            ["api1.example.com", "api12.example.com", "api.example.com"], scope
        )
        self.assertEqual(kept, ["api1.example.com"])

    def test_out_of_scope_wildcard_also_excludes_apex(self):
        """Exclusions read broadly: !*.internal.example.com drops internal.example.com too."""
        scope = {"in_scope": ["*.example.com"], "out_of_scope": ["*.internal.example.com"]}
        kept, dropped = filter_in_scope(
            ["api.example.com", "internal.example.com", "db.internal.example.com"], scope
        )
        self.assertEqual(kept, ["api.example.com"])
        self.assertIn("internal.example.com", dropped)
        self.assertIn("db.internal.example.com", dropped)

    def test_plain_text_wildcard_round_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scope_file = Path(tmpdir) / "scope.txt"
            scope_file.write_text("*.example.com\n!*.staging.example.com\n")
            scope = load_scope(str(scope_file))
            self.assertEqual(scope["in_scope"], ["*.example.com"])
            kept, _ = filter_in_scope(
                ["example.com", "www.example.com", "staging.example.com", "x.staging.example.com"],
                scope,
            )
            self.assertEqual(kept, ["www.example.com"])


class TestTakeover(unittest.TestCase):
    def test_fingerprints_cover_major_providers(self):
        self.assertIn("github.io", TAKEOVER_FINGERPRINTS)
        self.assertIn("s3.amazonaws.com", TAKEOVER_FINGERPRINTS)
        self.assertIn("herokuapp.com", TAKEOVER_FINGERPRINTS)

    def test_detect_confirms_matching_fingerprint(self):
        cname_findings = [{
            "subdomain": "old.example.com",
            "cname": "old-bucket.s3.amazonaws.com",
            "provider": "s3.amazonaws.com",
            "active_dns": False,
        }]
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            with patch("reconflow.takeover._fetch", return_value="<Error>NoSuchBucket</Error>"):
                confirmed = detect_subdomain_takeovers(cname_findings, out_dir)
            self.assertEqual(len(confirmed), 1)
            self.assertEqual(confirmed[0]["subdomain"], "old.example.com")

    def test_detect_no_match_when_fingerprint_absent(self):
        cname_findings = [{
            "subdomain": "live.example.com",
            "cname": "live-bucket.s3.amazonaws.com",
            "provider": "s3.amazonaws.com",
            "active_dns": True,
        }]
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            with patch("reconflow.takeover._fetch", return_value="<html>Welcome</html>"):
                confirmed = detect_subdomain_takeovers(cname_findings, out_dir)
            self.assertEqual(confirmed, [])

    def test_detect_matches_cname_target_when_provider_empty(self):
        """Match on cname even if provider is empty or unspecified."""
        cname_findings = [{
            "subdomain": "blog.example.com",
            "cname": "my-user.github.io",
            "provider": "",
            "active_dns": False,
        }]
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            with patch("reconflow.takeover._fetch",
                       return_value="404: There isn't a GitHub Pages site here"):
                confirmed = detect_subdomain_takeovers(cname_findings, out_dir)
            self.assertEqual(len(confirmed), 1)
            self.assertEqual(confirmed[0]["subdomain"], "blog.example.com")


class TestGithubLeaks(unittest.TestCase):
    def test_no_token_skips_cleanly(self):
        from reconflow.github_leaks import search_github_leaks
        with tempfile.TemporaryDirectory() as tmpdir:
            result = search_github_leaks("example.com", Path(tmpdir), token=None)
            self.assertEqual(result, [])


class TestCveCorrelate(unittest.TestCase):
    def test_no_tech_detected_returns_empty(self):
        from reconflow.cve_correlate import correlate_cves
        with tempfile.TemporaryDirectory() as tmpdir:
            result = correlate_cves([{"tech": []}], Path(tmpdir))
            self.assertEqual(result, [])

    @patch("reconflow.cve_correlate._query_nvd")
    def test_correlate_queries_each_detected_tech(self, mock_query):
        from reconflow.cve_correlate import correlate_cves
        mock_query.return_value = [{"cve_id": "CVE-2024-0001", "summary": "x", "cvss_score": 7.5}]
        httpx_records = [{"tech": ["nginx:1.18.0", "php:7.4"]}]
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("time.sleep"):  # skip the real rate-limit delay in tests
                result = correlate_cves(httpx_records, Path(tmpdir))
            self.assertEqual(mock_query.call_count, 2)
            self.assertEqual(len(result), 2)


if __name__ == "__main__":
    unittest.main()
