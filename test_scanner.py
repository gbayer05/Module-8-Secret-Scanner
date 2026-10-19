"""Unit tests. Run from the project root:  python -m unittest discover -s tests -v"""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "samples"))

import secret_scanner as ss                      # noqa: E402
from generate_samples import write_samples       # noqa: E402


class DemoProjectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        write_samples(cls.tmp.name)
        cls.findings, cls.stats = ss.scan_paths([cls.tmp.name])
        cls.names = {f.pattern for f in cls.findings}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_detects_expected_patterns(self):
        expected = {
            "AWS Access Key ID", "AWS Secret Access Key (keyword-gated)",
            "Google API Key", "GitHub Personal Access Token (classic)",
            "npm Access Token", "Stripe Secret/Restricted Key", "SendGrid API Key",
            "Twilio Account SID", "Hugging Face Access Token", "Anthropic API Key",
            "Slack Bot Token", "Slack Incoming Webhook URL", "PEM Private Key Block",
            "JSON Web Token (JWT)", "Hardcoded Password", "Password in Connection URL",
            "Bearer Token in Header",
        }
        self.assertTrue(expected <= self.names, f"missing: {expected - self.names}")

    def test_clean_files_have_no_findings(self):
        flagged = {os.path.basename(f.file) for f in self.findings}
        self.assertNotIn("app.py", flagged)        # env lookups, placeholder, nosecret
        self.assertNotIn("README.txt", flagged)

    def test_line_numbers(self):
        aws = next(f for f in self.findings if f.pattern == "AWS Access Key ID")
        self.assertEqual(aws.line, 2)


class UnitTests(unittest.TestCase):
    def test_placeholder_filtered_for_heuristics(self):
        self.assertEqual(ss.scan_line('password = "your-password-here"'), [])

    def test_real_looking_password_flagged(self):
        hits = ss.scan_line('password = "Tr0ub4dor&3xyz"')
        self.assertEqual(hits[0][0].name, "Hardcoded Password")

    def test_nosecret_marker(self):
        self.assertEqual(ss.scan_line('password = "Tr0ub4dor&3xyz"  # nosecret'), [])

    def test_no_duplicate_report_for_same_span(self):
        line = 'aws_secret_access_key = "' + "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + 'EXAMPLEKEY"'
        self.assertEqual(len(ss.scan_line(line)), 1)

    def test_redact(self):
        self.assertEqual(ss.redact("abcd"), "****")
        self.assertTrue(ss.redact("ghp_abcdefghijklmnop").startswith("ghp_"))
        self.assertNotIn("efghijkl", ss.redact("ghp_abcdefghijklmnop"))

    def test_binary_file_skipped(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"\x00\x01\x02AKIA")
        try:
            self.assertIsNone(ss.scan_file(fh.name))
        finally:
            os.unlink(fh.name)


class CliTests(unittest.TestCase):
    def test_exit_codes_and_json(self):
        with tempfile.TemporaryDirectory() as d:
            write_samples(d)
            out = os.path.join(d, "report.json")
            code = ss.main([d, "-f", "json", "-o", out, "-q", "--exclude", "report.json"])
            self.assertEqual(code, 1)
            with open(out) as fh:
                data = json.load(fh)
            self.assertGreater(data["summary"]["findings"], 10)

        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "ok.txt"), "w") as fh:
                fh.write("nothing here\n")
            self.assertEqual(ss.main([d, "-q"]), 0)

    def test_missing_path_returns_2(self):
        self.assertEqual(ss.main(["/definitely/not/here", "-q"]), 2)


if __name__ == "__main__":
    unittest.main()