#!/usr/bin/env python3
"""
Creates a small demo project full of FAKE secrets for testing the scanner.

The fake tokens are assembled from fragments at runtime so this source file
itself never contains a complete token (which keeps GitHub push protection
and other scanners from flagging the repo). None of these values are real.

Usage:  python samples/generate_samples.py [output_dir]   (default: demo_project)
"""
import os
import sys

ALNUM36 = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"


def build_samples() -> dict:
    """Return {relative_path: file_content} for the demo project."""
    pem = "-----BEGIN RSA " + "PRIVATE KEY-----"
    files = {
        "config.py": "\n".join([
            "# demo application settings (all values are fake)",
            'AWS_ACCESS_KEY_ID = "' + "AKIA" + "IOSFODNN7EXAMPLE" + '"',
            'aws_secret_access_key = "' + "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY" + '"',
            'GOOGLE_API_KEY = "' + "AIza" + "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY" + '"',
            'db_password = "Sup3rS3cret' + 'Pass!"',
            'DATABASE_URL = "postgres://admin:' + 'hunter2pw@db.internal:5432/app"',
            "DEBUG = True",
            "",
        ]),
        ".env": "\n".join([
            "GITHUB_TOKEN=" + "ghp_" + ALNUM36,
            "NPM_TOKEN=" + "npm_" + ALNUM36,
            "STRIPE_SECRET_KEY=" + "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
            "SENDGRID_API_KEY=" + "SG." + "ngeVfQFYQlKU0ufo8x5d1A" + "."
            + "TwL2iGABf9DHoTf-9kg6BSdRqVYMRRARBrsE3gdAVfw",
            "TWILIO_ACCOUNT_SID=" + "AC" + "0123456789abcdef0123456789abcdef",
            "HF_TOKEN=" + "hf_" + "abcdefghijklmnopqrstuvwxyzABCDEFGH",
            "ANTHROPIC_API_KEY=" + "sk-ant-" + "api03-" + ("Ab3" * 31) + "AA",
            "",
        ]),
        "deploy.sh": "\n".join([
            "#!/bin/bash",
            "# notify the team",
            'curl -X POST -H "Authorization: Bearer ' + "abcdEFGH1234ijklMNOP5678qrstUVWX" + '" https://api.example.com/deploy',
            'curl -X POST ' + "https://hooks.slack.com/services/" + "T01234ABCD/B01234ABCD/" + "abcdefghijklmnopqrstuvwx" + " -d 'deployed'",
            'export SLACK_BOT_TOKEN="' + "xoxb-" + "123456789012-123456789012-" + "abcdefghijklmnopqrstuvwx" + '"',
            "",
        ]),
        os.path.join("keys", "id_rsa_demo"): "\n".join([
            pem,
            "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu",
            "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm",
            "-----END RSA " + "PRIVATE KEY-----",
            "",
        ]),
        "auth_notes.txt": "token: " + "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "."
                          + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV" + "\n",
        # Files below should produce NO findings:
        "app.py": "\n".join([
            "import os",
            "",
            "# secrets are read from the environment, never hardcoded",
            'API_KEY = os.environ["API_KEY"]',
            'password = os.getenv("DB_PASSWORD")',
            'EXAMPLE_PASSWORD = "your-password-here"   # placeholder',
            'legacy_password = "OldPass123"  # nosecret',
            "",
        ]),
        "README.txt": "Demo project. Nothing sensitive in this file.\n",
    }
    return files


def write_samples(out_dir: str) -> list:
    written = []
    for rel, content in build_samples().items():
        full = os.path.join(out_dir, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(content)
        written.append(full)
    return written


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "demo_project"
    for path in write_samples(target):
        print("created", path)
    print(f"\nNow try:  python secret_scanner.py {target}")