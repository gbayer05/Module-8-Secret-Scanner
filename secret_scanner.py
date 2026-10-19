#!/usr/bin/env python3
"""
secret_scanner - find hardcoded secrets (API keys, tokens, passwords,
private keys) in files and directories using regular expressions.

Provider-specific patterns come from https://github.com/odomojuli/regextokens
(each pattern below links to the provider documentation it is based on).
A few generic "heuristic" patterns (password = "...", api_key = "...") are
added on top, because many leaked secrets have no recognisable prefix.

Exit codes:  0 = no findings, 1 = findings reported, 2 = usage / I/O error.
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import io
import json
import logging
import os
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple

__version__ = "1.0.0"

log = logging.getLogger("secret_scanner")

# --------------------------------------------------------------------------- #
# Pattern catalogue
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Pattern:
    name: str          # human readable name shown in the report
    category: str      # API key | Token | Password | Private key
    regex: "re.Pattern[str]"
    source: str        # documentation URL (or "heuristic")
    generic: bool = False  # heuristic patterns: lower priority + placeholder filter


def _p(name: str, category: str, regex: str, source: str, generic: bool = False) -> Pattern:
    return Pattern(name, category, re.compile(regex), source, generic)


PATTERNS: List[Pattern] = [
    # ---- Private keys ----------------------------------------------------- #
    _p("PEM Private Key Block", "Private key",
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
       "https://datatracker.ietf.org/doc/html/rfc7468"),

    # ---- Cloud ------------------------------------------------------------ #
    _p("AWS Access Key ID", "API key",
       r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b",
       "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html"),
    _p("AWS Secret Access Key (keyword-gated)", "API key",
       r"(?i)aws[\w.\-= :'\"]{0,25}([A-Za-z0-9/+]{40})",
       "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html"),
    _p("Google API Key", "API key",
       r"\bAIza[0-9A-Za-z_-]{35}\b",
       "https://cloud.google.com/docs/authentication/api-keys"),
    _p("Google OAuth Client Secret", "API key",
       r"\bGOCSPX-[0-9A-Za-z_-]{28}\b",
       "https://developers.google.com/identity/protocols/oauth2"),

    # ---- Source control / CI / package registries ------------------------- #
    _p("GitHub Personal Access Token (classic)", "Token",
       r"\bghp_[0-9A-Za-z]{36}\b",
       "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"),
    _p("GitHub Personal Access Token (fine-grained)", "Token",
       r"\bgithub_pat_[0-9A-Za-z_]{82}\b",
       "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"),
    _p("GitHub OAuth/User/Server/Refresh Token", "Token",
       r"\bgh[ousr]_[0-9A-Za-z]{36}\b",
       "https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps"),
    _p("GitLab Personal Access Token", "Token",
       r"\bglpat-[0-9A-Za-z_-]{20}\b",
       "https://docs.gitlab.com/ee/security/token_overview.html"),
    _p("npm Access Token", "Token",
       r"\bnpm_[0-9A-Za-z]{36}\b",
       "https://docs.npmjs.com/about-access-tokens"),

    # ---- Payments ---------------------------------------------------------- #
    _p("Stripe Secret/Restricted Key", "API key",
       r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,99}\b",
       "https://docs.stripe.com/keys"),
    _p("Shopify Access Token / Shared Secret", "Token",
       r"\bshp(?:at|ss|pa|ca)_[0-9a-fA-F]{32}\b",
       "https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens"),

    # ---- Communications --------------------------------------------------- #
    _p("Slack Bot Token", "Token",
       r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9A-Za-z]{24,34}\b",
       "https://api.slack.com/authentication/token-types"),
    _p("Slack User Token", "Token",
       r"\bxoxp-(?:[0-9]{10,13}-){3}[0-9A-Za-z]{28,34}\b",
       "https://api.slack.com/authentication/token-types"),
    _p("Slack Incoming Webhook URL", "Token",
       r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,12}/B[0-9A-Za-z_]{8,12}/[0-9A-Za-z]{24}",
       "https://api.slack.com/messaging/webhooks"),
    _p("SendGrid API Key", "API key",
       r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b",
       "https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys"),
    _p("Twilio Account SID", "API key",
       r"\bAC[0-9a-fA-F]{32}\b",
       "https://www.twilio.com/docs/iam/api-keys"),
    _p("Mailgun Private API Key", "API key",
       r"\bkey-[0-9a-f]{32}\b",
       "https://documentation.mailgun.com/docs/mailgun/api-reference/authentication/"),
    _p("Telegram Bot Token", "Token",
       r"\b[0-9]{8,12}:AA[0-9A-Za-z_-]{32,34}\b",
       "https://core.telegram.org/bots/features"),
    _p("Discord Bot Token", "Token",
       r"\b[MNO][0-9A-Za-z_-]{23,25}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27,38}\b",
       "https://discord.com/developers/docs/topics/oauth2"),

    # ---- AI providers ----------------------------------------------------- #
    _p("OpenAI API Key", "API key",
       r"\bsk-(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{20,74}T3BlbkFJ[0-9A-Za-z_-]{20,74}\b",
       "https://platform.openai.com/docs/api-reference/authentication"),
    _p("Anthropic API Key", "API key",
       r"\bsk-ant-(?:api03|admin01)-[0-9A-Za-z_-]{93}AA\b",
       "https://docs.anthropic.com/en/api/getting-started"),
    _p("Hugging Face Access Token", "Token",
       r"\bhf_[0-9A-Za-z]{34}\b",
       "https://huggingface.co/docs/hub/security-tokens"),

    # ---- Generic structures ------------------------------------------------ #
    _p("JSON Web Token (JWT)", "Token",
       r"\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9/_-]{10,}\.[A-Za-z0-9/_-]{10,}",
       "https://datatracker.ietf.org/doc/html/rfc7519"),

    # ---- Heuristics (not from regextokens; assignment-style detection) ---- #
    _p("Hardcoded Password", "Password",
       r"(?i)(?:password|passwd|pwd)[\"']?\s*[:=]\s*[\"']([^\"'\s]{6,})[\"']",
       "heuristic", generic=True),
    _p("Password in Connection URL", "Password",
       r"\b[a-z][a-z0-9+.\-]*://[^\s:/@\"']+:([^\s@/\"']{3,})@",
       "heuristic", generic=True),
    _p("Generic API Key / Secret Assignment", "API key",
       r"(?i)(?:api[_-]?key|api[_-]?secret|secret[_-]?key|client[_-]?secret|"
       r"access[_-]?token|auth[_-]?token)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_\-/+=.]{16,})[\"']",
       "heuristic", generic=True),
    _p("Bearer Token in Header", "Token",
       r"(?i)bearer\s+([A-Za-z0-9_\-.=]{20,})",
       "heuristic", generic=True),
]

# Values that are obviously placeholders; only applied to heuristic patterns.
PLACEHOLDER_MARKERS = ("example", "your", "changeme", "placeholder", "xxxx",
                       "dummy", "sample", "<", ">", "${", "{{", "%s", "...")
PLACEHOLDER_EXACT = {"password", "passwd", "secret", "123456", "12345678"}

DEFAULT_EXCLUDED_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__",
                         ".venv", "venv", ".tox", ".mypy_cache", ".idea", ".vscode"}
IGNORE_MARKER = "nosecret"       # add "# nosecret" to a line to suppress it
MAX_LINE_LENGTH = 10_000          # skip minified / generated mega-lines
DEFAULT_MAX_SIZE_KB = 1024


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    file: str
    line: int
    pattern: str
    category: str
    match: str


@dataclass
class ScanStats:
    files_scanned: int = 0
    files_skipped: int = 0


# --------------------------------------------------------------------------- #
# Scanning logic
# --------------------------------------------------------------------------- #

def _is_placeholder(value: str) -> bool:
    low = value.lower()
    return low in PLACEHOLDER_EXACT or any(m in low for m in PLACEHOLDER_MARKERS)


def _is_binary(path: str) -> bool:
    """Heuristic: a NUL byte in the first 8 KB means binary."""
    with open(path, "rb") as fh:
        return b"\x00" in fh.read(8192)


def scan_line(line: str) -> List[Tuple[Pattern, str, Tuple[int, int]]]:
    """Return (pattern, matched_text, span) tuples for one line.

    Specific patterns run first; heuristic patterns are dropped if they
    overlap something a specific pattern already caught (no duplicate reports).
    """
    if IGNORE_MARKER in line.lower():
        return []
    hits: List[Tuple[Pattern, str, Tuple[int, int]]] = []
    ordered = sorted(PATTERNS, key=lambda p: p.generic)  # specific first
    for pat in ordered:
        for m in pat.regex.finditer(line):
            # If the regex has a capture group, the group is the secret itself.
            if pat.regex.groups:
                text, span = m.group(1), m.span(1)
            else:
                text, span = m.group(0), m.span(0)
            if pat.generic and _is_placeholder(text):
                log.debug("placeholder ignored: %s", text)
                continue
            if any(span[0] < s[1] and s[0] < span[1] for _, _, s in hits):
                continue  # overlaps an earlier (higher priority) hit
            hits.append((pat, text, span))
    return hits


def scan_file(path: str, max_size_kb: int = DEFAULT_MAX_SIZE_KB) -> Optional[List[Finding]]:
    """Scan one file. Returns None if the file was skipped."""
    try:
        size = os.path.getsize(path)
        if size > max_size_kb * 1024:
            log.debug("skip (too large, %d KB): %s", size // 1024, path)
            return None
        if _is_binary(path):
            log.debug("skip (binary): %s", path)
            return None
        findings: List[Finding] = []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                if len(line) > MAX_LINE_LENGTH:
                    log.debug("skip long line %d in %s", lineno, path)
                    continue
                for pat, text, _ in scan_line(line):
                    log.info("%s:%d matched %s", path, lineno, pat.name)
                    findings.append(Finding(path, lineno, pat.name, pat.category, text))
        return findings
    except (OSError, PermissionError) as exc:
        log.warning("cannot read %s: %s", path, exc)
        return None


def iter_files(paths: Sequence[str], excludes: Sequence[str]) -> Iterator[str]:
    """Yield every file under the given paths, honouring exclusions."""
    def excluded(p: str) -> bool:
        name = os.path.basename(p)
        return any(fnmatch.fnmatch(name, g) or fnmatch.fnmatch(p, g) for g in excludes)

    for root_path in paths:
        if os.path.isfile(root_path):
            yield root_path
            continue
        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = sorted(d for d in dirnames
                                 if d not in DEFAULT_EXCLUDED_DIRS
                                 and not excluded(os.path.join(dirpath, d)))
            for fname in sorted(filenames):
                full = os.path.join(dirpath, fname)
                if excluded(full):
                    log.debug("skip (excluded): %s", full)
                    continue
                yield full


def scan_paths(paths: Sequence[str], excludes: Sequence[str] = (),
               max_size_kb: int = DEFAULT_MAX_SIZE_KB) -> Tuple[List[Finding], ScanStats]:
    findings: List[Finding] = []
    stats = ScanStats()
    for fpath in iter_files(paths, excludes):
        result = scan_file(fpath, max_size_kb)
        if result is None:
            stats.files_skipped += 1
        else:
            stats.files_scanned += 1
            findings.extend(result)
    return findings, stats


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def redact(secret: str) -> str:
    """Keep the first 4 and last 2 characters, mask the rest."""
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "*" * min(len(secret) - 6, 16) + secret[-2:]


def format_text(findings: List[Finding], stats: ScanStats, color: bool) -> str:
    c = (lambda code, s: f"\033[{code}m{s}\033[0m") if color else (lambda code, s: s)
    out = io.StringIO()
    out.write(c("1", "Secret scan report") + "\n" + "=" * 60 + "\n")
    for f in findings:
        out.write(f"{c('36', f.file)}:{c('33', str(f.line))}  "
                  f"{c('31', '[' + f.pattern + ']')}\n    {f.match}\n")
    out.write("=" * 60 + "\n")
    by_cat = Counter(f.category for f in findings)
    cats = ", ".join(f"{k}: {v}" for k, v in sorted(by_cat.items())) or "none"
    out.write(f"Files scanned: {stats.files_scanned}   skipped: {stats.files_skipped}\n")
    verdict = c("31", f"{len(findings)} potential secret(s) found") if findings \
        else c("32", "No secrets found")
    out.write(f"{verdict}  ({cats})\n")
    return out.getvalue()


def format_json(findings: List[Finding], stats: ScanStats) -> str:
    return json.dumps({"summary": {**asdict(stats), "findings": len(findings)},
                       "findings": [asdict(f) for f in findings]}, indent=2) + "\n"


def format_csv(findings: List[Finding]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["file", "line", "pattern", "category", "match"])
    for f in findings:
        w.writerow([f.file, f.line, f.pattern, f.category, f.match])
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secret_scanner",
        description="Scan files or directories for hardcoded secrets "
                    "(API keys, tokens, passwords, private keys).",
        epilog="Exit status: 0 = clean, 1 = findings, 2 = error. "
               "Add '# nosecret' to a line to suppress findings on it.")
    p.add_argument("paths", nargs="*", metavar="PATH",
                   help="file(s) or directory(ies) to scan")
    p.add_argument("-f", "--format", choices=("text", "json", "csv"), default="text",
                   help="report format (default: text)")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="write the report to FILE instead of stdout")
    p.add_argument("--redact", action="store_true",
                   help="mask matched secrets in the report (recommended for shared logs)")
    p.add_argument("-e", "--exclude", action="append", default=[], metavar="GLOB",
                   help="glob of files/dirs to skip, e.g. '*.min.js' (repeatable)")
    p.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE_KB, metavar="KB",
                   help=f"skip files larger than KB (default: {DEFAULT_MAX_SIZE_KB})")
    p.add_argument("--list-patterns", action="store_true",
                   help="print the detection patterns and exit")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    g = p.add_argument_group("logging")
    g.add_argument("-v", "--verbose", action="count", default=0,
                   help="-v = INFO (each match), -vv = DEBUG (skipped files, etc.)")
    g.add_argument("-q", "--quiet", action="store_true", help="only log errors")
    g.add_argument("--log-file", metavar="FILE", help="also write logs to FILE")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def setup_logging(verbose: int, quiet: bool, log_file: Optional[str]) -> None:
    level = logging.ERROR if quiet else (logging.WARNING, logging.INFO, logging.DEBUG)[min(verbose, 2)]
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S")
    log.setLevel(logging.DEBUG)
    log.handlers.clear()
    console = logging.StreamHandler(sys.stderr)   # stderr keeps stdout report clean
    console.setLevel(level)
    console.setFormatter(fmt)
    log.addHandler(console)
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        log.addHandler(fh)


def list_patterns() -> str:
    lines = [f"{len(PATTERNS)} patterns\n"]
    for p in PATTERNS:
        kind = "heuristic" if p.generic else "specific"
        lines.append(f"- {p.name} [{p.category}, {kind}]\n    {p.regex.pattern}\n    source: {p.source}")
    return "\n".join(lines) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_patterns:
        print(list_patterns())
        return 0
    if not args.paths:
        parser.error("at least one PATH is required (or use --list-patterns)")

    setup_logging(args.verbose, args.quiet, args.log_file)

    missing = [p for p in args.paths if not os.path.exists(p)]
    if missing:
        for p in missing:
            log.error("path does not exist: %s", p)
        return 2

    log.warning("scanning %s with %d patterns", ", ".join(args.paths), len(PATTERNS))
    findings, stats = scan_paths(args.paths, args.exclude, args.max_size)
    if args.redact:
        for f in findings:
            f.match = redact(f.match)
    log.warning("done: %d files scanned, %d skipped, %d finding(s)",
                stats.files_scanned, stats.files_skipped, len(findings))

    if args.format == "json":
        report = format_json(findings, stats)
    elif args.format == "csv":
        report = format_csv(findings)
    else:
        use_color = (not args.no_color and not args.output
                     and sys.stdout.isatty() and "NO_COLOR" not in os.environ)
        report = format_text(findings, stats, use_color)

    try:
        if args.output:
            with open(args.output, "w", encoding="utf-8", newline="") as fh:
                fh.write(report)
            log.warning("report written to %s", args.output)
        else:
            sys.stdout.write(report)
    except OSError as exc:
        log.error("cannot write report: %s", exc)
        return 2

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())