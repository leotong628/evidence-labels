"""Repository validity checks (stdlib only, Python 3.10+).

Added by the Cloudboard 261103 security audit. Run from anywhere:

    python -I -m unittest discover -s tests -v

Checks
  1. every SKILL.md has a YAML front matter block with `name` and `description`
     (parsed by hand, no PyYAML);
  2. relative Markdown links point at files that exist;
  3. every *.py file under skills/ or at the repo root that has an argparse CLI
     answers `--help` with exit code 0 (run as `python -I`, from a temp directory);
  4. a secrets / personal-identifier scan of all text files in the repo fails on
     any hit that is not in the explicit ALLOW list below;
  5. every `uses:` in .github/workflows is pinned to a full 40-character commit SHA.

Failure messages print only the file, line and kind of a hit, with the value redacted.
"""
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
THIS_FILE = Path(__file__).resolve()

# True for repos that ship an Agent Skill: at least one SKILL.md must exist.
REQUIRE_SKILL = True

# Explicit allow-list for the secrets / PII scan: (repo-relative path, kind, exact matched text) -> reason.
ALLOW = {

}

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", "exports", ".pytest_cache", "bin"}
MAX_BYTES = 2_000_000


def iter_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.is_symlink() or not p.is_file():
                continue
            yield p


def read_text(path):
    """Return the file's text, or None if it is binary / too large."""
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def rel(path):
    return path.relative_to(ROOT).as_posix()


# ---------------------------------------------------------------- 1. SKILL.md front matter

def parse_front_matter(text):
    """Return a dict of top-level `key: value` pairs from a leading --- block, or None."""
    lines = text.lstrip("﻿").splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    out = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return out
        m = re.match(r"^([A-Za-z_][\w-]*):\s*(.*)$", line)  # top-level keys only (no indent)
        if m:
            value = m.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            out[m.group(1)] = value
    return None  # never closed


class SkillFrontMatter(unittest.TestCase):
    def skill_files(self):
        return [p for p in iter_files() if p.name == "SKILL.md"]

    def test_skill_present_when_required(self):
        if REQUIRE_SKILL:
            self.assertTrue(self.skill_files(), "no SKILL.md found")

    def test_every_skill_has_name_and_description(self):
        for p in self.skill_files():
            text = read_text(p)
            self.assertIsNotNone(text, rel(p))
            fm = parse_front_matter(text)
            self.assertIsNotNone(fm, f"{rel(p)}: missing or unterminated YAML front matter")
            for key in ("name", "description"):
                self.assertTrue(fm.get(key), f"{rel(p)}: front matter has no non-empty `{key}`")
            self.assertRegex(fm["name"], r"^[a-z0-9]+(-[a-z0-9]+)*$", f"{rel(p)}: bad skill name")
            self.assertEqual(fm["name"], p.parent.name, f"{rel(p)}: name differs from its folder")
            self.assertLessEqual(len(fm["description"]), 1024, f"{rel(p)}: description over 1024 chars")


# ---------------------------------------------------------------- 2. Markdown links

FENCE = re.compile(r"^(```|~~~).*?^\1[^\n]*$", re.S | re.M)
INLINE_CODE = re.compile(r"`[^`\n]*`")
LINK = re.compile(r"!?\[[^\]\n]*\]\(\s*<?([^)\s>]+)>?(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)")
REFDEF = re.compile(r"^\s{0,3}\[[^\]\n]+\]:\s+<?(\S+?)>?(?:\s+.*)?$", re.M)


class MarkdownLinks(unittest.TestCase):
    def test_relative_links_resolve(self):
        checked = 0
        for p in iter_files():
            if p.suffix.lower() != ".md":
                continue
            text = read_text(p)
            if text is None:
                continue
            text = INLINE_CODE.sub("", FENCE.sub("", text))
            targets = LINK.findall(text) + REFDEF.findall(text)
            for target in targets:
                if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", target) or target.startswith(("#", "//")):
                    continue  # http:, https:, mailto:, anchors
                path_part = target.split("#", 1)[0].split("?", 1)[0]
                if not path_part:
                    continue
                from urllib.parse import unquote
                dest = (ROOT / path_part.lstrip("/")) if path_part.startswith("/") else (p.parent / unquote(path_part))
                checked += 1
                self.assertTrue(dest.exists(), f"{rel(p)}: broken relative link -> {target}")
                self.assertTrue(ROOT in dest.resolve().parents or dest.resolve() == ROOT,
                                f"{rel(p)}: link leaves the repository -> {target}")


# ---------------------------------------------------------------- 3. argparse CLIs answer --help

def third_party_missing(source):
    """Names of top-level imports that are neither stdlib nor local files and cannot be found."""
    missing = []
    stdlib = getattr(sys, "stdlib_module_names", frozenset())
    local = {p.stem for p in ROOT.glob("*.py")} | {p.name for p in ROOT.iterdir() if p.is_dir()}
    for m in re.finditer(r"^\s*(?:from|import)\s+([A-Za-z_]\w*)", source, re.M):
        top = m.group(1)
        if top in stdlib or top in local or top == "__future__":
            continue
        if importlib.util.find_spec(top) is None and top not in missing:
            missing.append(top)
    return missing


class CliHelp(unittest.TestCase):
    def cli_scripts(self):
        found = list(ROOT.glob("*.py"))
        skills = ROOT / "skills"
        if skills.is_dir():
            found += list(skills.rglob("*.py"))
        out = []
        for p in sorted(set(found)):
            text = read_text(p)
            if text and re.search(r"^\s*(?:import argparse|from argparse import)", text, re.M) and "ArgumentParser(" in text:
                out.append((p, text))
        return out

    def test_help_exits_zero(self):
        for p, text in self.cli_scripts():
            with self.subTest(script=rel(p)):
                missing = third_party_missing(text)
                if missing:
                    self.skipTest(f"{rel(p)} needs third-party module(s) not installed here: {', '.join(missing)}")
                with tempfile.TemporaryDirectory() as tmp:
                    env = {"PATH": os.environ.get("PATH", ""), "HOME": tmp, "LC_ALL": "C.UTF-8"}
                    r = subprocess.run([sys.executable, "-I", str(p), "--help"], cwd=tmp, env=env,
                                       capture_output=True, text=True, timeout=120)
                self.assertEqual(r.returncode, 0, f"{rel(p)} --help exited {r.returncode}: {r.stderr[-300:]}")
                self.assertIn("usage", r.stdout.lower())


# ---------------------------------------------------------------- 4. secrets / PII scan

PATTERNS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"),
    "phone-intl": re.compile(r"(?<![\w+])\+(?:852|86)[\s.-]?\d[\d\s.-]{6,}\d"),
    "phone-generic": re.compile(r"(?<![\w+])\+\d{1,3}[\s.-]\d{2,4}[\s.-]\d{3,4}(?:[\s.-]\d{2,4})?(?!\d)"),
    "long-digit-run": re.compile(r"(?<![\w.])\d{9,}(?![\w.])"),
    "ipv4": re.compile(r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w.])"),
    "github-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
    "openai-style-key": re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}"),
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
    "private-key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "slack-token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "telegram-bot-token": re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
    "password-assignment": re.compile(r"""(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\b["']?\s*[:=]\s*["'][^"'\s]{4,}["']"""),
}


def redact(value):
    return value[:2] + "***" + f"({len(value)} chars)"


def scan_text(relpath, text):
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for kind, rx in PATTERNS.items():
            for m in rx.finditer(line):
                hits.append((relpath, lineno, kind, m.group(0)))
    return hits


class SecretsScan(unittest.TestCase):
    def test_scan_detects_known_shapes(self):
        """Guard against a silently broken scanner (fixtures are built at run time, not stored)."""
        samples = {
            "email": "a" + "@" + "example.org",
            "ipv4": ".".join(["10", "20", "30", "40"]),
            "github-token": "ghp" + "_" + "A" * 24,
            "aws-access-key": "AKIA" + "B" * 16,
            "private-key": "-----BEGIN " + "RSA PRIVATE KEY-----",
            "long-digit-run": "1" * 10,
            "phone-intl": "+" + "852 1234 5678",
        }
        for kind, sample in samples.items():
            self.assertTrue(PATTERNS[kind].search(sample), kind)

    def test_no_secrets_or_personal_identifiers(self):
        problems, used = [], set()
        for p in iter_files():
            if p.resolve() == THIS_FILE:
                continue  # this file holds the patterns and the allow-list itself
            text = read_text(p)
            if text is None:
                continue
            for relpath, lineno, kind, value in scan_text(rel(p), text):
                key = (relpath, kind, value)
                if key in ALLOW:
                    used.add(key)
                    continue
                problems.append(f"{relpath}:{lineno}: {kind} {redact(value)}")
        self.assertEqual(problems, [], "secret / PII scan hits (values redacted):\n" + "\n".join(problems))

    def test_allow_list_has_no_stale_entries(self):
        present = set()
        for p in iter_files():
            if p.resolve() == THIS_FILE:
                continue
            text = read_text(p)
            if text is None:
                continue
            present.update((r, k, v) for r, _, k, v in scan_text(rel(p), text))
        stale = sorted(set(ALLOW) - present)
        self.assertEqual(stale, [], "allow-list entries that no longer match anything: " + repr([(a, b) for a, b, _ in stale]))


# ---------------------------------------------------------------- 5. workflow actions pinned

class WorkflowPins(unittest.TestCase):
    def test_actions_pinned_by_full_sha(self):
        wf_dir = ROOT / ".github" / "workflows"
        if not wf_dir.is_dir():
            self.skipTest("no workflows")
        for wf in sorted(wf_dir.glob("*.y*ml")):
            for lineno, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
                m = re.match(r"^\s*-?\s*uses:\s*(\S+)", line)
                if not m or m.group(1).startswith("./"):
                    continue
                self.assertRegex(m.group(1), r"@[0-9a-f]{40}$", f"{rel(wf)}:{lineno}: action not pinned to a full commit SHA")
                self.assertRegex(line, r"#\s*v\d+\.\d+\.\d+\s*$", f"{rel(wf)}:{lineno}: missing trailing '# vX.Y.Z' comment")


if __name__ == "__main__":
    unittest.main()
