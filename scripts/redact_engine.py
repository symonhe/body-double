#!/usr/bin/env python3
"""
Redaction engine for the body-double.

Stdlib only, Python 3.9 compatible, no network, no third-party imports.
Designed to run on every tool result, so it must stay fast and must never
raise into the caller.

The term list (the actual names) lives OUTSIDE this directory, in
~/.body-double/private/terms.json, mode 600. Nothing in this file contains
personal data. Nothing here ever prints a term back out.
"""

import json
import os
import re
import sys

# Set BODY_DOUBLE_HOME to keep separate profiles, point at an encrypted volume, or
# test against a throwaway list without touching your real one.
_HOME = os.environ.get("BODY_DOUBLE_HOME") or os.path.expanduser("~/.body-double")
PRIVATE_DIR = os.path.join(_HOME, "private")
TERMS_PATH = os.path.join(PRIVATE_DIR, "terms.json")
STATE_PATH = os.path.join(PRIVATE_DIR, "state")

# ---------------------------------------------------------------------------
# Built-in patterns. These contain NO personal data and are safe to ship.
# Order matters: earlier rules win, so specific beats generic.
# ---------------------------------------------------------------------------

BUILTIN = [
    # --- credentials and keys. Highest severity on a recording. ---
    ("secret", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", "[private-key]"),
    ("secret", r"\bsk-ant-[A-Za-z0-9_\-]{20,}", "[anthropic-key]"),
    ("secret", r"\bsk-proj-[A-Za-z0-9_\-]{20,}", "[openai-key]"),
    ("secret", r"\bsk-[A-Za-z0-9]{32,}", "[api-key]"),
    ("secret", r"\b(?:gh[pousr])_[A-Za-z0-9]{30,}", "[github-token]"),
    ("secret", r"\bgithub_pat_[A-Za-z0-9_]{50,}", "[github-token]"),
    ("secret", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "[aws-key-id]"),
    ("secret", r"\bAIza[0-9A-Za-z_\-]{35}\b", "[google-api-key]"),
    ("secret", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}", "[slack-token]"),
    ("secret", r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}", "[stripe-key]"),
    ("secret", r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}", "[sendgrid-key]"),
    ("secret", r"\bhf_[A-Za-z0-9]{30,}", "[hf-token]"),
    ("secret", r"\bnpm_[A-Za-z0-9]{30,}", "[npm-token]"),
    ("secret", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", "[jwt]"),
    ("secret", r"(?i)\b(?:authorization|bearer)\s*[:=]?\s*[\"']?[A-Za-z0-9_\-\.=]{24,}[\"']?", "[auth-header]"),
    ("secret", r"(?i)\b([A-Z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWD|PASSWORD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)[A-Z0-9_]*)\s*[:=]\s*[\"']?([^\s\"',;]{8,})[\"']?", r"\1=[redacted]"),

    # --- identity and contact ---
    ("email", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "[email]"),
    ("phone", r"(?<![\w.])(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}(?![\w.])", "[phone]"),
    ("phone", r"(?<![\w.])\+(?:[0-9][\s.\-]?){9,14}[0-9](?![\w.])", "[phone]"),
    ("gov_id", r"(?<![\w\-])\d{3}-\d{2}-\d{4}(?![\w\-])", "[gov-id]"),

    # --- financial ---
    ("financial", r"(?<![\w\-])[A-Z]{2}\d{2}[A-Z0-9]{11,30}(?![\w\-])", "[iban]"),
    ("financial", r"(?i)\b(?:acct|account|routing|aba)\s*(?:no\.?|number|#)?\s*[:=#]?\s*\d{6,17}\b", "[account-number]"),
    ("financial", r"(?i)\b(?:cvv|cvc|security code)\s*[:#=]?\s*\d{3,4}\b", "[cvv]"),
    ("financial", r"(?i)\bexp(?:iry|iration)?\s*(?:date)?\s*[:#=]?\s*(?:0[1-9]|1[0-2])\s*/\s*\d{2,4}\b", "[card-expiry]"),

    # --- dates of birth. Deliberately keyword-anchored: a bare date is not PII
    # and masking every ISO date would destroy ordinary log output. ---
    ("dob", r"(?i)\b(?:dob|d\.o\.b\.|date of birth|born(?:\s+on)?)\s*[:#=]?\s*[\w/\-\., ]{6,20}?(?=\s|$|[,;.])", "DOB: [date]"),

    # --- location ---
    ("address", r"(?i)\b\d{1,5}\s+(?:[A-Z][A-Za-z.'\-]*\s+){0,4}(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|way|place|pl|terrace|ter|circle|cir)\b\.?(?:[,\s]+(?:apt|apartment|unit|suite|ste|#)\s*[\w\-]+)?", "[street-address]"),
    ("geo", r"(?<![\w.])-?\d{1,2}\.\d{5,}\s*,\s*-?\d{1,3}\.\d{5,}(?![\w.])", "[coordinates]"),

    # --- network ---
    ("network", r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", "[ip]"),
    ("network", r"(?<![\w:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![\w:])", "[mac]"),

    # --- medical ---
    # Scoped (?i:...) on the TITLE only. A global (?i) would make [A-Z]
    # case-insensitive too, so "Dr. Alvarez prescribed" matched as a two-word
    # name and swallowed the verb. The name part must stay case-SENSITIVE.
    ("medical", r"\b(?i:Dr|Doctor|Prof)\.?\s+[A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+)?", "Dr. [provider]"),
    ("medical", r"\b[A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+)?,\s*(?:M\.?D\.?|D\.?O\.?|N\.?P\.?|P\.?A\.?|R\.?N\.?|D\.?D\.?S\.?)\b", "[provider], [credential]"),
    ("medical", r"(?i)(?<![\w.])\d+(?:\.\d+)?\s?(?:mg|mcg|ug|ml|cc|iu|units?)\b(?:\s?(?:bid|tid|qid|qd|prn|po|daily|twice daily))?", "[dose]"),
    ("medical", r"(?i)\b(?:MRN|medical record (?:no\.?|number)|patient (?:id|no\.?|number))\s*[:#=]?\s*[\w\-]{4,}", "[patient-id]"),
    # Accepts "policy: BCBS-IL-77120458" and "group number 0093311" alike: either an
    # id-word or an explicit separator will do, but one of them is required so that
    # ordinary phrases like "group of parents" are left alone.
    ("medical", r"(?i)\b(?:policy|member|group|medicare|medicaid)\s*(?:(?:id|no\.?|number|#)\s*[:#=]?\s*|[:#=]\s*)[\w\-]{5,}", "[insurance-id]"),
    # Medicare/Medicaid IDs are often written with no separator at all. Safe to
    # allow because the lookahead demands a digit in the token, so "Medicare
    # program" and "Medicaid expansion" are left alone.
    ("medical", r"(?i)\b(?:medicare|medicaid)\s+(?=[\w\-]*\d)[A-Za-z0-9][\w\-]{4,}", "[insurance-id]"),
]

# Compiled lazily and cached at module import.
_COMPILED_BUILTIN = []
for _name, _pat, _repl in BUILTIN:
    try:
        _COMPILED_BUILTIN.append((_name, re.compile(_pat), _repl))
    except re.error:  # pragma: no cover - a bad builtin should never ship
        pass


# ---------------------------------------------------------------------------
# Term list
# ---------------------------------------------------------------------------

def load_terms(path=TERMS_PATH):
    """Return (compiled_terms, config). Never raises."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return [], {}

    config = data.get("config", {}) or {}
    raw = data.get("terms", []) or []
    expanded = []
    for entry in raw:
        try:
            replacement = entry["replace"]
            forms = [entry["match"]] + list(entry.get("variants", []) or [])
        except (KeyError, TypeError):
            continue
        for form in forms:
            form = (form or "").strip()
            if form:
                expanded.append((form, replacement, entry.get("kind", "name")))

    # Longest first so "Jane Smith" wins over "Jane".
    expanded.sort(key=lambda t: len(t[0]), reverse=True)

    compiled = []
    for form, replacement, kind in expanded:
        # \b fails next to non-word chars, so bound on lookarounds instead.
        pattern = r"(?<![\w])" + re.escape(form).replace(r"\ ", r"[\s_\-]+") + r"(?![\w])"
        try:
            compiled.append((re.compile(pattern, re.IGNORECASE), replacement, kind, form))
        except re.error:
            continue
    return compiled, config


# ---------------------------------------------------------------------------
# Callable rules: things regex alone cannot decide.
# ---------------------------------------------------------------------------

_CARD_CANDIDATE = re.compile(r"(?<![\w\-])(?:\d[ \-]?){12,18}\d(?![\w\-])")


def _luhn_ok(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _mask_cards(text):
    """Mask only digit runs that actually validate as card numbers.

    Luhn is the whole point. Without it this rule would eat commit hashes,
    row counts, timestamps, and every other long number in ordinary output.
    """
    count = [0]

    def repl(m):
        raw = m.group(0)
        digits = re.sub(r"[ \-]", "", raw)
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            count[0] += 1
            return "[card-number]"
        return raw

    return _CARD_CANDIDATE.sub(repl, text), count[0]


SENTENCE_END = ".!?:;\n"


def _case_match(original, replacement, text=None, start=None):
    """Capitalize the replacement only at a sentence start.

    Naively copying the original's capitalization produced "left The school for
    The clinic", because a proper noun is capitalized wherever it appears while
    its replacement is usually a common noun phrase that should not be.
    """
    if replacement[:1].isupper():
        return replacement
    at_start = True
    if text is not None and start:
        before = text[:start].rstrip()
        at_start = (not before) or before[-1] in SENTENCE_END
    elif start == 0:
        at_start = True
    if at_start and original[:1].isupper():
        return replacement[:1].upper() + replacement[1:]
    return replacement


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def effective_disabled(config, cwd=None):
    """Global disabled categories plus any path-scoped override for this cwd.

    Exists because a category can be correct in one tree and actively harmful in
    another. Example: a directory of numeric data trips the account-number rule,
    and hiding numbers you need to read is worse than showing them.
    """
    disabled = set((config or {}).get("disabled_builtins", []) or [])
    if not cwd:
        return disabled
    for rule in (config or {}).get("path_overrides", []) or []:
        needle = rule.get("path_contains")
        if needle and needle in cwd:
            disabled |= set(rule.get("disable_builtins", []) or [])
    return disabled


def mask_text(text, compiled_terms=None, config=None, enabled_builtins=None, cwd=None):
    """Mask a string. Returns (masked_text, hit_counts_by_category)."""
    if not text or not isinstance(text, str):
        return text, {}

    if compiled_terms is None:
        compiled_terms, config = load_terms()
    config = config or {}
    hits = {}

    def bump(key, n=1):
        if n:
            hits[key] = hits.get(key, 0) + n

    # 1. Personal terms first. These are the ones that matter most.
    for regex, replacement, kind, _form in compiled_terms:
        def _sub(m, _r=replacement):
            return _case_match(m.group(0), _r, m.string, m.start())
        text, n = regex.subn(_sub, text)
        bump(kind, n)

    # 2. Home directory and username. Runs before generic path rules.
    user = config.get("username") or os.environ.get("USER") or ""
    if user and config.get("mask_username", True):
        text, n = re.subn(r"/Users/" + re.escape(user) + r"\b", "/Users/user", text)
        bump("path", n)
        text, n = re.subn(r"(?<![\w])" + re.escape(user) + r"(?![\w])", "user", text)
        bump("path", n)

    # 3. Extra path segments you flagged (e.g. a full name inside a directory path).
    for seg in config.get("path_segments", []) or []:
        try:
            text, n = re.subn(re.escape(seg), config.get("path_segment_replacement", "workspace"), text)
            bump("path", n)
        except re.error:
            continue

    # 4. Built-in category patterns.
    disabled = effective_disabled(config, cwd)
    for name, regex, replacement in _COMPILED_BUILTIN:
        if name in disabled:
            continue
        if enabled_builtins is not None and name not in enabled_builtins:
            continue
        text, n = regex.subn(replacement, text)
        bump(name, n)

    # 5. Callable rules that need more than a pattern to decide.
    if "financial" not in disabled:
        text, n = _mask_cards(text)
        bump("financial", n)

    return text, hits


def mask_any(obj, compiled_terms, config):
    """Recursively mask every string leaf of a JSON-ish structure."""
    total = {}

    def merge(h):
        for k, v in h.items():
            total[k] = total.get(k, 0) + v

    def walk(node):
        if isinstance(node, str):
            out, h = mask_text(node, compiled_terms, config)
            merge(h)
            return out
        if isinstance(node, list):
            return [walk(x) for x in node]
        if isinstance(node, dict):
            return dict((k, walk(v)) for k, v in node.items())
        return node

    return walk(obj), total


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

def is_armed():
    """True when masking should apply. Missing state file means disarmed."""
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as fh:
            return fh.read().strip().lower().startswith("armed")
    except Exception:
        return False


def set_armed(armed):
    os.makedirs(PRIVATE_DIR, mode=0o700, exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as fh:
        fh.write("armed" if armed else "disarmed")
    os.chmod(STATE_PATH, 0o600)


# ---------------------------------------------------------------------------
# CLI: acts as a plain stdin/stdout filter so it works outside Claude Code too.
#   some-command | python3 redact_engine.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    force = "--force" in sys.argv
    if not force and not is_armed():
        sys.stdout.write(sys.stdin.read())
        sys.exit(0)
    terms, cfg = load_terms()
    try:
        out, _ = mask_text(sys.stdin.read(), terms, cfg)
    except Exception:
        sys.stderr.write("mask: engine error, output withheld\n")
        sys.exit(1)
    sys.stdout.write(out)
