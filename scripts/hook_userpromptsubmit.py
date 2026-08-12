#!/usr/bin/env python3
"""
UserPromptSubmit hook: when redaction is armed and your own prompt contains a
protected term, tell Claude not to echo it back.

This closes the loop the PostToolUse hook cannot reach. Tool output is
redacted deterministically; Claude's own prose is not, so if you type a real
name the model will happily repeat it in its reply, on camera.

Limit worth stating plainly: the typed prompt is already rendered on screen
before any hook runs. This prevents the ECHO, not the original keystrokes.
The fix for keystrokes is habit, not software.

The injected context never contains the term itself, only a count.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

GUIDANCE = (
    "RECORDING MODE IS ARMED. The user's prompt contained {n} term(s) on the "
    "private mask list. Do not repeat those terms in your reply, in code, in "
    "commit messages, in file names, or in any file you write. Refer to the "
    "people or values generically (spouse, child, relative, provider, the "
    "account). If you must write one to disk for the work to function, say so "
    "first and ask. Never state which term was matched."
)


def main():
    raw = sys.stdin.read()
    try:
        import redact_engine
    except Exception:
        return 0
    if not redact_engine.is_armed():
        return 0
    try:
        payload = json.loads(raw) if raw.strip() else {}
        prompt = payload.get("prompt") or ""
        if not prompt:
            return 0
        terms, config = redact_engine.load_terms()
        _masked, hits = redact_engine.mask_text(prompt, terms, config)
    except Exception:
        return 0

    total = sum(hits.values())
    if total == 0:
        return 0

    json.dump({
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": GUIDANCE.format(n=total),
        }
    }, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(0)
