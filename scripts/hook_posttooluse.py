#!/usr/bin/env python3
"""
PostToolUse hook: rewrites tool results through the redaction engine.

Contract (Claude Code >= 2.1.121, verified on 2.1.227):
  stdin  <- {"tool_name":..., "tool_input":..., "tool_response":..., ...}
  stdout -> {"hookSpecificOutput": {"hookEventName":"PostToolUse",
                                    "updatedToolOutput": "..."}}

Two deliberate properties:

1. Emits NOTHING when the output did not change. Most tool results contain no
   personal data, and a silent no-op keeps their normal rendering intact. Blast
   radius is limited to results that actually matched something.

2. Fails LOUD while armed. If the engine throws, the raw result is passed
   through behind an unmissable banner rather than withheld. A withheld result
   loses the take anyway, and seeing the failure immediately is what lets you
   cut and re-record instead of discovering it in post.
   Prefer fail-closed? Set `fail_closed: true` in your config.

   Understand the tradeoff: on an engine error the unredacted data IS on screen
   for that frame. The banner does not prevent the leak, it guarantees you
   notice it. That footage must be cut, not shipped.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

FOOTER = "\n\n[redacted: {n} item(s)]"

BANNER = (
    "\n"
    "!!! ========================================================== !!!\n"
    "!!!  REDACTION FAILED. THE OUTPUT BELOW IS RAW.               !!!\n"
    "!!!  STOP RECORDING AND CUT THIS TAKE.                        !!!\n"
    "!!!  Then run: bodydouble doctor                              !!!\n"
    "!!!  reason: {err}\n"
    "!!! ========================================================== !!!\n\n"
)


def extract_text(response):
    """Best plain-text rendering of a tool_response of unknown shape."""
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        if "stdout" in response or "stderr" in response:
            parts = []
            out = response.get("stdout") or ""
            err = response.get("stderr") or ""
            if out:
                parts.append(out)
            if err:
                parts.append(err if not out else "\n" + err)
            return "".join(parts)
        for key in ("content", "text", "output", "result", "data"):
            if key in response:
                val = response[key]
                if isinstance(val, str):
                    return val
                if isinstance(val, list):
                    chunks = []
                    for block in val:
                        if isinstance(block, dict) and isinstance(block.get("text"), str):
                            chunks.append(block["text"])
                        elif isinstance(block, str):
                            chunks.append(block)
                    if chunks:
                        return "\n".join(chunks)
        if isinstance(response.get("file"), dict):
            content = response["file"].get("content")
            if isinstance(content, str):
                return content
    try:
        return json.dumps(response, indent=2, ensure_ascii=False)
    except Exception:
        return str(response)


def emit(text):
    json.dump({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": text,
        }
    }, sys.stdout)
    sys.stdout.write("\n")


def main():
    raw = sys.stdin.read()

    try:
        import redact_engine
    except Exception:
        # Engine missing entirely. Stay silent rather than break the session:
        # `bodydouble doctor` is what surfaces this, not a broken tool result.
        return 0

    if not redact_engine.is_armed():
        return 0

    try:
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        return 0

    original = ""
    config = {}
    try:
        original = extract_text(payload.get("tool_response"))
        if not original:
            return 0
        terms, config = redact_engine.load_terms()
        masked, hits = redact_engine.mask_text(
            original, terms, config, cwd=payload.get("cwd"))
    except Exception as exc:
        # Two honest ways to fail, and which is right depends on what you are doing.
        # fail_closed withholds the result: safest, but you lose the output.
        # Default is fail-loud: you see the raw data AND an unmissable banner, so you
        # cut the take deliberately instead of discovering the leak in post.
        try:
            if not config:
                config = redact_engine.load_terms()[1]
        except Exception:
            config = {}
        if (config or {}).get("fail_closed"):
            emit(BANNER.format(err=str(exc)[:200])
                 + "[output withheld: fail_closed is enabled]")
        else:
            emit(BANNER.format(err=str(exc)[:200]) + original)
        return 0

    total = sum(hits.values())
    if total == 0 or masked == original:
        return 0

    if (config or {}).get("show_footer", True):
        masked = masked + FOOTER.format(n=total)
    emit(masked)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(0)
