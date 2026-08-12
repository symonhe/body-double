# body-double

**Substitution-based redaction for terminal and AI-agent output, so you can record without scrubbing the footage afterward.**

A body double stands in for the real person on camera. This does the same for your data:
it replaces real values with readable stand-ins **before they render**, rather than
blurring pixels after the fact.

```
Jane took Riley to see Dr. Alvarez. 500 mg daily.  ANTHROPIC_API_KEY=sk-ant-api03-Rk9...
        ↓
Spouse took child one to see Dr. [provider]. [dose].  ANTHROPIC_API_KEY=[redacted]
```

Built for people who screen-record coding sessions, stream, pair on a shared screen, or
demo a real working environment that happens to contain real data.

---

## Why substitution instead of blur

Every other tool in this space obscures pixels after rendering. This changes text before
it renders. That is a category difference, not a setting.

| | Blur / pixelate / fill | Substitution |
|---|---|---|
| Operates on | rendered pixels | text, before render |
| Recoverable | blur is reversible at zoom, which is why it is unsafe for credentials | nothing to recover, the original never reached the screen |
| Output afterward | unreadable box | still readable, still useful |
| Works with an agent | no, it is on the glass | yes, it is in the data path |

That last row is the point. Because it runs in the data path, an AI agent reading your
files also receives the redacted text.

---

## What it actually covers

Be honest with yourself about this before you hit record. Only one layer is deterministic.

| Layer | Covers | Mechanism | Reliability |
|---|---|---|---|
| 1 | Tool output: shell commands, file reads, greps, MCP results | `PostToolUse` hook | **Deterministic** |
| 2 | The AI's own prose, code, and commit messages | instructions + prompt-hook context injection | Probabilistic |
| 3 | Your keystrokes, your shell prompt, other windows, images | your habits, plus `preflight` | Manual |

**Layer 1 cannot be talked out of it. Layers 2 and 3 can.** If a leak would be
career-ending, or it is somebody else's medical data, do not put it behind layer 2.

Things it does **not** and cannot do:

- Unsee what you typed. The prompt hook stops the model echoing a name; it cannot
  un-render your own keystrokes.
- Redact your shell prompt. If your working directory is `~/work/acme-layoffs/`, that is
  on screen continuously.
- Touch anything outside the terminal: your editor, browser tabs, notifications.
- Detect names it was never told about. There is no NER and no model. It redacts what you
  list, plus fixed high-confidence patterns. That refusal is deliberate: guessing is
  slower, misses uncommon names, and mangles ordinary output.

This is a **footage hygiene tool, not a security product.** It shrinks the manual scrub
pass. It does not replace reviewing your video.

---

## Install

Requires Python 3.9+ (the system `python3` on macOS is fine). No dependencies, stdlib only.

```bash
git clone https://github.com/symonhe/body-double.git ~/.body-double
python3 ~/.body-double/install.py
```

That creates `~/.body-double/private/` (mode 700), puts `bodydouble` on your PATH, and, if
you use Claude Code, registers the hooks in `~/.claude/settings.json`. It creates **no
terms**; those are yours.

Then add what you want protected:

```bash
bodydouble add        # input is hidden: never on screen, never in shell history
```

**Restart your AI session afterward.** Hooks load at startup.

---

## Use

```bash
bodydouble preflight ~/work   # what would leak if you opened this on camera
bodydouble doctor             # prove the wiring works
bodydouble on                 # arm before you record
bodydouble canary             # prove the hook is live in THIS session
bodydouble off                # disarm when you stop
```

### Without an AI agent

The engine is a plain stdin filter, so it works anywhere:

```bash
kubectl get secrets -o yaml | python3 ~/.body-double/scripts/redact_engine.py --force
tail -f app.log | python3 ~/.body-double/scripts/redact_engine.py --force
```

---

## Commands

| Command | Does |
|---|---|
| `on` / `off` / `status` | Arm, disarm, report. Never prints your terms. |
| `canary` | Prove the hook is live in this session. The only check that can. |
| `add` / `rm` / `list` | Manage terms. `list` shows counts and kinds only. |
| `footer on` / `off` | Show or hide the redaction count in output. |
| `doctor` | End-to-end proof: feeds the hook a synthetic payload, checks it redacts. |
| `selftest` | Collision check. Catches a term that would eat ordinary words. |
| `preflight [PATH]` | Per-directory leak severity. Prints no matched text. |
| `test` | Pipe stdin through the engine, ignoring the arm state. |

---

## What it detects out of the box

Your own terms, plus these built-in categories (35 patterns across 9 categories, plus two rules that need more than a pattern: Luhn-validated cards and line-scoped birth dates):

**Credentials** Anthropic, OpenAI, GitHub, AWS, Google, Slack, Stripe, SendGrid,
HuggingFace and npm keys; JWTs; PEM private keys; `Authorization:` headers; any
`*_KEY` / `*_SECRET` / `*_TOKEN` / `PASSWORD` assignment; and passwords hidden in
connection strings (`postgres://user:pw@host`, `redis://`, `mongodb://`).

**Identity** emails, phone numbers (US and international), SSN-shaped values.

**Financial** IBAN, routing and account numbers, CVV, card expiry, and card numbers
**validated by Luhn**.

**Medical** `Dr. Name`, `Name, MD`, dosages, MRN and patient IDs, insurance policy,
group, Medicare and Medicaid numbers, and birth dates on any line labelled as one.

**Location and network** street addresses, precise coordinates, IPv4, MAC addresses.

**System** your OS username, everywhere it appears, including inside every absolute path.

> Luhn validation is load-bearing. Without it, the card rule eats commit hashes,
> row counts, and millisecond timestamps. Verified: real Visa/Mastercard/Amex numbers
> redact; a 40-char commit SHA and a 16-digit millisecond count do not.

---

## Configuration

`~/.body-double/private/terms.json`, mode 600. See `terms.example.json`.

```json
{
  "config": {
    "username": "yourusername",
    "mask_username": true,
    "show_footer": true,
    "fail_closed": false,
    "disabled_builtins": [],
    "path_overrides": [
      {"path_contains": "/work/analytics/", "disable_builtins": ["financial"]}
    ]
  },
  "terms": [
    {"match": "Jane Smith", "replace": "spouse", "variants": ["Jane"], "kind": "name"}
  ]
}
```

**`path_overrides`** turns a category off under a matching directory. A category can be
correct in one tree and harmful in another: a folder full of numeric data will trip the
account-number rule, and hiding numbers you need to read is worse than showing them.

**`show_footer`** appends `[redacted: 3 item(s)]` to any output that was changed. It
defaults to **on**, because the first thing a new user needs is proof the thing works.
Turn it off before you record so it stays out of your footage: `bodydouble footer off`.

**`fail_closed`** decides what happens if the engine throws while armed. Default is
fail-loud: raw output behind an unmissable banner, so you notice immediately and cut the
take. Set `true` to withhold the output instead.

---

## Three properties worth knowing

**Silent when clean.** The hook emits nothing when a result contains no matches, so normal
output renders normally. Only results that actually matched are ever rewritten.

**Armed is effectively read-only mode.** The hook replaces the tool result *before the
model sees it*, not just before you see it. So while armed, an AI reading a file gets the
redacted text. An edit built on that fails loudly, which is safe, but a full-file rewrite
built on it would write a placeholder into your real file. **Do not do file surgery while
armed.** Recording sessions are for showing and asking.

**Your term list is the most sensitive file you own.** It is a directory of exactly the
names you are protecting. It lives outside this repo, mode 600, and nothing in this tool
ever prints a term back to the screen, including `status` and `list`. Do not sync it
anywhere you would not sync a password file.

---

## Gotchas

| Symptom | Cause | Fix |
|---|---|---|
| Nothing is redacted | session predates the hook, or disarmed | restart the session, `on`, then `canary` |
| `status` says ARMED but nothing redacts | the arm state is global, the hook is per session | `canary` reports the wire; `status` only reports the switch |
| Ordinary words replaced | a term short enough to stand alone as a real word | `selftest`, then use a longer form |
| Giant `REDACTION FAILED` banner | engine threw while armed | the text below it is RAW. Cut the take, run `doctor` |
| An edit fails on text you can see | you are armed, so the model read the redacted form | disarm for file work |

Word boundaries mean a short term does **not** eat longer words containing it. A
three-letter name will not break `origin`. Run `selftest` to confirm against your own list.

---

## Pre-record checklist

1. `bodydouble preflight <the repo you are demoing>`, note the HOT directories
2. Restart the session you will record in
3. `bodydouble doctor`, every line PASS
4. `cd` out of any path whose **name** is sensitive
5. `bodydouble on`
6. `bodydouble canary`, confirm the fake values come back redacted
7. `bodydouble footer off` so the redaction counter stays out of the video
8. Record
9. `bodydouble off`
10. Review the video anyway

---

## License

MIT. See [LICENSE](LICENSE).

Contributions welcome, especially additional built-in patterns. Please do not open an
issue containing real data you are trying to redact.
