---
name: body-double
description: Redacts personal and sensitive information from terminal output before it reaches the screen, for screen recording, streaming, and screen sharing. Substitutes readable stand-ins for names, credentials, medical details, financial numbers, emails, paths and IPs via a PostToolUse hook. Use when the user says redact, mask, sanitize, PII, sensitive info, "going on camera", "screen recording", "recording this", "streaming", "screen sharing", "demoing this", or asks what would leak if they opened a repo on screen. Also use before demoing any repo containing family, medical, client, or credential data.
---

# body-double

Substitution-based redaction. Deterministic where it can be, honest about where it cannot.

## Layers

Only one of these is deterministic. Know which is which before trusting it on camera.

| Layer | Covers | Mechanism | Reliability |
|---|---|---|---|
| 1 | Tool results (Bash, Read, Grep, Glob, MCP) | `PostToolUse` hook rewriting `updatedToolOutput` | Deterministic |
| 2 | Your own prose, code, commit messages | this file, plus `UserPromptSubmit` context injection | Probabilistic |
| 3 | The user's keystrokes, their shell prompt, other windows | their habits, plus `bodydouble preflight` | Manual |

**Layer 1 cannot be bypassed by the model. Layers 2 and 3 can.**

## Behavior when armed

Check `~/.body-double/private/state`. When it reads `armed`:

1. Never write a real name, address, provider, diagnosis, dose, account number, or key
   into your reply, into code, into a commit message, or into a file. Use the generic
   form the user configured: spouse, child one, the client, provider, the account.
2. Never state which term matched. "A protected term" is the whole report.
3. Prefer `rg -l` over `cat`, `head -20` over whole files, targeted reads over directory
   sweeps. Less output on screen is the cheapest mitigation available.
4. Treat armed as **read-only mode**. The hook replaces tool results before you see them,
   so a file you read comes back redacted. An `Edit` built on that fails loudly, which is
   safe, but a full-file `Write` built on it would put a placeholder into the user's real
   file. Do not do file surgery while armed; say so and ask them to disarm.
5. Before running anything against a directory `preflight` marked HOT, say so and ask.
6. If asked to disarm mid-recording, confirm explicitly first.

## Commands

`bodydouble` is on PATH after install.

| Command | Does |
|---|---|
| `on` / `off` / `status` | Arm, disarm, report. Never prints terms. |
| `canary` | Prove the hook is live in this session. The only check that can. |
| `doctor` | End-to-end proof that the wiring works. |
| `selftest` | Collision check on the user's term list. |
| `preflight [PATH]` | Per-directory leak severity. Prints no matched text. |
| `add` / `rm` / `list` | Manage terms. Never suggest the user type a term into chat. |
| `footer on` / `off` | Show or hide the redaction count. |

## Things to get right

**Never ask for a term in chat.** The transcript is written to disk. Direct them to
`bodydouble add`, which reads input hidden so it misses both the screen and shell history.

**`status` is not proof.** The arm state is global; the hook is per session. A session
started before the hook was registered reports ARMED and redacts nothing. Only `canary`
distinguishes them.

**Hooks load at session start.** After any install or settings change, the session must
be restarted. Only the session being recorded needs it; other terminals are unaffected and
usually should stay unredacted so real work can proceed.

Full detail, configuration, and the pre-record checklist: see `README.md`.
