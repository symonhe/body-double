#!/usr/bin/env python3
"""
Install body-double.

  python3 install.py              install, and wire Claude Code hooks if present
  python3 install.py --no-hooks   install the CLI only, skip hook registration
  python3 install.py --uninstall  remove the hooks and the PATH symlink

Idempotent: run it as often as you like. It creates NO terms; those are yours,
and `bodydouble add` is the safe way to enter them.

Nothing here touches your existing hooks or settings beyond appending the two
body-double entries, and it backs up settings.json before its first write.
"""

import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
SCRIPTS = os.path.join(HERE, "scripts")
PRIVATE = os.path.expanduser("~/.body-double/private")
CLAUDE_SETTINGS = os.path.expanduser("~/.claude/settings.json")

# The system python3 is the right interpreter for a hook: always present, no venv
# to activate, and the engine is stdlib-only by design. -B keeps __pycache__ out of
# a directory you may browse on camera.
PY = "/usr/bin/python3 -B" if os.path.exists("/usr/bin/python3") else "python3 -B"

HOOKS = [
    ("PostToolUse", {"matcher": "*", "hooks": [{
        "type": "command",
        "command": "%s %s/hook_posttooluse.py" % (PY, SCRIPTS),
        "timeout": 15}]}, "hook_posttooluse.py"),
    ("UserPromptSubmit", {"hooks": [{
        "type": "command",
        "command": "%s %s/hook_userpromptsubmit.py" % (PY, SCRIPTS),
        "timeout": 10}]}, "hook_userpromptsubmit.py"),
]


def bin_dir():
    """First writable directory on PATH we would actually want to use."""
    for candidate in (os.path.expanduser("~/.local/bin"), "/usr/local/bin"):
        if candidate in os.environ.get("PATH", "").split(os.pathsep):
            if os.path.isdir(candidate) and os.access(candidate, os.W_OK):
                return candidate
    fallback = os.path.expanduser("~/.local/bin")
    os.makedirs(fallback, exist_ok=True)
    return fallback


def read_settings():
    try:
        with open(CLAUDE_SETTINGS, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except Exception as exc:
        print("  ! ~/.claude/settings.json is unreadable (%s); skipping hooks" % exc)
        return False


def write_settings(data):
    backup = CLAUDE_SETTINGS + ".bak-body-double"
    if os.path.exists(CLAUDE_SETTINGS) and not os.path.exists(backup):
        shutil.copy2(CLAUDE_SETTINGS, backup)
        print("  backed up settings.json -> %s" % os.path.basename(backup))
    with open(CLAUDE_SETTINGS, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def uninstall():
    link = os.path.join(bin_dir(), "bodydouble")
    if os.path.islink(link):
        os.remove(link)
        print("  removed %s" % link)
    data = read_settings()
    if data:
        hooks = data.get("hooks", {})
        for event, _entry, marker in HOOKS:
            before = len(hooks.get(event, []))
            hooks[event] = [e for e in hooks.get(event, [])
                            if marker not in json.dumps(e)]
            if len(hooks[event]) != before:
                print("  unregistered %s hook" % event)
            if not hooks[event]:
                del hooks[event]
        write_settings(data)
    print("\nDone. Your terms at %s were NOT touched." % PRIVATE)
    print("Delete that directory yourself if you want them gone.")
    return 0


def main():
    if "--uninstall" in sys.argv:
        return uninstall()

    os.makedirs(PRIVATE, mode=0o700, exist_ok=True)
    os.chmod(PRIVATE, 0o700)
    os.chmod(os.path.dirname(PRIVATE), 0o700)
    print("  private dir: %s (0700)" % PRIVATE)

    for name in os.listdir(SCRIPTS):
        if not name.startswith("."):
            os.chmod(os.path.join(SCRIPTS, name), 0o755)

    target = os.path.join(SCRIPTS, "bodydouble")
    link = os.path.join(bin_dir(), "bodydouble")
    if os.path.islink(link) or os.path.exists(link):
        os.remove(link)
    os.symlink(target, link)
    print("  bodydouble -> %s" % link)
    if bin_dir() not in os.environ.get("PATH", ""):
        print("  ! %s is not on your PATH; add it to your shell profile" % bin_dir())

    # Register the agent-behavior layer too, if this machine has a skills dir.
    # SKILL.md is what tells the assistant how to behave while armed; without it
    # only the deterministic hook layer is active.
    skills_dir = os.path.expanduser("~/.claude/skills")
    if os.path.isdir(skills_dir):
        skill_link = os.path.join(skills_dir, "body-double")
        try:
            if os.path.islink(skill_link):
                os.remove(skill_link)
            if not os.path.exists(skill_link):
                os.symlink(HERE, skill_link)
                print("  skill -> %s" % skill_link)
            else:
                print("  ! %s exists and is not a symlink; left alone" % skill_link)
        except OSError as exc:
            print("  ! could not link the skill (%s)" % exc)

    if "--no-hooks" not in sys.argv:
        data = read_settings()
        if data is None:
            print("  no ~/.claude/settings.json found; skipping hook registration")
            print("  (the CLI and the stdin filter still work without Claude Code)")
        elif data is not False:
            hooks = data.setdefault("hooks", {})
            changed = False
            for event, entry, marker in HOOKS:
                existing = hooks.setdefault(event, [])
                if marker in json.dumps(existing):
                    print("  %s hook already registered" % event)
                    continue
                existing.append(entry)
                changed = True
                print("  registered %s hook" % event)
            if changed:
                write_settings(data)

    print("\nNext:")
    print("  1. bodydouble add        add what you want protected (input is hidden)")
    print("  2. restart your AI session   hooks load at startup")
    print("  3. bodydouble doctor     confirm the wiring")
    print("  4. bodydouble canary     confirm the hook is live in that session")
    print("\nNo terms were created. An annotated example is in terms.example.json.")

    print("\nRunning doctor:\n")
    sys.stdout.flush()  # subprocess writes straight to fd 1; flush or our summary lands after it
    subprocess.call([target, "doctor"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
