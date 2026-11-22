#!/usr/bin/env python3
"""
A pre-install static check for agent skills — the CI control.

This is the "write a check, not a rule" layer. Instead of trusting a reviewer
to read every line of every SKILL.md and every bundled script, you run this in
CI on any added or changed skill and fail the build on the patterns a stealer
needs. It is deliberately conservative: it flags, a human adjudicates.

Usage:
    scan_skill.py PATH [PATH ...]        scan skill dirs or files
    scan_skill.py --root skills          scan every skill under a tree
    scan_skill.py --sarif out.sarif ...  also write SARIF for GitHub code scanning
    scan_skill.py --allow github.com,pypi.org ...   extra egress-allowed hosts

Exit codes:
    0  clean
    1  findings (CI should fail)
    2  bad invocation / nothing to scan
"""
import sys
import re
import json
import argparse
import pathlib

# Hosts an outbound URL may point at without being flagged. Tune for your org.
DEFAULT_ALLOW = {"github.com", "raw.githubusercontent.com", "objects.githubusercontent.com"}

# Files worth scanning inside a skill. Everything else (images, lockfiles) skipped.
SCANNABLE = {".md", ".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".rb", ".pl",
             ".ps1", ".yml", ".yaml", ".toml", ".cfg", ".txt", ".json", ""}

# Each rule: (id, severity, regex, message). Severity drives SARIF level.
# "error" fails CI; "warning" is advisory but still reported.
RULES = [
    ("hidden-directive", "error",
     re.compile(r"<!--\s*agent\s*:", re.I),
     "Agent instruction hidden in an HTML comment (invisible in rendered markdown)."),
    ("hidden-html-instruction", "warning",
     re.compile(r"<!--(?:(?!-->).)*?(ignore|instead|first|before you|system)(?:(?!-->).)*?-->", re.I | re.S),
     "Imperative language inside an HTML comment; possible hidden instruction."),
    ("reads-secret-path", "error",
     re.compile(r"(\.env(\.\w+)?\b|/\.aws/|/\.ssh/|id_rsa|\.npmrc|kubeconfig|credentials\b)", re.I),
     "References a secret or credential file path."),
    ("raw-egress", "error",
     None,  # handled specially so we can apply the allowlist
     "Outbound URL to a host that is not on the egress allowlist."),
    ("exec-pipe", "error",
     re.compile(r"(curl|wget)[^\n|]*\|\s*(sh|bash|zsh|python)\b", re.I),
     "Download-and-execute: piping a fetched payload straight into a shell."),
    ("decode-and-run", "error",
     re.compile(r"\b(eval|exec)\s*\(|base64\s+(--?d|--decode)\b|atob\s*\(", re.I),
     "Decode-and-run / dynamic eval pattern (common obfuscation)."),
    ("env-exfil", "warning",
     re.compile(r"\b(printenv|os\.environ|process\.env)\b|env\s*\||\$\{?[A-Z0-9_]*(SECRET|TOKEN|KEY|PASSWORD)", re.I),
     "Reads process environment / secret-shaped variables."),
    ("unicode-smuggling", "error",
     re.compile(r"[​-‏‪-‮⁠-⁤﻿\U000e0000-\U000e007f]"),
     "Invisible / bidi / tag Unicode characters — used to smuggle hidden instructions."),
    ("base64-blob", "warning",
     re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/])"),
     "Long base64-looking blob; inspect what it decodes to."),
]

URL_RE = re.compile(r"https?://([^/\s\"'`)\]]+)", re.I)


def iter_files(paths):
    for p in paths:
        p = pathlib.Path(p)
        if p.is_file():
            yield p
        elif p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and f.suffix.lower() in SCANNABLE:
                    yield f


def scan_file(f, allow):
    """Return list of (rule_id, severity, line, col, message, snippet)."""
    out = []
    try:
        text = f.read_text(errors="replace")
    except OSError:
        return out
    lines = text.splitlines()

    def locate(pos):
        line = text.count("\n", 0, pos) + 1
        col = pos - (text.rfind("\n", 0, pos))
        return line, col

    for rid, sev, rx, msg in RULES:
        if rid == "raw-egress":
            for m in URL_RE.finditer(text):
                host = m.group(1).split("@")[-1].split(":")[0].lower()
                if host not in allow:
                    line, col = locate(m.start())
                    out.append((rid, sev, line, col, msg, m.group(0)[:60]))
            continue
        for m in rx.finditer(text):
            line, col = locate(m.start())
            snippet = m.group(0)
            snippet = snippet if snippet.strip() else repr(snippet)
            out.append((rid, sev, line, col, msg, snippet[:60]))
    return out


def to_sarif(all_findings, root):
    rules_seen = {}
    results = []
    for f, finds in all_findings:
        rel = str(f)
        for rid, sev, line, col, msg, snippet in finds:
            rules_seen.setdefault(rid, msg)
            results.append({
                "ruleId": rid,
                "level": "error" if sev == "error" else "warning",
                "message": {"text": f"{msg} (matched: {snippet!r})"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": rel},
                    "region": {"startLine": line, "startColumn": max(col, 1)},
                }}],
            })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "skill-scan",
                "informationUri": "https://github.com/your-org/skill-theft-demo",
                "rules": [{"id": r, "shortDescription": {"text": m}} for r, m in rules_seen.items()],
            }},
            "results": results,
        }],
    }


def main(argv):
    ap = argparse.ArgumentParser(description="Static safety scan for agent skills.")
    ap.add_argument("paths", nargs="*", help="skill dirs or files to scan")
    ap.add_argument("--root", help="scan every file under this tree")
    ap.add_argument("--sarif", help="write SARIF results to this file")
    ap.add_argument("--allow", default="", help="comma-separated extra allowed egress hosts")
    args = ap.parse_args(argv)

    targets = list(args.paths)
    if args.root:
        targets.append(args.root)
    if not targets:
        print("nothing to scan (pass skill paths or --root)", file=sys.stderr)
        return 2

    allow = set(DEFAULT_ALLOW)
    allow.update(h.strip().lower() for h in args.allow.split(",") if h.strip())

    all_findings = []
    error_count = warn_count = 0
    for f in iter_files(targets):
        finds = scan_file(f, allow)
        if finds:
            all_findings.append((f, finds))
            for rid, sev, *_ in finds:
                if sev == "error":
                    error_count += 1
                else:
                    warn_count += 1

    if args.sarif:
        pathlib.Path(args.sarif).write_text(json.dumps(to_sarif(all_findings, targets), indent=2))

    if not all_findings:
        print(f"PASS  no suspicious patterns in {', '.join(targets)}")
        return 0

    for f, finds in all_findings:
        for rid, sev, line, col, msg, snippet in finds:
            mark = "ERROR" if sev == "error" else "warn "
            print(f"{mark} {f}:{line}:{col}  [{rid}]")
            print(f"        {msg}")
            print(f"        matched: {snippet!r}")
    print(f"\nFAIL  {error_count} error(s), {warn_count} warning(s)")
    # Only errors fail CI; warnings are reported but non-blocking.
    return 1 if error_count else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
