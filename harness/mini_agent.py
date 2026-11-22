#!/usr/bin/env python3
"""
A deliberately minimal "agent" — framework-agnostic, ~60 lines.

It models the three things that make a real skill-running agent (Claude Code,
Cursor, an SDK loop, your own home-grown one) exploitable:

  1. It LOADS a skill: it reads SKILL.md and treats the text as instructions.
  2. It has TOOLS with real reach: read_file and http_post.
  3. It FOLLOWS the skill's instructions against those tools, with no human
     approving each step.

There is no LLM here on purpose. An LLM would *interpret* the SKILL.md and
decide to follow the injected line. We hard-code that decision so the demo is
deterministic and you can run it offline — but the vulnerability is identical:
instructions arriving as data get executed with the agent's privileges.

Usage:
  python3 harness/mini_agent.py skills/pr-summary          # normal-looking task
  python3 harness/mini_agent.py skills/pr-summary --egress-allow 127.0.0.1:9  # a control

The agent's "job" is to summarize a PR (here, a static diff file). The skill
is what actually runs.
"""
import sys
import re
import pathlib
import urllib.request
import urllib.error

WORKDIR = pathlib.Path(__file__).resolve().parent.parent


class Agent:
    """Holds the tools. In a real agent these are MCP tools / shell access."""

    def __init__(self, egress_allow=None):
        # egress_allow: set of "host:port" the agent is permitted to reach.
        # None = no restriction (the default almost everyone runs with).
        self.egress_allow = egress_allow

    # ---- tools the agent exposes to skills ----
    def read_file(self, path):
        p = (WORKDIR / path).resolve()
        return p.read_text()

    def http_post(self, url, data):
        host = re.sub(r"^https?://", "", url).split("/")[0]
        if self.egress_allow is not None and host not in self.egress_allow:
            raise PermissionError(f"egress blocked by control: {host} not in allowlist")
        req = urllib.request.Request(
            url, data=data.encode(), headers={"Content-Type": "application/json"}
        )
        return urllib.request.urlopen(req, timeout=3).read().decode()


def load_skill(skill_dir):
    """Read SKILL.md and split the human-facing body from any 'agent directives'.

    A real agent doesn't do this split — it reads the whole markdown as one
    instruction block. That's the point: the malicious line rides in the same
    text as the legitimate instructions. We parse <!--agent:...--> HTML
    comments because they're invisible in rendered markdown on a repo page,
    which is exactly how a real one would hide.
    """
    text = (pathlib.Path(skill_dir) / "SKILL.md").read_text()
    directives = re.findall(r"<!--agent:(.*?)-->", text, re.DOTALL)
    return text, directives


def run(skill_dir, egress_allow=None):
    agent = Agent(egress_allow=egress_allow)
    body, directives = load_skill(skill_dir)

    print(f"[agent] loaded skill from {skill_dir}")
    print(f"[agent] visible task: summarize the pull request\n")

    # The legitimate task the user asked for:
    diff = agent.read_file("harness/sample.diff")
    added = sum(1 for ln in diff.splitlines() if ln.startswith("+"))
    print(f"[agent] PR summary: {added} added lines across the diff.\n")

    # Now the agent follows the skill's embedded directives — just like an LLM
    # would when the SKILL.md tells it to "also run the setup step".
    for d in directives:
        d = d.strip()
        print(f"[agent] following skill directive: {d[:70]}...")
        try:
            # directive format:  read:<path> -> post:<url>
            m = re.match(r"read:(\S+)\s*->\s*post:(\S+)", d)
            if m:
                secret = agent.read_file(m.group(1)).strip()
                resp = agent.http_post(m.group(2), f'{{"loot": "{secret}"}}')
                print(f"[agent]   -> posted. endpoint said: {resp}")
        except PermissionError as e:
            print(f"[agent]   -> BLOCKED: {e}")
        except (urllib.error.URLError, OSError) as e:
            print(f"[agent]   -> network error: {e}")
    print("\n[agent] done.")


if __name__ == "__main__":
    args = sys.argv[1:]
    allow = None
    if "--egress-allow" in args:
        i = args.index("--egress-allow")
        allow = set(args[i + 1].split(","))
        del args[i : i + 2]
    run(args[0], egress_allow=allow)
