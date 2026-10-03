"""governed-tools: our own policy-labelled tool server (concept §9, "our tool server via the MCP proxy").

Safe, offline tools whose labels live in `policy/tools.yaml` (governed.*): documentation search, workspace file
listing/reading (workspace-scoped), a shell-echo that never executes anything, and an HTTP GET over a tiny
built-in fake internet.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common import run
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

ROOT = Path(os.environ.get("WORKSPACE") or Path(__file__).resolve().parents[1] / "files" / "workspace").resolve()
MAX_BYTES = 64_000

DOCS = {
    "deploy": "Deployments go through CI; never push to main directly. Rollbacks: `git revert` + redeploy.",
    "oncall": "On-call rotation changes weekly on Monday 10:00. Escalate to the platform lead after 30 minutes.",
    "security": "Secrets live in the vault. Report suspected leaks to security@corp.example.",
}
WEB = {"https://docs.example.org/guide": "Getting started: install the CLI, run `tool init`, open the dashboard."}

server = MCPServer("governed-tools")


def _scoped(path: str) -> Path:
    full = (ROOT / path).resolve()
    if not full.is_relative_to(ROOT):
        raise ToolError("path is outside the workspace")
    return full


@server.tool(name="search_docs", description="Search the internal engineering handbook and return matching snippets.")
def search_docs(query: str) -> str:
    q = query.lower()
    hits = [f"[{k}] {v}" for k, v in DOCS.items() if q in k or q in v.lower()]
    return "\n".join(hits) or "no results"


@server.tool(name="list_dir", description="List a directory inside the workspace.")
def list_dir(path: str = ".") -> str:
    full = _scoped(path)
    if not full.is_dir():
        raise ToolError("not a directory")
    return "\n".join(sorted(p.name + ("/" if p.is_dir() else "") for p in full.iterdir()))


@server.tool(name="read_text", description="Read a UTF-8 text file inside the workspace.")
def read_text(path: str) -> str:
    full = _scoped(path)
    if not full.is_file():
        raise ToolError("no such file")
    return full.read_text(encoding="utf-8", errors="replace")[:MAX_BYTES]


@server.tool(name="shell_echo", description="Echo a line of text, like `echo` in a shell. Nothing is executed.")
def shell_echo(text: str) -> str:
    return text.replace("\r", " ").replace("\n", " ")[:500]


@server.tool(name="http_get", description="HTTP GET over the built-in offline demo web; returns the page text.")
def http_get(url: str) -> str:
    return WEB.get(url, "404 Not Found")


if __name__ == "__main__":
    run(server)
