"""Policy view for MCP: which upstream tool name on which server is which policy tool id.

A policy tool id is `<alias>.<tool>`; the alias is NOT necessarily the server id (`bank.query` lives on
`core-banking`). `ToolDef.server` + (`ToolDef.name` or the id suffix) identify the upstream tool.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from acl.controls.mcp.canon import normalise_name
from acl.policy.models import Policy, ToolDef


def upstream_name(tool_id: str, tool: ToolDef) -> str:
    return tool.name or tool_id.split(".", 1)[1]


@dataclass(frozen=True)
class ToolCatalog:
    by_upstream: dict[tuple[str, str], tuple[str, ToolDef]] = field(default_factory=dict)
    # normalised upstream name -> servers that declare it (policy = authoritative "first" owner)
    owners: dict[str, set[str]] = field(default_factory=dict)

    @classmethod
    def build(cls, policy: Policy) -> ToolCatalog:
        by_upstream: dict[tuple[str, str], tuple[str, ToolDef]] = {}
        owners: dict[str, set[str]] = {}
        for tid, td in policy.tools.items():
            if td.server is None:
                continue
            name = upstream_name(tid, td)
            by_upstream[(td.server, name)] = (tid, td)
            owners.setdefault(normalise_name(name), set()).add(td.server)
        return cls(by_upstream, owners)

    def resolve(self, server: str, name: str) -> tuple[str, ToolDef] | None:
        return self.by_upstream.get((server, name))

    def other_owner(self, server: str, name: str) -> str | None:
        """A different server that the policy declares a tool of the same (normalised) name for."""
        for owner in sorted(self.owners.get(normalise_name(name), ())):
            if owner != server:
                return owner
        return None


_CACHE: OrderedDict[int, tuple[Policy, ToolCatalog]] = OrderedDict()


def catalog_for(policy: Policy) -> ToolCatalog:
    """Catalog of one `Policy` object (policy objects are immutable once loaded; small identity cache)."""
    hit = _CACHE.get(id(policy))
    if hit is not None and hit[0] is policy:
        return hit[1]
    cat = ToolCatalog.build(policy)
    _CACHE[id(policy)] = (policy, cat)
    while len(_CACHE) > 8:
        _CACHE.popitem(last=False)
    return cat
