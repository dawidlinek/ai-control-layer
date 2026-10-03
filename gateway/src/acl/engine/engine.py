"""Engine facade: compiled policy → pipeline → `evaluate(ctx) -> Decision`.

This is the in-process entry point used by the API, the MCP proxy, `/v1/decide`, dry-run replay
and the test harness. Policy swaps replace the whole Engine atomically (requests in flight keep
the instance they started with).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from acl.contracts.decision import Decision
from acl.contracts.inspection import InspectionContext
from acl.controls.base import ControlDeps, ControlRegistry, load_builtin_controls, registry
from acl.engine.pipeline import Pipeline
from acl.policy.models import Policy


@dataclass
class Engine:
    policy: Policy
    policy_version: str
    pipeline: Pipeline
    deps: ControlDeps = field(default_factory=ControlDeps)

    @classmethod
    def build(
        cls,
        policy: Policy,
        policy_version: str,
        deps: ControlDeps | None = None,
        *,
        control_registry: ControlRegistry = registry,
        load_builtins: bool = True,
    ) -> Engine:
        if load_builtins:
            load_builtin_controls()
        deps = deps or ControlDeps()
        controls = [control_registry.build(c, deps) for c in policy.controls if c.enabled]
        return cls(policy=policy, policy_version=policy_version, pipeline=Pipeline(controls, policy.global_), deps=deps)

    async def evaluate(self, ctx: InspectionContext) -> Decision:
        return await self.pipeline.run(ctx)

    async def aclose(self) -> None:
        for c in self.pipeline.controls:
            await c.aclose()
