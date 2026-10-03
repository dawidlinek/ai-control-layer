"""`model_access` control (SEC-MODEL-01), stages ingress / embeddings."""

from __future__ import annotations

import logging
from typing import Literal

from pydantic import BaseModel, ConfigDict

from acl.contracts.common import Action, Phase
from acl.contracts.decision import Verdict
from acl.contracts.inspection import InspectionContext
from acl.controls.base import Control, register_control
from acl.identity.access import RULE_MODEL, DefaultAccessResolver

log = logging.getLogger(__name__)


class ModelAccessParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    missing_service: Literal["block", "policy_only"] = "block"
    """When the `access` service is not registered (engine built without the identity wiring, e.g. the
    in-process case harness): `block` fails closed; `policy_only` resolves group policy + org locks from
    the engine's own policy and ignores DB grants (never more permissive than group policy + locks, but
    it cannot see DB *deny* grants). Production wiring always registers the service."""


@register_control
class ModelAccessControl(Control):
    type = "model_access"
    phase = Phase.deterministic
    Params = ModelAccessParams
    cacheable = False  # depends on the principal and on DB grants

    _warned = False

    def _resolver(self):  # type: ignore[no-untyped-def]
        access = self.deps.get("access")
        if access is not None:
            return access
        if self.params.missing_service == "policy_only":
            policy = self.deps.get("policy")
            version = self.deps.get("policy_version", "unknown")
            if policy is not None:
                if not ModelAccessControl._warned:
                    ModelAccessControl._warned = True
                    log.warning("model_access: no `access` service registered; using policy-only resolution")
                return DefaultAccessResolver(lambda: (policy, version))
        return None

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        requested = ctx.model_requested
        if not requested:
            return self.verdict(action=Action.allow, reason="no model requested")
        resolver = self._resolver()
        if resolver is None:
            return self.verdict(
                action=Action.block,
                final=True,
                rule_ids=[self.id],
                reason="model access cannot be decided: the access service is not available (fail closed)",
            )
        check = await resolver.check_model(ctx.principal, requested)
        if check.allowed:
            return self.verdict(action=Action.allow, reason=check.reason)
        rule = check.rule_id or RULE_MODEL
        rule_ids = [rule] if rule == self.id else [self.id, rule]
        return self.verdict(action=Action.block, final=True, rule_ids=rule_ids, reason=check.reason)
