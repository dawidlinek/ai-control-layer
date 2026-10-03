"""SEC-PII-01: PII tier T0 (regex + validators) with preset-driven action (concept §6.2, §6.3).

Action comes from the preset (`pii_action`: monitor | pseudonymise | redact | route_local | block):

    monitor       finding only
    pseudonymise  replacement = session-vault placeholder `<PESEL_1>` (typed mask `[REDACTED:PESEL]`
                  when no vault is registered: findings and action are unchanged, only the replacement
                  degrades)
    redact        replacement = typed mask
    route_local   no replacement; data stays raw and the router forces a local model
    block         final block

`data_class` is `confidential`. A hit inside a decoded view (Base64/hex/URL) is reported against the whole
encoded token, so the transform replaces the token. Findings carry salted `value_hash`es, never values.
Pseudonymisation state changes only in `commit()` (see `vault.py`).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from acl.contracts.common import Action, DataClass, Phase
from acl.contracts.decision import Decision, Finding, Verdict
from acl.contracts.inspection import InspectionContext
from acl.controls.base import Control, ControlDeps, register_control
from acl.controls.normalise.scan import ScanText, hash_value, scan_texts, value_salt
from acl.controls.pii.detect import ALL_ENTITIES, JOINABLE, canonical, detect
from acl.controls.pii.vault import Planned, PseudonymVault
from acl.policy.models import ControlConfig


class PiiParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entities: list[str] = list(ALL_ENTITIES)
    scan_line_joined: bool = True


@register_control
class PiiControl(Control):
    type = "pii"
    phase = Phase.deterministic
    Params = PiiParams
    cacheable = False  # placeholders depend on the session vault

    def __init__(self, config: ControlConfig, params: BaseModel, deps: ControlDeps) -> None:
        super().__init__(config, params, deps)
        self._salt = value_salt(deps)
        unknown = set(params.entities) - set(ALL_ENTITIES)  # type: ignore[attr-defined]
        if unknown:
            raise ValueError(f"unknown PII entities: {sorted(unknown)}")

    async def inspect(self, ctx: InspectionContext) -> Verdict:
        p: PiiParams = self.params  # type: ignore[assignment]
        settings = self.preset_settings(ctx)
        action = settings.pii_action if settings is not None else Action.pseudonymise
        entities = tuple(p.entities)
        joinable = tuple(e for e in entities if e in JOINABLE)

        found: list[tuple[ScanText, int, int, str, str, float, str]] = []  # st, start, end, entity, value, score, canon
        seen: set[tuple[str, int, int, str]] = set()
        for st in scan_texts(ctx, views=True, joined=p.scan_line_joined):
            if st.kind == "joined":
                hits = [h for h in detect(st.text, joinable) if st.crosses_break(h.start, h.end)]
            else:
                hits = detect(st.text, entities)
            for h in hits:
                start, end = st.locate(h.start, h.end)
                key = (st.field, start, end, h.entity)
                if key in seen:
                    continue
                seen.add(key)
                found.append((st, start, end, h.entity, h.value, h.score, canonical(h.entity, h.value)))
        if not found:
            return self.verdict()

        found.sort(key=lambda t: (t[0].field, t[1]))
        vault: PseudonymVault | None = self.deps.get("vault")
        plan: list[Planned] = []
        placeholders: dict[tuple[str, str], str] = {}
        if action == Action.pseudonymise and vault is not None:
            uniq: dict[tuple[str, str], str] = {}
            for _st, _s, _e, ent, val, _sc, canon in found:
                uniq.setdefault((ent, canon), val)
            plan = vault.plan(ctx.session_id, [(e, c, v) for (e, c), v in uniq.items()])
            placeholders = {(p_.entity_type, p_.key): p_.placeholder for p_ in plan}

        findings: list[Finding] = []
        for st, start, end, ent, _val, score, canon in found:
            if action == Action.pseudonymise and (ent, canon) in placeholders:
                replacement: str | None = placeholders[(ent, canon)]
            elif action in (Action.pseudonymise, Action.redact):
                replacement = f"[REDACTED:{ent}]"
            else:
                replacement = None
            findings.append(
                Finding(
                    entity_type=ent,
                    field=st.field,
                    start=start,
                    end=end,
                    score=score,
                    value_hash=hash_value(self._salt, canon),
                    replacement=replacement,
                    rule_id=self.id,
                )
            )

        types = sorted({f.entity_type for f in findings})
        degraded = action == Action.pseudonymise and vault is None
        reason = f"{len(findings)} PII span(s) ({', '.join(types)}); action {action.value}" + (
            "; no vault registered, typed masks used" if degraded else ""
        )
        outputs = {"pii_plan": plan, "pii_types": types}
        return self.verdict(
            action=action,
            final=action == Action.block,
            rule_ids=[self.id],
            findings=findings,
            data_class=DataClass.confidential,
            reason=reason,
            outputs=outputs,
        )

    async def commit(self, ctx: InspectionContext, decision: Decision) -> None:
        """Persist the placeholders that were actually issued (real traffic only)."""
        vault: PseudonymVault | None = self.deps.get("vault")
        plan = ctx.attributes.get("pii_plan")
        if vault is None or not plan or Action.pseudonymise not in decision.applied:
            return
        if decision.action in (Action.block, Action.require_approval):
            return  # nothing is forwarded: no placeholder was issued
        vault.register(ctx.session_id, plan)
