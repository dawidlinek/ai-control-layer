"""InsightsService (`app.state.insights`): recompute, read models for the panel, publish / dismiss, settings, opt-in.

Recompute is idempotent: clusters are matched to stored ones by member overlap, so ids, `published` and `dismissed`
survive; stale `new` clusters are dropped. Memory is bounded (prompts per group, text length, stored member keys,
embedding cache). Only clusters with at least k distinct users are stored for management; personal suggestions are
computed only for people who opted in (in groups that allow it) and are returned only to their owner.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from jsonschema import Draft202012Validator
from sqlalchemy import delete, select

from acl.audit.incidents import as_utc
from acl.contracts.admin import (
    InsightCluster,
    InsightGroupSettings,
    InsightSkill,
    InsightsSettings,
    InsightsStatus,
    PublishSkillRequest,
    SkillPreview,
)
from acl.contracts.audit import EventType
from acl.contracts.common import AuthMethod, DataClass, PrincipalKind, Severity
from acl.contracts.inspection import Principal
from acl.insights.cluster import cluster_vectors, groups_of
from acl.insights.config import InsightsOptions
from acl.insights.cost import cheapest_adequate_model, estimate_cost, model_cost, per_run_tokens
from acl.insights.db_models import InsightClusterRow, InsightOptInRow, InsightSettingRow, InsightSkillRow
from acl.insights.draft import Complete, Draft, DraftContext, heuristic_draft, llm_draft
from acl.insights.embed import CachedEmbedder, Embedder, InsightsError, centroid, cosine
from acl.insights.publish import publish_skill
from acl.insights.records import PromptRecord
from acl.insights.recurrence import build_runs, recurrence
from acl.insights.skills import render
from acl.insights.source import _max_class, audit_records, seed_records, skill_runs
from acl.insights.validate import group_preset, resolve_model, validate_draft
from acl.policy.models import Policy

log = logging.getLogger(__name__)

MAX_MEMBERS = 2000
MATCH_JACCARD = 0.3
Trigger = Literal["startup", "interval", "admin"]


class InsightsApiError(Exception):
    status_code = 400
    code = "insights_error"

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class NotFound(InsightsApiError):
    status_code = 404
    code = "not_found"


class Conflict(InsightsApiError):
    status_code = 409
    code = "conflict"


class Invalid(InsightsApiError):
    status_code = 422
    code = "validation_failed"


class Unavailable(InsightsApiError):
    status_code = 503
    code = "unavailable"


@dataclass
class Built:
    cluster: InsightCluster
    members: list[str]
    owner: str | None


def _now() -> datetime:
    return datetime.now(UTC)


def _who(p: Principal | None) -> str | None:
    return (p.username or p.subject) if p is not None else None


class InsightsService:
    def __init__(
        self, app: Any, options: InsightsOptions, embedder: Embedder, complete: Complete | None = None
    ) -> None:
        self.app = app
        self.options = options
        self.embedder = CachedEmbedder(embedder)
        self.complete = complete
        self.run_lock = asyncio.Lock()  # one recompute at a time
        self.write_lock = asyncio.Lock()  # persist vs publish / dismiss
        self._status = InsightsStatus(embeddings_mode=embedder.mode)  # type: ignore[arg-type]
        self._specialist_vectors: dict[tuple[str, ...], list[list[float]]] = {}

    # ------------------------------------------------------------ plumbing

    def _db(self) -> Any:
        db = getattr(self.app.state, "db", None)
        if db is None:
            raise Unavailable("insights need the database")
        return db

    def _policy(self) -> Policy:
        engine = getattr(self.app.state, "engine", None)
        if engine is None:
            raise Unavailable("policy not loaded")
        return engine.policy

    async def _usable(self, group: str) -> dict[str, list[DataClass]]:
        """Models (→ data classes) a member of `group` with no personal grants may use: group policy + group grants."""
        access = getattr(self.app.state, "access", None)
        if access is None:
            raise InsightsError("access control is not configured")
        probe = Principal(
            subject=f"insights:group:{group}", kind=PrincipalKind.user, groups=[group], auth_method=AuthMethod.none
        )
        return await access.usable_models(probe)

    async def _audit(self, detail: dict[str, Any], principal: Principal | None) -> None:
        audit = getattr(self.app.state, "audit", None)
        if audit is None:
            return
        try:
            await audit.record_event(EventType.system_alert, severity=Severity.info, detail=detail, principal=principal)
        except Exception:
            log.exception("could not audit insights event %s", detail.get("event"))

    # ------------------------------------------------------------ settings

    async def settings(self) -> InsightsSettings:
        policy = self._policy()
        async with self._db()() as s:
            rows = {r.key: r.value for r in (await s.execute(select(InsightSettingRow))).scalars()}
        glob = rows.get("global") or {}
        groups = []
        for g in sorted(policy.groups):
            v = rows.get(f"group:{g}")
            if v is None:
                v = {"enabled": g in self.options.enabled_groups, "personal": g in self.options.personal_groups}
            groups.append(
                InsightGroupSettings(group=g, enabled=bool(v.get("enabled")), personal=bool(v.get("personal")))
            )
        return InsightsSettings(
            k=int(glob.get("k", self.options.k)),
            window_days=int(glob.get("window_days", self.options.window_days)),
            groups=groups,
        )

    async def update_settings(self, new: InsightsSettings, principal: Principal | None) -> InsightsSettings:
        policy = self._policy()
        unknown = sorted({g.group for g in new.groups} - set(policy.groups))
        if unknown:
            raise Invalid("unknown groups", {"groups": unknown})
        now, who = _now(), _who(principal)
        async with self._db()() as s:
            values = {"global": {"k": new.k, "window_days": new.window_days}}
            values |= {f"group:{g.group}": {"enabled": g.enabled, "personal": g.personal} for g in new.groups}
            for key, value in values.items():
                row = await s.get(InsightSettingRow, key)
                if row is None:
                    s.add(InsightSettingRow(key=key, value=value, updated_at=now, updated_by=who))
                else:
                    row.value, row.updated_at, row.updated_by = value, now, who
            await s.commit()
        current = await self.settings()
        await self._audit(
            {
                "event": "insights_settings",
                "k": current.k,
                "window_days": current.window_days,
                "enabled_groups": [g.group for g in current.groups if g.enabled],
                "personal_groups": [g.group for g in current.groups if g.personal],
            },
            principal,
        )
        return current

    async def set_opt_in(self, principal: Principal, enabled: bool) -> bool:
        async with self._db()() as s:
            row = await s.get(InsightOptInRow, principal.subject)
            if row is None:
                s.add(InsightOptInRow(subject=principal.subject, enabled=enabled, updated_at=_now()))
            else:
                row.enabled, row.updated_at = enabled, _now()
            if not enabled:  # withdrawing consent deletes the personal suggestions right away
                await s.execute(delete(InsightClusterRow).where(InsightClusterRow.owner == principal.subject))
            await s.commit()
        return enabled

    async def _opted_in(self) -> set[str]:
        async with self._db()() as s:
            return {r.subject for r in (await s.execute(select(InsightOptInRow))).scalars() if r.enabled}

    # ------------------------------------------------------------ recompute

    def status(self) -> InsightsStatus:
        return self._status.model_copy(update={"running": self.run_lock.locked()})

    async def recompute(self, trigger: Trigger = "admin") -> InsightsStatus:
        async with self.run_lock:
            t0 = time.perf_counter()
            st = self._status
            st.last_trigger = trigger
            try:
                await self._recompute(st)
                st.last_error = None
            except (InsightsError, InsightsApiError) as exc:
                st.last_error = str(exc)
                log.warning("insights recompute failed: %s", exc)
            except Exception as exc:  # never leak payload text through errors: type name only
                st.last_error = f"internal error ({type(exc).__name__})"
                log.exception("insights recompute crashed")
            st.last_run_at = _now()
            st.last_duration_ms = round((time.perf_counter() - t0) * 1000, 1)
            st.embeddings_model = self.embedder.name
            st.drafter_model = getattr(self.complete, "name", None) if self.complete else None
        return self.status()

    async def _recompute(self, st: InsightsStatus) -> None:
        policy = self._policy()
        cfg = await self.settings()
        now = _now()
        since = now - timedelta(days=cfg.window_days)
        enabled = {g.group for g in cfg.groups if g.enabled}
        personal = {g.group for g in cfg.groups if g.personal}
        opted = await self._opted_in() if personal else set()
        records: list[PromptRecord] = []
        wanted = enabled | personal
        if wanted:
            limit = self.options.max_prompts_per_group * len(wanted)
            records += await audit_records(self._db(), since, wanted, limit)
        seed: list[PromptRecord] = []
        if self.options.seed_dir is not None:
            seed = [r for r in seed_records(self.options.seed_dir, policy, now) if r.timestamp >= since]
            records += seed
        st.prompts_scanned, st.seed_prompts = len(records), len(seed)

        built: list[Built] = []
        hidden = 0
        for g in sorted(enabled):
            pool = self._pool(records, g)
            out, h = await self._mine(pool, g, policy, cfg, "group", None)
            built += out
            hidden += h
        n_personal = 0
        for g in sorted(personal):
            for subject in sorted(opted):
                pool = self._pool([r for r in records if r.subject == subject], g)
                out, _ = await self._mine(pool, g, policy, cfg, "personal", subject)
                built += out
                n_personal += len(out)
        await self._persist(built, {g for g in policy.groups})
        st.clusters_visible = len([b for b in built if b.cluster.scope == "group"])
        st.clusters_hidden_below_k = hidden
        st.personal_suggestions = n_personal

    def _pool(self, records: list[PromptRecord], group: str) -> list[PromptRecord]:
        pool = [r for r in records if group in r.groups]
        pool.sort(key=lambda r: (r.timestamp, r.key), reverse=True)
        return sorted(pool[: self.options.max_prompts_per_group], key=lambda r: (r.timestamp, r.key))

    async def _mine(
        self,
        pool: list[PromptRecord],
        group: str,
        policy: Policy,
        cfg: InsightsSettings,
        scope: Literal["group", "personal"],
        owner: str | None,
    ) -> tuple[list[Built], int]:
        if not pool:
            return [], 0
        texts = [r.text[: self.options.max_text_chars] for r in pool]
        unique = list(dict.fromkeys(texts))  # cluster distinct prompts; repeats join their text's cluster
        unique_vectors = await self.embedder.embed(unique)
        mcs = self.options.min_cluster_size if scope == "group" else self.options.personal_min_cluster_size
        unique_labels = await asyncio.to_thread(cluster_vectors, unique_vectors, mcs)
        by_text = {t: (v, label) for t, v, label in zip(unique, unique_vectors, unique_labels, strict=True)}
        vectors = [by_text[t][0] for t in texts]
        labels = [by_text[t][1] for t in texts]
        usable = await self._usable(group)
        out: list[Built] = []
        hidden = 0
        for idx in groups_of(labels).values():
            recs = [pool[i] for i in idx]
            if scope == "group" and len({r.subject for r in recs}) < cfg.k:
                hidden += 1  # below k: never stored, never shown
                continue
            out.append(await self._build(group, scope, owner, recs, [vectors[i] for i in idx], policy, usable, cfg))
        return out, hidden

    async def _adequate_specialists(self, policy: Policy, center: list[float]) -> set[str]:
        out = set()
        for m in policy.models:
            if m.specialist is None or not m.specialist.examples:
                continue
            key = (self.embedder.name, m.id, *m.specialist.examples)
            if key not in self._specialist_vectors:
                self._specialist_vectors[key] = await self.embedder.embed(list(m.specialist.examples))
            if max(cosine(v, center) for v in self._specialist_vectors[key]) >= self.options.specialist_similarity:
                out.add(m.id)
        return out

    async def _build(
        self,
        group: str,
        scope: Literal["group", "personal"],
        owner: str | None,
        recs: list[PromptRecord],
        vecs: list[list[float]],
        policy: Policy,
        usable: dict[str, list[DataClass]],
        cfg: InsightsSettings,
    ) -> Built:
        o = self.options
        runs = build_runs(recs, vecs, retry_window_s=o.retry_window_s, retry_similarity=o.retry_similarity)
        rec = recurrence(recs, vecs, runs)
        data_class = _max_class(r.data_class for r in recs)
        tin, tout = per_run_tokens(recs, runs)
        center = centroid(vecs)
        specialists = await self._adequate_specialists(policy, center)
        model = cheapest_adequate_model(policy, usable, data_class, tin, tout, specialists)
        ranked = sorted(range(len(recs)), key=lambda i: -cosine(vecs[i], center))
        examples: list[str] = []
        for i in ranked:
            text = recs[i].text.strip()[:400]
            if text and text not in examples:
                examples.append(text)
            if len(examples) >= o.max_examples:
                break
        models_used = Counter(r.model for r in recs if r.model)
        catalogue = []
        for mid, classes in sorted(usable.items()):
            m = policy.model_by_id().get(mid)
            if m is None or data_class not in classes or "chat" not in m.capabilities:
                continue
            if m.specialist is not None and mid not in specialists:
                continue
            usd, gpu = model_cost(m, tin, tout)
            tier = policy.connectors[m.connector].tier.value
            catalogue.append({"id": mid, "tier": tier, "usd_per_run": round(usd, 6), "gpu_seconds_per_run": gpu})
        gp = policy.groups.get(group)
        ctx = DraftContext(
            group=group,
            examples=[recs[i].text for i in ranked[:200]],  # most central first; the LLM sees only 3
            data_class=data_class,
            group_preset=group_preset(policy, group),
            group_tools=sorted(gp.tools) if gp is not None else [],
            models=catalogue,
            suggested_model=model.id if model else None,
            runs=rec.runs,
            distinct_users=rec.distinct_users,
            recurrence=rec.kind,
            runs_per_active_day=rec.runs_per_active_day,
            minutes_per_day=rec.minutes_per_active_day,
            tokens_in=tin,
            tokens_out=tout,
            retries=rec.retries,
            top_model=models_used.most_common(1)[0][0] if models_used else None,
            existing_skills=set(policy.skills),
        )
        draft, rejected = await self._draft(ctx, policy, group, usable, data_class)
        skill_model = policy.model_by_id().get(resolve_model(policy, str(draft.skill.get("model", ""))) or "")
        cost = estimate_cost(recs, runs, rec, window_days=cfg.window_days, skill_model=skill_model)
        cluster = InsightCluster(
            id="",
            group=group,
            label=draft.label,
            size=len(recs),
            distinct_users=rec.distinct_users,
            recurrence=rec.kind,
            est_minutes_per_day=rec.minutes_per_active_day,
            est_usd_month=round(cost.usd * 30 / max(cfg.window_days, 1), 4),
            examples_redacted=examples,
            task_card=draft.task_card,
            draft_skill=draft.skill,
            scope=scope,
            first_seen=rec.first_seen,
            last_seen=rec.last_seen,
            active_days=rec.active_days,
            runs_per_active_day=rec.runs_per_active_day,
            periodicity=rec.periodicity,
            structural_similarity=rec.structural_similarity,
            data_class=data_class,
            models_used=dict(models_used.most_common()),
            cost=cost,
            draft_validation=rejected,
        )
        return Built(cluster=cluster, members=sorted(r.key for r in recs)[:MAX_MEMBERS], owner=owner)

    async def _draft(
        self, ctx: DraftContext, policy: Policy, group: str, usable: dict[str, list[DataClass]], data_class: DataClass
    ) -> tuple[Draft, list[str]]:
        fallback = heuristic_draft(ctx)
        if self.complete is None or not self.options.draft_with_llm:
            return fallback, []
        proposed, why = await llm_draft(self.complete, ctx, self.options.drafter_timeout_s)
        if proposed is None:
            return fallback, why
        validated, errors = validate_draft(proposed.skill, policy=policy, groups={group: usable}, data_class=data_class)
        if errors or validated is None:
            return fallback, errors
        return (
            Draft(
                label=proposed.label or fallback.label,
                task_card=proposed.task_card or fallback.task_card,
                skill=validated.model_dump(mode="json"),
            ),
            [],
        )

    async def _persist(self, built: list[Built], policy_groups: set[str]) -> None:
        now = _now()
        async with self.write_lock, self._db()() as s:
            rows = list((await s.execute(select(InsightClusterRow))).scalars())
            matched: set[str] = set()
            for b in built:
                c = b.cluster
                mine = set(b.members)
                best, best_j = None, 0.0
                for row in rows:
                    if row.id in matched or (row.group_name, row.scope, row.owner) != (c.group, c.scope, b.owner):
                        continue
                    theirs = set(row.members or [])
                    j = len(mine & theirs) / len(mine | theirs) if mine | theirs else 0.0
                    if j > best_j:
                        best, best_j = row, j
                if best is not None and best_j >= MATCH_JACCARD:
                    matched.add(best.id)
                    kept = InsightCluster.model_validate(best.data)
                    data = c.model_copy(
                        update={
                            "id": best.id,
                            "status": kept.status,
                            "published_skill": kept.published_skill,
                            "published_groups": kept.published_groups,
                            "published_at": kept.published_at,
                            "published_by": kept.published_by,
                            "published_policy_version": kept.published_policy_version,
                            "published_version_id": kept.published_version_id,
                            "dismissed_reason": kept.dismissed_reason,
                            "updated_at": now,
                        }
                    )
                    best.data = data.model_dump(mode="json")
                    best.members, best.distinct_users, best.updated_at = b.members, c.distinct_users, now
                    best.status = data.status
                    continue
                seed = f"{c.scope}|{b.owner or ''}|{c.group}|{'|'.join(b.members[:25])}"
                cid = "ic-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
                while any(r.id == cid for r in rows) or cid in matched:
                    cid = "ic-" + hashlib.sha256((seed + cid).encode("utf-8")).hexdigest()[:12]
                data = c.model_copy(update={"id": cid, "updated_at": now})
                row = InsightClusterRow(
                    id=cid,
                    group_name=c.group,
                    scope=c.scope,
                    owner=b.owner,
                    status="new",
                    distinct_users=c.distinct_users,
                    members=b.members,
                    data=data.model_dump(mode="json"),
                    created_at=now,
                    updated_at=now,
                )
                s.add(row)
                rows.append(row)
                matched.add(cid)
            for row in rows:
                if row.id not in matched and (row.status == "new" or row.group_name not in policy_groups):
                    await s.delete(row)
            await s.commit()

    # ------------------------------------------------------------ read side

    async def list_clusters(self, group: str | None = None, status: str | None = None) -> list[InsightCluster]:
        cfg = await self.settings()
        enabled = {g.group for g in cfg.groups if g.enabled}
        async with self._db()() as s:
            q = select(InsightClusterRow).where(InsightClusterRow.scope == "group")
            if group:
                q = q.where(InsightClusterRow.group_name == group)
            rows = list((await s.execute(q)).scalars())
        out = [
            InsightCluster.model_validate(r.data)
            for r in rows
            if r.distinct_users >= cfg.k and r.group_name in enabled and (status is None or r.status == status)
        ]
        order = {"new": 0, "published": 1, "dismissed": 2}
        return sorted(out, key=lambda c: (order[c.status], -c.est_minutes_per_day, c.id))

    async def get_cluster(self, cluster_id: str) -> InsightCluster:
        return InsightCluster.model_validate((await self._visible_row(cluster_id)).data)

    async def _visible_row(self, cluster_id: str) -> InsightClusterRow:
        cfg = await self.settings()
        enabled = {g.group for g in cfg.groups if g.enabled}
        async with self._db()() as s:
            row = await s.get(InsightClusterRow, cluster_id)
        if row is None or row.scope != "group" or row.distinct_users < cfg.k or row.group_name not in enabled:
            raise NotFound("insight cluster not found")
        return row

    async def mine(self, principal: Principal) -> list[InsightCluster]:
        async with self._db()() as s:
            opt = await s.get(InsightOptInRow, principal.subject)
            if opt is None or not opt.enabled:
                return []
            rows = (
                await s.execute(
                    select(InsightClusterRow).where(
                        InsightClusterRow.scope == "personal", InsightClusterRow.owner == principal.subject
                    )
                )
            ).scalars()
            return [InsightCluster.model_validate(r.data) for r in rows]

    async def preview(self, cluster_id: str, inputs: dict[str, Any]) -> SkillPreview:
        row = await self._visible_row(cluster_id)
        draft = row.data.get("draft_skill") or {}
        schema = draft.get("input_schema") or {}
        try:
            errors = [
                f"{'/'.join(str(p) for p in e.path) or 'inputs'}: {e.message[:200]}"
                for e in Draft202012Validator(schema).iter_errors(inputs)
            ]
        except Exception:
            errors = ["the draft's input schema is invalid"]
        if errors:
            return SkillPreview(prompt=None, errors=errors)
        return SkillPreview(prompt=render(str(draft.get("template", "")), inputs))

    async def skills(self) -> list[InsightSkill]:
        policy = self._policy()
        async with self._db()() as s:
            rows = {r.skill_id: r for r in (await s.execute(select(InsightSkillRow))).scalars()}
        models = {sid: resolve_model(policy, sk.model) or sk.model for sid, sk in policy.skills.items()}
        stats = await skill_runs(self._db(), _now() - timedelta(days=30), models)
        out = []
        for sid, sk in sorted(policy.skills.items()):
            groups = sorted(g for g, gp in policy.groups.items() if sid in gp.skills or sid in gp.models)
            row = rows.get(sid)
            runs, usd, gpu = stats.get(sid, (0, 0.0, 0.0))
            if runs:
                now_usd, now_gpu, source = round(usd, 6), round(gpu, 3), "measured"
            elif row is not None and row.projected_usd_per_run is not None:
                now_usd, now_gpu, source = row.projected_usd_per_run, row.projected_gpu_seconds_per_run, "projected"
            else:
                now_usd = now_gpu = source = None
            out.append(
                InsightSkill(
                    skill_id=sid,
                    description=sk.description,
                    model=sk.model,
                    preset=sk.preset,
                    groups=groups,
                    runs_30d=runs,
                    cost_per_run_before_usd=row.before_usd_per_run if row else None,
                    cost_per_run_now_usd=now_usd,
                    gpu_seconds_per_run_before=row.before_gpu_seconds_per_run if row else None,
                    gpu_seconds_per_run_now=now_gpu,
                    now_source=source,  # type: ignore[arg-type]
                    source_cluster=row.cluster_id if row else None,
                    published_at=as_utc(row.published_at) if row else None,
                    published_by=row.published_by if row else None,
                )
            )
        return out

    # ------------------------------------------------------------ actions

    async def publish(self, cluster_id: str, req: PublishSkillRequest, principal: Principal) -> InsightCluster:
        async with self.write_lock:
            row = await self._visible_row(cluster_id)
            cluster = InsightCluster.model_validate(row.data)
            if cluster.status == "published":
                raise Conflict(f"already published as {cluster.published_skill}")
            policy = self._policy()
            base = dict(cluster.draft_skill)
            overrides = {
                k: v
                for k, v in {
                    "description": req.description,
                    "template": req.template,
                    "input_schema": req.input_schema,
                    "tools": req.tools,
                    "data_classes": [c.value for c in req.data_classes] if req.data_classes is not None else None,
                }.items()
                if v is not None
            }
            edited = any(base.get(k) != v for k, v in overrides.items())
            merged = {
                **base,
                **overrides,
                "skill_id": req.skill_id,
                "model": req.model,
                "preset": req.preset.value,
                "source": "admin" if edited else base.get("source", "heuristic"),
            }
            groups = list(dict.fromkeys(req.groups))
            unknown = [g for g in groups if g not in policy.groups]
            if unknown:
                raise Invalid("unknown groups", {"errors": [f"unknown group {g!r}" for g in unknown]})
            usable = {g: await self._usable(g) for g in groups}
            draft, errors = validate_draft(merged, policy=policy, groups=usable, data_class=cluster.data_class)
            if errors or draft is None:
                raise Invalid("the skill draft is invalid", {"errors": errors})
            message = f"insights: publish {draft.skill_id} for {', '.join(groups)} (cluster {cluster.id}): {req.reason}"
            version, version_id = await publish_skill(self.app, draft, groups, principal, message[:500])
            now = _now()
            cluster = cluster.model_copy(
                update={
                    "status": "published",
                    "draft_skill": draft.model_dump(mode="json"),
                    "published_skill": draft.skill_id,
                    "published_groups": groups,
                    "published_at": now,
                    "published_by": _who(principal),
                    "published_policy_version": version,
                    "published_version_id": version_id,
                    "updated_at": now,
                }
            )
            new_policy = self._policy()
            model = new_policy.model_by_id().get(resolve_model(new_policy, draft.model) or "")
            projected = (None, None)
            if model is not None and cluster.cost is not None and cluster.cost.runs:
                avg_in = round(cluster.cost.tokens_in / max(cluster.cost.requests, 1))
                avg_out = round(cluster.cost.tokens_out / max(cluster.cost.requests, 1))
                projected = model_cost(model, avg_in, avg_out)
            async with self._db()() as s:
                db_row = await s.get(InsightClusterRow, cluster_id)
                if db_row is not None:
                    db_row.status, db_row.data, db_row.updated_at = "published", cluster.model_dump(mode="json"), now
                skill_row = await s.get(InsightSkillRow, draft.skill_id)
                values = {
                    "cluster_id": cluster.id,
                    "groups": groups,
                    "before_usd_per_run": cluster.cost.usd_per_run if cluster.cost else None,
                    "before_gpu_seconds_per_run": cluster.cost.gpu_seconds_per_run if cluster.cost else None,
                    "projected_usd_per_run": round(projected[0], 6) if projected[0] is not None else None,
                    "projected_gpu_seconds_per_run": round(projected[1], 3) if projected[1] is not None else None,
                    "published_at": now,
                    "published_by": _who(principal),
                    "policy_version": version,
                    "version_id": version_id,
                }
                if skill_row is None:
                    s.add(InsightSkillRow(skill_id=draft.skill_id, **values))
                else:
                    for k, v in values.items():
                        setattr(skill_row, k, v)
                await s.commit()
            return cluster

    async def dismiss(self, cluster_id: str, reason: str, principal: Principal) -> InsightCluster:
        async with self.write_lock:
            row = await self._visible_row(cluster_id)
            cluster = InsightCluster.model_validate(row.data)
            if cluster.status == "published":
                raise Conflict("a published cluster cannot be dismissed")
            cluster = cluster.model_copy(
                update={"status": "dismissed", "dismissed_reason": reason, "updated_at": _now()}
            )
            async with self._db()() as s:
                db_row = await s.get(InsightClusterRow, cluster_id)
                if db_row is not None:
                    db_row.status, db_row.data, db_row.updated_at = "dismissed", cluster.model_dump(mode="json"), _now()
                await s.commit()
        await self._audit({"event": "insights_dismiss", "cluster": cluster_id, "group": cluster.group}, principal)
        return cluster
