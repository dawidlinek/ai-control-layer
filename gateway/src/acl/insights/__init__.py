"""Automation Insights (concept §14): mine repeated tasks from redacted prompts and publish them as governed skills.

    audit index (redacted prompts) [+ demo seed]  →  embed (local model)  →  cluster per group (HDBSCAN)
    →  recurrence + cost  →  task card + draft skill (local LLM proposes, code validates)  →  admin publishes
    `skill/<name>` through the policy writer  →  the skill shows in the group's `/v1/models`

Privacy by design: only redacted text is read (never the vault), only local models are used, management sees only
clusters with at least k distinct users, and personal suggestions are shown to their owner only (opt-in).
"""
