"""Clustering per group: HDBSCAN (scikit-learn, BSD-3-Clause) on L2-normalised embeddings, then a centroid merge.

Euclidean distance on unit vectors is a monotone function of cosine distance, so this is density clustering by
cosine similarity. HDBSCAN needs no cluster count, labels ad-hoc prompts as noise (-1) and is deterministic.
HDBSCAN tends to split one task into sub-clusters by phrasing variant ("Summarise this…" vs "Please summarise…"),
so clusters whose centroids are at least `merge_similarity` apart are merged (average linkage on centroids).
Callers cluster unique texts: exact repeats (regenerations) would otherwise form tiny dense clusters of their own.
"""

from __future__ import annotations

from typing import Any

MERGE_SIMILARITY = 0.75


def _hdbscan(x: Any, min_cluster_size: int, single: bool) -> list[int]:
    from sklearn.cluster import HDBSCAN  # heavy import only in the worker, not at gateway start

    model = HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min(min_cluster_size, len(x) - 1),
        metric="euclidean",
        cluster_selection_method="eom",
        allow_single_cluster=single,
        copy=True,
    )
    return [int(v) for v in model.fit(x).labels_]


def cluster_vectors(
    vectors: list[list[float]], min_cluster_size: int, merge_similarity: float = MERGE_SIMILARITY
) -> list[int]:
    """Cluster label per vector (-1 = noise). Fewer vectors than `min_cluster_size` → all noise."""
    n = len(vectors)
    if n < max(2, min_cluster_size):
        return [-1] * n
    import numpy as np

    x = np.asarray(vectors, dtype=np.float64)
    norms = np.linalg.norm(x, axis=1, keepdims=True)
    x = x / np.where(norms == 0, 1.0, norms)
    labels = _hdbscan(x, min_cluster_size, single=False)
    if all(v < 0 for v in labels):  # one task and nothing else: HDBSCAN needs permission for a single cluster
        labels = _hdbscan(x, min_cluster_size, single=True)
    members = groups_of(labels)
    while len(members) > 1:
        cents = {k: x[idx].mean(axis=0) for k, idx in members.items()}
        cents = {k: c / (np.linalg.norm(c) or 1.0) for k, c in cents.items()}
        keys = sorted(cents)
        best, pair = merge_similarity, None
        for i, a in enumerate(keys):
            for b in keys[i + 1 :]:
                sim = float(cents[a] @ cents[b])
                if sim >= best:
                    best, pair = sim, (a, b)
        if pair is None:
            break
        members[pair[0]] = sorted(members[pair[0]] + members.pop(pair[1]))
    out = [-1] * n
    for new, idx in enumerate(sorted(members.values(), key=lambda m: m[0])):
        for i in idx:
            out[i] = new
    return out


def groups_of(labels: list[int]) -> dict[int, list[int]]:
    """Cluster label → member indices (noise dropped), ordered by label."""
    out: dict[int, list[int]] = {}
    for i, label in enumerate(labels):
        if label >= 0:
            out.setdefault(label, []).append(i)
    return dict(sorted(out.items()))
