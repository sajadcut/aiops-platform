from __future__ import annotations

from typing import Iterable, Mapping, Sequence


def recall_at_k(ranked_ids: Sequence[str], relevant_ids: Iterable[str], k: int) -> float:
    relevant = set(relevant_ids)
    if not relevant:
        return 1.0
    found = relevant.intersection(ranked_ids[: max(0, int(k))])
    return len(found) / len(relevant)


def precision_at_k(ranked_ids: Sequence[str], relevant_ids: Iterable[str], k: int) -> float:
    k = max(0, int(k))
    if k == 0:
        return 0.0
    relevant = set(relevant_ids)
    window = ranked_ids[:k]
    return sum(1 for item in window if item in relevant) / len(window) if window else 0.0


def reciprocal_rank(ranked_ids: Sequence[str], relevant_ids: Iterable[str]) -> float:
    relevant = set(relevant_ids)
    for rank, item in enumerate(ranked_ids, 1):
        if item in relevant:
            return 1.0 / rank
    return 0.0


def successful_remediation_retrieval_rate(
    ranked_ids: Sequence[str],
    outcomes: Mapping[str, str],
    *,
    k: int,
) -> float:
    window = ranked_ids[: max(0, int(k))]
    if not window:
        return 0.0
    return sum(
        1 for item in window if outcomes.get(item) == "successful_recovery"
    ) / len(window)


def failed_action_avoidance_rate(
    surfaced_failed_ids: Iterable[str],
    blindly_repeated_ids: Iterable[str],
) -> float:
    failed = set(surfaced_failed_ids)
    if not failed:
        return 1.0
    repeated = failed.intersection(blindly_repeated_ids)
    return 1.0 - (len(repeated) / len(failed))


def evaluate_golden_ranking(
    ranked_ids: Sequence[str],
    *,
    relevant_ids: Iterable[str],
    outcomes: Mapping[str, str],
    surfaced_failed_ids: Iterable[str] = (),
    blindly_repeated_ids: Iterable[str] = (),
    k: int = 3,
) -> dict[str, float]:
    return {
        "recall_at_k": recall_at_k(ranked_ids, relevant_ids, k),
        "precision_at_k": precision_at_k(ranked_ids, relevant_ids, k),
        "mrr": reciprocal_rank(ranked_ids, relevant_ids),
        "successful_remediation_retrieval_rate": successful_remediation_retrieval_rate(
            ranked_ids, outcomes, k=k
        ),
        "failed_action_avoidance_rate": failed_action_avoidance_rate(
            surfaced_failed_ids, blindly_repeated_ids
        ),
    }
