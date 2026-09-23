from apps.memory_service.quality import evaluate_golden_ranking


def test_operational_memory_golden_dataset_quality_contract():
    # Golden cases from the Operational Memory v2 acceptance specification:
    # A: nginx stopped, start_service succeeded.
    # B: nginx active, firewall blocked the port; not the same cause.
    # C: nginx bad config, start_service failed and must be a warning.
    # D: memory pressure killed a process; must not rank high merely for nginx.
    # E: similar symptom but different environment/version.
    ranked = ["A", "C", "E", "B", "D"]
    outcomes = {
        "A": "successful_recovery",
        "B": "diagnostic_only",
        "C": "failed_recovery",
        "D": "diagnostic_only",
        "E": "successful_recovery",
    }

    metrics = evaluate_golden_ranking(
        ranked,
        relevant_ids={"A", "C"},
        outcomes=outcomes,
        surfaced_failed_ids={"C"},
        blindly_repeated_ids=set(),
        k=3,
    )

    assert ranked[0] == "A"
    assert ranked.index("B") > ranked.index("C")
    assert ranked.index("D") >= 3
    assert metrics["recall_at_k"] == 1.0
    assert metrics["precision_at_k"] >= 2 / 3
    assert metrics["mrr"] == 1.0
    assert metrics["successful_remediation_retrieval_rate"] >= 1 / 3
    assert metrics["failed_action_avoidance_rate"] == 1.0


def test_failed_action_avoidance_metric_detects_blind_repeat():
    metrics = evaluate_golden_ranking(
        ["C", "A"],
        relevant_ids={"A", "C"},
        outcomes={"A": "successful_recovery", "C": "failed_recovery"},
        surfaced_failed_ids={"C"},
        blindly_repeated_ids={"C"},
        k=2,
    )
    assert metrics["failed_action_avoidance_rate"] == 0.0
