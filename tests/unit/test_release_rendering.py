from pathlib import Path

import pytest

from scripts.render_k8s_release import render, validate_image_ref


VALID = "registry.internal/aiops-platform@sha256:" + ("a" * 64)


def test_release_renderer_rejects_tags_and_zero_digest():
    with pytest.raises(ValueError):
        validate_image_ref("registry.internal/aiops-platform:2.2")
    with pytest.raises(ValueError):
        validate_image_ref("registry.internal/aiops-platform@sha256:" + ("0" * 64))


def test_release_renderer_uses_same_immutable_artifact_for_api_migration_and_memory_jobs(tmp_path: Path):
    outputs = render(VALID, tmp_path)
    assert len(outputs) == 4
    texts = [path.read_text(encoding="utf-8") for path in outputs]
    for text in texts:
        assert VALID in text
        assert "registry.invalid/aiops-platform" not in text
        assert "registry.internal/aiops-platform:2.2" not in text
    assert sum(text.count(VALID) for text in texts) == 4


def test_raw_templates_are_fail_closed_and_never_mutable():
    paths = (
        Path("deployment/kubernetes/aiops-platform.yaml"),
        Path("deployment/kubernetes/migrate-job.yaml"),
        Path("deployment/kubernetes/memory-embedding-backfill-cronjob.yaml"),
        Path("deployment/kubernetes/memory-stale-cronjob.yaml"),
    )
    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert "registry.invalid/aiops-platform@sha256:" + ("0" * 64) in text
        assert ":latest" not in text
        assert "registry.internal/aiops-platform:2.2" not in text
