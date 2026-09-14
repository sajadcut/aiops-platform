from pathlib import Path


def test_offline_runtime_uses_isolated_multistage_build():
    text = Path("deployment/docker/offline/Dockerfile").read_text()

    builder_marker = "FROM ${PYTHON_BUILDER_IMAGE} AS builder"
    runtime_marker = "FROM ${PYTHON_RUNTIME_IMAGE} AS runtime"
    assert builder_marker in text
    assert runtime_marker in text

    builder, runtime = text.split(runtime_marker, 1)
    assert "--find-links=/opt/wheels" in builder
    assert "COPY --from=builder --chown=root:root /opt/venv /opt/venv" in runtime
    assert "--find-links=/opt/wheels" not in runtime
    assert "test ! -e /opt/wheels" in runtime
    assert "test ! -e /build" in runtime


def test_container_acceptance_checks_final_filesystem_not_builder_layers():
    workflow = Path(".github/workflows/container-acceptance.yml").read_text()

    assert "--build-arg PYTHON_BUILDER_IMAGE=aiops-wheelhouse-ci" in workflow
    assert "--build-arg PYTHON_RUNTIME_IMAGE=aiops-runtime-base-ci" in workflow
    assert "docker export" in workflow
    assert "test ! -e runtime-rootfs/opt/wheels" in workflow
    assert "test ! -e runtime-rootfs/build" in workflow
    assert "Generate CycloneDX SBOM from merged runtime filesystem" in workflow
    assert "cosign verify-blob" in workflow
