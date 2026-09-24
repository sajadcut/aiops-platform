from pathlib import Path


def test_sqlalchemy_asyncio_runtime_extra_is_declared():
    requirements = Path("requirements.txt").read_text(encoding="utf-8").splitlines()
    normalized = {line.strip().lower() for line in requirements if line.strip() and not line.lstrip().startswith("#")}

    assert any(line.startswith("sqlalchemy[asyncio]>=") for line in normalized)
    assert not any(line.startswith("sqlalchemy>=") for line in normalized)
