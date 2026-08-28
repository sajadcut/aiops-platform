from __future__ import annotations

import argparse
import re
from pathlib import Path

_PLACEHOLDER = "registry.invalid/aiops-platform@sha256:" + ("0" * 64)
_DIGEST_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@[sS][hH][aA]256:[0-9a-f]{64}$")


def validate_image_ref(image_ref: str) -> str:
    value = str(image_ref).strip()
    if not _DIGEST_RE.fullmatch(value):
        raise ValueError("image_ref_must_be_immutable_sha256_digest")
    digest = value.rsplit("sha256:", 1)[-1]
    if digest == "0" * 64:
        raise ValueError("zero_digest_is_not_a_promotable_artifact")
    return value


def render(image_ref: str, output_dir: Path) -> list[Path]:
    image_ref = validate_image_ref(image_ref)
    output_dir.mkdir(parents=True, exist_ok=True)
    source_dir = Path("deployment/kubernetes")
    outputs: list[Path] = []
    for name in ("aiops-platform.yaml", "migrate-job.yaml"):
        source = source_dir / name
        text = source.read_text(encoding="utf-8")
        count = text.count(_PLACEHOLDER)
        if count != 1:
            raise ValueError(f"expected_exactly_one_release_placeholder:{name}:{count}")
        rendered = text.replace(_PLACEHOLDER, image_ref)
        if _PLACEHOLDER in rendered:
            raise ValueError(f"release_placeholder_not_replaced:{name}")
        target = output_dir / name
        target.write_text(rendered, encoding="utf-8")
        outputs.append(target)
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description="Render fail-closed Kubernetes templates with one immutable OCI digest")
    parser.add_argument("image_ref", help="e.g. registry.example/aiops-platform@sha256:<64 hex>")
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    paths = render(args.image_ref, args.output_dir)
    for path in paths:
        print(path)


if __name__ == "__main__":
    main()
