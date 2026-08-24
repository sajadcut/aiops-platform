from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


if len(sys.argv) != 3:
    raise SystemExit("usage: generate_image_attestation.py <image-reference.txt> <output.json>")

source = Path(sys.argv[1])
output = Path(sys.argv[2])
reference = source.read_text(encoding="utf-8").strip()
if "@sha256:" not in reference:
    raise SystemExit("immutable digest reference required")

attestation = {
    "schema": "aiops.offline-image-attestation/v1",
    "image": reference.split("@", 1)[0],
    "digest": reference.split("@", 1)[1],
    "reference_sha256": hashlib.sha256(reference.encode("utf-8")).hexdigest(),
    "promotion": "internal-registry-only",
    "internet_required": False,
}
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(attestation, indent=2), encoding="utf-8")
