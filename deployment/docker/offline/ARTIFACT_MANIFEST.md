# Offline Artifact Manifest

Required offline inputs for production deployment:

- Python wheels for the locked dependency set
- Application container image
- Approved model artifact or internal LLM endpoint configuration
- PostgreSQL/pgvector compatibility package set
- Kubernetes/Docker manifests from this repository

Rules:

1. No runtime dependency may download from the public internet.
2. Artifacts must be checksummed before import.
3. Image and wheel provenance must be recorded.
4. Model/provider selection remains adapter-based.
