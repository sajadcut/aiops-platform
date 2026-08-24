# Offline Production Deployment

This directory defines the offline deployment contract for the AIOps platform.

## Required internal artifacts

- Python base image mirrored in the internal registry
- Application image mirrored in the internal registry
- PostgreSQL image/package approved for the environment
- pgvector PostgreSQL extension/package
- LLM/model artifacts supplied through the internal registry/repository
- Python wheels mirrored into Nexus or an equivalent internal repository

## Rules

1. Runtime containers must not require direct Internet access.
2. Secrets are supplied through environment/secret management, never baked into images.
3. Tool execution defaults to deny and must be governed by Policy + Approval.
4. Health checks must verify API, PostgreSQL and pgvector readiness.
5. Deployment promotion must be traceable to an immutable image digest.
