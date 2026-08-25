from __future__ import annotations

import hashlib
import random
from typing import List

import httpx
import numpy as np

from domain.contracts.config import settings
from domain.contracts.logging import logger


class EmbeddingService:
    """Provider-neutral embedding service for Knowledge RAG and Memory.

    ``deterministic`` is intentionally available for tests and offline
    development. Production refuses that provider and requires an explicitly
    configured OpenAI-compatible internal/offline embedding gateway.
    """

    @staticmethod
    def _deterministic_embedding(text: str) -> List[float]:
        hash_val = int(hashlib.sha256(text.encode("utf-8")).hexdigest(), 16)
        rng = random.Random(hash_val)
        embedding = [rng.random() for _ in range(settings.EMBEDDING_DIMENSION)]
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = [float(v / norm) for v in embedding]
        return embedding

    @staticmethod
    async def generate_embedding(text: str) -> List[float]:
        if not text or not text.strip():
            raise ValueError("embedding_text_required")

        provider = settings.EMBEDDING_PROVIDER.strip().lower()
        if provider == "deterministic":
            if settings.APP_ENV == "production":
                raise RuntimeError("deterministic_embedding_provider_forbidden_in_production")
            embedding = EmbeddingService._deterministic_embedding(text)
        elif provider in {"openai-compatible", "openai_compatible"}:
            if not settings.EMBEDDING_BASE_URL:
                raise RuntimeError("EMBEDDING_BASE_URL is required")
            url = settings.EMBEDDING_BASE_URL.rstrip("/") + "/embeddings"
            headers = {"Content-Type": "application/json"}
            if settings.EMBEDDING_API_KEY:
                headers["Authorization"] = f"Bearer {settings.EMBEDDING_API_KEY}"
            async with httpx.AsyncClient(timeout=settings.EMBEDDING_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    url,
                    headers=headers,
                    json={"model": settings.EMBEDDING_MODEL, "input": text},
                )
                response.raise_for_status()
                payload = response.json()
            try:
                embedding = [float(value) for value in payload["data"][0]["embedding"]]
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise RuntimeError("invalid_embedding_gateway_response") from exc
        else:
            raise RuntimeError(f"unsupported_embedding_provider:{provider}")

        if len(embedding) != settings.EMBEDDING_DIMENSION:
            raise RuntimeError(
                f"embedding_dimension_mismatch:expected={settings.EMBEDDING_DIMENSION},actual={len(embedding)}"
            )
        logger.info(
            f"Generated embedding provider={provider} dimension={len(embedding)} text_length={len(text)}"
        )
        return embedding

    @staticmethod
    async def generate_embeddings(texts: List[str]) -> List[List[float]]:
        return [await EmbeddingService.generate_embedding(text) for text in texts]
