"""Compatibility facade for the canonical production-safe ContextBuilder.

Alert ingestion is handled by the multi-source Signal Gateway. This module no
longer owns a duplicate/mock evidence collection implementation.
"""

from apps.context_service import ContextBuilder

__all__ = ["ContextBuilder"]
