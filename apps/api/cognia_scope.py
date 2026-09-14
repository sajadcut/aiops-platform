from __future__ import annotations

from typing import Any, Mapping

from fastapi import HTTPException


def reject_untrusted_knowledge_subject(context: Mapping[str, Any] | None) -> None:
    """Reject caller-supplied Cognia ExternalSubject scope on public workflow APIs.

    The AIOps service uses one Cognia Machine Client identity. A public caller's
    ability to read an Incident does not prove that caller is authorized for an
    arbitrary customer/account/case ExternalSubject. Trusted server-side
    integrations may bind a Subject after their own domain authorization; public
    free-form context cannot manufacture that authority.
    """
    if not context:
        return
    if "knowledge_subject" in context or "knowledgeSubject" in context:
        raise HTTPException(
            status_code=403,
            detail="knowledge_subject_requires_trusted_server_binding",
        )
