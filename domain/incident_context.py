from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass(slots=True)
class IncidentContext:
    incident_id: Optional[str]
    service: Optional[str]
    environment: Optional[str]
    time_window: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    knowledge_refs: List[Dict[str, Any]] = field(default_factory=list)
    memory_refs: List[Dict[str, Any]] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    recent_deployments: List[Dict[str, Any]] = field(default_factory=list)
