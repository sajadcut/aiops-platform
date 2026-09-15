import json

import pytest

from agents.shared.base import AgentInput
from agents.storage import StorageAgent
from integrations.llm.base import LLMAdapter, LLMResponse


class DiskExhaustionScenarioLLM(LLMAdapter):
    @property
    def provider_name(self):
        return "disk-exhaustion-acceptance"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        payload = {
            "severity": "critical",
            "health_status": "degraded",
            "findings": [
                "root filesystem has less than one percent free space",
                "inode availability is exhausted",
            ],
            "affected_components": ["payments-vm-01", "/var"],
            "probable_dependencies": ["payments-api"],
            "blast_radius": "writes, logs and application persistence on payments-vm-01",
            "hypotheses": [{
                "hypothesis": "filesystem capacity and inode exhaustion are blocking writes",
                "probability": 0.96,
                "evidence_ids": ["disk-free-critical", "inode-free-zero", "write-enospc"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["inspect filesystem and inode utilization without modifying files"],
                "impacted_components": ["payments-vm-01", "/var"],
                "recommended_next_evidence": ["largest filesystem consumers and inode distribution"],
            }],
            "missing_evidence": [],
            "handoff_agents": ["infrastructure", "vm"],
            # Deliberately unsafe: analysis must never turn this into an executable tool action.
            "immediate_checks": [
                "Inspect filesystem and inode utilization",
                "Delete old log files from /var/log",
            ],
            "escalation_target": "infrastructure-sre",
            "risk_level": "high",
            "uncertainty_reason": "",
            "confidence": 0.96,
        }
        return LLMResponse(content=json.dumps(payload), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


@pytest.mark.asyncio
async def test_disk_inode_exhaustion_is_grounded_and_delete_is_approval_bound():
    incident = AgentInput(
        incident_id="inc-storage-exhaustion-007",
        service_name="payments-api",
        evidence_summary="payments VM cannot write because disk space and inodes are exhausted",
        context={
            "evidence": [
                {"id": "disk-free-critical", "type": "metric", "source": "prometheus", "name": "node_filesystem_avail_bytes", "value": 10485760},
                {"id": "inode-free-zero", "type": "metric", "source": "prometheus", "name": "node_filesystem_files_free", "value": 0},
                {"id": "write-enospc", "type": "log", "source": "elasticsearch", "message": "write failed: no space left on device"},
            ]
        },
    )

    result = await StorageAgent(DiskExhaustionScenarioLLM()).analyze(incident)

    assert result.evidence_count == 3
    assert set(result.evidence_ids) == {"disk-free-critical", "inode-free-zero", "write-enospc"}
    assert result.hypotheses[0].evidence_ids == ["disk-free-critical", "inode-free-zero", "write-enospc"]
    assert not result.missing_evidence

    read_check, delete_action = result.recommended_actions
    assert read_check.read_only is True
    assert read_check.requires_approval is False
    assert delete_action.read_only is False
    assert delete_action.requires_approval is True
    assert delete_action.risk_level == "high"
    assert delete_action.purpose == "untrusted_write_recommendation"
    assert delete_action.suggested_tool is None
