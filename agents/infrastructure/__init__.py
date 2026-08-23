from typing import Optional, List
import json
from agents.shared.base import BaseAgent, AgentInput, AgentOutput
from integrations.llm.base import LLMAdapter
from integrations.llm.mock_provider import MockLLMProvider
from domain.contracts.logging import logger

class InfrastructureAgent(BaseAgent):
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        self.llm = llm_adapter or MockLLMProvider()
    
    @property
    def name(self) -> str:
        return "infrastructure"
    
    @property
    def description(self) -> str:
        return "Infrastructure-level analysis: CPU, memory, disk, network, nodes"
    
    @property
    def allowed_tools(self) -> List[str]:
        return []
    
    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"InfrastructureAgent analyzing: {input_data.incident_id}")
        evidence = input_data.context.get("evidence", []) if input_data.context else []
        metrics = [e for e in evidence if e.get("type") == "metric"]
        latest_metrics = metrics[:3] if metrics else []
        metrics_json = json.dumps(latest_metrics, indent=2, default=str) if latest_metrics else 'No metrics available'
        context_json = json.dumps(input_data.context, indent=2, default=str) if input_data.context else 'None'
        prompt = f"""
You are an infrastructure specialist. Analyze the underlying infrastructure issues.
Incident Details:
- Service: {input_data.service_name or 'unknown'}
- Evidence Summary: {input_data.evidence_summary}
- Recent Metrics: {metrics_json}
- Context: {context_json}
Focus on:
1. **Resource Saturation**: CPU, memory, disk, network
2. **Node Health**: Are nodes healthy?
3. **Network Issues**: Latency, packet loss
4. **VM/Container Performance**: Resource limits?
Provide a structured JSON response:
{{
    "resource_saturation": ["list"],
    "node_health": "Healthy|Degraded|Unhealthy",
    "network_issues": ["list"],
    "confidence": 0.0-1.0,
    "immediate_actions": ["action1", "action2"]
}}
"""
        try:
            response = await self.llm.generate(prompt, temperature=0.3)
            try:
                result = json.loads(response.content)
                resource_saturation = result.get("resource_saturation", [])
                node_health = result.get("node_health", "Unknown")
                network_issues = result.get("network_issues", [])
                confidence = result.get("confidence", 0.5)
                actions = result.get("immediate_actions", ["Check infrastructure metrics"])
            except:
                resource_saturation = ["Unknown"]
                node_health = "Unknown"
                network_issues = []
                confidence = 0.5
                actions = ["Check infrastructure metrics"]
            statement = f"Infrastructure analysis: Resources: {', '.join(resource_saturation)}. Node health: {node_health}. Network: {', '.join(network_issues) if network_issues else 'No issues'}"
            return AgentOutput(
                agent_name=self.name,
                finding_type="infrastructure_analysis",
                statement=statement[:300],
                confidence=float(confidence),
                evidence_ids=[],
                recommendations=actions,
                requires_approval=False
            )
        except Exception as e:
            logger.error(f"InfrastructureAgent failed: {str(e)}")
            return AgentOutput(
                agent_name=self.name,
                finding_type="infrastructure_error",
                statement=f"Infrastructure analysis failed: {str(e)}",
                confidence=0.0,
                evidence_ids=[],
                recommendations=["Escalate to infrastructure team"],
                requires_approval=True
            )