from typing import Optional, List
import json
from agents.shared.base import BaseAgent, AgentInput, AgentOutput
from integrations.llm.base import LLMAdapter
from integrations.llm.mock_provider import MockLLMProvider
from domain.contracts.logging import logger

class KubernetesAgent(BaseAgent):
    """
    Agent تخصصی برای تحلیل مشکلات Kubernetes
    شامل: Pods, Deployments, Services, Ingress, Events
    """
    
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        self.llm = llm_adapter or MockLLMProvider()
    
    @property
    def name(self) -> str:
        return "kubernetes"
    
    @property
    def description(self) -> str:
        return "Kubernetes-level analysis: pods, deployments, services, ingress, events"
    
    @property
    def allowed_tools(self) -> List[str]:
        return ["kubectl_get", "kubectl_describe", "kubectl_logs"]
    
    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"KubernetesAgent analyzing: {input_data.incident_id}")
        
        evidence = input_data.context.get("evidence", []) if input_data.context else []
        logs = [e for e in evidence if e.get("type") == "log"]
        metrics = [e for e in evidence if e.get("type") == "metric"]
        
        # استخراج اطلاعات مرتبط با Kubernetes از Context
        context_summary = input_data.context.get("summary", {}) if input_data.context else {}
        
        prompt = f"""
You are a Kubernetes specialist. Analyze the Kubernetes-related issues.

Incident Details:
- Service: {input_data.service_name or 'unknown'}
- Evidence Summary: {input_data.evidence_summary}
- Logs: {len(logs)} items
- Metrics: {len(metrics)} items
- Context Summary: {json.dumps(context_summary, indent=2, default=str) if context_summary else 'None'}

Focus on:
1. **Pod Health**: Are pods running? Any CrashLoopBackOff, ImagePullBackOff, or OOMKilled?
2. **Deployment Status**: Is the deployment healthy? Any rollout failures?
3. **Service/Ingress**: Are services and ingress routes properly configured?
4. **Resource Limits**: Are there any resource constraints (CPU/Memory limits)?
5. **Events**: Any warning or error events in the namespace?

Provide a structured JSON response:
{{
    "pod_health": "Healthy|Degraded|Unhealthy",
    "deployment_issues": ["list", "of", "issues"],
    "service_status": "Healthy|Degraded|Unhealthy",
    "resource_constraints": ["list", "of", "constraints"],
    "confidence": 0.0-1.0,
    "immediate_actions": ["action1", "action2"]
}}
"""
        
        try:
            response = await self.llm.generate(prompt, temperature=0.3)
            try:
                result = json.loads(response.content)
                pod_health = result.get("pod_health", "Unknown")
                deployment_issues = result.get("deployment_issues", [])
                service_status = result.get("service_status", "Unknown")
                resource_constraints = result.get("resource_constraints", [])
                confidence = result.get("confidence", 0.5)
                actions = result.get("immediate_actions", ["Check pod status"])
            except json.JSONDecodeError:
                pod_health = "Unknown"
                deployment_issues = []
                service_status = "Unknown"
                resource_constraints = []
                confidence = 0.5
                actions = ["Check pod status and logs"]
            
            statement = (
                f"Kubernetes analysis: Pod health: {pod_health}. "
                f"Deployment issues: {', '.join(deployment_issues) if deployment_issues else 'None'}. "
                f"Service status: {service_status}. "
                f"Resource constraints: {', '.join(resource_constraints) if resource_constraints else 'None'}"
            )
            
            return AgentOutput(
                agent_name=self.name,
                finding_type="kubernetes_analysis",
                statement=statement[:300],
                confidence=float(confidence),
                evidence_ids=[],
                recommendations=actions,
                requires_approval=False
            )
            
        except Exception as e:
            logger.error(f"KubernetesAgent failed: {str(e)}")
            return AgentOutput(
                agent_name=self.name,
                finding_type="kubernetes_error",
                statement=f"Kubernetes analysis failed: {str(e)}",
                confidence=0.0,
                evidence_ids=[],
                recommendations=["Check Kubernetes cluster status manually"],
                requires_approval=True
            )