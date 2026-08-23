from typing import Optional, List
import json
from app.agents.base import BaseAgent, AgentInput, AgentOutput
from app.llm.base import LLMAdapter
from app.llm.mock_provider import MockLLMProvider
from app.core.logging import logger

class ApplicationAgent(BaseAgent):
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        self.llm = llm_adapter or MockLLMProvider()
    
    @property
    def name(self) -> str:
        return "application"
    
    @property
    def description(self) -> str:
        return "Application-level analysis: logs, deployments, error patterns"
    
    @property
    def allowed_tools(self) -> List[str]:
        return []
    
    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"ApplicationAgent analyzing: {input_data.incident_id}")
        evidence = input_data.context.get("evidence", []) if input_data.context else []
        logs = [e for e in evidence if e.get("type") == "log"]
        latest_logs = logs[:3] if logs else []
        logs_json = json.dumps(latest_logs, indent=2, default=str) if latest_logs else 'No logs available'
        context_json = json.dumps(input_data.context, indent=2, default=str) if input_data.context else 'None'
        prompt = f"""
You are an application specialist. Analyze the application-level issues based on logs, deployment history, and error patterns.
Incident Details:
- Service: {input_data.service_name or 'unknown'}
- Evidence Summary: {input_data.evidence_summary}
- Recent Logs: {logs_json}
- Context: {context_json}
Focus on:
1. **Error Pattern**: What specific errors are occurring?
2. **Deployment Correlation**: Has there been a recent deployment?
3. **Dependency Health**: Are downstream services or databases healthy?
4. **Code/Config Issues**: Any known bugs or misconfigurations?
Provide a structured JSON response:
{{
    "error_pattern": "Description",
    "deployment_related": true/false,
    "dependency_issues": ["list"],
    "confidence": 0.0-1.0,
    "immediate_actions": ["action1", "action2"]
}}
"""
        try:
            response = await self.llm.generate(prompt, temperature=0.3)
            try:
                result = json.loads(response.content)
                error_pattern = result.get("error_pattern", "Unknown")
                deployment_related = result.get("deployment_related", False)
                dependency_issues = result.get("dependency_issues", [])
                confidence = result.get("confidence", 0.5)
                actions = result.get("immediate_actions", ["Review application logs"])
            except:
                error_pattern = "Application errors detected"
                deployment_related = False
                dependency_issues = []
                confidence = 0.5
                actions = ["Review application logs"]
            statement = f"Application analysis: {error_pattern}. Deployment related: {deployment_related}. Dependencies: {', '.join(dependency_issues) if dependency_issues else 'None'}"
            return AgentOutput(
                agent_name=self.name,
                finding_type="application_analysis",
                statement=statement[:300],
                confidence=float(confidence),
                evidence_ids=[],
                recommendations=actions,
                requires_approval=False
            )
        except Exception as e:
            logger.error(f"ApplicationAgent failed: {str(e)}")
            return AgentOutput(
                agent_name=self.name,
                finding_type="application_error",
                statement=f"Application analysis failed: {str(e)}",
                confidence=0.0,
                evidence_ids=[],
                recommendations=["Escalate to human operator"],
                requires_approval=True
            )