from typing import Optional, List
import json
from app.agents.base import BaseAgent, AgentInput, AgentOutput
from app.llm.base import LLMAdapter
from app.llm.mock_provider import MockLLMProvider
from app.core.logging import logger

class SecurityAgent(BaseAgent):
    """
    Agent تخصصی برای تحلیل مسائل امنیتی
    شامل: Authentication, Authorization, Security Policies, Suspicious Patterns
    """
    
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        self.llm = llm_adapter or MockLLMProvider()
    
    @property
    def name(self) -> str:
        return "security"
    
    @property
    def description(self) -> str:
        return "Security analysis: authentication, authorization, security policies, suspicious patterns"
    
    @property
    def allowed_tools(self) -> List[str]:
        return []
    
    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"SecurityAgent analyzing: {input_data.incident_id}")
        
        evidence = input_data.context.get("evidence", []) if input_data.context else []
        logs = [e for e in evidence if e.get("type") == "log"]
        
        # استخراج اطلاعات مرتبط با امنیت
        context_summary = input_data.context.get("summary", {}) if input_data.context else {}
        
        prompt = f"""
You are a security specialist. Analyze the security-related issues.

Incident Details:
- Service: {input_data.service_name or 'unknown'}
- Evidence Summary: {input_data.evidence_summary}
- Logs: {len(logs)} items
- Context Summary: {json.dumps(context_summary, indent=2, default=str) if context_summary else 'None'}

Focus on:
1. **Authentication Issues**: Any authentication failures? Invalid tokens? Expired credentials?
2. **Authorization Issues**: Any permission denied errors? Unauthorized access attempts?
3. **Security Policies**: Any policy violations? (e.g., rate limiting, IP blocking)
4. **Suspicious Patterns**: Any unusual access patterns, brute force attempts, or anomalies?
5. **Data Access**: Any sensitive data exposure?

Provide a structured JSON response:
{{
    "authentication_issues": ["list", "of", "issues"],
    "authorization_issues": ["list", "of", "issues"],
    "policy_violations": ["list", "of", "violations"],
    "suspicious_patterns": ["list", "of", "patterns"],
    "severity": "Critical|High|Medium|Low",
    "confidence": 0.0-1.0,
    "immediate_actions": ["action1", "action2"]
}}
"""
        
        try:
            response = await self.llm.generate(prompt, temperature=0.3)
            try:
                result = json.loads(response.content)
                auth_issues = result.get("authentication_issues", [])
                authz_issues = result.get("authorization_issues", [])
                policy_violations = result.get("policy_violations", [])
                suspicious = result.get("suspicious_patterns", [])
                severity = result.get("severity", "Medium")
                confidence = result.get("confidence", 0.5)
                actions = result.get("immediate_actions", ["Review security logs"])
            except json.JSONDecodeError:
                auth_issues = []
                authz_issues = []
                policy_violations = []
                suspicious = []
                severity = "Medium"
                confidence = 0.5
                actions = ["Review security logs"]
            
            statement = (
                f"Security analysis: Auth issues: {', '.join(auth_issues) if auth_issues else 'None'}. "
                f"Authz issues: {', '.join(authz_issues) if authz_issues else 'None'}. "
                f"Policy violations: {', '.join(policy_violations) if policy_violations else 'None'}. "
                f"Suspicious patterns: {', '.join(suspicious) if suspicious else 'None'}"
            )
            
            return AgentOutput(
                agent_name=self.name,
                finding_type=f"security_{severity.lower()}",
                statement=statement[:300],
                confidence=float(confidence),
                evidence_ids=[],
                recommendations=actions,
                requires_approval=(severity.lower() in ["critical", "high"])
            )
            
        except Exception as e:
            logger.error(f"SecurityAgent failed: {str(e)}")
            return AgentOutput(
                agent_name=self.name,
                finding_type="security_error",
                statement=f"Security analysis failed: {str(e)}",
                confidence=0.0,
                evidence_ids=[],
                recommendations=["Escalate to security team"],
                requires_approval=True
            )