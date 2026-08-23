from typing import Optional, List
import json
from app.agents.base import BaseAgent, AgentInput, AgentOutput
from app.llm.base import LLMAdapter
from app.llm.mock_provider import MockLLMProvider
from app.core.logging import logger

class TriageAgent(BaseAgent):
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        self.llm = llm_adapter or MockLLMProvider()
    
    @property
    def name(self) -> str:
        return "triage"
    
    @property
    def description(self) -> str:
        return "Initial triage and classification of incidents"
    
    @property
    def allowed_tools(self) -> List[str]:
        return []
    
    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"TriageAgent analyzing: {input_data.incident_id}")
        
        # ================================================================
        # ✅ STEP 1: Rule-based detection (بدون LLM)
        # ================================================================
        evidence_summary = input_data.evidence_summary.lower()
        service_name = (input_data.service_name or "").lower()
        combined_text = f"{evidence_summary} {service_name}"
        
        # کلمات کلیدی برای تشخیص VM
        vm_keywords = [
            "debian", "ubuntu", "centos", "redhat", "fedora", "windows server",
            "virtual machine", "guest os", "vmware vm", "hyper-v", "kvm",
            "vsphere", "esxi", "vm", "virtual"
        ]
        
        detected_type = None
        confidence = 0.7
        severity = "Medium"
        description = ""
        recommendations = []
        
        # تشخیص VM
        for keyword in vm_keywords:
            if keyword in combined_text:
                detected_type = "vm"
                severity = "High"
                confidence = 0.85
                description = "Virtual Machine (Guest OS) issue detected."
                recommendations = ["Check VM status via SSH", "Review system logs", "Check resource utilization"]
                logger.info(f"Rule-based detection: VM detected (keyword: {keyword})")
                break
        
        # اگر VM تشخیص داده شد، مستقیماً خروجی بده (بدون LLM)
        if detected_type == "vm":
            return AgentOutput(
                agent_name=self.name,
                finding_type="triage_vm",
                statement=f"Incident categorized as VM with {severity} severity. {description}",
                confidence=confidence,
                evidence_ids=[],
                recommendations=recommendations,
                requires_approval=False
            )
        
        # ================================================================
        # STEP 2: اگر Rule-based تشخیص نداد، از LLM استفاده کن
        # ================================================================
        context_json = json.dumps(input_data.context, indent=2, default=str) if input_data.context else 'None'
        context_summary = input_data.context.get("summary", {}) if input_data.context else {}
        evidence_count = len(input_data.context.get("evidence", [])) if input_data.context else 0
        
        prompt = f"""
You are an expert triage analyst. Analyze the incident details and classify it precisely.

Incident Details:
- Incident ID: {input_data.incident_id or 'unknown'}
- Service: {input_data.service_name or 'unknown'}
- Evidence Summary: {input_data.evidence_summary}
- Evidence Count: {evidence_count} items
- Context Summary: {json.dumps(context_summary, indent=2, default=str) if context_summary else 'None'}
- Full Context: {context_json}

Based on the evidence, classify the incident into ONE of these categories:
- **application**: issues related to code, deployment, configuration, dependencies, or application logic
- **infrastructure**: issues related to CPU, memory, disk, network, VM, or node failures (EXCLUDING specific VM Guest OS issues)
- **kubernetes**: issues related to pods, deployments, services, ingress, or cluster resources
- **security**: issues related to authentication, authorization, or security policy violations
- **vm**: issues related to a specific Virtual Machine (Guest OS) such as Debian, Ubuntu, Windows Server, including CPU load, RAM, Disk, Processes, System Logs, Service status
- **unknown**: if none of the above clearly fit

**CRITICAL:** If the issue mentions a specific VM name (e.g., debian10-vm, ubuntu-server, windows-vm) or keywords like "guest os", "virtual machine", "vmware vm", "hyper-v vm", classify as **vm**.

Also provide:
1. **Severity**: Critical, High, Medium, or Low
2. **Brief Description**: 2-3 sentences
3. **Confidence**: 0.0 to 1.0
4. **Initial Recommendations**: 1-2 actionable items

Respond ONLY with valid JSON in this format:
{{
    "incident_type": "application|infrastructure|kubernetes|security|vm|unknown",
    "severity": "Critical|High|Medium|Low",
    "description": "Brief description of the issue",
    "confidence": 0.0-1.0,
    "recommendations": ["recommendation1", "recommendation2"]
}}
"""
        
        try:
            response = await self.llm.generate(prompt, temperature=0.3)
            
            try:
                result = json.loads(response.content)
                incident_type = result.get("incident_type", "unknown")
                severity = result.get("severity", "Medium")
                description = result.get("description", response.content[:200])
                confidence = result.get("confidence", 0.5)
                recommendations = result.get("recommendations", ["Investigate logs for more details"])
            except json.JSONDecodeError:
                incident_type = "unknown"
                severity = "Medium"
                description = response.content[:300]
                confidence = 0.5
                recommendations = ["Manual review required"]
            
            return AgentOutput(
                agent_name=self.name,
                finding_type=f"triage_{incident_type}",
                statement=f"Incident categorized as {incident_type} with {severity} severity. {description[:200]}",
                confidence=float(confidence),
                evidence_ids=[],
                recommendations=recommendations,
                requires_approval=False
            )
            
        except Exception as e:
            logger.error(f"TriageAgent failed: {str(e)}")
            return AgentOutput(
                agent_name=self.name,
                finding_type="triage_error",
                statement=f"Triage analysis failed: {str(e)}. Manual review required.",
                confidence=0.0,
                evidence_ids=[],
                recommendations=["Escalate to human operator"],
                requires_approval=True
            )