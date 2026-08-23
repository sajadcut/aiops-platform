from typing import Optional, List
import json
from agents.shared.base import BaseAgent, AgentInput, AgentOutput
from integrations.llm.base import LLMAdapter
from integrations.llm.mock_provider import MockLLMProvider
from domain.contracts.logging import logger

class VMAgent(BaseAgent):
    """
    Agent تخصصی برای تحلیل وضعیت یک ماشین مجازی خاص (Guest OS)
    شامل: Debian 10/11, Ubuntu, CentOS, Windows Server
    بررسی: CPU, RAM, Disk, Network, Processes, System Logs
    """
    
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        self.llm = llm_adapter or MockLLMProvider()
    
    @property
    def name(self) -> str:
        return "vm"
    
    @property
    def description(self) -> str:
        return "Virtual Machine (Guest OS) analysis: CPU, RAM, Disk, Network, Processes, System Logs"
    
    @property
    def allowed_tools(self) -> List[str]:
        return ["ssh_cmd", "vm_stat", "get_logs"]
    
    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"VMAgent analyzing VM for: {input_data.incident_id}")
        
        evidence = input_data.context.get("evidence", []) if input_data.context else []
        metrics = [e for e in evidence if e.get("type") == "metric"]
        logs = [e for e in evidence if e.get("type") == "log"]
        alerts = [e for e in evidence if e.get("type") == "alert"]
        
        context_summary = input_data.context.get("summary", {}) if input_data.context else {}
        
        # ساخت یک نمای کلی از VM برای LLM
        vm_summary = f"""
        VM Information:
        - Service: {input_data.service_name or 'unknown-vm'}
        - OS: Debian 10 (Buster) / Linux
        - Metrics available: {len(metrics)}
        - Logs available: {len(logs)}
        - Alerts available: {len(alerts)}
        - Avg CPU: {context_summary.get('avg_cpu', 'N/A')}%
        - Avg Memory: {context_summary.get('avg_memory', 'N/A')}%
        - Error Rate: {context_summary.get('error_rate', 'N/A')}%
        """
        
        prompt = f"""
You are a Virtual Machine (Guest OS) specialist. Analyze the state of this specific VM.

{vm_summary}

Focus on the following aspects (as if you are checking the VM directly):

1. **VM Status**: Is the VM powered on and reachable? (Running/Stopped/Unreachable)
2. **CPU Load**: CPU usage percentage and load average (1m, 5m, 15m).
3. **Memory Usage**: RAM usage percentage, swap usage, available memory.
4. **Disk Storage**: Disk usage percentage (especially root partition), I/O wait.
5. **Network**: Inbound/Outbound traffic, packet loss, interface status (eth0, ens33).
6. **Critical Processes**: Are essential services running? (e.g., nginx, postgresql, docker, systemd)
7. **System Logs**: Any errors in /var/log/syslog, /var/log/kern.log, or /var/log/auth.log?

Provide a structured JSON response:
{{
    "vm_status": "Running|Stopped|Unreachable",
    "cpu_load": {{
        "usage_percent": 0.0,
        "load_avg": "x.xx, x.xx, x.xx"
    }},
    "memory_usage_percent": 0.0,
    "disk_usage_percent": 0.0,
    "network": "Healthy|Degraded|Congested",
    "critical_processes": {{"nginx": "running", "postgresql": "running"}},
    "system_log_issues": ["list", "of", "errors"],
    "confidence": 0.0-1.0,
    "immediate_actions": ["action1", "action2"]
}}
"""
        
        try:
            response = await self.llm.generate(prompt, temperature=0.3)
            try:
                result = json.loads(response.content)
                vm_status = result.get("vm_status", "Unknown")
                cpu_load = result.get("cpu_load", {})
                memory_usage = result.get("memory_usage_percent", 0.0)
                disk_usage = result.get("disk_usage_percent", 0.0)
                network = result.get("network", "Unknown")
                processes = result.get("critical_processes", {})
                log_issues = result.get("system_log_issues", [])
                confidence = result.get("confidence", 0.5)
                actions = result.get("immediate_actions", ["Check VM via SSH"])
            except json.JSONDecodeError:
                vm_status = "Unknown"
                cpu_load = {}
                memory_usage = 0.0
                disk_usage = 0.0
                network = "Unknown"
                processes = {}
                log_issues = []
                confidence = 0.5
                actions = ["Check VM via SSH"]
            
            # خلاصه‌سازی وضعیت
            running_processes = [f"{k}: {v}" for k, v in processes.items()]
            statement = (
                f"VM analysis: Status: {vm_status}. "
                f"CPU: {cpu_load.get('usage_percent', 'N/A')}% "
                f"(Load: {cpu_load.get('load_avg', 'N/A')}). "
                f"Memory: {memory_usage}%. "
                f"Disk: {disk_usage}%. "
                f"Network: {network}. "
                f"Processes: {', '.join(running_processes) if running_processes else 'N/A'}. "
                f"Log issues: {len(log_issues)} found."
            )
            
            return AgentOutput(
                agent_name=self.name,
                finding_type="vm_analysis",
                statement=statement[:300],
                confidence=float(confidence),
                evidence_ids=[],
                recommendations=actions,
                requires_approval=(vm_status.lower() in ["stopped", "unreachable"])
            )
            
        except Exception as e:
            logger.error(f"VMAgent failed: {str(e)}")
            return AgentOutput(
                agent_name=self.name,
                finding_type="vm_error",
                statement=f"VM analysis failed: {str(e)}. Manual SSH check required.",
                confidence=0.0,
                evidence_ids=[],
                recommendations=["Escalate to infrastructure team for manual VM check"],
                requires_approval=True
            )