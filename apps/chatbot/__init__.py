"""Production AIOps Chatbot / Operations Copilot.

The chatbot is a control-plane orchestration layer. It may ask the configured
LLM to classify intent and select allowlisted semantic tools, but it never turns
model output into shell/SSH/kubectl execution. Reads go through governed MCP
connectors; writes remain behind the durable Approval -> Execution boundary.
"""

from apps.chatbot.service import ChatbotService

__all__ = ["ChatbotService"]
