"""AgentShield OS - A comprehensive security framework for LLM agents"""

from agentshield.core.security_layer import SecurityLayer
from agentshield.firewall.llm_data_firewall import LLMDataFirewall
from agentshield.firewall.injection.prompt_injection import PromptInjectionFirewall
from agentshield.toolguard.tool_manager import ToolManager
from agentshield.datagateway.data_gateway import DataGateway
from agentshield.audit.audit_logger import AuditLogger
from agentshield.monitoring.dashboard import MonitoringDashboard
from agentshield.monitoring.behavior.behavior_monitor import BehaviorMonitor
from agentshield.core.policy.policy_engine import PolicyEngine
from agentshield.security.attack_simulation import AttackSimulator, SecurityTestSuite
from agentshield.security.compliance import ComplianceManager
from agentshield.security.governance import GovernanceSystem
from agentshield.sdk.client import AgentShieldClient

__version__ = "0.3.0"

__all__ = [
    "SecurityLayer",
    "LLMDataFirewall",
    "PromptInjectionFirewall",
    "ToolManager",
    "DataGateway",
    "AuditLogger",
    "MonitoringDashboard",
    "BehaviorMonitor",
    "PolicyEngine",
    "AttackSimulator",
    "SecurityTestSuite",
    "ComplianceManager",
    "GovernanceSystem",
    "AgentShieldClient",
]
