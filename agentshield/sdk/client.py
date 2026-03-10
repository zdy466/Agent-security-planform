"""AgentShield SDK Client - Main client interface for AgentShield OS"""

import logging
from typing import Any, Dict, Optional

from agentshield.core.security_layer import SecurityLayer
from agentshield.firewall.llm_data_firewall import LLMDataFirewall
from agentshield.toolguard.tool_manager import ToolManager
from agentshield.datagateway.data_gateway import DataGateway
from agentshield.audit.audit_logger import AuditLogger


class AgentShieldClient:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        self.security_layer = SecurityLayer(
            self.config.get("security_layer", {})
        )
        self.firewall = LLMDataFirewall(
            self.config.get("firewall", {})
        )
        self.tool_manager = ToolManager(
            self.config.get("tool_manager", {})
        )
        self.data_gateway = DataGateway(
            self.config.get("data_gateway", {})
        )
        self.audit_logger = AuditLogger(
            self.config.get("audit_logger", {})
        )

    def process_input(self, data: str, user: Optional[str] = None) -> Dict[str, Any]:
        self.audit_logger.log(
            event_type="input_processing",
            user=user,
            action="process_input"
        )

        if not self.security_layer.validate_input(data):
            return {"allowed": False, "reason": "security_validation_failed"}

        firewall_result = self.firewall.check_input(data)
        if not firewall_result.get("allowed"):
            return firewall_result

        return {"allowed": True, "data": data}

    def process_output(self, data: str, user: Optional[str] = None) -> Dict[str, Any]:
        self.audit_logger.log(
            event_type="output_processing",
            user=user,
            action="process_output"
        )

        if not self.security_layer.validate_output(data):
            return {"allowed": False, "reason": "security_validation_failed"}

        firewall_result = self.firewall.check_output(data)
        if not firewall_result.get("allowed"):
            return firewall_result

        return {"allowed": True, "data": data}

    def execute_tool(
        self,
        tool_name: str,
        params: Dict[str, Any],
        user: Optional[str] = None
    ) -> Any:
        self.audit_logger.log(
            event_type="tool_execution",
            user=user,
            action="execute_tool",
            resource=tool_name
        )

        return self.tool_manager.execute(tool_name, params)

    def read_data(
        self,
        source: str,
        query: Optional[Dict[str, Any]] = None,
        user: Optional[str] = None
    ) -> Any:
        self.audit_logger.log(
            event_type="data_read",
            user=user,
            action="read_data",
            resource=source
        )

        return self.data_gateway.read_data(source, query)

    def write_data(
        self,
        source: str,
        data: Any,
        user: Optional[str] = None
    ) -> bool:
        self.audit_logger.log(
            event_type="data_write",
            user=user,
            action="write_data",
            resource=source
        )

        return self.data_gateway.write_data(source, data)

    def get_audit_events(self, **kwargs) -> list:
        return self.audit_logger.get_events(**kwargs)
