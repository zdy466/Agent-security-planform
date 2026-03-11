"""AgentShield SDK Client - Main client interface for AgentShield OS"""

import logging
from typing import Any, Dict, Optional

from agentshield.core.security_layer import SecurityLayer
from agentshield.firewall.llm_data_firewall import EnhancedLLMDataFirewall as LLMDataFirewall
from agentshield.toolguard.tool_manager import ToolManager
from agentshield.datagateway.data_gateway import DataGateway
from agentshield.audit.audit_logger import AuditLogger


class AgentShieldClient:
    """AgentShield SDK Client - Main client interface for AgentShield OS

    AgentShield SDK 客户端，是访问 AgentShield 安全框架的主要接口。
    该类整合了安全层的各个组件，提供统一的安全操作入口，包括输入/输出处理、
    工具执行、数据访问控制和审计日志。

    集成的安全组件:
        - SecurityLayer: 安全验证层
        - LLMDataFirewall: LLM数据防火墙
        - ToolManager: 工具管理器
        - DataGateway: 数据网关
        - AuditLogger: 审计日志

    构造函数参数:
        config (Optional[Dict[str, Any]]): 配置字典，包含以下可选键:
            - security_layer (Dict): 安全层配置
            - firewall (Dict): 防火墙配置
            - tool_manager (Dict): 工具管理器配置
            - data_gateway (Dict): 数据网关配置
            - audit_logger (Dict): 审计日志配置

    主要方法:
        process_input(data: str, user: Optional[str] = None) -> Dict[str, Any]:
            处理输入数据，通过安全层和防火墙进行验证。

            参数:
                data (str): 待处理的输入数据
                user (Optional[str]): 用户标识

            返回:
                Dict[str, Any]: 处理结果，包含以下键:
                    - allowed (bool): 是否允许通过
                    - reason (str): 通过/拒绝原因
                    - data (str): 处理后的数据（仅当 allowed 为 True 时）

        process_output(data: str, user: Optional[str] = None) -> Dict[str, Any]:
            处理输出数据，通过安全层和防火墙进行验证。

            参数:
                data (str): 待处理的输出数据
                user (Optional[str]): 用户标识

            返回:
                Dict[str, Any]: 处理结果，包含以下键:
                    - allowed (bool): 是否允许通过
                    - reason (str): 通过/拒绝原因
                    - data (str): 处理后的数据（仅当 allowed 为 True 时）

        execute_tool(
            tool_name: str,
            params: Dict[str, Any],
            user: Optional[str] = None
        ) -> Any:
            执行工具，通过工具管理器进行验证和执行。

            参数:
                tool_name (str): 工具名称
                params (Dict[str, Any]): 工具参数
                user (Optional[str]): 用户标识

            返回:
                Any: 工具执行结果

            异常:
                PermissionError: 工具被禁止执行或需要审批
                ValueError: 参数验证失败

        read_data(
            source: str,
            query: Optional[Dict[str, Any]] = None,
            user: Optional[str] = None
        ) -> Any:
            从数据源读取数据，通过数据网关进行权限验证。

            参数:
                source (str): 数据源名称
                query (Optional[Dict[str, Any]]): 查询条件
                user (Optional[str]): 用户标识

            返回:
                Any: 读取的数据

            异常:
                PermissionError: 没有读取权限
                ValueError: 查询验证失败

        write_data(
            source: str,
            data: Any,
            user: Optional[str] = None
        ) -> bool:
            向数据源写入数据，通过数据网关进行权限验证。

            参数:
                source (str): 数据源名称
                data (Any): 待写入的数据
                user (Optional[str]): 用户标识

            返回:
                bool: 写入是否成功

            异常:
                PermissionError: 没有写入权限

        get_audit_events(**kwargs) -> list:
            获取审计日志事件。

            参数:
                **kwargs: 可选的过滤参数，如 event_type, user, action 等

            返回:
                list: 审计事件列表

    使用示例:
        >>> # 创建客户端实例
        >>> client = AgentShieldClient({
        ...     "firewall": {
        ...         "enabled": True,
        ...         "blocker": {"block_critical": True}
        ...     },
        ...     "tool_manager": {
        ...         "enable_whitelist": True,
        ...         "whitelist": ["search", "calculator"]
        ...     }
        ... })
        >>>
        >>> # 处理输入
        >>> result = client.process_input("用户输入的内容", user="user1")
        >>> if result["allowed"]:
        ...     print("输入通过验证")
        >>>
        >>> # 执行工具
        >>> try:
        ...     tool_result = client.execute_tool("calculator", {"a": 10, "b": 5}, user="user1")
        ...     print(f"工具执行结果: {tool_result}")
        ... except PermissionError as e:
        ...     print(f"工具执行被拒绝: {e}")
        >>>
        >>> # 读取数据
        >>> data = client.read_data("database", user="user1")
        >>>
        >>> # 获取审计日志
        >>> events = client.get_audit_events(event_type="tool_execution")
        >>> for event in events:
        ...     print(event)
    """

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
