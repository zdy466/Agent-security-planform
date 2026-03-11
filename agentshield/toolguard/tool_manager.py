"""Tool Manager - Manages and monitors tool execution for LLM agents"""

import logging
import subprocess
import tempfile
import os
import json
import hashlib
from typing import Any, Callable, Dict, List, Optional
from datetime import datetime
from enum import Enum
from dataclasses import dataclass


class ToolStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    SANDBOXED = "sandboxed"


class ParameterType(Enum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    OBJECT = "object"
    ARRAY = "array"


@dataclass
class ParameterSchema:
    name: str
    param_type: ParameterType
    required: bool = False
    default: Any = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    max_length: Optional[int] = None
    allowed_values: Optional[List[Any]] = None
    pattern: Optional[str] = None


class ParameterValidator:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.strict_mode = self.config.get("strict_mode", True)

    def validate(self, params: Dict[str, Any], schema: List[ParameterSchema]) -> Dict[str, Any]:
        errors = []

        for field in schema:
            value = params.get(field.name)

            if value is None:
                if field.required:
                    errors.append(f"Missing required parameter: {field.name}")
                continue

            type_error = self._validate_type(value, field.param_type)
            if type_error:
                errors.append(f"Parameter {field.name}: {type_error}")
                continue

            if field.param_type == ParameterType.STRING:
                if field.max_length and len(value) > field.max_length:
                    errors.append(f"Parameter {field.name}: exceeds max length {field.max_length}")
                if field.pattern:
                    import re
                    if not re.match(field.pattern, value):
                        errors.append(f"Parameter {field.name}: does not match required pattern")

            if field.param_type in [ParameterType.INTEGER, ParameterType.FLOAT]:
                if field.min_value is not None and value < field.min_value:
                    errors.append(f"Parameter {field.name}: below minimum value {field.min_value}")
                if field.max_value is not None and value > field.max_value:
                    errors.append(f"Parameter {field.name}: exceeds maximum value {field.max_value}")

            if field.allowed_values and value not in field.allowed_values:
                errors.append(f"Parameter {field.name}: value must be one of {field.allowed_values}")

        if errors and self.strict_mode:
            return {"valid": False, "errors": errors}
        elif errors:
            return {"valid": True, "warnings": errors}
        return {"valid": True}

    def _validate_type(self, value: Any, param_type: ParameterType) -> Optional[str]:
        type_map = {
            ParameterType.STRING: str,
            ParameterType.INTEGER: int,
            ParameterType.FLOAT: (int, float),
            ParameterType.BOOLEAN: bool,
            ParameterType.OBJECT: dict,
            ParameterType.ARRAY: list
        }
        
        expected = type_map.get(param_type)
        if expected and not isinstance(value, expected):
            return f"expected {param_type.value}, got {type(value).__name__}"
        
        if param_type == ParameterType.INTEGER and isinstance(value, float):
            if not value.is_integer():
                return "expected integer value"
        
        return None


class ToolDefinition:
    def __init__(
        self,
        name: str,
        func: Callable,
        description: str = "",
        allowed: bool = True,
        requires_approval: bool = False,
        parameter_schema: Optional[List[ParameterSchema]] = None,
        sandboxed: bool = False,
        timeout: int = 30
    ):
        self.name = name
        self.func = func
        self.description = description
        self.allowed = allowed
        self.requires_approval = requires_approval
        self.parameter_schema = parameter_schema or []
        self.sandboxed = sandboxed
        self.timeout = timeout


class ToolExecution:
    def __init__(self, tool_name: str, params: Dict[str, Any]):
        self.tool_name = tool_name
        self.params = params
        self.status = ToolStatus.PENDING
        self.start_time = None
        self.end_time = None
        self.result = None
        self.error = None
        self.sandboxed = False
        self.approval_required = False
        self.approved = False


class SandboxExecutor:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.timeout = self.config.get("timeout", 30)
        self.max_memory_mb = self.config.get("max_memory_mb", 256)
        self.allowed_paths = self.config.get("allowed_paths", [])
        self.blocked_commands = self.config.get("blocked_commands", [
            "rm", "del", "format", "fdisk", "mkfs",
            "shutdown", "reboot", "halt", "poweroff",
            "wget", "curl", "nc", "netcat"
        ])

    def can_execute(self, command: str) -> tuple:
        if not self.enabled:
            return True, ""
        
        cmd_parts = command.split()
        if not cmd_parts:
            return False, "Empty command"
        
        cmd_name = cmd_parts[0].lower()
        if cmd_name in self.blocked_commands:
            return False, f"Command '{cmd_name}' is blocked for security"
        
        for path in self.allowed_paths:
            if path in command and not self._is_path_allowed(path):
                return False, f"Path '{path}' is not in allowed paths"
        
        return True, ""

    def _is_path_allowed(self, path: str) -> bool:
        if not self.allowed_paths:
            return True
        for allowed in self.allowed_paths:
            if path.startswith(allowed):
                return True
        return False

    def execute_in_sandbox(self, func: Callable, **kwargs) -> Any:
        if not self.enabled:
            return func(**kwargs)
        
        import threading
        result = [None]
        error = [None]
        
        def run():
            try:
                result[0] = func(**kwargs)
            except Exception as e:
                error[0] = e
        
        thread = threading.Thread(target=run)
        thread.start()
        thread.join(timeout=self.timeout)
        
        if thread.is_alive():
            raise TimeoutError(f"Execution exceeded timeout of {self.timeout}s")
        
        if error[0]:
            raise error[0]
        
        return result[0]

    def validate_path_access(self, path: str) -> bool:
        if not self.enabled:
            return True
        return self._is_path_allowed(path)


class ToolManager:
    """Tool Manager - Manages and monitors tool execution for LLM agents

    工具管理器，用于注册、验证、执行和管理LLM Agent的工具调用。
    该类提供完整的工具生命周期管理，包括参数验证、沙盒执行、执行审批和历史记录。

    主要功能:
        - 工具注册与注销
        - 参数模式验证与类型检查
        - 沙盒环境执行（可选）
        - 执行审批机制
        - 执行历史记录与审计

    构造函数参数:
        config (Optional[Dict[str, Any]]): 配置字典，包含以下可选键:
            - enable_whitelist (bool): 是否启用白名单模式，默认为 True
            - whitelist (List[str]): 允许执行的工具名称列表
            - validator (Dict): 参数验证器配置
                - strict_mode (bool): 是否为严格模式，默认为 True
            - sandbox (Dict): 沙盒执行器配置
                - enabled (bool): 是否启用沙盒，默认为 True
                - timeout (int): 执行超时时间（秒），默认为 30
                - max_memory_mb (int): 最大内存限制（MB），默认为 256
                - allowed_paths (List[str]): 允许访问的路径列表
                - blocked_commands (List[str]): 禁止执行的命令列表

    主要方法:
        register_tool(
            name: str,
            func: Callable,
            description: str = "",
            allowed: bool = True,
            requires_approval: bool = False,
            parameter_schema: Optional[List[ParameterSchema]] = None,
            sandboxed: bool = False,
            timeout: int = 30
        ):
            注册一个工具到管理器。

            参数:
                name (str): 工具名称
                func (Callable): 工具函数
                description (str): 工具描述
                allowed (bool): 是否允许执行，默认为 True
                requires_approval (bool): 是否需要审批，默认为 False
                parameter_schema (Optional[List[ParameterSchema]]): 参数模式定义
                sandboxed (bool): 是否在沙盒中执行，默认为 False
                timeout (int): 执行超时时间（秒），默认为 30

        unregister_tool(name: str):
            从管理器中注销一个工具。

            参数:
                name (str): 工具名称

        get_tool(name: str) -> Optional[ToolDefinition]:
            获取工具定义对象。

            参数:
                name (str): 工具名称

            返回:
                Optional[ToolDefinition]: 工具定义对象，如果不存在则返回 None

        can_execute(tool_name: str) -> bool:
            检查工具是否可执行。

            参数:
                tool_name (str): 工具名称

            返回:
                bool: 如果工具可执行返回 True，否则返回 False

        validate_parameters(tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
            验证工具参数是否符合模式定义。

            参数:
                tool_name (str): 工具名称
                params (Dict[str, Any]): 待验证的参数

            返回:
                Dict[str, Any]: 验证结果，包含:
                    - valid (bool): 验证是否通过
                    - errors (List[str]): 错误列表（仅当 valid 为 False 时）
                    - warnings (List[str]): 警告列表（仅当 valid 为 True 且处于非严格模式）

        execute(tool_name: str, params: Dict[str, Any]) -> Any:
            执行工具。

            参数:
                tool_name (str): 工具名称
                params (Dict[str, Any]): 工具参数

            返回:
                Any: 工具执行结果

            异常:
                PermissionError: 工具被禁止执行或需要审批
                ValueError: 参数验证失败
                TimeoutError: 执行超时

        approve_tool(tool_name: str, params: Dict[str, Any]) -> Any:
            审批并执行需要审批的工具。

            参数:
                tool_name (str): 工具名称
                params (Dict[str, Any]): 工具参数

            返回:
                Any: 工具执行结果

        get_history(limit: int = 100) -> List[ToolExecution]:
            获取工具执行历史记录。

            参数:
                limit (int): 返回的记录数量限制，默认为 100

            返回:
                List[ToolExecution]: 执行记录列表

        get_blocked_tools() -> List[str]:
            获取被禁止执行的工具列表。

            返回:
                List[str]: 被禁止的工具名称列表

        get_allowed_tools() -> List[str]:
            获取允许执行的工具列表。

            返回:
                List[str]: 允许的工具名称列表

    使用示例:
        >>> # 创建工具管理器
        >>> manager = ToolManager({
        ...     "enable_whitelist": True,
        ...     "whitelist": ["calculator", "search"]
        ... })
        >>>
        >>> # 定义工具函数
        >>> def calculator(a: int, b: int, operation: str) -> int:
        ...     if operation == "add":
        ...         return a + b
        ...     elif operation == "subtract":
        ...         return a - b
        ...     return 0
        ...
        >>> # 注册工具
        >>> manager.register_tool(
        ...     "calculator",
        ...     calculator,
        ...     description="简单计算器",
        ...     parameter_schema=[
        ...         ParameterSchema("a", ParameterType.INTEGER, required=True),
        ...         ParameterSchema("b", ParameterType.INTEGER, required=True),
        ...         ParameterSchema("operation", ParameterType.STRING, allowed_values=["add", "subtract"])
        ...     ]
        ... )
        >>>
        >>> # 检查工具是否可执行
        >>> can_exec = manager.can_execute("calculator")
        >>> print(f"可执行: {can_exec}")
        >>>
        >>> # 执行工具
        >>> result = manager.execute("calculator", {"a": 10, "b": 5, "operation": "add"})
        >>> print(f"结果: {result}")
        >>>
        >>> # 获取执行历史
        >>> history = manager.get_history()
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.tools: Dict[str, ToolDefinition] = {}
        self.execution_history: List[ToolExecution] = []
        
        self.validator = ParameterValidator(self.config.get("validator", {}))
        self.sandbox = SandboxExecutor(self.config.get("sandbox", {}))
        
        self.enable_whitelist = self.config.get("enable_whitelist", True)
        self.whitelist: Set[str] = set(self.config.get("whitelist", []))

    def register_tool(
        self,
        name: str,
        func: Callable,
        description: str = "",
        allowed: bool = True,
        requires_approval: bool = False,
        parameter_schema: Optional[List[ParameterSchema]] = None,
        sandboxed: bool = False,
        timeout: int = 30
    ):
        tool = ToolDefinition(
            name, func, description, allowed, requires_approval,
            parameter_schema, sandboxed, timeout
        )
        self.tools[name] = tool
        self.logger.info(f"Registered tool: {name}")

    def unregister_tool(self, name: str):
        if name in self.tools:
            del self.tools[name]
            self.logger.info(f"Unregistered tool: {name}")

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self.tools.get(name)

    def can_execute(self, tool_name: str) -> bool:
        if self.enable_whitelist and tool_name not in self.whitelist:
            return False
        
        tool = self.get_tool(tool_name)
        if not tool:
            return False
        return tool.allowed

    def validate_parameters(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        tool = self.get_tool(tool_name)
        if not tool:
            return {"valid": False, "errors": [f"Tool {tool_name} not found"]}
        
        if not tool.parameter_schema:
            return {"valid": True}
        
        return self.validator.validate(params, tool.parameter_schema)

    def execute(self, tool_name: str, params: Dict[str, Any]) -> Any:
        execution = ToolExecution(tool_name, params)

        if not self.can_execute(tool_name):
            execution.status = ToolStatus.BLOCKED
            self.execution_history.append(execution)
            self.logger.warning(f"Tool execution blocked: {tool_name}")
            raise PermissionError(f"Tool {tool_name} is not allowed to execute")

        tool = self.get_tool(tool_name)
        if not tool:
            execution.status = ToolStatus.FAILED
            execution.error = f"Tool {tool_name} not found"
            self.execution_history.append(execution)
            raise ValueError(execution.error)

        validation_result = self.validate_parameters(tool_name, params)
        if not validation_result.get("valid"):
            execution.status = ToolStatus.FAILED
            execution.error = str(validation_result.get("errors"))
            self.execution_history.append(execution)
            raise ValueError(f"Parameter validation failed: {execution.error}")

        if tool.requires_approval:
            execution.approval_required = True
            execution.approved = False
            self.execution_history.append(execution)
            self.logger.warning(f"Tool {tool_name} requires approval")
            raise PermissionError(f"Tool {tool_name} requires approval before execution")

        execution.status = ToolStatus.RUNNING
        execution.start_time = datetime.now()

        try:
            if tool.sandboxed or self.sandbox.enabled:
                execution.sandboxed = True
                result = self.sandbox.execute_in_sandbox(
                    tool.func,
                    timeout=tool.timeout,
                    **params
                )
            else:
                result = tool.func(**params)
            
            execution.status = ToolStatus.COMPLETED
            execution.result = result
            self.logger.info(f"Tool executed successfully: {tool_name}")
            return result
        except Exception as e:
            execution.status = ToolStatus.FAILED
            execution.error = str(e)
            self.logger.error(f"Tool execution failed: {tool_name} - {e}")
            raise
        finally:
            execution.end_time = datetime.now()
            self.execution_history.append(execution)

    def approve_tool(self, tool_name: str, params: Dict[str, Any]) -> Any:
        for execution in reversed(self.execution_history):
            if execution.tool_name == tool_name and execution.approval_required and not execution.approved:
                execution.approved = True
                execution.start_time = datetime.now()
                
                tool = self.get_tool(tool_name)
                try:
                    if tool.sandboxed:
                        result = self.sandbox.execute_in_sandbox(
                            tool.func,
                            timeout=tool.timeout,
                            **params
                        )
                    else:
                        result = tool.func(**params)
                    execution.status = ToolStatus.COMPLETED
                    execution.result = result
                    return result
                except Exception as e:
                    execution.status = ToolStatus.FAILED
                    execution.error = str(e)
                    raise
                finally:
                    execution.end_time = datetime.now()
        
        raise ValueError(f"No pending approval found for tool: {tool_name}")

    def get_history(self, limit: int = 100) -> List[ToolExecution]:
        return self.execution_history[-limit:]

    def get_blocked_tools(self) -> List[str]:
        return [name for name, tool in self.tools.items() if not tool.allowed]

    def get_allowed_tools(self) -> List[str]:
        return [name for name, tool in self.tools.items() if tool.allowed]
