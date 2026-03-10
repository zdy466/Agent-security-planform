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
