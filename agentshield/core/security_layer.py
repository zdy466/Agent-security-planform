"""Security Layer - Core security component for AgentShield OS"""

import logging
import re
import hashlib
import json
from typing import Any, Callable, Dict, List, Optional, Set
from datetime import datetime
from enum import Enum
from dataclasses import dataclass
from abc import ABC, abstractmethod


class SecurityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TrustLevel(Enum):
    SYSTEM = "system"
    INTERNAL = "internal"
    AGENT = "agent"
    USER = "user"
    EXTERNAL = "external"


@dataclass
class SecurityEvent:
    event_type: str
    timestamp: datetime
    source: str
    action: str
    result: str
    details: Dict[str, Any]


class Interceptor(ABC):
    @abstractmethod
    def intercept(self, data: Any) -> Any:
        pass
    
    @abstractmethod
    def should_intercept(self, data: Any) -> bool:
        pass


class RequestInterceptor(Interceptor):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.blocked_patterns = self.config.get("blocked_patterns", [])
        self.max_length = self.config.get("max_length", 100000)
        self._compile_patterns()

    def _compile_patterns(self):
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.blocked_patterns]

    def should_intercept(self, data: Any) -> bool:
        if not self.enabled:
            return False
        return isinstance(data, (str, dict))

    def intercept(self, data: Any) -> Any:
        if not self.should_intercept(data):
            return data
        
        if isinstance(data, str):
            if len(data) > self.max_length:
                return {"error": "Request too long", "max_length": self.max_length}
            
            for pattern in self.compiled_patterns:
                if pattern.search(data):
                    return {"error": "Blocked pattern detected", "pattern": pattern.pattern}
        
        return data


class ResponseInterceptor(Interceptor):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.blocked_patterns = self.config.get("blocked_patterns", [])
        self.max_length = self.config.get("max_length", 100000)

    def should_intercept(self, data: Any) -> bool:
        if not self.enabled:
            return False
        return True

    def intercept(self, data: Any) -> Any:
        if not self.should_intercept(data):
            return data
        
        if isinstance(data, str) and len(data) > self.max_length:
            return data[:self.max_length] + "...[truncated]"
        
        return data


class ToolCallInterceptor(Interceptor):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.blocked_tools = self.config.get("blocked_tools", [])
        self.allowed_tools = self.config.get("allowed_tools", [])
        self.require_approval_tools = self.config.get("require_approval_tools", [])

    def should_intercept(self, data: Any) -> bool:
        if not self.enabled:
            return False
        return isinstance(data, dict) and "tool_name" in data

    def intercept(self, data: Any) -> Any:
        if not self.should_intercept(data):
            return data
        
        tool_name = data.get("tool_name")
        
        if self.blocked_tools and tool_name in self.blocked_tools:
            return {"error": f"Tool '{tool_name}' is blocked", "blocked": True}
        
        if self.allowed_tools and tool_name not in self.allowed_tools:
            return {"error": f"Tool '{tool_name}' is not in allowed list", "blocked": True}
        
        if tool_name in self.require_approval_tools:
            data["requires_approval"] = True
        
        return data


class DataAccessInterceptor(Interceptor):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.blocked_sources = self.config.get("blocked_sources", [])
        self.allowed_sources = self.config.get("allowed_sources", [])
        self.blocked_operations = self.config.get("blocked_operations", ["DROP", "DELETE", "TRUNCATE"])

    def should_intercept(self, data: Any) -> bool:
        if not self.enabled:
            return False
        return isinstance(data, dict) and "source" in data

    def intercept(self, data: Any) -> Any:
        if not self.should_intercept(data):
            return data
        
        source = data.get("source")
        
        if self.blocked_sources and source in self.blocked_sources:
            return {"error": f"Data source '{source}' is blocked", "blocked": True}
        
        if self.allowed_sources and source not in self.allowed_sources:
            return {"error": f"Data source '{source}' is not in allowed list", "blocked": True}
        
        operation = data.get("operation", "").upper()
        if operation in self.blocked_operations:
            return {"error": f"Operation '{operation}' is blocked", "blocked": True}
        
        return data


class LLMRequestInterceptor(Interceptor):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.max_tokens = self.config.get("max_tokens", 8000)
        self.blocked_prompts = self.config.get("blocked_prompts", [])
        self.enable_content_filtering = self.config.get("enable_content_filtering", True)
        self._compile_patterns()

    def _compile_patterns(self):
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.blocked_prompts]

    def should_intercept(self, data: Any) -> bool:
        if not self.enabled:
            return False
        return isinstance(data, dict) and "prompt" in data

    def intercept(self, data: Any) -> Any:
        if not self.should_intercept(data):
            return data
        
        prompt = data.get("prompt", "")
        
        if len(prompt) > self.max_tokens * 4:
            return {"error": "Prompt exceeds maximum token limit", "max_tokens": self.max_tokens}
        
        for pattern in self.compiled_patterns:
            if pattern.search(prompt):
                return {"error": "Blocked prompt pattern detected", "pattern": pattern.pattern}
        
        if self.enable_content_filtering:
            filtered_prompt = self._filter_content(prompt)
            data["prompt"] = filtered_prompt
        
        return data

    def _filter_content(self, text: str) -> str:
        sensitive_patterns = [
            (r"\b\d{3}-\d{3}-\d{4}\b", "[PHONE]"),
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[EMAIL]"),
            (r"sk-[a-zA-Z0-9]{20,}", "[API_KEY]"),
        ]
        
        result = text
        for pattern, replacement in sensitive_patterns:
            result = re.sub(pattern, replacement, result)
        
        return result


class SecurityLayer:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.security_level = SecurityLevel(
            self.config.get("security_level", "medium")
        )
        self.enabled = self.config.get("enabled", True)
        
        self.request_interceptor = RequestInterceptor(
            self.config.get("request_interceptor", {})
        )
        self.response_interceptor = ResponseInterceptor(
            self.config.get("response_interceptor", {})
        )
        self.tool_call_interceptor = ToolCallInterceptor(
            self.config.get("tool_call_interceptor", {})
        )
        self.data_access_interceptor = DataAccessInterceptor(
            self.config.get("data_access_interceptor", {})
        )
        self.llm_request_interceptor = LLMRequestInterceptor(
            self.config.get("llm_request_interceptor", {})
        )
        
        self.trust_levels = {level: TrustLevel(level) for level in TrustLevel}
        self.security_events: List[SecurityEvent] = []

    def validate_input(self, data: Any) -> bool:
        if not self.enabled:
            return True
        
        intercepted = self.request_interceptor.intercept(data)
        if isinstance(intercepted, dict) and intercepted.get("error"):
            self.log_security_event("input_validation_failed", {"data": str(data)[:100], "error": intercepted.get("error")})
            return False
        
        return True

    def validate_output(self, data: Any) -> bool:
        if not self.enabled:
            return True
        
        intercepted = self.response_interceptor.intercept(data)
        if isinstance(intercepted, dict) and intercepted.get("error"):
            self.log_security_event("output_validation_failed", {"error": intercepted.get("error")})
            return False
        
        return True

    def intercept_tool_call(self, tool_data: Dict[str, Any]) -> Any:
        if not self.enabled:
            return tool_data
        
        intercepted = self.tool_call_interceptor.intercept(tool_data)
        if isinstance(intercepted, dict) and intercepted.get("blocked"):
            self.log_security_event("tool_call_blocked", {"tool": tool_data.get("tool_name")})
        
        return intercepted

    def intercept_data_access(self, data: Dict[str, Any]) -> Any:
        if not self.enabled:
            return data
        
        intercepted = self.data_access_interceptor.intercept(data)
        if isinstance(intercepted, dict) and intercepted.get("blocked"):
            self.log_security_event("data_access_blocked", {"source": data.get("source")})
        
        return intercepted

    def intercept_llm_request(self, request: Dict[str, Any]) -> Any:
        if not self.enabled:
            return request
        
        intercepted = self.llm_request_interceptor.intercept(request)
        if isinstance(intercepted, dict) and intercepted.get("error"):
            self.log_security_event("llm_request_blocked", {"error": intercepted.get("error")})
        
        return intercepted

    def sanitize(self, data: Any) -> Any:
        if isinstance(data, str):
            dangerous_patterns = [
                (r"<script[^>]*>.*?</script>", ""),
                (r"javascript:", ""),
                (r"on\w+\s*=", ""),
            ]
            for pattern, replacement in dangerous_patterns:
                data = re.sub(pattern, replacement, data, flags=re.IGNORECASE)
        
        return data

    def check_permission(self, action: str, resource: str) -> bool:
        permission_map = self.config.get("permission_map", {})
        
        action_permissions = permission_map.get(action, {})
        allowed_resources = action_permissions.get("allowed_resources", [])
        
        if not allowed_resources:
            return True
        
        return resource in allowed_resources

    def get_trust_level(self, source: str) -> TrustLevel:
        trust_level_map = self.config.get("trust_level_map", {})
        
        for level_name, sources in trust_level_map.items():
            if source in sources:
                return TrustLevel[level_name.upper()]
        
        return TrustLevel.EXTERNAL

    def restrict_by_trust(self, source_trust: TrustLevel, target_trust: TrustLevel) -> bool:
        trust_hierarchy = {
            TrustLevel.SYSTEM: 5,
            TrustLevel.INTERNAL: 4,
            TrustLevel.AGENT: 3,
            TrustLevel.USER: 2,
            TrustLevel.EXTERNAL: 1,
        }
        
        return trust_hierarchy.get(source_trust, 0) >= trust_hierarchy.get(target_trust, 0)

    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        event = SecurityEvent(
            event_type=event_type,
            timestamp=datetime.now(),
            source="security_layer",
            action=event_type,
            result="logged",
            details=details
        )
        self.security_events.append(event)
        self.logger.info(f"Security event: {event_type}", extra=details)

    def get_security_events(self, limit: int = 100) -> List[SecurityEvent]:
        return self.security_events[-limit:]
