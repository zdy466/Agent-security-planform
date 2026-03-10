"""Audit Logger - Comprehensive audit logging for AgentShield OS"""

import logging
import json
import os
from typing import Any, Callable, Dict, List, Optional, Set
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field, asdict
from collections import defaultdict


class EventType(Enum):
    REQUEST = "request"
    RESPONSE = "response"
    TOOL_EXECUTION = "tool_execution"
    DATA_ACCESS = "data_access"
    LLM_REQUEST = "llm_request"
    SECURITY_EVENT = "security_event"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONFIGURATION_CHANGE = "configuration_change"
    SYSTEM_ERROR = "system_error"


class EventSeverity(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventResult(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    PENDING = "pending"
    TIMEOUT = "timeout"


@dataclass
class AuditEvent:
    event_id: str
    event_type: str
    timestamp: datetime
    user: Optional[str] = None
    session_id: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    result: Optional[str] = None
    severity: str = "info"
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    duration_ms: Optional[int] = None
    risk_score: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class EventMetrics:
    total_events: int = 0
    events_by_type: Dict[str, int] = field(default_factory=dict)
    events_by_severity: Dict[str, int] = field(default_factory=dict)
    events_by_result: Dict[str, int] = field(default_factory=dict)
    events_by_user: Dict[str, int] = field(default_factory=dict)
    average_duration_ms: float = 0.0
    blocked_count: int = 0
    failed_count: int = 0


class AuditLogger:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.enabled = self.config.get("enabled", True)
        
        self.events: List[AuditEvent] = []
        self.max_events = self.config.get("max_events", 10000)
        
        self.persist_to_file = self.config.get("persist_to_file", False)
        self.log_file_path = self.config.get("log_file_path", "agentshield_audit.log")
        self.log_format = self.config.get("log_format", "json")
        
        self.event_counter = 0
        self.enable_metrics = self.config.get("enable_metrics", True)
        self.metrics = EventMetrics()

    def _generate_event_id(self) -> str:
        self.event_counter += 1
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"EVT-{timestamp}-{self.event_counter:06d}"

    def _persist_event(self, event: AuditEvent):
        if not self.persist_to_file:
            return
        
        try:
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                if self.log_format == "json":
                    f.write(event.to_json() + "\n")
                else:
                    f.write(f"{event.timestamp.isoformat()} | {event.event_type} | {event.user} | {event.action} | {event.result}\n")
        except Exception as e:
            self.logger.error(f"Failed to persist audit event: {e}")

    def _update_metrics(self, event: AuditEvent):
        if not self.enable_metrics:
            return
        
        self.metrics.total_events += 1
        
        event_type = event.event_type
        self.metrics.events_by_type[event_type] = self.metrics.events_by_type.get(event_type, 0) + 1
        
        severity = event.severity
        self.metrics.events_by_severity[severity] = self.metrics.events_by_severity.get(severity, 0) + 1
        
        if event.result:
            self.metrics.events_by_result[event.result] = self.metrics.events_by_result.get(event.result, 0) + 1
        
        if event.user:
            self.metrics.events_by_user[event.user] = self.metrics.events_by_user.get(event.user, 0) + 1
        
        if event.result == EventResult.BLOCKED.value:
            self.metrics.blocked_count += 1
        elif event.result == EventResult.FAILED.value:
            self.metrics.failed_count += 1
        
        if event.duration_ms:
            total_durations = self.metrics.average_duration_ms * (self.metrics.total_events - 1)
            self.metrics.average_duration_ms = (total_durations + event.duration_ms) / self.metrics.total_events

    def log(
        self,
        event_type: str,
        user: Optional[str] = None,
        action: Optional[str] = None,
        resource: Optional[str] = None,
        result: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "info",
        session_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        duration_ms: Optional[int] = None,
        risk_score: Optional[float] = None
    ):
        if not self.enabled:
            return

        event = AuditEvent(
            event_id=self._generate_event_id(),
            event_type=event_type,
            timestamp=datetime.now(),
            user=user,
            action=action,
            resource=resource,
            result=result,
            severity=severity,
            session_id=session_id,
            source_ip=source_ip,
            user_agent=user_agent,
            request_id=request_id,
            correlation_id=correlation_id,
            duration_ms=duration_ms,
            risk_score=risk_score,
            details=details or {}
        )

        self.events.append(event)
        self._persist_event(event)
        self._update_metrics(event)

        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]

        log_level = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL
        }.get(severity, logging.INFO)

        self.logger.log(log_level, f"Audit: {event_type}", extra=event.to_dict())

    def log_request(
        self,
        user: Optional[str] = None,
        action: str = "request",
        resource: Optional[str] = None,
        result: str = "success",
        details: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[int] = None,
        **kwargs
    ):
        self.log(
            event_type=EventType.REQUEST.value,
            user=user,
            action=action,
            resource=resource,
            result=result,
            details=details,
            duration_ms=duration_ms,
            **kwargs
        )

    def log_tool_execution(
        self,
        user: Optional[str] = None,
        tool_name: str = "",
        result: str = "success",
        details: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[int] = None,
        **kwargs
    ):
        self.log(
            event_type=EventType.TOOL_EXECUTION.value,
            user=user,
            action=f"execute_tool:{tool_name}",
            resource=tool_name,
            result=result,
            details=details,
            duration_ms=duration_ms,
            **kwargs
        )

    def log_data_access(
        self,
        user: Optional[str] = None,
        source: str = "",
        operation: str = "read",
        result: str = "success",
        details: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[int] = None,
        **kwargs
    ):
        self.log(
            event_type=EventType.DATA_ACCESS.value,
            user=user,
            action=f"{operation}_data",
            resource=source,
            result=result,
            details=details,
            duration_ms=duration_ms,
            **kwargs
        )

    def log_security_event(
        self,
        event_type: str,
        user: Optional[str] = None,
        result: str = "blocked",
        details: Optional[Dict[str, Any]] = None,
        severity: str = "warning",
        risk_score: Optional[float] = None,
        **kwargs
    ):
        self.log(
            event_type=EventType.SECURITY_EVENT.value,
            user=user,
            action=event_type,
            result=result,
            details=details,
            severity=severity,
            risk_score=risk_score,
            **kwargs
        )

    def log_llm_request(
        self,
        user: Optional[str] = None,
        prompt_length: int = 0,
        result: str = "success",
        details: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[int] = None,
        **kwargs
    ):
        self.log(
            event_type=EventType.LLM_REQUEST.value,
            user=user,
            action="llm_request",
            result=result,
            details={"prompt_length": prompt_length, **(details or {})},
            duration_ms=duration_ms,
            **kwargs
        )

    def get_events(
        self,
        event_type: Optional[str] = None,
        user: Optional[str] = None,
        action: Optional[str] = None,
        resource: Optional[str] = None,
        result: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[AuditEvent]:
        filtered = self.events

        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type]

        if user:
            filtered = [e for e in filtered if e.user == user]

        if action:
            filtered = [e for e in filtered if e.action == action]

        if resource:
            filtered = [e for e in filtered if e.resource == resource]

        if result:
            filtered = [e for e in filtered if e.result == result]

        if severity:
            filtered = [e for e in filtered if e.severity == severity]

        if start_time:
            filtered = [e for e in filtered if e.timestamp >= start_time]

        if end_time:
            filtered = [e for e in filtered if e.timestamp <= end_time]

        return filtered[-limit:]

    def get_security_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> List[AuditEvent]:
        return self.get_events(
            event_type=EventType.SECURITY_EVENT.value,
            start_time=start_time,
            end_time=end_time,
            limit=limit
        )

    def get_events_by_session(
        self,
        session_id: str,
        limit: int = 100
    ) -> List[AuditEvent]:
        return [e for e in self.events if e.session_id == session_id][-limit:]

    def get_events_by_request(
        self,
        request_id: str
    ) -> List[AuditEvent]:
        return [e for e in self.events if e.request_id == request_id]

    def get_metrics(self) -> EventMetrics:
        return self.metrics

    def get_risk_events(
        self,
        min_risk_score: float = 0.5,
        limit: int = 100
    ) -> List[AuditEvent]:
        return [
            e for e in self.events 
            if e.risk_score is not None and e.risk_score >= min_risk_score
        ][-limit:]

    def clear_old_events(self, before: datetime):
        self.events = [e for e in self.events if e.timestamp >= before]

    def export_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        format: str = "json"
    ) -> str:
        events = self.get_events(start_time=start_time, end_time=end_time, limit=self.max_events)
        
        if format == "json":
            return json.dumps([e.to_dict() for e in events], ensure_ascii=False, indent=2)
        elif format == "csv":
            if not events:
                return ""
            headers = ["event_id", "event_type", "timestamp", "user", "action", "resource", "result", "severity"]
            lines = [",".join(headers)]
            for e in events:
                lines.append(",".join([
                    str(getattr(e, h, "") or "") for h in headers
                ]))
            return "\n".join(lines)
        else:
            return str(events)

    def search_events(
        self,
        query: str,
        fields: Optional[List[str]] = None,
        limit: int = 100
    ) -> List[AuditEvent]:
        if fields is None:
            fields = ["action", "resource", "details"]
        
        results = []
        query_lower = query.lower()
        
        for event in self.events:
            for field in fields:
                value = getattr(event, field, None)
                if value and query_lower in str(value).lower():
                    results.append(event)
                    break
            
            if len(results) >= limit:
                break
        
        return results
