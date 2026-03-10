"""AI Behavior Monitoring - Monitors and analyzes AI Agent behavior patterns"""

import logging
from typing import Any, Callable, Dict, List, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from collections import deque, defaultdict
import hashlib


class BehaviorType(Enum):
    INPUT = "input"
    OUTPUT = "output"
    TOOL_CALL = "tool_call"
    DATA_ACCESS = "data_access"
    LLM_REQUEST = "llm_request"
    DECISION = "decision"


class AnomalyLevel(Enum):
    NORMAL = "normal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BehaviorEvent:
    event_id: str
    timestamp: datetime
    session_id: str
    agent_id: str
    event_type: BehaviorType
    action: str
    details: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0


@dataclass
class BehaviorSequence:
    session_id: str
    agent_id: str
    events: List[BehaviorEvent] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)


@dataclass
class AnomalyResult:
    is_anomalous: bool
    anomaly_level: AnomalyLevel
    risk_score: float
    anomaly_type: Optional[str] = None
    description: str = ""
    recommendations: List[str] = field(default_factory=list)


class BehaviorPattern:
    NORMAL_PATTERNS = {
        "query_response": ["input", "llm_request", "output"],
        "tool_usage": ["input", "llm_request", "tool_call", "output"],
        "data_retrieval": ["input", "llm_request", "data_access", "llm_request", "output"],
    }

    SUSPICIOUS_PATTERNS = [
        ["data_access", "data_access", "data_access"],
        ["tool_call", "data_access", "data_access"],
        ["input", "tool_call", "data_access"],
        ["llm_request", "data_access", "llm_request", "data_access"],
    ]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.normal_patterns = self.NORMAL_PATTERNS.copy()
        self.suspicious_patterns = self.SUSPICIOUS_PATTERNS.copy()

    def match_sequence(self, events: List[BehaviorEvent]) -> bool:
        if len(events) < 3:
            return False

        sequence = [e.event_type.value for e in events[-5:]]

        for suspicious in self.suspicious_patterns:
            if self._pattern_matches(sequence, suspicious):
                return True

        return False

    def _pattern_matches(self, sequence: List[str], pattern: List[str]) -> bool:
        if len(sequence) < len(pattern):
            return False

        for i in range(len(sequence) - len(pattern) + 1):
            if sequence[i:i+len(pattern)] == pattern:
                return True
        return False


class BehaviorAnalyzer:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        self.frequency_threshold = self.config.get("frequency_threshold", 10)
        self.time_window_minutes = self.config.get("time_window_minutes", 5)
        self.risk_score_threshold = self.config.get("risk_score_threshold", 0.7)

    def analyze_frequency(self, events: List[BehaviorEvent]) -> AnomalyResult:
        if not events:
            return AnomalyResult(
                is_anomalous=False,
                anomaly_level=AnomalyLevel.NORMAL,
                risk_score=0.0
            )

        now = datetime.now()
        window_start = now - timedelta(minutes=self.time_window_minutes)
        recent_events = [e for e in events if e.timestamp >= window_start]

        event_counts = defaultdict(int)
        for e in recent_events:
            event_counts[e.event_type.value] += 1

        for event_type, count in event_counts.items():
            if count > self.frequency_threshold:
                return AnomalyResult(
                    is_anomalous=True,
                    anomaly_level=AnomalyLevel.HIGH,
                    risk_score=0.8,
                    anomaly_type="high_frequency",
                    description=f"Event type '{event_type}' triggered {count} times in {self.time_window_minutes} minutes",
                    recommendations=["Rate limiting should be applied", "Review user intent"]
                )

        return AnomalyResult(
            is_anomalous=False,
            anomaly_level=AnomalyLevel.NORMAL,
            risk_score=0.0
        )

    def analyze_sequence(self, events: List[BehaviorEvent]) -> AnomalyResult:
        pattern_matcher = BehaviorPattern(self.config.get("pattern_config", {}))

        if pattern_matcher.match_sequence(events):
            return AnomalyResult(
                is_anomalous=True,
                anomaly_level=AnomalyLevel.HIGH,
                risk_score=0.85,
                anomaly_type="suspicious_pattern",
                description="Behavior sequence matches known suspicious patterns",
                recommendations=["Investigate agent behavior", "Block if confirmed malicious"]
            )

        return AnomalyResult(
            is_anomalous=False,
            anomaly_level=AnomalyLevel.NORMAL,
            risk_score=0.0
        )

    def analyze_data_access_pattern(self, events: List[BehaviorEvent]) -> AnomalyResult:
        data_access_events = [e for e in events if e.event_type == BehaviorType.DATA_ACCESS]

        if len(data_access_events) > 5:
            return AnomalyResult(
                is_anomalous=True,
                anomaly_level=AnomalyLevel.MEDIUM,
                risk_score=0.6,
                anomaly_type="excessive_data_access",
                description=f"Agent accessed data {len(data_access_events)} times in current session",
                recommendations=["Review data access necessity", "Consider implementing data access limits"]
            )

        sensitive_tables = ["password", "credit_card", "ssn", "secret", "key"]
        for event in data_access_events:
            resource = event.details.get("resource", "").lower()
            if any(table in resource for table in sensitive_tables):
                return AnomalyResult(
                    is_anomalous=True,
                    anomaly_level=AnomalyLevel.HIGH,
                    risk_score=0.9,
                    anomaly_type="sensitive_data_access",
                    description=f"Access to sensitive resource: {resource}",
                    recommendations=["Immediately block access", "Alert security team"]
                )

        return AnomalyResult(
            is_anomalous=False,
            anomaly_level=AnomalyLevel.NORMAL,
            risk_score=0.0
        )

    def analyze_tool_usage(self, events: List[BehaviorEvent]) -> AnomalyResult:
        tool_events = [e for e in events if e.event_type == BehaviorType.TOOL_CALL]

        blocked_tools = ["delete", "drop", "truncate", "shutdown", "reboot"]
        for event in tool_events:
            tool_name = event.details.get("tool_name", "").lower()
            if any(blocked in tool_name for blocked in blocked_tools):
                return AnomalyResult(
                    is_anomalous=True,
                    anomaly_level=AnomalyLevel.CRITICAL,
                    risk_score=0.95,
                    anomaly_type="dangerous_tool_usage",
                    description=f"Attempted to use dangerous tool: {tool_name}",
                    recommendations=["Block tool execution", "Alert security team immediately"]
                )

        return AnomalyResult(
            is_anomalous=False,
            anomaly_level=AnomalyLevel.NORMAL,
            risk_score=0.0
        )


class BehaviorMonitor:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        self.max_events_per_session = self.config.get("max_events_per_session", 1000)
        self.session_timeout_minutes = self.config.get("session_timeout_minutes", 30)
        self.enable_auto_response = self.config.get("enable_auto_response", True)

        self.sessions: Dict[str, BehaviorSequence] = {}
        self.event_counter = 0

        self.analyzer = BehaviorAnalyzer(self.config.get("analyzer", {}))
        self.alert_callback: Optional[Callable] = None

    def record_event(
        self,
        session_id: str,
        agent_id: str,
        event_type: BehaviorType,
        action: str,
        details: Optional[Dict[str, Any]] = None
    ) -> BehaviorEvent:
        self.event_counter += 1

        event = BehaviorEvent(
            event_id=f"BE-{datetime.now().strftime('%Y%m%d%H%M%S')}-{self.event_counter:06d}",
            timestamp=datetime.now(),
            session_id=session_id,
            agent_id=agent_id,
            event_type=event_type,
            action=action,
            details=details or {}
        )

        if session_id not in self.sessions:
            self.sessions[session_id] = BehaviorSequence(
                session_id=session_id,
                agent_id=agent_id
            )

        self.sessions[session_id].events.append(event)

        if len(self.sessions[session_id].events) > self.max_events_per_session:
            self.sessions[session_id].events = self.sessions[session_id].events[-self.max_events_per_session:]

        self._check_anomalies(session_id)

        self._cleanup_old_sessions()

        return event

    def _check_anomalies(self, session_id: str):
        if session_id not in self.sessions:
            return
        
        session = self.sessions[session_id]
        events = session.events

        frequency_result = self.analyzer.analyze_frequency(events)
        if frequency_result.is_anomalous:
            self._handle_anomaly(session_id, frequency_result)

        sequence_result = self.analyzer.analyze_sequence(events)
        if sequence_result.is_anomalous:
            self._handle_anomaly(session_id, sequence_result)

        data_result = self.analyzer.analyze_data_access_pattern(events)
        if data_result.is_anomalous:
            self._handle_anomaly(session_id, data_result)

        tool_result = self.analyzer.analyze_tool_usage(events)
        if tool_result.is_anomalous:
            self._handle_anomaly(session_id, tool_result)

    def _handle_anomaly(self, session_id: str, result: AnomalyResult):
        self.logger.warning(f"Anomaly detected in session {session_id}: {result.description}")

        if self.enable_auto_response and self.alert_callback:
            self.alert_callback(session_id, result)

    def set_alert_callback(self, callback: Callable):
        self.alert_callback = callback

    def get_session_events(self, session_id: str, limit: int = 100) -> List[BehaviorEvent]:
        if session_id not in self.sessions:
            return []
        return self.sessions[session_id].events[-limit:]

    def get_all_sessions(self) -> List[str]:
        return list(self.sessions.keys())

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        if session_id not in self.sessions:
            return {}

        session = self.sessions[session_id]
        events = session.events

        event_counts = defaultdict(int)
        for e in events:
            event_counts[e.event_type.value] += 1

        total_risk = sum(e.risk_score for e in events) / len(events) if events else 0

        return {
            "session_id": session_id,
            "agent_id": session.agent_id,
            "event_count": len(events),
            "event_types": dict(event_counts),
            "start_time": session.start_time.isoformat(),
            "last_activity": events[-1].timestamp.isoformat() if events else None,
            "average_risk_score": total_risk
        }

    def _cleanup_old_sessions(self):
        now = datetime.now()
        timeout = timedelta(minutes=self.session_timeout_minutes)

        to_remove = []
        for session_id, session in self.sessions.items():
            if session.events:
                last_event = session.events[-1]
                if now - last_event.timestamp > timeout:
                    to_remove.append(session_id)

        for session_id in to_remove:
            del self.sessions[session_id]

    def get_risk_summary(self) -> Dict[str, Any]:
        high_risk_sessions = []
        medium_risk_sessions = []

        for session_id, session in self.sessions.items():
            if not session.events:
                continue

            avg_risk = sum(e.risk_score for e in session.events) / len(session.events)

            if avg_risk >= 0.7:
                high_risk_sessions.append(session_id)
            elif avg_risk >= 0.4:
                medium_risk_sessions.append(session_id)

        return {
            "total_sessions": len(self.sessions),
            "high_risk_sessions": high_risk_sessions,
            "medium_risk_sessions": medium_risk_sessions,
            "total_events": sum(len(s.events) for s in self.sessions.values())
        }
