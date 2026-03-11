import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
import threading


class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


@dataclass
class Metric:
    name: str
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


class MetricsCollector:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._counters: Dict[str, float] = defaultdict(float)
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        self._labels: Dict[str, Dict[str, str]] = {}
        self._lock = threading.Lock()

    def reset(self):
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()
            self._labels.clear()

    def counter(self, name: str, value: float = 1, labels: Optional[Dict[str, str]] = None):
        key = self._make_key(name, labels)
        with self._lock:
            self._counters[key] += value

    def gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        key = self._make_key(name, labels)
        with self._lock:
            self._gauges[key] = value

    def histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        key = self._make_key(name, labels)
        with self._lock:
            self._histograms[key].append(value)

    def _make_key(self, name: str, labels: Optional[Dict[str, str]] = None) -> str:
        if not labels:
            return name
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def get_metrics(self) -> List[Metric]:
        metrics = []
        with self._lock:
            for key, value in self._counters.items():
                metrics.append(Metric(name=key, value=value))
            for key, value in self._gauges.items():
                metrics.append(Metric(name=key, value=value))
            for key, values in self._histograms.items():
                if values:
                    avg = sum(values) / len(values)
                    metrics.append(Metric(name=key, value=avg))
        return metrics

    def to_prometheus_format(self) -> str:
        lines = []
        with self._lock:
            for key, value in self._counters.items():
                lines.append(f"{key} {value}")
            for key, value in self._gauges.items():
                lines.append(f"{key} {value}")
            for key, values in self._histograms.items():
                if values:
                    avg = sum(values) / len(values)
                    lines.append(f"{key}_sum {sum(values)}")
                    lines.append(f"{key}_count {len(values)}")
        return "\n".join(lines)


class SecurityMetrics:
    def __init__(self, collector: Optional[MetricsCollector] = None):
        self.collector = collector or MetricsCollector()

    def record_request(self, allowed: bool, latency: float):
        self.collector.counter("agentshield_requests_total", 1, {"allowed": str(allowed).lower()})
        self.collector.histogram("agentshield_request_duration_seconds", latency)

    def record_blocked(self, reason: str):
        self.collector.counter("agentshield_blocked_total", 1, {"reason": reason})

    def record_sensitive_data(self, detected_types: List[str]):
        for dtype in detected_types:
            self.collector.counter("agentshield_sensitive_data_detected_total", 1, {"type": dtype})

    def record_prompt_injection(self, detected: bool, risk_level: str):
        self.collector.counter("agentshield_prompt_injection_total", 1, {"detected": str(detected).lower()})
        if detected:
            self.collector.counter("agentshield_prompt_injection_blocked_total", 1, {"risk_level": risk_level})

    def record_tool_execution(self, tool_name: str, allowed: bool):
        self.collector.counter("agentshield_tool_executions_total", 1, {
            "tool": tool_name,
            "allowed": str(allowed).lower()
        })

    def record_policy_violation(self, policy_name: str):
        self.collector.counter("agentshield_policy_violations_total", 1, {"policy": policy_name})

    def record_compliance_check(self, framework: str, passed: bool):
        self.collector.counter("agentshield_compliance_checks_total", 1, {
            "framework": framework,
            "passed": str(passed).lower()
        })

    def set_active_sessions(self, count: int):
        self.collector.gauge("agentshield_active_sessions", count)

    def set_security_score(self, score: float):
        self.collector.gauge("agentshield_security_score", score)


class MetricsExporter:
    def __init__(self, collector: Optional[MetricsCollector] = None):
        self.collector = collector or MetricsCollector()

    def export_prometheus(self) -> str:
        header = """# HELP agentshield_requests_total Total number of requests processed
# TYPE agentshield_requests_total counter
# HELP agentshield_blocked_total Total number of blocked requests
# TYPE agentshield_blocked_total counter
# HELP agentshield_sensitive_data_detected_total Total sensitive data detections
# TYPE agentshield_sensitive_data_detected_total counter
# HELP agentshield_prompt_injection_total Total prompt injection checks
# TYPE agentshield_prompt_injection_total counter
# HELP agentshield_tool_executions_total Total tool executions
# TYPE agentshield_tool_executions_total counter
# HELP agentshield_active_sessions Current active sessions
# TYPE agentshield_active_sessions gauge
# HELP agentshield_security_score Current security score
# TYPE agentshield_security_score gauge

"""
        return header + self.collector.to_prometheus_format()

    def export_json(self) -> str:
        import json
        metrics = self.collector.get_metrics()
        return json.dumps([
            {
                "name": m.name,
                "value": m.value,
                "timestamp": m.timestamp.isoformat()
            }
            for m in metrics
        ], indent=2)


class Timer:
    def __init__(self, metrics: SecurityMetrics, metric_name: str, labels: Optional[Dict[str, str]] = None):
        self.metrics = metrics
        self.metric_name = metric_name
        self.labels = labels
        self.start_time = None

    def __enter__(self):
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        self.metrics.collector.histogram(self.metric_name, duration, self.labels)
