"""Monitoring Dashboard - Real-time monitoring dashboard for AgentShield OS"""

import logging
import json
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class MetricSnapshot:
    timestamp: datetime
    metric_name: str
    value: float
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class Alert:
    alert_id: str
    timestamp: datetime
    severity: str
    title: str
    message: str
    source: str
    acknowledged: bool = False
    resolved: bool = False


class MetricsCollector:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.metrics: Dict[str, List[MetricSnapshot]] = defaultdict(list)
        self.max_points = self.config.get("max_points", 1000)

    def record(self, metric_name: str, value: float, tags: Optional[Dict[str, str]] = None):
        snapshot = MetricSnapshot(
            timestamp=datetime.now(),
            metric_name=metric_name,
            value=value,
            tags=tags or {}
        )
        self.metrics[metric_name].append(snapshot)

        if len(self.metrics[metric_name]) > self.max_points:
            self.metrics[metric_name] = self.metrics[metric_name][-self.max_points:]

    def get_metrics(self, metric_name: str, limit: int = 100) -> List[MetricSnapshot]:
        return self.metrics.get(metric_name, [])[-limit:]

    def get_all_metrics(self) -> Dict[str, List[MetricSnapshot]]:
        return dict(self.metrics)

    def get_latest_value(self, metric_name: str) -> Optional[float]:
        metrics = self.metrics.get(metric_name, [])
        return metrics[-1].value if metrics else None

    def clear_old_metrics(self, before: datetime):
        for metric_name in self.metrics:
            self.metrics[metric_name] = [
                m for m in self.metrics[metric_name]
                if m.timestamp >= before
            ]


class AlertManager:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.alerts: List[Alert] = []
        self.alert_counter = 0

    def create_alert(
        self,
        severity: str,
        title: str,
        message: str,
        source: str
    ) -> Alert:
        self.alert_counter += 1
        alert = Alert(
            alert_id=f"ALERT-{self.alert_counter:06d}",
            timestamp=datetime.now(),
            severity=severity,
            title=title,
            message=message,
            source=source
        )
        self.alerts.append(alert)
        self.logger.warning(f"Alert created: {title}")
        return alert

    def acknowledge_alert(self, alert_id: str) -> bool:
        for alert in reversed(self.alerts):
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                return True
        return False

    def resolve_alert(self, alert_id: str) -> bool:
        for alert in reversed(self.alerts):
            if alert.alert_id == alert_id:
                alert.resolved = True
                return True
        return False

    def get_active_alerts(self) -> List[Alert]:
        return [a for a in self.alerts if not a.resolved]

    def get_alerts_by_severity(self, severity: str) -> List[Alert]:
        return [a for a in self.alerts if a.severity == severity and not a.resolved]


class MonitoringDashboard:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        self.metrics_collector = MetricsCollector(
            self.config.get("metrics", {})
        )
        self.alert_manager = AlertManager(
            self.config.get("alerts", {})
        )
        
        self.refresh_interval = self.config.get("refresh_interval", 60)
        self.enable_auto_alerts = self.config.get("enable_auto_alerts", True)

    def record_request(self, user: Optional[str] = None):
        self.metrics_collector.record("requests_total", 1, {"user": user or "anonymous"})

    def record_blocked_request(self, reason: str):
        self.metrics_collector.record("requests_blocked", 1, {"reason": reason})
        self.alert_manager.create_alert(
            severity="warning",
            title="Request Blocked",
            message=f"Request blocked: {reason}",
            source="firewall"
        )

    def record_tool_execution(self, tool_name: str, success: bool):
        status = "success" if success else "failure"
        self.metrics_collector.record(f"tool_execution_{status}", 1, {"tool": tool_name})

    def record_data_access(self, source: str, operation: str):
        self.metrics_collector.record("data_access_total", 1, {"source": source, "operation": operation})

    def record_llm_request(self, prompt_length: int, response_time_ms: float):
        self.metrics_collector.record("llm_requests_total", 1)
        self.metrics_collector.record("llm_prompt_tokens", prompt_length)
        self.metrics_collector.record("llm_response_time_ms", response_time_ms)

    def get_dashboard_summary(self) -> Dict[str, Any]:
        total_requests = self.metrics_collector.get_latest_value("requests_total") or 0
        blocked_requests = self.metrics_collector.get_latest_value("requests_blocked") or 0
        
        active_alerts = self.alert_manager.get_active_alerts()
        critical_alerts = [a for a in active_alerts if a.severity == "critical"]
        warning_alerts = [a for a in active_alerts if a.severity == "warning"]

        return {
            "timestamp": datetime.now().isoformat(),
            "overview": {
                "total_requests": total_requests,
                "blocked_requests": blocked_requests,
                "block_rate": f"{(blocked_requests / total_requests * 100):.2f}%" if total_requests > 0 else "0%",
            },
            "alerts": {
                "active_count": len(active_alerts),
                "critical_count": len(critical_alerts),
                "warning_count": len(warning_alerts),
            },
            "metrics": {
                "llm_response_time_ms": self.metrics_collector.get_latest_value("llm_response_time_ms"),
                "llm_prompt_tokens": self.metrics_collector.get_latest_value("llm_prompt_tokens"),
            }
        }

    def get_metrics_data(self, metric_name: Optional[str] = None, limit: int = 50) -> Dict[str, Any]:
        if metric_name:
            metrics = self.metrics_collector.get_metrics(metric_name, limit)
            return {
                "metric": metric_name,
                "data": [
                    {
                        "timestamp": m.timestamp.isoformat(),
                        "value": m.value,
                        "tags": m.tags
                    }
                    for m in metrics
                ]
            }
        
        all_metrics = self.metrics_collector.get_all_metrics()
        result = {}
        for name, snapshots in all_metrics.items():
            result[name] = [
                {"timestamp": m.timestamp.isoformat(), "value": m.value}
                for m in snapshots[-limit:]
            ]
        return result

    def get_alerts_data(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        if severity:
            alerts = self.alert_manager.get_alerts_by_severity(severity)
        else:
            alerts = self.alert_manager.get_active_alerts()
        
        return [
            {
                "alert_id": a.alert_id,
                "timestamp": a.timestamp.isoformat(),
                "severity": a.severity,
                "title": a.title,
                "message": a.message,
                "source": a.source,
                "acknowledged": a.acknowledged,
                "resolved": a.resolved
            }
            for a in alerts
        ]

    def export_dashboard_json(self) -> str:
        data = {
            "summary": self.get_dashboard_summary(),
            "metrics": self.get_metrics_data(limit=20),
            "alerts": self.get_alerts_data()
        }
        return json.dumps(data, ensure_ascii=False, indent=2)


class DashboardRenderer:
    @staticmethod
    def render_text_summary(dashboard: MonitoringDashboard) -> str:
        summary = dashboard.get_dashboard_summary()
        
        lines = [
            "=" * 50,
            "AgentShield OS 监控仪表板",
            "=" * 50,
            "",
            f"更新时间: {summary['timestamp']}",
            "",
            "概览:",
            f"  总请求数: {summary['overview']['total_requests']}",
            f"  阻止请求数: {summary['overview']['blocked_requests']}",
            f"  阻止率: {summary['overview']['block_rate']}",
            "",
            "告警:",
            f"  活跃告警: {summary['alerts']['active_count']}",
            f"  严重告警: {summary['alerts']['critical_count']}",
            f"  警告告警: {summary['alerts']['warning_count']}",
            "",
            "LLM 指标:",
            f"  响应时间: {summary['metrics'].get('llm_response_time_ms', 0):.2f} ms",
            "",
            "=" * 50,
        ]
        
        return "\n".join(lines)

    @staticmethod
    def render_html_dashboard(dashboard: MonitoringDashboard) -> str:
        summary = dashboard.get_dashboard_summary()
        alerts = dashboard.get_alerts_data()
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AgentShield OS 监控仪表板</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: #ecf0f1; padding: 20px; border-radius: 5px; flex: 1; }}
        .stat-value {{ font-size: 32px; font-weight: bold; color: #2c3e50; }}
        .stat-label {{ color: #7f8c8d; }}
        .alert-critical {{ background: #e74c3c; color: white; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .alert-warning {{ background: #f39c12; color: white; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .section {{ margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>AgentShield OS 监控仪表板</h1>
        <p>更新时间: {summary['timestamp']}</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-value">{summary['overview']['total_requests']}</div>
            <div class="stat-label">总请求数</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{summary['overview']['blocked_requests']}</div>
            <div class="stat-label">阻止请求数</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{summary['overview']['block_rate']}</div>
            <div class="stat-label">阻止率</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{summary['alerts']['active_count']}</div>
            <div class="stat-label">活跃告警</div>
        </div>
    </div>
    
    <div class="section">
        <h2>活跃告警</h2>
        {''.join(f'<div class="alert-{a["severity"]}">{a["title"]}: {a["message"]}</div>' for a in alerts[:5]) if alerts else '<p>暂无告警</p>'}
    </div>
</body>
</html>
"""
        return html
