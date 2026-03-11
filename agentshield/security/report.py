import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
from collections import defaultdict


class ReportFormat(Enum):
    JSON = "json"
    HTML = "html"
    PDF = "pdf"


class ReportPeriod(Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


@dataclass
class SecurityMetric:
    name: str
    value: Any
    change: Optional[float] = None
    unit: str = ""


@dataclass
class ThreatSummary:
    total_threats: int = 0
    blocked_threats: int = 0
    allowed_threats: int = 0
    top_threats: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ComplianceSummary:
    framework: str
    total_rules: int = 0
    compliant_rules: int = 0
    score: float = 0.0
    status: str = "unknown"


@dataclass
class SecurityReport:
    title: str
    period: ReportPeriod
    generated_at: datetime
    summary: Dict[str, Any] = field(default_factory=dict)
    metrics: List[SecurityMetric] = field(default_factory=list)
    threats: ThreatSummary = field(default_factory=ThreatSummary)
    compliance: List[ComplianceSummary] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class SecurityReportGenerator:
    def __init__(self, audit_logger=None, compliance_manager=None):
        self.audit_logger = audit_logger
        self.compliance_manager = compliance_manager
        self._data_cache: Dict[str, Any] = {}

    def generate_report(
        self,
        title: str,
        period: ReportPeriod,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> SecurityReport:
        if not end_date:
            end_date = datetime.now()
        if not start_date:
            if period == ReportPeriod.DAILY:
                start_date = end_date - timedelta(days=1)
            elif period == ReportPeriod.WEEKLY:
                start_date = end_date - timedelta(weeks=1)
            else:
                start_date = end_date - timedelta(days=30)

        report = SecurityReport(
            title=title,
            period=period,
            generated_at=datetime.now()
        )

        report.summary = self._generate_summary(start_date, end_date)
        report.metrics = self._generate_metrics(start_date, end_date)
        report.threats = self._analyze_threats(start_date, end_date)
        report.compliance = self._check_compliance()
        report.recommendations = self._generate_recommendations(report)

        return report

    def _generate_summary(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        return {
            "period_start": start_date.isoformat(),
            "period_end": end_date.isoformat(),
            "total_requests": 0,
            "blocked_requests": 0,
            "sensitive_data_detections": 0,
            "prompt_injections": 0,
            "policy_violations": 0,
            "security_score": 100.0
        }

    def _generate_metrics(self, start_date: datetime, end_date: datetime) -> List[SecurityMetric]:
        metrics = [
            SecurityMetric("Total Requests", 0, unit="count"),
            SecurityMetric("Blocked Requests", 0, unit="count"),
            SecurityMetric("Sensitive Data Detections", 0, unit="count"),
            SecurityMetric("Prompt Injection Attempts", 0, unit="count"),
            SecurityMetric("Policy Violations", 0, unit="count"),
            SecurityMetric("Average Response Time", 0.0, unit="ms"),
            SecurityMetric("Security Score", 100.0, unit="%"),
        ]
        return metrics

    def _analyze_threats(self, start_date: datetime, end_date: datetime) -> ThreatSummary:
        summary = ThreatSummary()
        summary.top_threats = [
            {"type": "sensitive_data", "count": 0, "severity": "high"},
            {"type": "prompt_injection", "count": 0, "severity": "critical"},
            {"type": "tool_abuse", "count": 0, "severity": "medium"},
        ]
        return summary

    def _check_compliance(self) -> List[ComplianceSummary]:
        summaries = [
            ComplianceSummary(framework="GDPR", total_rules=10, compliant_rules=10, score=100.0, status="compliant"),
            ComplianceSummary(framework="HIPAA", total_rules=8, compliant_rules=7, score=87.5, status="partial"),
            ComplianceSummary(framework="SOC2", total_rules=12, compliant_rules=11, score=91.7, status="compliant"),
        ]
        return summaries

    def _generate_recommendations(self, report: SecurityReport) -> List[str]:
        recommendations = []

        if report.threats.total_threats > 0:
            recommendations.append("建议增加敏感数据检测规则的覆盖率")

        for comp in report.compliance:
            if comp.score < 100:
                recommendations.append(f"{comp.framework}: 有 {comp.total_rules - comp.compliant_rules} 条规则未满足，建议优化")

        if report.summary.get("security_score", 100) < 80:
            recommendations.append("安全评分较低，建议全面审查安全策略")

        if not recommendations:
            recommendations.append("系统运行良好，建议保持当前安全配置")

        return recommendations

    def export_json(self, report: SecurityReport) -> str:
        return json.dumps({
            "title": report.title,
            "period": report.period.value,
            "generated_at": report.generated_at.isoformat(),
            "summary": report.summary,
            "metrics": [
                {
                    "name": m.name,
                    "value": m.value,
                    "change": m.change,
                    "unit": m.unit
                }
                for m in report.metrics
            ],
            "threats": {
                "total_threats": report.threats.total_threats,
                "blocked_threats": report.threats.blocked_threats,
                "allowed_threats": report.threats.allowed_threats,
                "top_threats": report.threats.top_threats
            },
            "compliance": [
                {
                    "framework": c.framework,
                    "total_rules": c.total_rules,
                    "compliant_rules": c.compliant_rules,
                    "score": c.score,
                    "status": c.status
                }
                for c in report.compliance
            ],
            "recommendations": report.recommendations
        }, ensure_ascii=False, indent=2)

    def export_html(self, report: SecurityReport) -> str:
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report.title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #1a73e8; border-bottom: 2px solid #1a73e8; padding-bottom: 10px; }}
        h2 {{ color: #333; margin-top: 30px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .summary-item {{ background: white; padding: 15px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .summary-item h3 {{ margin: 0 0 10px 0; color: #666; font-size: 14px; }}
        .summary-item .value {{ font-size: 24px; font-weight: bold; color: #1a73e8; }}
        .metric {{ background: white; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #1a73e8; }}
        .threat {{ background: white; padding: 15px; margin: 10px 0; border-radius: 8px; }}
        .threat.high {{ border-left-color: #d32f2f; }}
        .threat.critical {{ border-left-color: #7b1fa2; }}
        .threat.medium {{ border-left-color: #f57c00; }}
        .compliance {{ background: white; padding: 20px; margin: 10px 0; border-radius: 8px; }}
        .compliance-score {{ font-size: 36px; font-weight: bold; }}
        .compliance-score.high {{ color: #2e7d32; }}
        .compliance-score.medium {{ color: #f57c00; }}
        .compliance-score.low {{ color: #d32f2f; }}
        .recommendation {{ background: #e8f5e9; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #2e7d32; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>🛡️ {report.title}</h1>
    <p><strong>生成时间:</strong> {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p><strong>报告周期:</strong> {report.period.value}</p>

    <h2>📊 安全概览</h2>
    <div class="summary">
        <div class="summary-item">
            <h3>总请求数</h3>
            <div class="value">{report.summary.get('total_requests', 0):,}</div>
        </div>
        <div class="summary-item">
            <h3>拦截请求</h3>
            <div class="value" style="color: #d32f2f;">{report.summary.get('blocked_requests', 0):,}</div>
        </div>
        <div class="summary-item">
            <h3>敏感数据检测</h3>
            <div class="value" style="color: #f57c00;">{report.summary.get('sensitive_data_detections', 0):,}</div>
        </div>
        <div class="summary-item">
            <h3>安全评分</h3>
            <div class="value">{report.summary.get('security_score', 100):.1f}%</div>
        </div>
    </div>

    <h2>📈 详细指标</h2>
"""
        for metric in report.metrics:
            html += f"""
    <div class="metric">
        <strong>{metric.name}</strong>: {metric.value} {metric.unit}
    </div>
"""

        html += """
    <h2>🚨 威胁分析</h2>
"""
        for threat in report.threats.top_threats:
            severity = threat.get("severity", "medium")
            html += f"""
    <div class="threat {severity}">
        <strong>{threat['type']}</strong>: {threat['count']} 次 (严重程度: {severity})
    </div>
"""

        html += """
    <h2>📋 合规状态</h2>
"""
        for comp in report.compliance:
            score_class = "high" if comp.score >= 90 else "medium" if comp.score >= 70 else "low"
            html += f"""
    <div class="compliance">
        <h3>{comp.framework}</h3>
        <div class="compliance-score {score_class}">{comp.score:.1f}%</div>
        <p>合规规则: {comp.compliant_rules}/{comp.total_rules}</p>
        <p>状态: {comp.status}</p>
    </div>
"""

        html += """
    <h2>💡 建议</h2>
"""
        for rec in report.recommendations:
            html += f"""
    <div class="recommendation">{rec}</div>
"""

        html += f"""
    <div class="footer">
        <p>Generated by AgentShield OS v0.5.0</p>
    </div>
</body>
</html>"""
        return html


class ReportScheduler:
    def __init__(self, generator: SecurityReportGenerator):
        self.generator = generator
        self._scheduled_reports: Dict[str, Any] = {}

    def schedule_report(
        self,
        name: str,
        period: ReportPeriod,
        recipients: List[str],
        format: ReportFormat = ReportFormat.HTML
    ):
        self._scheduled_reports[name] = {
            "period": period,
            "recipients": recipients,
            "format": format,
            "last_run": None,
            "next_run": self._calculate_next_run(period)
        }

    def _calculate_next_run(self, period: ReportPeriod) -> datetime:
        now = datetime.now()
        if period == ReportPeriod.DAILY:
            return now + timedelta(days=1)
        elif period == ReportPeriod.WEEKLY:
            return now + timedelta(weeks=1)
        else:
            return now + timedelta(days=30)

    def get_scheduled_reports(self) -> Dict[str, Any]:
        return self._scheduled_reports.copy()
