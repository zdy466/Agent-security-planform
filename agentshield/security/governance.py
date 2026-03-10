"""AI Governance System - Comprehensive governance framework for AI systems"""

import logging
import json
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from abc import ABC, abstractmethod


class GovernanceDomain(Enum):
    SECURITY = "security"
    PRIVACY = "privacy"
    FAIRNESS = "fairness"
    TRANSPARENCY = "transparency"
    ACCOUNTABILITY = "accountability"
    SAFETY = "safety"


class GovernanceStatus(Enum):
    COMPLIANT = "compliant"
    AT_RISK = "at_risk"
    NON_COMPLIANT = "non_compliant"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class GovernancePolicy:
    policy_id: str
    name: str
    domain: GovernanceDomain
    description: str
    requirements: List[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    enabled: bool = True
    version: str = "1.0"
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class GovernanceMetric:
    metric_id: str
    name: str
    domain: GovernanceDomain
    value: float
    threshold: float
    status: GovernanceStatus
    last_updated: datetime
    trend: str = "stable"


@dataclass
class GovernanceAlert:
    alert_id: str
    domain: GovernanceDomain
    severity: RiskLevel
    title: str
    description: str
    timestamp: datetime
    acknowledged: bool = False
    resolved: bool = False
    resolution_notes: Optional[str] = None


@dataclass
class GovernanceAssessment:
    assessment_id: str
    domain: GovernanceDomain
    timestamp: datetime
    status: GovernanceStatus
    score: float
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class GovernanceFramework(ABC):
    @abstractmethod
    def assess(self, context: Dict[str, Any]) -> GovernanceAssessment:
        pass

    @abstractmethod
    def get_policies(self) -> List[GovernancePolicy]:
        pass


class SecurityGovernance(GovernanceFramework):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.policies = self._load_default_policies()

    def _load_default_policies(self) -> List[GovernancePolicy]:
        return [
            GovernancePolicy(
                policy_id="sec-001",
                name="Access Control Policy",
                domain=GovernanceDomain.SECURITY,
                description="Ensure proper access controls for AI systems",
                requirements=[
                    "Implement role-based access control",
                    "Enforce least privilege principle",
                    "Regular access reviews"
                ],
                risk_level=RiskLevel.HIGH
            ),
            GovernancePolicy(
                policy_id="sec-002",
                name="Data Protection Policy",
                domain=GovernanceDomain.SECURITY,
                description="Protect data throughout its lifecycle",
                requirements=[
                    "Encrypt data at rest and in transit",
                    "Implement data loss prevention",
                    "Regular security audits"
                ],
                risk_level=RiskLevel.CRITICAL
            ),
            GovernancePolicy(
                policy_id="sec-003",
                name="Incident Response Policy",
                domain=GovernanceDomain.SECURITY,
                description="Respond to security incidents",
                requirements=[
                    "Document incident response procedures",
                    "Establish response team",
                    "Regular incident drills"
                ],
                risk_level=RiskLevel.HIGH
            ),
        ]

    def assess(self, context: Dict[str, Any]) -> GovernanceAssessment:
        score = 100.0
        findings = []
        recommendations = []

        if not context.get("access_control_enabled"):
            score -= 20
            findings.append("Access control not enabled")
            recommendations.append("Enable role-based access control")

        if not context.get("encryption_enabled"):
            score -= 25
            findings.append("Data encryption not enabled")
            recommendations.append("Enable encryption for data at rest and in transit")

        if not context.get("audit_logging"):
            score -= 15
            findings.append("Audit logging not configured")
            recommendations.append("Configure comprehensive audit logging")

        if not context.get("incident_response"):
            score -= 20
            findings.append("Incident response plan not in place")
            recommendations.append("Develop incident response procedures")

        status = GovernanceStatus.COMPLIANT
        if score < 50:
            status = GovernanceStatus.NON_COMPLIANT
        elif score < 80:
            status = GovernanceStatus.AT_RISK

        return GovernanceAssessment(
            assessment_id=f"SEC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            domain=GovernanceDomain.SECURITY,
            timestamp=datetime.now(),
            status=status,
            score=score,
            findings=findings,
            recommendations=recommendations
        )

    def get_policies(self) -> List[GovernancePolicy]:
        return self.policies


class PrivacyGovernance(GovernanceFramework):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.policies = self._load_default_policies()

    def _load_default_policies(self) -> List[GovernancePolicy]:
        return [
            GovernancePolicy(
                policy_id="priv-001",
                name="Data Minimization Policy",
                domain=GovernanceDomain.PRIVACY,
                description="Collect only necessary data",
                requirements=[
                    "Limit data collection to necessary items",
                    "Document data collection purpose",
                    "Regular data audits"
                ],
                risk_level=RiskLevel.HIGH
            ),
            GovernancePolicy(
                policy_id="priv-002",
                name="User Consent Policy",
                domain=GovernanceDomain.PRIVACY,
                description="Obtain and manage user consent",
                requirements=[
                    "Clear consent mechanisms",
                    "Easy consent withdrawal",
                    "Consent records maintenance"
                ],
                risk_level=RiskLevel.CRITICAL
            ),
        ]

    def assess(self, context: Dict[str, Any]) -> GovernanceAssessment:
        score = 100.0
        findings = []
        recommendations = []

        if not context.get("consent_management"):
            score -= 30
            findings.append("Consent management not implemented")
            recommendations.append("Implement consent management system")

        if not context.get("data_retention_policy"):
            score -= 20
            findings.append("Data retention policy not defined")
            recommendations.append("Define and enforce data retention policies")

        if not context.get("privacy_by_design"):
            score -= 25
            findings.append("Privacy by design not implemented")
            recommendations.append("Implement privacy by design principles")

        status = GovernanceStatus.COMPLIANT
        if score < 50:
            status = GovernanceStatus.NON_COMPLIANT
        elif score < 80:
            status = GovernanceStatus.AT_RISK

        return GovernanceAssessment(
            assessment_id=f"PRIV-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            domain=GovernanceDomain.PRIVACY,
            timestamp=datetime.now(),
            status=status,
            score=score,
            findings=findings,
            recommendations=recommendations
        )

    def get_policies(self) -> List[GovernancePolicy]:
        return self.policies


class FairnessGovernance(GovernanceFramework):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.policies = self._load_default_policies()

    def _load_default_policies(self) -> List[GovernancePolicy]:
        return [
            GovernancePolicy(
                policy_id="fair-001",
                name="Bias Detection Policy",
                domain=GovernanceDomain.FAIRNESS,
                description="Detect and mitigate bias in AI systems",
                requirements=[
                    "Regular bias audits",
                    "Diverse training data",
                    "Bias mitigation procedures"
                ],
                risk_level=RiskLevel.HIGH
            ),
            GovernancePolicy(
                policy_id="fair-002",
                name="Equal Access Policy",
                domain=GovernanceDomain.FAIRNESS,
                description="Ensure equal access to AI services",
                requirements=[
                    "Accessibility standards compliance",
                    "Non-discriminatory service delivery",
                    "Regular fairness assessments"
                ],
                risk_level=RiskLevel.HIGH
            ),
        ]

    def assess(self, context: Dict[str, Any]) -> GovernanceAssessment:
        score = 100.0
        findings = []
        recommendations = []

        if not context.get("bias_monitoring"):
            score -= 25
            findings.append("Bias monitoring not implemented")
            recommendations.append("Implement bias detection and monitoring")

        if not context.get("fairness_testing"):
            score -= 25
            findings.append("Fairness testing not conducted")
            recommendations.append("Conduct regular fairness testing")

        if not context.get("diversity_in_data"):
            score -= 20
            findings.append("Training data diversity insufficient")
            recommendations.append("Ensure diverse and representative training data")

        status = GovernanceStatus.COMPLIANT
        if score < 50:
            status = GovernanceStatus.NON_COMPLIANT
        elif score < 80:
            status = GovernanceStatus.AT_RISK

        return GovernanceAssessment(
            assessment_id=f"FAIR-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            domain=GovernanceDomain.FAIRNESS,
            timestamp=datetime.now(),
            status=status,
            score=score,
            findings=findings,
            recommendations=recommendations
        )

    def get_policies(self) -> List[GovernancePolicy]:
        return self.policies


class GovernanceSystem:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        self.frameworks: Dict[GovernanceDomain, GovernanceFramework] = {
            GovernanceDomain.SECURITY: SecurityGovernance(self.config.get("security", {})),
            GovernanceDomain.PRIVACY: PrivacyGovernance(self.config.get("privacy", {})),
            GovernanceDomain.FAIRNESS: FairnessGovernance(self.config.get("fairness", {})),
        }

        self.alerts: List[GovernanceAlert] = []
        self.metrics: List[GovernanceMetric] = []
        self.assessments: List[GovernanceAssessment] = []

        self.alert_counter = 0
        self.metric_counter = 0

    def assess_domain(self, domain: GovernanceDomain, context: Dict[str, Any]) -> GovernanceAssessment:
        framework = self.frameworks.get(domain)
        if not framework:
            raise ValueError(f"No governance framework for domain: {domain}")

        assessment = framework.assess(context)
        self.assessments.append(assessment)

        if assessment.status != GovernanceStatus.COMPLIANT:
            self._create_alert(domain, assessment)

        return assessment

    def assess_all_domains(self, contexts: Dict[GovernanceDomain, Dict[str, Any]]) -> Dict[str, Any]:
        results = {}
        
        for domain in GovernanceDomain:
            context = contexts.get(domain, {})
            assessment = self.assess_domain(domain, context)
            results[domain.value] = {
                "status": assessment.status.value,
                "score": assessment.score,
                "findings": assessment.findings,
                "recommendations": assessment.recommendations
            }

        return results

    def _create_alert(self, domain: GovernanceDomain, assessment: GovernanceAssessment):
        self.alert_counter += 1

        severity = RiskLevel.LOW
        if assessment.score < 50:
            severity = RiskLevel.CRITICAL
        elif assessment.score < 70:
            severity = RiskLevel.HIGH
        elif assessment.score < 80:
            severity = RiskLevel.MEDIUM

        alert = GovernanceAlert(
            alert_id=f"ALERT-{self.alert_counter:06d}",
            domain=domain,
            severity=severity,
            title=f"{domain.value.title()} Governance Assessment Failed",
            description=f"Assessment score: {assessment.score:.1f}. Findings: {len(assessment.findings)}",
            timestamp=datetime.now()
        )

        self.alerts.append(alert)

    def record_metric(
        self,
        name: str,
        domain: GovernanceDomain,
        value: float,
        threshold: float
    ) -> GovernanceMetric:
        self.metric_counter += 1

        status = GovernanceStatus.COMPLIANT
        if value > threshold:
            status = GovernanceStatus.AT_RISK

        metric = GovernanceMetric(
            metric_id=f"METRIC-{self.metric_counter:06d}",
            name=name,
            domain=domain,
            value=value,
            threshold=threshold,
            status=status,
            last_updated=datetime.now()
        )

        self.metrics.append(metric)
        return metric

    def get_alerts(
        self,
        domain: Optional[GovernanceDomain] = None,
        acknowledged: Optional[bool] = None,
        limit: int = 50
    ) -> List[GovernanceAlert]:
        alerts = self.alerts

        if domain:
            alerts = [a for a in alerts if a.domain == domain]
        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]

        return alerts[-limit:]

    def acknowledge_alert(self, alert_id: str, notes: str = "") -> bool:
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                return True
        return False

    def resolve_alert(self, alert_id: str, resolution_notes: str) -> bool:
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.resolved = True
                alert.resolution_notes = resolution_notes
                return True
        return False

    def get_dashboard_summary(self) -> Dict[str, Any]:
        total_alerts = len(self.alerts)
        open_alerts = len([a for a in self.alerts if not a.resolved])
        critical_alerts = len([a for a in self.alerts if a.severity == RiskLevel.CRITICAL and not a.resolved])

        recent_assessments = self.assessments[-5:] if self.assessments else []
        avg_score = sum(a.score for a in recent_assessments) / len(recent_assessments) if recent_assessments else 0

        by_domain = {}
        for domain in GovernanceDomain:
            domain_assessments = [a for a in self.assessments if a.domain == domain]
            if domain_assessments:
                by_domain[domain.value] = {
                    "latest_score": domain_assessments[-1].score,
                    "status": domain_assessments[-1].status.value
                }

        return {
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "critical_alerts": critical_alerts,
            "average_assessment_score": avg_score,
            "domain_scores": by_domain,
            "total_policies": sum(len(f.get_policies()) for f in self.frameworks.values())
        }

    def export_governance_report(self, format: str = "json") -> str:
        summary = self.get_dashboard_summary()
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
            "recent_alerts": [
                {
                    "alert_id": a.alert_id,
                    "domain": a.domain.value,
                    "severity": a.severity.value,
                    "title": a.title,
                    "acknowledged": a.acknowledged,
                    "resolved": a.resolved
                }
                for a in self.alerts[-10:]
            ],
            "recent_assessments": [
                {
                    "assessment_id": a.assessment_id,
                    "domain": a.domain.value,
                    "score": a.score,
                    "status": a.status.value
                }
                for a in self.assessments[-10:]
            ]
        }

        if format == "json":
            return json.dumps(report, indent=2, ensure_ascii=False)

        return str(report)

    def get_policy_summary(self) -> List[Dict[str, Any]]:
        policies = []
        for domain, framework in self.frameworks.items():
            for policy in framework.get_policies():
                policies.append({
                    "policy_id": policy.policy_id,
                    "name": policy.name,
                    "domain": policy.domain.value,
                    "risk_level": policy.risk_level.value,
                    "enabled": policy.enabled,
                    "requirements_count": len(policy.requirements)
                })
        return policies
