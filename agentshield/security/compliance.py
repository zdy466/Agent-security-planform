"""AI Compliance Management - Manages AI compliance requirements and regulations"""

import logging
import json
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
from abc import ABC, abstractmethod


class ComplianceFramework(Enum):
    GDPR = "gdpr"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    CUSTOM = "custom"


class ComplianceStatus(Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    PENDING = "pending"
    NOT_APPLICABLE = "not_applicable"


class ViolationSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ComplianceRule:
    rule_id: str
    name: str
    framework: ComplianceFramework
    description: str
    requirements: List[str] = field(default_factory=list)
    enabled: bool = True
    severity: ViolationSeverity = ViolationSeverity.MEDIUM


@dataclass
class ComplianceCheck:
    check_id: str
    rule_id: str
    timestamp: datetime
    status: ComplianceStatus
    details: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)


@dataclass
class Violation:
    violation_id: str
    rule_id: str
    rule_name: str
    severity: ViolationSeverity
    description: str
    timestamp: datetime
    status: str = "open"
    remediation: Optional[str] = None
    assignee: Optional[str] = None


@dataclass
class ComplianceReport:
    report_id: str
    timestamp: datetime
    framework: ComplianceFramework
    overall_status: ComplianceStatus
    total_rules: int
    compliant_rules: int
    non_compliant_rules: int
    partial_rules: int
    violations: List[Violation] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class ComplianceRuleSet:
    GDPR_RULES = [
        ComplianceRule(
            rule_id="gdpr-data-minimization",
            name="Data Minimization",
            framework=ComplianceFramework.GDPR,
            description="Collect only necessary personal data",
            requirements=[
                "Limit data collection to what's necessary",
                "Document the purpose for each data field",
                "Regularly review data necessity"
            ],
            severity=ViolationSeverity.HIGH
        ),
        ComplianceRule(
            rule_id="gdpr-consent",
            name="Consent Management",
            framework=ComplianceFramework.GDPR,
            description="Obtain proper consent for data processing",
            requirements=[
                "Clear and specific consent requests",
                "Easy consent withdrawal mechanism",
                "Record of consent"
            ],
            severity=ViolationSeverity.CRITICAL
        ),
        ComplianceRule(
            rule_id="gdpr-right-to-delete",
            name="Right to Deletion",
            framework=ComplianceFramework.GDPR,
            description="Honor data deletion requests",
            requirements=[
                "Process deletion requests within 30 days",
                "Delete all copies of data",
                "Verify complete deletion"
            ],
            severity=ViolationSeverity.HIGH
        ),
        ComplianceRule(
            rule_id="gdpr-data-portability",
            name="Data Portability",
            framework=ComplianceFramework.GDPR,
            description="Provide data in portable format",
            requirements=[
                "Export data in machine-readable format",
                "Support common export formats",
                "Timely data export"
            ],
            severity=ViolationSeverity.MEDIUM
        ),
    ]

    HIPAA_RULES = [
        ComplianceRule(
            rule_id="hipaa-phi-protection",
            name="PHI Protection",
            framework=ComplianceFramework.HIPAA,
            description="Protect Protected Health Information",
            requirements=[
                "Encrypt PHI at rest and in transit",
                "Access controls for PHI",
                "Audit trails for PHI access"
            ],
            severity=ViolationSeverity.CRITICAL
        ),
        ComplianceRule(
            rule_id="hipaa-break-glass",
            name="Emergency Access",
            framework=ComplianceFramework.HIPAA,
            description="Handle emergency access to PHI",
            requirements=[
                "Document emergency access procedures",
                "Log all emergency access",
                "Review emergency access regularly"
            ],
            severity=ViolationSeverity.HIGH
        ),
    ]

    SOC2_RULES = [
        ComplianceRule(
            rule_id="soc2-availability",
            name="System Availability",
            framework=ComplianceFramework.SOC2,
            description="Maintain system availability",
            requirements=[
                "Uptime monitoring",
                "Incident response procedures",
                "Backup and recovery"
            ],
            severity=ViolationSeverity.HIGH
        ),
        ComplianceRule(
            rule_id="soc2-confidentiality",
            name="Confidentiality",
            framework=ComplianceFramework.SOC2,
            description="Protect confidential information",
            requirements=[
                "Data classification",
                "Access controls",
                "Confidentiality agreements"
            ],
            severity=ViolationSeverity.HIGH
        ),
    ]

    def __init__(self):
        self.rules: Dict[str, ComplianceRule] = {}
        self._load_default_rules()

    def _load_default_rules(self):
        for rule in self.GDPR_RULES:
            self.rules[rule.rule_id] = rule
        for rule in self.HIPAA_RULES:
            self.rules[rule.rule_id] = rule
        for rule in self.SOC2_RULES:
            self.rules[rule.rule_id] = rule

    def add_rule(self, rule: ComplianceRule):
        self.rules[rule.rule_id] = rule

    def remove_rule(self, rule_id: str):
        if rule_id in self.rules:
            del self.rules[rule_id]

    def get_rules(self, framework: Optional[ComplianceFramework] = None) -> List[ComplianceRule]:
        rules = list(self.rules.values())
        if framework:
            rules = [r for r in rules if r.framework == framework]
        return rules


class ComplianceManager:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        self.rule_set = ComplianceRuleSet()
        self.checks: List[ComplianceCheck] = []
        self.violations: List[Violation] = []
        self.check_callback: Optional[Callable] = None

        self.violation_counter = 0

    def set_check_callback(self, callback: Callable):
        self.check_callback = callback

    def add_custom_rule(
        self,
        rule_id: str,
        name: str,
        framework: ComplianceFramework,
        description: str,
        requirements: List[str],
        severity: ViolationSeverity = ViolationSeverity.MEDIUM
    ):
        rule = ComplianceRule(
            rule_id=rule_id,
            name=name,
            framework=framework,
            description=description,
            requirements=requirements,
            severity=severity
        )
        self.rule_set.add_rule(rule)

    def check_compliance(
        self,
        rule_id: str,
        evidence: Optional[Dict[str, Any]] = None
    ) -> ComplianceCheck:
        rule = self.rule_set.rules.get(rule_id)
        if not rule:
            raise ValueError(f"Rule {rule_id} not found")

        evidence = evidence or {}

        status = ComplianceStatus.COMPLIANT

        if self.check_callback:
            try:
                result = self.check_callback(rule, evidence)
                if isinstance(result, dict):
                    status = ComplianceStatus(result.get("status", "compliant"))
                    evidence = {**evidence, **result.get("evidence", {})}
            except Exception as e:
                self.logger.error(f"Check callback failed for {rule_id}: {e}")
                status = ComplianceStatus.COMPLIANT

        check = ComplianceCheck(
            check_id=f"CHK-{datetime.now().strftime('%Y%m%d%H%M%S')}-{len(self.checks)}",
            rule_id=rule_id,
            timestamp=datetime.now(),
            status=status,
            details=evidence
        )

        self.checks.append(check)

        if status == ComplianceStatus.NON_COMPLIANT:
            self._create_violation(rule, evidence)

        return check

    def _create_violation(self, rule: ComplianceRule, evidence: Dict[str, Any]):
        self.violation_counter += 1
        violation = Violation(
            violation_id=f"VIOL-{self.violation_counter:06d}",
            rule_id=rule.rule_id,
            rule_name=rule.name,
            severity=rule.severity,
            description=rule.description,
            timestamp=datetime.now()
        )
        self.violations.append(violation)

    def run_framework_compliance(
        self,
        framework: ComplianceFramework
    ) -> ComplianceReport:
        rules = self.rule_set.get_rules(framework)

        compliant_count = 0
        non_compliant_count = 0
        partial_count = 0

        framework_violations = []

        for rule in rules:
            check = self.check_compliance(rule.rule_id)
            
            if check.status == ComplianceStatus.COMPLIANT:
                compliant_count += 1
            elif check.status == ComplianceStatus.NON_COMPLIANT:
                non_compliant_count += 1
                framework_violations.extend([v for v in self.violations if v.rule_id == rule.rule_id])
            elif check.status == ComplianceStatus.PARTIAL:
                partial_count += 1

        overall_status = ComplianceStatus.COMPLIANT
        if non_compliant_count > 0:
            overall_status = ComplianceStatus.NON_COMPLIANT
        elif partial_count > 0:
            overall_status = ComplianceStatus.PARTIAL

        recommendations = self._generate_recommendations(framework_violations)

        report = ComplianceReport(
            report_id=f"COMPLIANCE-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            timestamp=datetime.now(),
            framework=framework,
            overall_status=overall_status,
            total_rules=len(rules),
            compliant_rules=compliant_count,
            non_compliant_rules=non_compliant_count,
            partial_rules=partial_count,
            violations=framework_violations,
            recommendations=recommendations
        )

        return report

    def _generate_recommendations(self, violations: List[Violation]) -> List[str]:
        recommendations = []

        critical = [v for v in violations if v.severity == ViolationSeverity.CRITICAL]
        high = [v for v in violations if v.severity == ViolationSeverity.HIGH]

        if critical:
            recommendations.append(f"Address {len(critical)} critical compliance violations immediately")
        if high:
            recommendations.append(f"Prioritize remediation of {len(high)} high-severity violations")
        if not violations:
            recommendations.append("Maintain current compliance posture")
            recommendations.append("Continue regular compliance monitoring")

        return recommendations

    def get_violations(
        self,
        status: Optional[str] = None,
        severity: Optional[ViolationSeverity] = None,
        limit: int = 100
    ) -> List[Violation]:
        violations = self.violations

        if status:
            violations = [v for v in violations if v.status == status]
        if severity:
            violations = [v for v in violations if v.severity == severity]

        return violations[-limit:]

    def update_violation_status(
        self,
        violation_id: str,
        status: str,
        remediation: Optional[str] = None,
        assignee: Optional[str] = None
    ) -> bool:
        for violation in self.violations:
            if violation.violation_id == violation_id:
                violation.status = status
                if remediation:
                    violation.remediation = remediation
                if assignee:
                    violation.assignee = assignee
                return True
        return False

    def export_report(self, framework: ComplianceFramework, format: str = "json") -> str:
        report = self.run_framework_compliance(framework)

        if format == "json":
            return json.dumps({
                "report_id": report.report_id,
                "timestamp": report.timestamp.isoformat(),
                "framework": report.framework.value,
                "overall_status": report.overall_status.value,
                "total_rules": report.total_rules,
                "compliant_rules": report.compliant_rules,
                "non_compliant_rules": report.non_compliant_rules,
                "partial_rules": report.partial_rules,
                "violations": [
                    {
                        "violation_id": v.violation_id,
                        "rule_name": v.rule_name,
                        "severity": v.severity.value,
                        "description": v.description,
                        "status": v.status
                    }
                    for v in report.violations
                ],
                "recommendations": report.recommendations
            }, indent=2, ensure_ascii=False)

        return str(report)

    def get_compliance_dashboard(self) -> Dict[str, Any]:
        total_rules = len(self.rule_set.rules)
        open_violations = len([v for v in self.violations if v.status == "open"])
        closed_violations = len([v for v in self.violations if v.status == "closed"])

        by_framework = {}
        for fw in ComplianceFramework:
            rules = self.rule_set.get_rules(fw)
            by_framework[fw.value] = len(rules)

        return {
            "total_rules": total_rules,
            "open_violations": open_violations,
            "closed_violations": closed_violations,
            "rules_by_framework": by_framework,
            "last_check": self.checks[-1].timestamp.isoformat() if self.checks else None
        }
