"""Security Scoring Module - System security status scoring"""

import time
import logging
import hashlib
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import threading
import json


class ScoreCategory(Enum):
    IDENTITY = "identity"
    ACCESS_CONTROL = "access_control"
    DATA_PROTECTION = "data_protection"
    NETWORK_SECURITY = "network_security"
    APPLICATION_SECURITY = "application_security"
    COMPLIANCE = "compliance"
    MONITORING = "monitoring"
    INCIDENT_RESPONSE = "incident_response"


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class ScoreItem:
    category: ScoreCategory
    name: str
    description: str
    score: float
    max_score: float
    weight: float
    risk_level: RiskLevel
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    last_updated: datetime = field(default_factory=datetime.now)


@dataclass
class SecurityScore:
    overall_score: float
    grade: str
    max_score: float
    category_scores: Dict[str, ScoreItem]
    trend: str
    last_scan: datetime
    risk_summary: Dict[str, int] = field(default_factory=dict)


@dataclass
class SecurityCheck:
    id: str
    name: str
    category: ScoreCategory
    check_type: str
    weight: float
    check_function: Callable
    enabled: bool = True
    description: str = ""


class SecurityScorer:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        self.categories = {cat: [] for cat in ScoreCategory}
        self.score_history: List[SecurityScore] = []
        
        self.baseline_score = self.config.get("baseline_score", 80)
        self.trend_window_days = self.config.get("trend_window_days", 30)
        
        self._register_default_checks()
        
        self.lock = threading.Lock()
        
        self.last_full_scan: Optional[datetime] = None
        self.current_score: Optional[SecurityScore] = None

    def _register_default_checks(self):
        self.register_check(SecurityCheck(
            id="auth_enabled",
            name="Authentication Enabled",
            category=ScoreCategory.IDENTITY,
            check_type="configuration",
            weight=10.0,
            check_function=self._check_authentication,
            description="Verify authentication is enabled"
        ))
        
        self.register_check(SecurityCheck(
            id="mfa_enabled",
            name="Multi-Factor Authentication",
            category=ScoreCategory.IDENTITY,
            check_type="configuration",
            weight=15.0,
            check_function=self._check_mfa,
            description="Check if MFA is enforced"
        ))
        
        self.register_check(SecurityCheck(
            id="rbac_configured",
            name="Role-Based Access Control",
            category=ScoreCategory.ACCESS_CONTROL,
            check_type="configuration",
            weight=12.0,
            check_function=self._check_rbac,
            description="Verify RBAC is properly configured"
        ))
        
        self.register_check(SecurityCheck(
            id="encryption_at_rest",
            name="Data Encryption at Rest",
            category=ScoreCategory.DATA_PROTECTION,
            check_type="encryption",
            weight=15.0,
            check_function=self._check_encryption_at_rest,
            description="Check if data is encrypted at rest"
        ))
        
        self.register_check(SecurityCheck(
            id="encryption_in_transit",
            name="Data Encryption in Transit",
            category=ScoreCategory.DATA_PROTECTION,
            check_type="encryption",
            weight=12.0,
            check_function=self._check_encryption_in_transit,
            description="Verify TLS is enforced"
        ))
        
        self.register_check(SecurityCheck(
            id="rate_limiting",
            name="Rate Limiting Enabled",
            category=ScoreCategory.NETWORK_SECURITY,
            check_type="configuration",
            weight=10.0,
            check_function=self._check_rate_limiting,
            description="Verify rate limiting is configured"
        ))
        
        self.register_check(SecurityCheck(
            id="waf_enabled",
            name="Web Application Firewall",
            category=ScoreCategory.APPLICATION_SECURITY,
            check_type="configuration",
            weight=12.0,
            check_function=self._check_waf,
            description="Check if WAF is enabled"
        ))
        
        self.register_check(SecurityCheck(
            id="audit_logging",
            name="Audit Logging",
            category=ScoreCategory.MONITORING,
            check_type="logging",
            weight=10.0,
            check_function=self._check_audit_logging,
            description="Verify audit logging is enabled"
        ))
        
        self.register_check(SecurityCheck(
            id="compliance_framework",
            name="Compliance Framework",
            category=ScoreCategory.COMPLIANCE,
            check_type="configuration",
            weight=8.0,
            check_function=self._check_compliance,
            description="Check compliance framework implementation"
        ))

    def _check_authentication(self, context: Dict) -> Dict:
        auth_enabled = context.get("auth_enabled", True)
        
        if auth_enabled:
            return {
                "score": 10.0,
                "risk_level": RiskLevel.NONE,
                "findings": [],
                "recommendations": []
            }
        
        return {
            "score": 0.0,
            "risk_level": RiskLevel.CRITICAL,
            "findings": ["Authentication is not enabled"],
            "recommendations": ["Enable authentication immediately"]
        }

    def _check_mfa(self, context: Dict) -> Dict:
        mfa_enabled = context.get("mfa_enabled", True)
        
        if mfa_enabled:
            return {
                "score": 15.0,
                "risk_level": RiskLevel.NONE,
                "findings": [],
                "recommendations": []
            }
        
        return {
            "score": 5.0,
            "risk_level": RiskLevel.HIGH,
            "findings": ["Multi-factor authentication is not enforced"],
            "recommendations": ["Enable and enforce MFA for all users"]
        }

    def _check_rbac(self, context: Dict) -> Dict:
        rbac_configured = context.get("rbac_configured", True)
        roles_count = context.get("roles_count", 3)
        
        if rbac_configured and roles_count >= 3:
            return {
                "score": 12.0,
                "risk_level": RiskLevel.NONE,
                "findings": [],
                "recommendations": []
            }
        
        return {
            "score": 6.0,
            "risk_level": RiskLevel.MEDIUM,
            "findings": ["RBAC may not be fully configured"],
            "recommendations": ["Configure granular role-based access controls"]
        }

    def _check_encryption_at_rest(self, context: Dict) -> Dict:
        encryption_enabled = context.get("encryption_at_rest", True)
        
        if encryption_enabled:
            return {
                "score": 15.0,
                "risk_level": RiskLevel.NONE,
                "findings": [],
                "recommendations": []
            }
        
        return {
            "score": 0.0,
            "risk_level": RiskLevel.CRITICAL,
            "findings": ["Data is not encrypted at rest"],
            "recommendations": ["Enable encryption for all stored data"]
        }

    def _check_encryption_in_transit(self, context: Dict) -> Dict:
        tls_enabled = context.get("tls_enabled", True)
        
        if tls_enabled:
            return {
                "score": 12.0,
                "risk_level": RiskLevel.NONE,
                "findings": [],
                "recommendations": []
            }
        
        return {
            "score": 0.0,
            "risk_level": RiskLevel.HIGH,
            "findings": ["TLS is not enforced"],
            "recommendations": ["Enable TLS 1.2 or higher for all connections"]
        }

    def _check_rate_limiting(self, context: Dict) -> Dict:
        rate_limiting = context.get("rate_limiting_enabled", True)
        
        if rate_limiting:
            return {
                "score": 10.0,
                "risk_level": RiskLevel.NONE,
                "findings": [],
                "recommendations": []
            }
        
        return {
            "score": 3.0,
            "risk_level": RiskLevel.MEDIUM,
            "findings": ["Rate limiting is not configured"],
            "recommendations": ["Configure rate limiting to prevent abuse"]
        }

    def _check_waf(self, context: Dict) -> Dict:
        waf_enabled = context.get("waf_enabled", True)
        
        if waf_enabled:
            return {
                "score": 12.0,
                "risk_level": RiskLevel.NONE,
                "findings": [],
                "recommendations": []
            }
        
        return {
            "score": 4.0,
            "risk_level": RiskLevel.HIGH,
            "findings": ["WAF is not enabled"],
            "recommendations": ["Enable Web Application Firewall"]
        }

    def _check_audit_logging(self, context: Dict) -> Dict:
        audit_enabled = context.get("audit_logging_enabled", True)
        
        if audit_enabled:
            return {
                "score": 10.0,
                "risk_level": RiskLevel.NONE,
                "findings": [],
                "recommendations": []
            }
        
        return {
            "score": 2.0,
            "risk_level": RiskLevel.MEDIUM,
            "findings": ["Audit logging is not enabled"],
            "recommendations": ["Enable comprehensive audit logging"]
        }

    def _check_compliance(self, context: Dict) -> Dict:
        compliance_framework = context.get("compliance_framework", "SOC2")
        
        if compliance_framework:
            return {
                "score": 8.0,
                "risk_level": RiskLevel.NONE,
                "findings": [f"Compliance framework: {compliance_framework}"],
                "recommendations": []
            }
        
        return {
            "score": 2.0,
            "risk_level": RiskLevel.MEDIUM,
            "findings": ["No compliance framework configured"],
            "recommendations": ["Implement a compliance framework"]
        }

    def register_check(self, check: SecurityCheck):
        self.categories[check.category].append(check)

    def calculate_score(self, context: Optional[Dict[str, Any]] = None) -> SecurityScore:
        context = context or {}
        
        category_scores: Dict[str, ScoreItem] = {}
        total_score = 0.0
        total_max = 0.0
        
        risk_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for category, checks in self.categories.items():
            category_max = 0.0
            category_score = 0.0
            
            for check in checks:
                if not check.enabled:
                    continue
                
                category_max += check.weight
                
                try:
                    result = check.check_function(context)
                except Exception as e:
                    self.logger.error(f"Check {check.id} failed: {e}")
                    result = {
                        "score": 0,
                        "risk_level": RiskLevel.UNKNOWN,
                        "findings": [f"Check failed: {str(e)}"],
                        "recommendations": ["Review check configuration"]
                    }
                
                weight_factor = result.get("score", 0) / check.weight if check.weight > 0 else 0
                category_score += check.weight * weight_factor
                
                risk_level = result.get("risk_level", RiskLevel.NONE)
                if risk_level != RiskLevel.NONE and risk_level != RiskLevel.LOW and risk_level != RiskLevel.MEDIUM:
                    risk_counts[risk_level.value] += 1
            
            if category_max > 0:
                total_score += category_score
                total_max += category_max
                
                category_scores[category.value] = ScoreItem(
                    category=category,
                    name=category.value.replace("_", " ").title(),
                    description=f"{category.value} security assessment",
                    score=category_score,
                    max_score=category_max,
                    weight=category_max / total_max if total_max > 0 else 0,
                    risk_level=self._calculate_category_risk(category_score, category_max),
                    findings=[],
                    recommendations=[]
                )
        
        overall_score = (total_score / total_max * 100) if total_max > 0 else 0
        grade = self._calculate_grade(overall_score)
        
        trend = self._calculate_trend()
        
        score = SecurityScore(
            overall_score=overall_score,
            grade=grade,
            max_score=100.0,
            category_scores=category_scores,
            trend=trend,
            last_scan=datetime.now(),
            risk_summary=risk_counts
        )
        
        with self.lock:
            self.current_score = score
            self.score_history.append(score)
            if len(self.score_history) > 100:
                self.score_history = self.score_history[-100:]
        
        self.last_full_scan = datetime.now()
        
        return score

    def _calculate_category_risk(self, score: float, max_score: float) -> RiskLevel:
        if max_score == 0:
            return RiskLevel.NONE
        
        percentage = (score / max_score) * 100
        
        if percentage >= 90:
            return RiskLevel.NONE
        elif percentage >= 70:
            return RiskLevel.LOW
        elif percentage >= 50:
            return RiskLevel.MEDIUM
        elif percentage >= 30:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    def _calculate_grade(self, score: float) -> str:
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def _calculate_trend(self) -> str:
        with self.lock:
            if len(self.score_history) < 2:
                return "stable"
            
            recent = self.score_history[-5:]
            scores = [s.overall_score for s in recent]
            
            if len(scores) < 2:
                return "stable"
            
            diff = scores[-1] - scores[0]
            
            if diff > 5:
                return "improving"
            elif diff < -5:
                return "declining"
            else:
                return "stable"

    def get_score_history(self, days: int = 30) -> List[SecurityScore]:
        cutoff = datetime.now() - timedelta(days=days)
        
        with self.lock:
            return [s for s in self.score_history if s.last_scan >= cutoff]

    def generate_report(self, format: str = "json") -> Dict[str, Any]:
        score = self.current_score
        
        if not score:
            return {"error": "No score available. Run calculate_score first."}
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "overall_score": score.overall_score,
            "grade": score.grade,
            "trend": score.trend,
            "risk_summary": score.risk_summary,
            "categories": {},
            "recommendations": []
        }
        
        for cat_id, cat_score in score.category_scores.items():
            report["categories"][cat_id] = {
                "score": cat_score.score,
                "max_score": cat_score.max_score,
                "percentage": (cat_score.score / cat_score.max_score * 100) if cat_score.max_score > 0 else 0,
                "risk_level": cat_score.risk_level.value,
                "findings": cat_score.findings,
                "recommendations": cat_score.recommendations
            }
            
            if cat_score.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                report["recommendations"].extend(cat_score.recommendations)
        
        return report

    def compare_scores(
        self,
        score1: SecurityScore,
        score2: SecurityScore
    ) -> Dict[str, Any]:
        return {
            "score_change": score2.overall_score - score1.overall_score,
            "grade_change": score1.grade != score2.grade,
            "category_changes": {
                cat: score2.category_scores[cat].score - score1.category_scores[cat].score
                for cat in score1.category_scores
                if cat in score2.category_scores
            }
        }

    def get_security_posture(self) -> str:
        if not self.current_score:
            return "unknown"
        
        score = self.current_score.overall_score
        
        if score >= 90:
            return "excellent"
        elif score >= 80:
            return "good"
        elif score >= 70:
            return "fair"
        elif score >= 60:
            return "poor"
        else:
            return "critical"
