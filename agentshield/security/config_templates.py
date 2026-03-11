"""Configuration Templates Module - Ready-to-use configurations"""

import os
import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class TemplateCategory(Enum):
    SECURITY = "security"
    MONITORING = "monitoring"
    ENTERPRISE = "enterprise"
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    COMPLIANCE = "compliance"


@dataclass
class ConfigTemplate:
    name: str
    category: TemplateCategory
    description: str
    config: Dict[str, Any]
    tags: List[str] = field(default_factory=list)
    version: str = "1.0.0"
    created_at: datetime = field(default_factory=datetime.now)


class TemplateManager:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        self.templates: Dict[str, ConfigTemplate] = {}
        self._load_default_templates()

    def _load_default_templates(self):
        self.templates["security_basic"] = ConfigTemplate(
            name="Security Basic",
            category=TemplateCategory.SECURITY,
            description="Basic security configuration with essential protections",
            config=self._get_security_basic_config(),
            tags=["security", "basic", "essential"]
        )
        
        self.templates["security_advanced"] = ConfigTemplate(
            name="Security Advanced",
            category=TemplateCategory.SECURITY,
            description="Advanced security with all protections enabled",
            config=self._get_security_advanced_config(),
            tags=["security", "advanced", "maximum"]
        )
        
        self.templates["monitoring_full"] = ConfigTemplate(
            name="Full Monitoring",
            category=TemplateCategory.MONITORING,
            description="Complete monitoring setup with alerts",
            config=self._get_monitoring_config(),
            tags=["monitoring", "alerts", "metrics"]
        )
        
        self.templates["enterprise"] = ConfigTemplate(
            name="Enterprise",
            category=TemplateCategory.ENTERPRISE,
            description="Full enterprise features with RBAC and audit",
            config=self._get_enterprise_config(),
            tags=["enterprise", "rbac", "audit", "sso"]
        )
        
        self.templates["development"] = ConfigTemplate(
            name="Development",
            category=TemplateCategory.DEVELOPMENT,
            description="Optimized for development environment",
            config=self._get_development_config(),
            tags=["dev", "development", "debug"]
        )
        
        self.templates["production"] = ConfigTemplate(
            name="Production",
            category=TemplateCategory.PRODUCTION,
            description="Production-ready secure configuration",
            config=self._get_production_config(),
            tags=["prod", "production", "secure"]
        )
        
        self.templates["compliance_soc2"] = ConfigTemplate(
            name="SOC2 Compliant",
            category=TemplateCategory.COMPLIANCE,
            description="Configuration for SOC2 compliance",
            config=self._get_soc2_config(),
            tags=["compliance", "soc2", "audit"]
        )
        
        self.templates["compliance_gdpr"] = ConfigTemplate(
            name="GDPR Compliant",
            category=TemplateCategory.COMPLIANCE,
            description="Configuration for GDPR compliance",
            config=self._get_gdpr_config(),
            tags=["compliance", "gdpr", "privacy"]
        )

    def _get_security_basic_config(self) -> Dict[str, Any]:
        return {
            "security": {
                "enabled": True,
                "level": "medium",
                "request_interceptor": {
                    "enabled": True,
                    "blocked_patterns": [
                        r"<script.*?>",
                        r"javascript:",
                        r"onerror=",
                        r"onclick="
                    ],
                    "max_length": 10000
                },
                "response_interceptor": {
                    "enabled": True,
                    "max_length": 50000
                },
                "tool_call_interceptor": {
                    "enabled": True,
                    "require_approval_tools": ["delete", "drop", "execute"]
                },
                "data_access_interceptor": {
                    "enabled": True,
                    "blocked_operations": ["DROP", "TRUNCATE", "DELETE"]
                }
            },
            "encryption": {
                "enabled": True,
                "algorithm": "fernet",
                "key_rotation_days": 90
            },
            "rate_limiting": {
                "enabled": True,
                "default_rate": 100,
                "default_window": 60
            }
        }

    def _get_security_advanced_config(self) -> Dict[str, Any]:
        config = self._get_security_basic_config()
        config["security"]["level"] = "high"
        config["security"]["request_interceptor"]["blocked_patterns"].extend([
            r"union\s+select",
            r"exec\s*\(",
            r"\$\(",
            r"\.\./"
        ])
        config["waf"] = {
            "enabled": True,
            "default_action": "block",
            "blocked_status_code": 403
        }
        config["key_rotation"] = {
            "enabled": True,
            "default_rotation_days": 30,
            "auto_rotate": True
        }
        return config

    def _get_monitoring_config(self) -> Dict[str, Any]:
        return {
            "monitoring": {
                "enabled": True,
                "metrics": {
                    "enabled": True,
                    "export_interval": 60,
                    "exporters": ["prometheus", "statsd"]
                },
                "health_check": {
                    "enabled": True,
                    "port": 8080,
                    "path": "/health"
                }
            },
            "alerts": {
                "enabled": True,
                "channels": ["email", "slack"],
                "rules": [
                    {
                        "name": "high_error_rate",
                        "condition": "error_rate > 0.05",
                        "severity": "high",
                        "channels": ["email", "slack", "pagerduty"]
                    },
                    {
                        "name": "authentication_failure",
                        "condition": "auth_failures > 10",
                        "severity": "medium",
                        "channels": ["email", "slack"]
                    }
                ]
            },
            "audit": {
                "enabled": True,
                "log_level": "info",
                "events": ["login", "logout", "data_access", "tool_call", "configuration_change"]
            }
        }

    def _get_enterprise_config(self) -> Dict[str, Any]:
        return {
            "enterprise": {
                "enabled": True,
                "rbac": {
                    "enabled": True,
                    "roles": ["admin", "operator", "analyst", "viewer"],
                    "default_role": "viewer"
                },
                "sso": {
                    "enabled": True,
                    "providers": ["okta", "azure_ad", "google"]
                },
                "audit": {
                    "enabled": True,
                    "retention_days": 365,
                    "export_siem": True
                },
                "compliance": {
                    "enabled": True,
                    "frameworks": ["SOC2", "ISO27001", "GDPR"]
                }
            },
            "security": {
                "enabled": True,
                "level": "high",
                "mfa_required": True,
                "session_timeout": 1800,
                "max_login_attempts": 5
            },
            "monitoring": {
                "enabled": True,
                "detailed_metrics": True,
                "apm_enabled": True
            }
        }

    def _get_development_config(self) -> Dict[str, Any]:
        return {
            "security": {
                "enabled": True,
                "level": "low",
                "debug_mode": True
            },
            "monitoring": {
                "enabled": True,
                "debug_logging": True
            },
            "rate_limiting": {
                "enabled": False
            }
        }

    def _get_production_config(self) -> Dict[str, Any]:
        return {
            "security": {
                "enabled": True,
                "level": "critical",
                "mfa_required": True,
                "session_timeout": 900,
                "max_login_attempts": 3,
                "ip_whitelist": [],
                "ip_blacklist": []
            },
            "encryption": {
                "enabled": True,
                "algorithm": "fernet",
                "key_rotation_days": 30,
                "field_level_encryption": True
            },
            "rate_limiting": {
                "enabled": True,
                "default_rate": 50,
                "default_window": 60,
                "strict_mode": True
            },
            "waf": {
                "enabled": True,
                "strict_mode": True
            },
            "monitoring": {
                "enabled": True,
                "detailed_metrics": True,
                "alert_on_anomalies": True
            },
            "audit": {
                "enabled": True,
                "log_level": "debug",
                "retention_days": 730
            }
        }

    def _get_soc2_config(self) -> Dict[str, Any]:
        return {
            "security": {
                "enabled": True,
                "level": "high",
                "mfa_required": True,
                "encryption_at_rest": True,
                "encryption_in_transit": True
            },
            "access_control": {
                "rbac_enabled": True,
                "least_privilege": True,
                "separation_of_duties": True
            },
            "audit": {
                "enabled": True,
                "comprehensive_logging": True,
                "log_integrity": True,
                "retention_years": 7
            },
            "monitoring": {
                "enabled": True,
                "continuous_monitoring": True,
                "anomaly_detection": True
            },
            "incident_response": {
                "enabled": True,
                "documented_procedures": True,
                "notification_requirements": True
            }
        }

    def _get_gdpr_config(self) -> Dict[str, Any]:
        return {
            "data_protection": {
                "encryption_at_rest": True,
                "encryption_in_transit": True,
                "data_retention_policy": True,
                "right_to_deletion": True,
                "consent_management": True
            },
            "privacy": {
                "pii_detection": True,
                "data_masking": True,
                "anonymization": True,
                "breach_notification": True
            },
            "access_control": {
                "rbac_enabled": True,
                "purpose_limitation": True,
                "data_minimization": True
            },
            "audit": {
                "enabled": True,
                "consent_tracking": True,
                "data_access_logging": True,
                "retention_years": 2
            }
        }

    def get_template(self, name: str) -> Optional[ConfigTemplate]:
        return self.templates.get(name)

    def list_templates(
        self,
        category: Optional[TemplateCategory] = None,
        tags: Optional[List[str]] = None
    ) -> List[ConfigTemplate]:
        result = []
        
        for template in self.templates.values():
            if category and template.category != category:
                continue
            
            if tags:
                if not any(tag in template.tags for tag in tags):
                    continue
            
            result.append(template)
        
        return result

    def apply_template(self, name: str, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        template = self.get_template(name)
        
        if not template:
            raise ValueError(f"Template '{name}' not found")
        
        config = template.config.copy()
        
        if overrides:
            config = self._deep_merge(config, overrides)
        
        return config

    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result

    def save_template(self, template: ConfigTemplate):
        self.templates[template.name] = template

    def delete_template(self, name: str) -> bool:
        if name in self.templates:
            del self.templates[name]
            return True
        return False

    def export_template(self, name: str, path: str) -> bool:
        template = self.get_template(name)
        
        if not template:
            return False
        
        try:
            with open(path, 'w') as f:
                json.dump({
                    "name": template.name,
                    "category": template.category.value,
                    "description": template.description,
                    "config": template.config,
                    "tags": template.tags,
                    "version": template.version
                }, f, indent=2)
            return True
        except Exception as e:
            self.logger.error(f"Failed to export template: {e}")
            return False

    def import_template(self, path: str) -> bool:
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            
            template = ConfigTemplate(
                name=data["name"],
                category=TemplateCategory(data.get("category", "security")),
                description=data.get("description", ""),
                config=data["config"],
                tags=data.get("tags", []),
                version=data.get("version", "1.0.0")
            )
            
            self.save_template(template)
            return True
        except Exception as e:
            self.logger.error(f"Failed to import template: {e}")
            return False


class ConfigValidator:
    @staticmethod
    def validate(config: Dict[str, Any]) -> Dict[str, Any]:
        errors = []
        warnings = []
        
        if "security" in config:
            if not config["security"].get("enabled"):
                warnings.append("Security is not enabled")
        
        if "encryption" in config:
            if not config["encryption"].get("enabled"):
                warnings.append("Encryption is not enabled")
        
        if "rate_limiting" in config:
            if not config["rate_limiting"].get("enabled"):
                warnings.append("Rate limiting is not enabled")
        
        if "monitoring" in config:
            if not config["monitoring"].get("enabled"):
                warnings.append("Monitoring is not enabled")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }
