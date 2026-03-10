"""AI Policy Engine - Central policy management for AgentShield OS"""

import logging
import yaml
import json
from typing import Any, Callable, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from abc import ABC, abstractmethod


class PolicyType(Enum):
    TOOL_POLICY = "tool_policy"
    DATA_POLICY = "data_policy"
    RATE_POLICY = "rate_policy"
    SECURITY_POLICY = "security_policy"
    COMPLIANCE_POLICY = "compliance_policy"


class PolicyAction(Enum):
    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"
    WARN = "warn"
    RATE_LIMIT = "rate_limit"
    BLOCK = "block"


class PolicyScope(Enum):
    GLOBAL = "global"
    AGENT = "agent"
    USER = "user"
    SESSION = "session"
    SOURCE = "source"


class PolicyEffect(Enum):
    PERMIT = "permit"
    DENY = "deny"


@dataclass
class PolicyRule:
    rule_id: str
    name: str
    policy_type: PolicyType
    action: PolicyAction
    conditions: Dict[str, Any] = field(default_factory=dict)
    effect: PolicyEffect = PolicyEffect.PERMIT
    priority: int = 0
    enabled: bool = True
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyEvaluationResult:
    allowed: bool
    action: PolicyAction
    policy_rules: List[PolicyRule] = field(default_factory=list)
    reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class PolicyCondition(ABC):
    @abstractmethod
    def evaluate(self, context: Dict[str, Any]) -> bool:
        pass


class IPAddressCondition(PolicyCondition):
    def __init__(self, allowed_ips: List[str]):
        self.allowed_ips = allowed_ips

    def evaluate(self, context: Dict[str, Any]) -> bool:
        client_ip = context.get("client_ip", "")
        return client_ip in self.allowed_ips


class TimeCondition(PolicyCondition):
    def __init__(self, allowed_hours: Optional[Dict[str, int]] = None):
        self.allowed_hours = allowed_hours or {"start": 0, "end": 23}

    def evaluate(self, context: Dict[str, Any]) -> bool:
        now = datetime.now()
        current_hour = now.hour
        return self.allowed_hours["start"] <= current_hour <= self.allowed_hours["end"]


class RoleCondition(PolicyCondition):
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = set(allowed_roles)

    def evaluate(self, context: Dict[str, Any]) -> bool:
        user_role = context.get("user_role", "")
        return user_role in self.allowed_roles


class ResourceCondition(PolicyCondition):
    def __init__(self, allowed_resources: List[str]):
        self.allowed_resources = set(allowed_resources)

    def evaluate(self, context: Dict[str, Any]) -> bool:
        resource = context.get("resource", "")
        return resource in self.allowed_resources


class PolicyEngine:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        self.policies: Dict[str, PolicyRule] = {}
        self.policy_groups: Dict[str, List[str]] = {}

        self.default_action = PolicyAction(
            self.config.get("default_action", "deny")
        )
        self.enable_audit = self.config.get("enable_audit", True)

        self.evaluation_callbacks: List[Callable] = []
        self._load_default_policies()

    def _load_default_policies(self):
        self.add_policy(PolicyRule(
            rule_id="default-allow-tool",
            name="Default Tool Allow",
            policy_type=PolicyType.TOOL_POLICY,
            action=PolicyAction.ALLOW,
            conditions={},
            priority=1,
            description="Default policy to allow tool execution"
        ))

        self.add_policy(PolicyRule(
            rule_id="default-allow-data",
            name="Default Data Access Allow",
            policy_type=PolicyType.DATA_POLICY,
            action=PolicyAction.ALLOW,
            conditions={},
            priority=1,
            description="Default policy to allow data access"
        ))

    def add_policy(self, policy: PolicyRule):
        self.policies[policy.rule_id] = policy
        self.logger.info(f"Added policy: {policy.name}")

    def remove_policy(self, rule_id: str):
        if rule_id in self.policies:
            del self.policies[rule_id]
            self.logger.info(f"Removed policy: {rule_id}")

    def get_policy(self, rule_id: str) -> Optional[PolicyRule]:
        return self.policies.get(rule_id)

    def list_policies(self, policy_type: Optional[PolicyType] = None) -> List[PolicyRule]:
        policies = list(self.policies.values())
        if policy_type:
            policies = [p for p in policies if p.policy_type == policy_type]
        return sorted(policies, key=lambda p: p.priority, reverse=True)

    def evaluate(
        self,
        policy_type: PolicyType,
        context: Dict[str, Any]
    ) -> PolicyEvaluationResult:
        relevant_policies = [
            p for p in self.policies.values()
            if p.policy_type == policy_type and p.enabled
        ]

        relevant_policies = sorted(relevant_policies, key=lambda p: p.priority, reverse=True)

        matched_rules = []

        for policy in relevant_policies:
            if self._evaluate_conditions(policy.conditions, context):
                matched_rules.append(policy)

                if policy.effect == PolicyEffect.DENY:
                    return PolicyEvaluationResult(
                        allowed=False,
                        action=policy.action,
                        policy_rules=matched_rules,
                        reason=f"Denied by policy: {policy.name}",
                        metadata={"rule_id": policy.rule_id}
                    )

                if policy.effect == PolicyEffect.PERMIT and policy.action == PolicyAction.DENY:
                    return PolicyEvaluationResult(
                        allowed=False,
                        action=PolicyAction.DENY,
                        policy_rules=matched_rules,
                        reason=f"Denied by policy: {policy.name}",
                        metadata={"rule_id": policy.rule_id}
                    )

        for callback in self.evaluation_callbacks:
            callback(policy_type, context, matched_rules)

        return PolicyEvaluationResult(
            allowed=True,
            action=PolicyAction.ALLOW,
            policy_rules=matched_rules,
            reason="Allowed by default policy"
        )

    def _evaluate_conditions(
        self,
        conditions: Dict[str, Any],
        context: Dict[str, Any]
    ) -> bool:
        if not conditions:
            return True

        for key, expected_value in conditions.items():
            context_value = context.get(key)

            if isinstance(expected_value, list):
                if context_value not in expected_value:
                    return False
            elif isinstance(expected_value, dict):
                operator = expected_value.get("operator", "eq")
                value = expected_value.get("value")

                if operator == "eq" and context_value != value:
                    return False
                elif operator == "ne" and context_value == value:
                    return False
                elif operator == "gt" and not (context_value and context_value > value):
                    return False
                elif operator == "lt" and not (context_value and context_value < value):
                    return False
                elif operator == "in" and context_value not in value:
                    return False
                elif operator == "regex":
                    import re
                    if not re.match(value, str(context_value)):
                        return False
            else:
                if context_value != expected_value:
                    return False

        return True

    def can_execute_tool(
        self,
        tool_name: str,
        user: str = "",
        user_role: str = "",
        client_ip: str = "",
        **kwargs
    ) -> PolicyEvaluationResult:
        context = {
            "tool_name": tool_name,
            "user": user,
            "user_role": user_role,
            "client_ip": client_ip,
            **kwargs
        }

        return self.evaluate(PolicyType.TOOL_POLICY, context)

    def can_access_data(
        self,
        resource: str,
        operation: str,
        user: str = "",
        user_role: str = "",
        **kwargs
    ) -> PolicyEvaluationResult:
        context = {
            "resource": resource,
            "operation": operation,
            "user": user,
            "user_role": user_role,
            **kwargs
        }

        return self.evaluate(PolicyType.DATA_POLICY, context)

    def check_rate_limit(
        self,
        identifier: str,
        limit: int = 100,
        window_seconds: int = 60
    ) -> PolicyEvaluationResult:
        context = {
            "identifier": identifier,
            "limit": limit,
            "window_seconds": window_seconds
        }

        return self.evaluate(PolicyType.RATE_POLICY, context)

    def evaluate_security(
        self,
        event_type: str,
        severity: str,
        source: str = "",
        **kwargs
    ) -> PolicyEvaluationResult:
        context = {
            "event_type": event_type,
            "severity": severity,
            "source": source,
            **kwargs
        }

        return self.evaluate(PolicyType.SECURITY_POLICY, context)

    def load_from_yaml(self, yaml_path: str):
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if "policies" in data:
                for policy_data in data["policies"]:
                    policy = PolicyRule(
                        rule_id=policy_data.get("rule_id", ""),
                        name=policy_data.get("name", ""),
                        policy_type=PolicyType(policy_data.get("policy_type", "tool_policy")),
                        action=PolicyAction(policy_data.get("action", "allow")),
                        conditions=policy_data.get("conditions", {}),
                        effect=PolicyEffect(policy_data.get("effect", "permit")),
                        priority=policy_data.get("priority", 0),
                        enabled=policy_data.get("enabled", True),
                        description=policy_data.get("description", "")
                    )
                    self.add_policy(policy)

            self.logger.info(f"Loaded policies from {yaml_path}")
        except Exception as e:
            self.logger.error(f"Failed to load policies from {yaml_path}: {e}")

    def load_from_json(self, json_path: str):
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if "policies" in data:
                for policy_data in data["policies"]:
                    policy = PolicyRule(
                        rule_id=policy_data.get("rule_id", ""),
                        name=policy_data.get("name", ""),
                        policy_type=PolicyType(policy_data.get("policy_type", "tool_policy")),
                        action=PolicyAction(policy_data.get("action", "allow")),
                        conditions=policy_data.get("conditions", {}),
                        effect=PolicyEffect(policy_data.get("effect", "permit")),
                        priority=policy_data.get("priority", 0),
                        enabled=policy_data.get("enabled", True),
                        description=policy_data.get("description", "")
                    )
                    self.add_policy(policy)

            self.logger.info(f"Loaded policies from {json_path}")
        except Exception as e:
            self.logger.error(f"Failed to load policies from {json_path}: {e}")

    def export_to_yaml(self, yaml_path: str):
        policies_data = {
            "policies": [
                {
                    "rule_id": p.rule_id,
                    "name": p.name,
                    "policy_type": p.policy_type.value,
                    "action": p.action.value,
                    "conditions": p.conditions,
                    "effect": p.effect.value,
                    "priority": p.priority,
                    "enabled": p.enabled,
                    "description": p.description
                }
                for p in self.policies.values()
            ]
        }

        with open(yaml_path, 'w', encoding='utf-8') as f:
            yaml.dump(policies_data, f, default_flow_style=False)

        self.logger.info(f"Exported policies to {yaml_path}")

    def add_evaluation_callback(self, callback: Callable):
        self.evaluation_callbacks.append(callback)

    def get_statistics(self) -> Dict[str, Any]:
        policy_counts = {}
        for ptype in PolicyType:
            policy_counts[ptype.value] = len([
                p for p in self.policies.values() if p.policy_type == ptype
            ])

        return {
            "total_policies": len(self.policies),
            "policies_by_type": policy_counts,
            "enabled_policies": len([p for p in self.policies.values() if p.enabled]),
            "disabled_policies": len([p for p in self.policies.values() if not p.enabled])
        }
