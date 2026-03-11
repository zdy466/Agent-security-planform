"""Policy as Code Module - IaC style policy management"""

import os
import json
import logging
import hashlib
import re
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import threading


class PolicyEffect(Enum):
    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"
    MUTE = "mute"


class PolicyResource(Enum):
    USER = "user"
    TOOL = "tool"
    DATA = "data"
    API = "api"
    LLM = "llm"
    SESSION = "session"


class PolicyCondition(Enum):
    ALWAYS = "always"
    NEVER = "never"
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    MATCHES = "matches"
    IN_LIST = "in_list"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"


@dataclass
class PolicyRule:
    id: str
    name: str
    description: str
    effect: PolicyEffect
    resource: PolicyResource
    conditions: List[Dict[str, Any]]
    actions: List[str] = field(default_factory=list)
    priority: int = 0
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyEvaluation:
    policy_id: str
    rule_id: str
    effect: PolicyEffect
    resource: str
    timestamp: datetime
    passed: bool
    reason: str


@dataclass
class PolicyBundle:
    id: str
    name: str
    version: str
    rules: List[PolicyRule]
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


class ConditionEvaluator:
    @staticmethod
    def evaluate(condition: Dict[str, Any], context: Dict[str, Any]) -> bool:
        condition_type = condition.get("type", PolicyCondition.ALWAYS.value)
        
        if condition_type == PolicyCondition.ALWAYS.value:
            return True
        
        if condition_type == PolicyCondition.NEVER.value:
            return False
        
        field_path = condition.get("field", "")
        value = ConditionEvaluator._get_nested_value(context, field_path)
        expected = condition.get("value")
        
        if condition_type == PolicyCondition.EQUALS.value:
            return value == expected
        
        if condition_type == PolicyCondition.NOT_EQUALS.value:
            return value != expected
        
        if condition_type == PolicyCondition.CONTAINS.value:
            return expected in str(value) if value else False
        
        if condition_type == PolicyCondition.MATCHES.value:
            try:
                pattern = re.compile(expected)
                return bool(pattern.search(str(value)))
            except re.error:
                return False
        
        if condition_type == PolicyCondition.IN_LIST.value:
            return value in expected if isinstance(expected, list) else False
        
        if condition_type == PolicyCondition.GREATER_THAN.value:
            try:
                return float(value) > float(expected)
            except (ValueError, TypeError):
                return False
        
        if condition_type == PolicyCondition.LESS_THAN.value:
            try:
                return float(value) < float(expected)
            except (ValueError, TypeError):
                return False
        
        return False

    @staticmethod
    def _get_nested_value(data: Dict, path: str) -> Any:
        keys = path.split(".")
        value = data
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        
        return value


class PolicyEngine:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        self.policies: Dict[str, PolicyBundle] = {}
        self.evaluation_history: List[PolicyEvaluation] = []
        
        self.default_effect = PolicyEffect(
            self.config.get("default_effect", "allow")
        )
        
        self.enforce_mode = self.config.get("enforce_mode", True)
        
        self.lock = threading.RLock()
        
        self._load_default_policies()

    def _load_default_policies(self):
        self.policies["security"] = PolicyBundle(
            id="security",
            name="Security Policies",
            version="1.0.0",
            rules=[
                PolicyRule(
                    id="block_malicious_inputs",
                    name="Block Malicious Inputs",
                    description="Block known malicious input patterns",
                    effect=PolicyEffect.DENY,
                    resource=PolicyResource.LLM,
                    conditions=[
                        {"type": "matches", "field": "input", "value": r"<script|javascript:|onerror="}
                    ],
                    priority=100
                ),
                PolicyRule(
                    id="require_auth",
                    name="Require Authentication",
                    description="All requests must be authenticated",
                    effect=PolicyEffect.DENY,
                    resource=PolicyResource.API,
                    conditions=[
                        {"type": "never", "field": "auth.token"}
                    ],
                    priority=90
                ),
                PolicyRule(
                    id="rate_limit_check",
                    name="Rate Limiting",
                    description="Enforce rate limits",
                    effect=PolicyEffect.DENY,
                    resource=PolicyResource.API,
                    conditions=[
                        {"type": "greater_than", "field": "request.count", "value": 100}
                    ],
                    priority=80
                )
            ]
        )
        
        self.policies["data_access"] = PolicyBundle(
            id="data_access",
            name="Data Access Policies",
            version="1.0.0",
            rules=[
                PolicyRule(
                    id="block_sensitive_delete",
                    name="Block Sensitive Data Deletion",
                    description="Prevent deletion of sensitive data",
                    effect=PolicyEffect.DENY,
                    resource=PolicyResource.DATA,
                    conditions=[
                        {"type": "equals", "field": "operation", "value": "delete"},
                        {"type": "contains", "field": "resource", "value": "sensitive"}
                    ],
                    priority=95
                ),
                PolicyRule(
                    id="audit_data_access",
                    name="Audit Data Access",
                    description="Log all data access events",
                    effect=PolicyEffect.AUDIT,
                    resource=PolicyResource.DATA,
                    conditions=[
                        {"type": "always", "field": ""}
                    ],
                    priority=10
                )
            ]
        )

    def add_policy_bundle(self, bundle: PolicyBundle):
        with self.lock:
            self.policies[bundle.id] = bundle

    def remove_policy_bundle(self, bundle_id: str) -> bool:
        with self.lock:
            if bundle_id in self.policies:
                del self.policies[bundle_id]
                return True
            return False

    def add_rule(self, bundle_id: str, rule: PolicyRule) -> bool:
        with self.lock:
            if bundle_id not in self.policies:
                return False
            
            bundle = self.policies[bundle_id]
            bundle.rules.append(rule)
            bundle.updated_at = datetime.now()
            return True

    def remove_rule(self, bundle_id: str, rule_id: str) -> bool:
        with self.lock:
            if bundle_id not in self.policies:
                return False
            
            bundle = self.policies[bundle_id]
            bundle.rules = [r for r in bundle.rules if r.id != rule_id]
            bundle.updated_at = datetime.now()
            return True

    def enable_rule(self, bundle_id: str, rule_id: str) -> bool:
        with self.lock:
            if bundle_id not in self.policies:
                return False
            
            bundle = self.policies[bundle_id]
            for rule in bundle.rules:
                if rule.id == rule_id:
                    rule.enabled = True
                    return True
            return False

    def disable_rule(self, bundle_id: str, rule_id: str) -> bool:
        with self.lock:
            if bundle_id not in self.policies:
                return False
            
            bundle = self.policies[bundle_id]
            for rule in bundle.rules:
                if rule.id == rule_id:
                    rule.enabled = False
                    return True
            return False

    def evaluate(
        self,
        resource_type: PolicyResource,
        context: Dict[str, Any]
    ) -> List[PolicyEvaluation]:
        evaluations = []
        
        with self.lock:
            all_rules = []
            
            for bundle in self.policies.values():
                for rule in bundle.rules:
                    if rule.enabled and rule.resource == resource_type:
                        all_rules.append((bundle.id, rule))
            
            all_rules.sort(key=lambda x: x[1].priority, reverse=True)
            
            for bundle_id, rule in all_rules:
                passed = self._evaluate_conditions(rule.conditions, context)
                
                effect = rule.effect if passed else PolicyEffect.ALLOW
                
                evaluation = PolicyEvaluation(
                    policy_id=bundle_id,
                    rule_id=rule.id,
                    effect=effect,
                    resource=context.get("resource", ""),
                    timestamp=datetime.now(),
                    passed=passed,
                    reason=f"Rule {rule.name}: {'matched' if passed else 'not matched'}"
                )
                
                evaluations.append(evaluation)
                self.evaluation_history.append(evaluation)
                
                if len(self.evaluation_history) > 10000:
                    self.evaluation_history = self.evaluation_history[-5000:]
                
                if passed and effect in (PolicyEffect.DENY, PolicyEffect.ALLOW):
                    break
        
        return evaluations

    def _evaluate_conditions(
        self,
        conditions: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> bool:
        if not conditions:
            return True
        
        for condition in conditions:
            if not ConditionEvaluator.evaluate(condition, context):
                return False
        
        return True

    def check_permission(
        self,
        action: str,
        resource: str,
        context: Dict[str, Any]
    ) -> bool:
        resource_type = self._get_resource_type(resource)
        
        context["action"] = action
        context["resource"] = resource
        context["resource_type"] = resource_type.value
        
        evaluations = self.evaluate(resource_type, context)
        
        for eval in evaluations:
            if eval.passed and eval.effect == PolicyEffect.DENY:
                self.logger.warning(f"Access denied: {eval.reason}")
                return False
            
            if eval.passed and eval.effect == PolicyEffect.ALLOW:
                return True
        
        return self.default_effect == PolicyEffect.ALLOW

    def _get_resource_type(self, resource: str) -> PolicyResource:
        resource_lower = resource.lower()
        
        if "user" in resource_lower:
            return PolicyResource.USER
        elif "tool" in resource_lower:
            return PolicyResource.TOOL
        elif "data" in resource_lower:
            return PolicyResource.DATA
        elif "api" in resource_lower:
            return PolicyResource.API
        elif "llm" in resource_lower or "prompt" in resource_lower:
            return PolicyResource.LLM
        elif "session" in resource_lower:
            return PolicyResource.SESSION
        
        return PolicyResource.API

    def get_evaluations(
        self,
        policy_id: Optional[str] = None,
        limit: int = 100
    ) -> List[PolicyEvaluation]:
        with self.lock:
            result = self.evaluation_history
            
            if policy_id:
                result = [e for e in result if e.policy_id == policy_id]
            
            return result[-limit:]

    def get_policy_bundle(self, bundle_id: str) -> Optional[PolicyBundle]:
        return self.policies.get(bundle_id)

    def list_policy_bundles(self) -> List[PolicyBundle]:
        return list(self.policies.values())

    def export_policy(self, bundle_id: str) -> Optional[Dict[str, Any]]:
        bundle = self.policies.get(bundle_id)
        
        if not bundle:
            return None
        
        return {
            "id": bundle.id,
            "name": bundle.name,
            "version": bundle.version,
            "rules": [
                {
                    "id": rule.id,
                    "name": rule.name,
                    "description": rule.description,
                    "effect": rule.effect.value,
                    "resource": rule.resource.value,
                    "conditions": rule.conditions,
                    "actions": rule.actions,
                    "priority": rule.priority,
                    "enabled": rule.enabled,
                    "metadata": rule.metadata
                }
                for rule in bundle.rules
            ],
            "metadata": bundle.metadata,
            "created_at": bundle.created_at.isoformat(),
            "updated_at": bundle.updated_at.isoformat()
        }

    def import_policy(self, policy_data: Dict[str, Any]) -> bool:
        try:
            rules = []
            for rule_data in policy_data.get("rules", []):
                rules.append(PolicyRule(
                    id=rule_data["id"],
                    name=rule_data["name"],
                    description=rule_data.get("description", ""),
                    effect=PolicyEffect(rule_data["effect"]),
                    resource=PolicyResource(rule_data["resource"]),
                    conditions=rule_data.get("conditions", []),
                    actions=rule_data.get("actions", []),
                    priority=rule_data.get("priority", 0),
                    enabled=rule_data.get("enabled", True),
                    metadata=rule_data.get("metadata", {})
                ))
            
            bundle = PolicyBundle(
                id=policy_data["id"],
                name=policy_data["name"],
                version=policy_data.get("version", "1.0.0"),
                rules=rules,
                metadata=policy_data.get("metadata", {})
            )
            
            self.add_policy_bundle(bundle)
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to import policy: {e}")
            return False


class PolicyValidator:
    @staticmethod
    def validate(policy_data: Dict[str, Any]) -> Dict[str, Any]:
        errors = []
        warnings = []
        
        required_fields = ["id", "name", "rules"]
        for field in required_fields:
            if field not in policy_data:
                errors.append(f"Missing required field: {field}")
        
        if "rules" in policy_data:
            for i, rule in enumerate(policy_data["rules"]):
                if "id" not in rule:
                    errors.append(f"Rule {i}: missing id")
                if "name" not in rule:
                    errors.append(f"Rule {i}: missing name")
                if "effect" not in rule:
                    errors.append(f"Rule {i}: missing effect")
                if "resource" not in rule:
                    errors.append(f"Rule {i}: missing resource")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }


class PolicyEnforcer:
    def __init__(self, engine: PolicyEngine):
        self.engine = engine
        self.logger = logging.getLogger(__name__)
        
        self.enforcement_handlers: Dict[PolicyEffect, List[Callable]] = {
            effect: [] for effect in PolicyEffect
        }

    def register_handler(self, effect: PolicyEffect, handler: Callable):
        self.enforcement_handlers[effect].append(handler)

    def enforce(
        self,
        resource_type: PolicyResource,
        context: Dict[str, Any]
    ) -> tuple:
        evaluations = self.engine.evaluate(resource_type, context)
        
        denied = False
        audit_events = []
        
        for eval in evaluations:
            if eval.passed:
                if eval.effect == PolicyEffect.DENY:
                    denied = True
                    self._execute_handlers(PolicyEffect.DENY, eval, context)
                    break
                
                elif eval.effect == PolicyEffect.AUDIT:
                    audit_events.append(eval)
                    self._execute_handlers(PolicyEffect.AUDIT, eval, context)
                
                elif eval.effect == PolicyEffect.ALLOW:
                    break
        
        if audit_events:
            self._execute_handlers(PolicyEffect.AUDIT, audit_events[-1], context)
        
        return denied, audit_events

    def _execute_handlers(self, effect: PolicyEffect, evaluation: PolicyEvaluation, context: Dict[str, Any]):
        for handler in self.enforcement_handlers.get(effect, []):
            try:
                handler(evaluation, context)
            except Exception as e:
                self.logger.error(f"Handler error: {e}")
