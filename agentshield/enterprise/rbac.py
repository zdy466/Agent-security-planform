from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
from uuid import uuid4


class ResourceType(Enum):
    SECURITY_LOG = "security_log"
    AUDIT_LOG = "audit_log"
    POLICY = "policy"
    USER = "user"
    CONFIG = "config"
    FIREWALL_RULE = "firewall_rule"
    REPORT = "report"
    DASHBOARD = "dashboard"
    SIMULATION = "simulation"
    ALERT = "alert"


class Action(Enum):
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    EXPORT = "export"
    IMPORT = "import"


RESOURCE_ACTIONS: Dict[ResourceType, Set[Action]] = {
    ResourceType.SECURITY_LOG: {Action.READ, Action.EXPORT},
    ResourceType.AUDIT_LOG: {Action.READ, Action.EXPORT},
    ResourceType.POLICY: {Action.CREATE, Action.READ, Action.UPDATE, Action.DELETE},
    ResourceType.USER: {Action.CREATE, Action.READ, Action.UPDATE, Action.DELETE},
    ResourceType.CONFIG: {Action.READ, Action.UPDATE},
    ResourceType.FIREWALL_RULE: {
        Action.CREATE,
        Action.READ,
        Action.UPDATE,
        Action.DELETE,
    },
    ResourceType.REPORT: {Action.CREATE, Action.READ, Action.EXPORT},
    ResourceType.DASHBOARD: {Action.READ},
    ResourceType.SIMULATION: {Action.CREATE, Action.READ, Action.EXECUTE},
    ResourceType.ALERT: {Action.READ, Action.UPDATE},
}


@dataclass
class Resource:
    resource_id: str
    resource_type: ResourceType
    owner_id: str
    name: str
    description: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class PermissionGrant:
    grant_id: str
    principal_id: str
    principal_type: str
    resource_type: ResourceType
    resource_id: Optional[str]
    actions: Set[Action]
    granted_at: datetime = field(default_factory=datetime.now)
    granted_by: Optional[str] = None
    expires_at: Optional[datetime] = None
    conditions: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyRule:
    rule_id: str
    name: str
    description: Optional[str]
    principal_pattern: str
    resource_pattern: str
    actions: Set[Action]
    effect: bool
    priority: int = 0
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


class AccessDecision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    NO_MATCH = "no_match"


@dataclass
class AccessRequest:
    principal_id: str
    principal_type: str
    action: Action
    resource: Resource
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AccessResponse:
    decision: AccessDecision
    reason: Optional[str] = None
    obligations: List[Dict[str, Any]] = field(default_factory=list)


class PermissionStore:
    def __init__(self):
        self._grants: Dict[str, PermissionGrant] = {}
        self._principal_grants: Dict[str, List[str]] = {}
        self._resource_grants: Dict[str, List[str]] = {}

    def add_grant(self, grant: PermissionGrant) -> None:
        self._grants[grant.grant_id] = grant
        self._principal_grants.setdefault(grant.principal_id, []).append(
            grant.grant_id
        )
        if grant.resource_id:
            self._resource_grants.setdefault(grant.resource_id, []).append(
                grant.grant_id
            )

    def get_grants_for_principal(self, principal_id: str) -> List[PermissionGrant]:
        grant_ids = self._principal_grants.get(principal_id, [])
        return [self._grants[gid] for gid in grant_ids if gid in self._grants]

    def get_grants_for_resource(self, resource_id: str) -> List[PermissionGrant]:
        grant_ids = self._resource_grants.get(resource_id, [])
        return [self._grants[gid] for gid in grant_ids if gid in self._grants]

    def revoke_grant(self, grant_id: str) -> bool:
        grant = self._grants.pop(grant_id, None)
        if grant:
            if grant.principal_id in self._principal_grants:
                self._principal_grants[grant.principal_id].remove(grant_id)
            if grant.resource_id and grant.resource_id in self._resource_grants:
                self._resource_grants[grant.resource_id].remove(grant_id)
            return True
        return False

    def revoke_all_principal_grants(self, principal_id: str) -> int:
        grant_ids = self._principal_grants.get(principal_id, [])
        count = 0
        for gid in grant_ids:
            if self.revoke_grant(gid):
                count += 1
        return count


class RBACEngine:
    def __init__(self):
        self._policies: Dict[str, PolicyRule] = {}
        self.permission_store = PermissionStore()
        self._default_deny = True

    def add_policy(self, policy: PolicyRule) -> None:
        self._policies[policy.rule_id] = policy

    def remove_policy(self, rule_id: str) -> bool:
        return self._policies.pop(rule_id, None) is not None

    def get_policy(self, rule_id: str) -> Optional[PolicyRule]:
        return self._policies.get(rule_id)

    def list_policies(self) -> List[PolicyRule]:
        return sorted(self._policies.values(), key=lambda p: p.priority)

    def _match_pattern(
        self, pattern: str, value: str, context: Dict[str, Any]
    ) -> bool:
        if pattern == "*":
            return True
        if pattern == value:
            return True
        if pattern.startswith("role:"):
            return value == pattern[5:]
        if pattern.startswith("attr:"):
            attr_name = pattern[5:]
            return context.get(attr_name) == value
        return False

    def check_permission(
        self,
        principal_id: str,
        principal_type: str,
        action: Action,
        resource: Resource,
        context: Optional[Dict[str, Any]] = None,
    ) -> AccessResponse:
        context = context or {}

        for policy in self.list_policies():
            if not policy.enabled:
                continue

            if not self._match_pattern(
                policy.principal_pattern, principal_id, context
            ):
                continue

            if not self._match_pattern(
                policy.resource_pattern, resource.resource_type.value, context
            ):
                continue

            if action not in policy.actions:
                continue

            return AccessResponse(
                decision=AccessDecision.ALLOW if policy.effect else AccessDecision.DENY,
                reason=f"Matched policy: {policy.name}",
            )

        grants = self.permission_store.get_grants_for_principal(principal_id)
        now = datetime.now()

        for grant in grants:
            if grant.expires_at and grant.expires_at < now:
                continue

            if grant.resource_type != resource.resource_type:
                continue

            if grant.resource_id and grant.resource_id != resource.resource_id:
                continue

            if action not in grant.actions:
                continue

            return AccessResponse(
                decision=AccessDecision.ALLOW,
                reason=f"Matched grant: {grant.grant_id}",
            )

        if self._default_deny:
            return AccessResponse(
                decision=AccessDecision.DENY,
                reason="No matching policy or grant found",
            )

        return AccessResponse(decision=AccessDecision.NO_MATCH)

    def grant_permission(
        self,
        principal_id: str,
        principal_type: str,
        resource_type: ResourceType,
        resource_id: Optional[str],
        actions: Set[Action],
        granted_by: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> PermissionGrant:
        grant = PermissionGrant(
            grant_id=uuid4().hex,
            principal_id=principal_id,
            principal_type=principal_type,
            resource_type=resource_type,
            resource_id=resource_id,
            actions=actions,
            granted_by=granted_by,
            expires_at=expires_at,
        )
        self.permission_store.add_grant(grant)
        return grant

    def revoke_permission(self, grant_id: str) -> bool:
        return self.permission_store.revoke_grant(grant_id)

    def set_default_deny(self, deny: bool) -> None:
        self._default_deny = deny


class ResourceValidator:
    @staticmethod
    def validate_resource(resource: Resource) -> List[str]:
        errors = []
        if not resource.name:
            errors.append("Resource name is required")
        if not resource.owner_id:
            errors.append("Resource owner is required")
        if not resource.resource_type:
            errors.append("Resource type is required")
        return errors

    @staticmethod
    def can_access_resource(
        user_role: str, resource: Resource, action: Action
    ) -> bool:
        role_permissions = {
            "admin": {Action.CREATE, Action.READ, Action.UPDATE, Action.DELETE, Action.EXECUTE, Action.EXPORT, Action.IMPORT},
            "security_analyst": {Action.READ, Action.UPDATE, Action.EXECUTE},
            "auditor": {Action.READ, Action.EXPORT},
            "operator": {Action.READ, Action.CREATE, Action.UPDATE},
            "viewer": {Action.READ},
        }
        allowed_actions = role_permissions.get(user_role, set())
        return action in allowed_actions


class AuditLogger:
    def __init__(self):
        self._audit_log: List[Dict[str, Any]] = []

    def log_access(
        self,
        principal_id: str,
        resource: Resource,
        action: Action,
        decision: AccessDecision,
        reason: Optional[str] = None,
    ) -> None:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "principal_id": principal_id,
            "resource_id": resource.resource_id,
            "resource_type": resource.resource_type.value,
            "action": action.value,
            "decision": decision.value,
            "reason": reason,
        }
        self._audit_log.append(entry)

    def get_logs(
        self,
        principal_id: Optional[str] = None,
        resource_type: Optional[ResourceType] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        logs = self._audit_log
        if principal_id:
            logs = [l for l in logs if l.get("principal_id") == principal_id]
        if resource_type:
            logs = [l for l in logs if l.get("resource_type") == resource_type.value]
        return logs[-limit:]
