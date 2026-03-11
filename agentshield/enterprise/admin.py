import asyncio
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


class WebSocketEventType(Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    SECURITY_ALERT = "security_alert"
    AUDIT_EVENT = "audit_event"
    METRICS_UPDATE = "metrics_update"
    POLICY_CHANGED = "policy_changed"
    USER_ACTIVITY = "user_activity"
    SYSTEM_STATUS = "system_status"


@dataclass
class WebSocketMessage:
    event_type: WebSocketEventType
    data: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    message_id: str = field(default_factory=lambda: uuid4().hex)


@dataclass
class DashboardMetrics:
    total_requests: int = 0
    blocked_requests: int = 0
    active_users: int = 0
    active_sessions: int = 0
    avg_response_time: float = 0.0
    error_rate: float = 0.0
    security_score: float = 100.0
    top_threats: List[Dict[str, Any]] = field(default_factory=list)
    recent_alerts: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class SecurityAlert:
    alert_id: str
    severity: str
    title: str
    description: str
    source: str
    timestamp: datetime
    acknowledged: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UserActivity:
    user_id: str
    username: str
    action: str
    resource: str
    ip_address: Optional[str]
    timestamp: datetime = field(default_factory=datetime.now)
    success: bool = True
    details: Optional[Dict[str, Any]] = None


class AdminAPIError(Exception):
    def __init__(self, message: str, code: str = "INTERNAL_ERROR", status_code: int = 500):
        self.message = message
        self.code = code
        self.status_code = status_code
        super().__init__(self.message)


class RequestValidator:
    @staticmethod
    def validate_user_create(data: Dict[str, Any]) -> List[str]:
        errors = []
        if not data.get("username"):
            errors.append("username is required")
        if not data.get("email"):
            errors.append("email is required")
        if not data.get("password"):
            errors.append("password is required")
        if data.get("email") and "@" not in data.get("email", ""):
            errors.append("invalid email format")
        return errors

    @staticmethod
    def validate_policy_create(data: Dict[str, Any]) -> List[str]:
        errors = []
        if not data.get("name"):
            errors.append("name is required")
        if not data.get("rules"):
            errors.append("rules is required")
        return errors

    @staticmethod
    def validate_firewall_rule(data: Dict[str, Any]) -> List[str]:
        errors = []
        if not data.get("name"):
            errors.append("name is required")
        if not data.get("action"):
            errors.append("action is required")
        return errors


class AdminAPIHandler:
    def __init__(self, auth_service=None, security_service=None):
        self.auth_service = auth_service
        self.security_service = security_service
        self._metrics = DashboardMetrics()
        self._alerts: List[SecurityAlert] = []
        self._activities: List[UserActivity] = []

    async def handle_request(
        self,
        endpoint: str,
        method: str,
        data: Optional[Dict[str, Any]],
        user_context: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        handlers = {
            ("GET", "/api/dashboard"): self._get_dashboard,
            ("GET", "/api/alerts"): self._get_alerts,
            ("POST", "/api/alerts/:id/acknowledge"): self._acknowledge_alert,
            ("GET", "/api/users"): self._get_users,
            ("POST", "/api/users"): self._create_user,
            ("PUT", "/api/users/:id"): self._update_user,
            ("DELETE", "/api/users/:id"): self._delete_user,
            ("GET", "/api/policies"): self._get_policies,
            ("POST", "/api/policies"): self._create_policy,
            ("PUT", "/api/policies/:id"): self._update_policy,
            ("DELETE", "/api/policies/:id"): self._delete_policy,
            ("GET", "/api/firewall/rules"): self._get_firewall_rules,
            ("POST", "/api/firewall/rules"): self._create_firewall_rule,
            ("PUT", "/api/firewall/rules/:id"): self._update_firewall_rule,
            ("DELETE", "/api/firewall/rules/:id"): self._delete_firewall_rule,
            ("GET", "/api/audit/logs"): self._get_audit_logs,
            ("GET", "/api/reports"): self._get_reports,
            ("POST", "/api/reports/generate"): self._generate_report,
            ("GET", "/api/system/health"): self._get_system_health,
        }

        key = (method, endpoint)
        handler = handlers.get(key)

        if not handler:
            for (m, e), h in handlers.items():
                if e.replace(":id", "") in endpoint.replace(":id", "") and m == method:
                    handler = h
                    break

        if not handler:
            raise AdminAPIError(f"Endpoint not found: {method} {endpoint}", "NOT_FOUND", 404)

        try:
            return await handler(data or {}, user_context)
        except AdminAPIError:
            raise
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            raise AdminAPIError(str(e), "INTERNAL_ERROR", 500)

    async def _get_dashboard(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return {
            "metrics": {
                "total_requests": self._metrics.total_requests,
                "blocked_requests": self._metrics.blocked_requests,
                "active_users": self._metrics.active_users,
                "active_sessions": self._metrics.active_sessions,
                "avg_response_time": self._metrics.avg_response_time,
                "error_rate": self._metrics.error_rate,
                "security_score": self._metrics.security_score,
            },
            "top_threats": self._metrics.top_threats,
            "recent_alerts": [
                {
                    "alert_id": a.alert_id,
                    "severity": a.severity,
                    "title": a.title,
                    "timestamp": a.timestamp.isoformat(),
                }
                for a in self._metrics.recent_alerts
            ],
        }

    async def _get_alerts(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        severity = data.get("severity")
        acknowledged = data.get("acknowledged")
        limit = data.get("limit", 50)

        alerts = self._alerts
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]

        return {
            "alerts": [
                {
                    "alert_id": a.alert_id,
                    "severity": a.severity,
                    "title": a.title,
                    "description": a.description,
                    "source": a.source,
                    "timestamp": a.timestamp.isoformat(),
                    "acknowledged": a.acknowledged,
                }
                for a in alerts[-limit:]
            ],
            "total": len(alerts),
        }

    async def _acknowledge_alert(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        alert_id = data.get("alert_id")
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                return {"success": True, "alert_id": alert_id}
        raise AdminAPIError("Alert not found", "NOT_FOUND", 404)

    async def _get_users(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        if not self.auth_service:
            return {"users": [], "total": 0}
        users = self.auth_service.get_all_users()
        return {
            "users": [
                {
                    "user_id": u.user_id,
                    "username": u.username,
                    "email": u.email,
                    "role": u.role.value,
                    "is_active": u.is_active,
                    "last_login": u.last_login.isoformat() if u.last_login else None,
                    "created_at": u.created_at.isoformat(),
                }
                for u in users
            ],
            "total": len(users),
        }

    async def _create_user(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        errors = RequestValidator.validate_user_create(data)
        if errors:
            raise AdminAPIError(f"Validation errors: {', '.join(errors)}", "VALIDATION_ERROR", 400)

        if not self.auth_service:
            raise AdminAPIError("Auth service not configured", "NOT_CONFIGURED", 500)

        from .auth import UserRole
        role = UserRole(data.get("role", "viewer"))
        user = self.auth_service.create_user(
            username=data["username"],
            email=data["email"],
            password=data["password"],
            role=role,
        )
        return {
            "success": True,
            "user": {
                "user_id": user.user_id,
                "username": user.username,
                "email": user.email,
                "role": user.role.value,
            },
        }

    async def _update_user(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        user_id = data.get("user_id")
        if not self.auth_service:
            raise AdminAPIError("Auth service not configured", "NOT_CONFIGURED", 500)

        if "role" in data:
            from .auth import UserRole
            self.auth_service.update_user_role(user_id, UserRole(data["role"]))

        return {"success": True, "user_id": user_id}

    async def _delete_user(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        user_id = data.get("user_id")
        if not self.auth_service:
            raise AdminAPIError("Auth service not configured", "NOT_CONFIGURED", 500)

        self.auth_service.deactivate_user(user_id)
        return {"success": True}

    async def _get_policies(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return {"policies": [], "total": 0}

    async def _create_policy(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        errors = RequestValidator.validate_policy_create(data)
        if errors:
            raise AdminAPIError(f"Validation errors: {', '.join(errors)}", "VALIDATION_ERROR", 400)

        policy_id = uuid4().hex
        return {"success": True, "policy_id": policy_id}

    async def _update_policy(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return {"success": True}

    async def _delete_policy(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return {"success": True}

    async def _get_firewall_rules(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return {"rules": [], "total": 0}

    async def _create_firewall_rule(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        errors = RequestValidator.validate_firewall_rule(data)
        if errors:
            raise AdminAPIError(f"Validation errors: {', '.join(errors)}", "VALIDATION_ERROR", 400)

        rule_id = uuid4().hex
        return {"success": True, "rule_id": rule_id}

    async def _update_firewall_rule(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return {"success": True}

    async def _delete_firewall_rule(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return {"success": True}

    async def _get_audit_logs(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return {"logs": [], "total": 0}

    async def _get_reports(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return {"reports": [], "total": 0}

    async def _generate_report(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        report_type = data.get("type", "security")
        report_id = uuid4().hex
        return {
            "success": True,
            "report_id": report_id,
            "status": "generating",
            "type": report_type,
        }

    async def _get_system_health(
        self, data: Dict[str, Any], user_context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        return {
            "status": "healthy",
            "components": {
                "database": "healthy",
                "cache": "healthy",
                "security": "healthy",
            },
            "timestamp": datetime.now().isoformat(),
        }

    def update_metrics(self, metrics: DashboardMetrics) -> None:
        self._metrics = metrics

    def add_alert(self, alert: SecurityAlert) -> None:
        self._alerts.append(alert)

    def add_activity(self, activity: UserActivity) -> None:
        self._activities.append(activity)


class WebSocketManager:
    def __init__(self):
        self._connections: Dict[str, asyncio.Queue] = {}
        self._message_handlers: Dict[WebSocketEventType, List[Callable]] = {}

    async def connect(self, client_id: str) -> asyncio.Queue:
        queue = asyncio.Queue()
        self._connections[client_id] = queue
        return queue

    async def disconnect(self, client_id: str) -> None:
        self._connections.pop(client_id, None)

    async def send_message(self, client_id: str, message: WebSocketMessage) -> None:
        queue = self._connections.get(client_id)
        if queue:
            await queue.put(message)

    async def broadcast(self, message: WebSocketMessage) -> None:
        for client_id in self._connections:
            await self.send_message(client_id, message)

    def register_handler(
        self, event_type: WebSocketEventType, handler: Callable
    ) -> None:
        self._message_handlers.setdefault(event_type, []).append(handler)

    async def handle_message(
        self, client_id: str, message: WebSocketMessage
    ) -> None:
        handlers = self._message_handlers.get(message.event_type, [])
        for handler in handlers:
            await handler(client_id, message)


class AdminServer:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        api_handler: Optional[AdminAPIHandler] = None,
        ws_manager: Optional[WebSocketManager] = None,
    ):
        self.host = host
        self.port = port
        self.api_handler = api_handler or AdminAPIHandler()
        self.ws_manager = ws_manager or WebSocketManager()
        self._running = False
        self._server = None

    async def start(self) -> None:
        self._running = True
        logger.info(f"Admin server starting on {self.host}:{self.port}")

    async def stop(self) -> None:
        self._running = False
        logger.info("Admin server stopped")

    def is_running(self) -> bool:
        return self._running


class AdminDashboard:
    def __init__(self, api_handler: Optional[AdminAPIHandler] = None):
        self.api_handler = api_handler or AdminAPIHandler()
        self.ws_manager = WebSocketManager()

    async def initialize(self) -> None:
        logger.info("Initializing admin dashboard")

    async def get_dashboard_data(self) -> Dict[str, Any]:
        return await self.api_handler.handle_request(
            "GET", "/api/dashboard", {}, None
        )

    async def get_security_status(self) -> Dict[str, Any]:
        return {
            "firewall_status": "active",
            "threat_detection": "enabled",
            "audit_logging": "enabled",
            "encryption": "AES-256",
        }
