"""Alert Escalation Module - Multi-level alert notifications"""

import os
import logging
import threading
import time
import json
import queue
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from abc import ABC, abstractmethod
import hashlib


class AlertSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    CLOSED = "closed"


class NotificationChannel(Enum):
    EMAIL = "email"
    SMS = "sms"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    PAGERDUTY = "pagerduty"
    CUSTOM = "custom"


@dataclass
class AlertRule:
    id: str
    name: str
    condition: Callable[[dict], bool]
    severity: AlertSeverity
    channels: List[NotificationChannel]
    escalation_delay_minutes: int = 15
    escalation_levels: List[AlertSeverity] = field(default_factory=list)
    enabled: bool = True
    description: str = ""


@dataclass
class Alert:
    id: str
    title: str
    description: str
    severity: AlertSeverity
    status: AlertStatus
    source: str
    created_at: datetime
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    assigned_to: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    escalation_level: int = 0
    notifications_sent: int = 0


@dataclass
class EscalationPolicy:
    name: str
    levels: List["EscalationLevel"]
    auto_escalate: bool = True
    escalation_timeout_minutes: int = 15


@dataclass
class EscalationLevel:
    level: int
    severity: AlertSeverity
    notify_channels: List[NotificationChannel]
    assignees: List[str]
    timeout_minutes: int = 15


class BaseNotificationClient(ABC):
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    @abstractmethod
    def send(self, alert: Alert, message: str) -> bool:
        pass
    
    @abstractmethod
    def test_connection(self) -> bool:
        pass


class EmailNotifier(BaseNotificationClient):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.smtp_host = config.get("smtp_host", os.getenv("SMTP_HOST", ""))
        self.smtp_port = config.get("smtp_port", 587)
        self.smtp_user = config.get("smtp_user", os.getenv("SMTP_USER", ""))
        self.smtp_password = config.get("smtp_password", os.getenv("SMTP_PASSWORD", ""))
        self.from_email = config.get("from_email", "alerts@agentshield.io")
        self.to_emails = config.get("to_emails", [])
    
    def test_connection(self) -> bool:
        if not self.smtp_host or not self.to_emails:
            return False
        return True
    
    def send(self, alert: Alert, message: str) -> bool:
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            msg = MIMEMultipart()
            msg["From"] = self.from_email
            msg["To"] = ", ".join(self.to_emails)
            msg["Subject"] = f"[{alert.severity.value.upper()}] {alert.title}"
            
            body = f"""
Alert Details:
- ID: {alert.id}
- Severity: {alert.severity.value}
- Status: {alert.status.value}
- Source: {alert.source}
- Created: {alert.created_at.isoformat()}
- Description: {alert.description}

{message}
"""
            msg.attach(MIMEText(body, "plain"))
            
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                if self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
            
            return True
        
        except Exception as e:
            self.logger.error(f"Email send failed: {e}")
            return False


class SlackNotifier(BaseNotificationClient):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get("webhook_url", os.getenv("SLACK_WEBHOOK_URL", ""))
        self.channel = config.get("channel", "#alerts")
        self.username = config.get("username", "AgentShield Alert")
    
    def test_connection(self) -> bool:
        return bool(self.webhook_url)
    
    def send(self, alert: Alert, message: str) -> bool:
        try:
            import requests
            
            severity_colors = {
                AlertSeverity.LOW: "#36a64f",
                AlertSeverity.MEDIUM: "#ff9900",
                AlertSeverity.HIGH: "#ff6600",
                AlertSeverity.CRITICAL: "#ff0000"
            }
            
            payload = {
                "channel": self.channel,
                "username": self.username,
                "attachments": [{
                    "color": severity_colors.get(alert.severity, "#cccccc"),
                    "title": f"[{alert.severity.value.upper()}] {alert.title}",
                    "text": f"{alert.description}\n\n{message}",
                    "fields": [
                        {"title": "Alert ID", "value": alert.id, "short": True},
                        {"title": "Status", "value": alert.status.value, "short": True},
                        {"title": "Source", "value": alert.source, "short": True},
                        {"title": "Created", "value": alert.created_at.isoformat(), "short": True}
                    ],
                    "footer": "AgentShield OS",
                    "ts": int(alert.created_at.timestamp())
                }]
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code == 200
        
        except Exception as e:
            self.logger.error(f"Slack send failed: {e}")
            return False


class WebhookNotifier(BaseNotificationClient):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get("webhook_url", "")
        self.headers = config.get("headers", {"Content-Type": "application/json"})
        self.auth_header = config.get("auth_header")
    
    def test_connection(self) -> bool:
        return bool(self.webhook_url)
    
    def send(self, alert: Alert, message: str) -> bool:
        try:
            import requests
            
            payload = {
                "alert_id": alert.id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity.value,
                "status": alert.status.value,
                "source": alert.source,
                "created_at": alert.created_at.isoformat(),
                "message": message,
                "metadata": alert.metadata
            }
            
            headers = self.headers.copy()
            if self.auth_header:
                headers["Authorization"] = self.auth_header
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers=headers,
                timeout=30
            )
            
            return response.status_code in (200, 201, 202)
        
        except Exception as e:
            self.logger.error(f"Webhook send failed: {e}")
            return False


class PagerDutyNotifier(BaseNotificationClient):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.api_key = config.get("api_key", os.getenv("PAGERDUTY_API_KEY", ""))
        self.service_id = config.get("service_id", "")
        self.integration_key = config.get("integration_key", os.getenv("PAGERDUTY_INTEGRATION_KEY", ""))
    
    def test_connection(self) -> bool:
        return bool(self.api_key)
    
    def send(self, alert: Alert, message: str) -> bool:
        try:
            import requests
            
            payload = {
                "routing_key": self.integration_key,
                "event_action": "trigger",
                "payload": {
                    "summary": f"[{alert.severity.value.upper()}] {alert.title}",
                    "severity": alert.severity.value,
                    "source": alert.source,
                    "timestamp": alert.created_at.isoformat(),
                    "custom_details": {
                        "alert_id": alert.id,
                        "description": alert.description,
                        "message": message,
                        "metadata": alert.metadata
                    }
                }
            }
            
            headers = {
                "Authorization": f"Token token={self.api_key}",
                "Content-Type": "application/json"
            }
            
            response = requests.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                headers=headers,
                timeout=10
            )
            
            return response.status_code == 202
        
        except Exception as e:
            self.logger.error(f"PagerDuty send failed: {e}")
            return False


class AlertEscalator:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        self.alerts: Dict[str, Alert] = {}
        self.alert_rules: List[AlertRule] = []
        
        self.notification_channels: Dict[NotificationChannel, BaseNotificationClient] = {}
        self._init_notification_channels()
        
        self.escalation_policies: Dict[str, EscalationPolicy] = {}
        self.default_policy = self._create_default_policy()
        
        self.alert_queue: queue.Queue = queue.Queue()
        self.running = False
        self.worker_thread: Optional[threading.Thread] = None
        
        self.handlers: Dict[AlertSeverity, List[Callable]] = {
            severity: [] for severity in AlertSeverity
        }
        
        if self.config.get("auto_start", True):
            self.start()

    def _create_default_policy(self) -> EscalationPolicy:
        return EscalationPolicy(
            name="default",
            levels=[
                EscalationLevel(
                    level=0,
                    severity=AlertSeverity.LOW,
                    notify_channels=[NotificationChannel.EMAIL],
                    assignees=["security-team"],
                    timeout_minutes=60
                ),
                EscalationLevel(
                    level=1,
                    severity=AlertSeverity.MEDIUM,
                    notify_channels=[NotificationChannel.EMAIL, NotificationChannel.SLACK],
                    assignees=["security-team", "oncall"],
                    timeout_minutes=30
                ),
                EscalationLevel(
                    level=2,
                    severity=AlertSeverity.HIGH,
                    notify_channels=[NotificationChannel.EMAIL, NotificationChannel.SLACK, NotificationChannel.PAGERDUTY],
                    assignees=["oncall", "security-manager"],
                    timeout_minutes=15
                ),
                EscalationLevel(
                    level=3,
                    severity=AlertSeverity.CRITICAL,
                    notify_channels=[NotificationChannel.EMAIL, NotificationChannel.SLACK, NotificationChannel.PAGERDUTY, NotificationChannel.SMS],
                    assignees=["security-manager", "cto"],
                    timeout_minutes=5
                ),
            ],
            auto_escalate=True,
            escalation_timeout_minutes=15
        )

    def _init_notification_channels(self):
        channel_configs = self.config.get("channels", {})
        
        if "email" in channel_configs:
            self.notification_channels[NotificationChannel.EMAIL] = EmailNotifier(
                channel_configs["email"]
            )
        
        if "slack" in channel_configs:
            self.notification_channels[NotificationChannel.SLACK] = SlackNotifier(
                channel_configs["slack"]
            )
        
        if "webhook" in channel_configs:
            self.notification_channels[NotificationChannel.WEBHOOK] = WebhookNotifier(
                channel_configs["webhook"]
            )
        
        if "pagerduty" in channel_configs:
            self.notification_channels[NotificationChannel.PAGERDUTY] = PagerDutyNotifier(
                channel_configs["pagerduty"]
            )

    def start(self):
        if self.running:
            return
        
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
        self.logger.info("Alert escalator started")

    def stop(self):
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        self.logger.info("Alert escalator stopped")

    def _worker(self):
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1)
                self._process_alert(alert)
            except queue.Empty:
                self._check_escalations()
            except Exception as e:
                self.logger.error(f"Worker error: {e}")

    def _process_alert(self, alert: Alert):
        self._send_notifications(alert)
        
        for handler in self.handlers.get(alert.severity, []):
            try:
                handler(alert)
            except Exception as e:
                self.logger.error(f"Handler error: {e}")

    def _send_notifications(self, alert: Alert):
        channels = self._get_notification_channels(alert)
        
        message = f"Alert ID: {alert.id}\nStatus: {alert.status.value}"
        
        for channel in channels:
            client = self.notification_channels.get(channel)
            if client:
                try:
                    if client.send(alert, message):
                        alert.notifications_sent += 1
                except Exception as e:
                    self.logger.error(f"Notification failed on {channel}: {e}")

    def _get_notification_channels(self, alert: Alert) -> List[NotificationChannel]:
        policy = self.default_policy
        
        if alert.escalation_level < len(policy.levels):
            return policy.levels[alert.escalation_level].notify_channels
        
        return [NotificationChannel.EMAIL]

    def _check_escalations(self):
        now = datetime.now()
        
        for alert in self.alerts.values():
            if alert.status in (AlertStatus.RESOLVED, AlertStatus.CLOSED):
                continue
            
            policy = self.default_policy
            current_level = alert.escalation_level
            
            if current_level >= len(policy.levels) - 1:
                continue
            
            level_config = policy.levels[current_level]
            timeout = timedelta(minutes=level_config.timeout_minutes)
            
            ack_time = alert.acknowledged_at or alert.created_at
            if now - ack_time > timeout:
                self._escalate_alert(alert)

    def _escalate_alert(self, alert: Alert):
        alert.escalation_level += 1
        alert.status = AlertStatus.ESCALATED
        
        policy = self.default_policy
        if alert.escalation_level < len(policy.levels):
            next_level = policy.levels[alert.escalation_level]
            
            for assignee in next_level.assignees:
                if not alert.assigned_to:
                    alert.assigned_to = assignee
        
        self._send_notifications(alert)
        self.logger.info(f"Escalated alert {alert.id} to level {alert.escalation_level}")

    def create_alert(
        self,
        title: str,
        description: str,
        severity: AlertSeverity,
        source: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Alert:
        alert_id = hashlib.md5(
            f"{title}{source}{time.time()}".encode()
        ).hexdigest()[:12]
        
        alert = Alert(
            id=alert_id,
            title=title,
            description=description,
            severity=severity,
            status=AlertStatus.NEW,
            source=source,
            created_at=datetime.now(),
            metadata=metadata or {}
        )
        
        self.alerts[alert_id] = alert
        self.alert_queue.put(alert)
        
        self.logger.info(f"Created alert: {alert_id} - {title}")
        
        return alert

    def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        if alert_id not in self.alerts:
            return False
        
        alert = self.alerts[alert_id]
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_at = datetime.now()
        alert.assigned_to = user
        
        self.logger.info(f"Acknowledged alert {alert_id} by {user}")
        return True

    def resolve_alert(self, alert_id: str, resolution: str = "") -> bool:
        if alert_id not in self.alerts:
            return False
        
        alert = self.alerts[alert_id]
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = datetime.now()
        alert.metadata["resolution"] = resolution
        
        self.logger.info(f"Resolved alert {alert_id}")
        return True

    def close_alert(self, alert_id: str) -> bool:
        if alert_id not in self.alerts:
            return False
        
        alert = self.alerts[alert_id]
        alert.status = AlertStatus.CLOSED
        
        return True

    def add_rule(self, rule: AlertRule):
        self.alert_rules.append(rule)

    def register_handler(self, severity: AlertSeverity, handler: Callable):
        self.handlers[severity].append(handler)

    def add_notification_channel(
        self,
        channel: NotificationChannel,
        client: BaseNotificationClient
    ):
        self.notification_channels[channel] = client

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        return self.alerts.get(alert_id)

    def get_alerts(
        self,
        status: Optional[AlertStatus] = None,
        severity: Optional[AlertSeverity] = None,
        limit: int = 100
    ) -> List[Alert]:
        result = []
        
        for alert in self.alerts.values():
            if status and alert.status != status:
                continue
            if severity and alert.severity != severity:
                continue
            result.append(alert)
        
        result.sort(key=lambda a: a.created_at, reverse=True)
        return result[:limit]

    def test_notifications(self) -> Dict[str, bool]:
        test_alert = Alert(
            id="test",
            title="Test Alert",
            description="This is a test notification",
            severity=AlertSeverity.INFO,
            status=AlertStatus.NEW,
            source="test",
            created_at=datetime.now()
        )
        
        results = {}
        for channel, client in self.notification_channels.items():
            results[channel.value] = client.send(test_alert, "Test message")
        
        return results
