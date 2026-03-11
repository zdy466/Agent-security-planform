import asyncio
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import aiohttp
import asyncio


class AlertLevel(Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class Alert:
    title: str
    message: str
    level: AlertLevel = AlertLevel.INFO
    source: str = "AgentShield"
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


class AlertNotifier(ABC):
    @abstractmethod
    async def send(self, alert: Alert) -> bool:
        pass

    @abstractmethod
    async def send_batch(self, alerts: List[Alert]) -> bool:
        pass


class SlackNotifier(AlertNotifier):
    def __init__(self, webhook_url: str, channel: Optional[str] = None, username: str = "AgentShield"):
        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username

    def _format_level_color(self, level: AlertLevel) -> str:
        colors = {
            AlertLevel.INFO: "#36a64f",
            AlertLevel.WARNING: "#ff9800",
            AlertLevel.ERROR: "#f44336",
            AlertLevel.CRITICAL: "#9c27b0"
        }
        return colors.get(level, "#36a64f")

    def _format_slack_message(self, alert: Alert) -> Dict[str, Any]:
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔔 {alert.title}",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Level:*\n{alert.level.value.upper()}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Source:*\n{alert.source}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Time:*\n{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": alert.message
                }
            }
        ]

        if alert.metadata:
            fields = []
            for key, value in alert.metadata.items():
                fields.append({
                    "type": "mrkdwn",
                    "text": f"*{key}:*\n{value}"
                })
            if fields:
                blocks.append({
                    "type": "section",
                    "fields": fields[:10]
                })

        if alert.tags:
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Tags: {', '.join(alert.tags)}"
                    }
                ]
            })

        payload = {
            "username": self.username,
            "blocks": blocks
        }

        if self.channel:
            payload["channel"] = self.channel

        return payload

    async def send(self, alert: Alert) -> bool:
        payload = self._format_slack_message(alert)
        return await self._send_webhook(payload)

    async def send_batch(self, alerts: List[Alert]) -> bool:
        for alert in alerts:
            await self.send(alert)
        return True

    async def _send_webhook(self, payload: Dict[str, Any]) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    return response.status == 200
        except Exception:
            return False


class DingTalkNotifier(AlertNotifier):
    def __init__(self, webhook_url: str, secret: Optional[str] = None):
        self.webhook_url = webhook_url
        self.secret = secret
        self._sign_cache: Dict[str, float] = {}

    def _get_sign(self) -> Optional[str]:
        if not self.secret:
            return None

        import hmac
        import hashlib
        import base64
        import time

        timestamp = str(round(time.time() * 1000))
        sign_str = f"{timestamp}\n{self.secret}"
        sign = hmac.new(
            self.secret.encode('utf-8'),
            sign_str.encode('utf-8'),
            hashlib.sha256
        ).digest()
        sign = base64.b64encode(sign).decode('utf-8')
        return f"{timestamp},{sign}"

    def _format_dingtalk_message(self, alert: Alert) -> Dict[str, Any]:
        level_colors = {
            AlertLevel.INFO: "green",
            AlertLevel.WARNING: "orange",
            AlertLevel.ERROR: "red",
            AlertLevel.CRITICAL: "red"
        }

        message = {
            "msgtype": "markdown",
            "markdown": {
                "title": alert.title,
                "text": f"### {alert.title}\n\n" +
                       f"**级别**: {alert.level.value.upper()}\n\n" +
                       f"**来源**: {alert.source}\n\n" +
                       f"**时间**: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n\n" +
                       f"{alert.message}\n\n" +
                       (f"**标签**: {', '.join(alert.tags)}" if alert.tags else "")
            },
            "at": {
                "isAtAll": False
            }
        }

        return message

    async def send(self, alert: Alert) -> bool:
        message = self._format_dingtalk_message(alert)
        return await self._send_webhook(message)

    async def send_batch(self, alerts: List[Alert]) -> bool:
        for alert in alerts:
            await self.send(alert)
        return True

    async def _send_webhook(self, message: Dict[str, Any]) -> bool:
        try:
            url = self.webhook_url
            sign = self._get_sign()
            if sign:
                url = f"{self.webhook_url}&sign={sign}"

            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=message) as response:
                    result = await response.json()
                    return result.get("errcode", 1) == 0
        except Exception:
            return False


class WebhookNotifier(AlertNotifier):
    def __init__(self, webhook_url: str, method: str = "POST", headers: Optional[Dict[str, str]] = None):
        self.webhook_url = webhook_url
        self.method = method.upper()
        self.headers = headers or {"Content-Type": "application/json"}

    def _format_message(self, alert: Alert) -> Dict[str, Any]:
        return {
            "title": alert.title,
            "message": alert.message,
            "level": alert.level.value,
            "source": alert.source,
            "timestamp": alert.timestamp.isoformat(),
            "metadata": alert.metadata,
            "tags": alert.tags
        }

    async def send(self, alert: Alert) -> bool:
        payload = self._format_message(alert)
        return await self._send_request(payload)

    async def send_batch(self, alerts: List[Alert]) -> bool:
        payload = [self._format_message(alert) for alert in alerts]
        return await self._send_request(payload)

    async def _send_request(self, payload: Any) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    self.method,
                    self.webhook_url,
                    json=payload,
                    headers=self.headers
                ) as response:
                    return 200 <= response.status < 300
        except Exception:
            return False


class AlertManager:
    def __init__(self):
        self._notifiers: Dict[str, AlertNotifier] = {}
        self._alert_history: List[Alert] = []
        self._enabled = True

    def register_notifier(self, name: str, notifier: AlertNotifier):
        self._notifiers[name] = notifier

    def unregister_notifier(self, name: str) -> bool:
        return self._notifiers.pop(name, None) is not None

    def get_notifier(self, name: str) -> Optional[AlertNotifier]:
        return self._notifiers.get(name)

    async def send_alert(
        self,
        title: str,
        message: str,
        level: AlertLevel = AlertLevel.INFO,
        source: str = "AgentShield",
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        notifiers: Optional[List[str]] = None
    ) -> Dict[str, bool]:
        if not self._enabled:
            return {}

        alert = Alert(
            title=title,
            message=message,
            level=level,
            source=source,
            metadata=metadata or {},
            tags=tags or []
        )

        self._alert_history.append(alert)

        results = {}
        target_notifiers = notifiers or list(self._notifiers.keys())

        tasks = []
        for name in target_notifiers:
            notifier = self._notifiers.get(name)
            if notifier:
                tasks.append(self._send_to_notifier(name, notifier, alert))

        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        for i, name in enumerate(target_notifiers):
            results[name] = not isinstance(results_list[i], Exception) and results_list[i]

        return results

    async def _send_to_notifier(self, name: str, notifier: AlertNotifier, alert: Alert) -> bool:
        try:
            return await notifier.send(alert)
        except Exception:
            return False

    def get_alert_history(
        self,
        level: Optional[AlertLevel] = None,
        limit: int = 100
    ) -> List[Alert]:
        alerts = self._alert_history
        if level:
            alerts = [a for a in alerts if a.level == level]
        return alerts[-limit:]

    def clear_history(self):
        self._alert_history.clear()

    def enable(self):
        self._enabled = True

    def disable(self):
        self._enabled = False


def create_slack_notifier(webhook_url: str, channel: Optional[str] = None) -> SlackNotifier:
    return SlackNotifier(webhook_url, channel)


def create_dingtalk_notifier(webhook_url: str, secret: Optional[str] = None) -> DingTalkNotifier:
    return DingTalkNotifier(webhook_url, secret)


def create_webhook_notifier(webhook_url: str, method: str = "POST", headers: Optional[Dict[str, str]] = None) -> WebhookNotifier:
    return WebhookNotifier(webhook_url, method, headers)
