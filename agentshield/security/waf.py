"""Web Application Firewall (WAF) - HTTP request filtering"""

import re
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import html
import json
import threading
from collections import defaultdict


class WAFAction(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    LOG = "log"
    CHALLENGE = "challenge"
    REDIRECT = "redirect"


class ThreatLevel(Enum):
    SAFE = 0
    LOW = 1
    MEDIUM = 5
    HIGH = 8
    CRITICAL = 10


class AttackType(Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    LDAP_INJECTION = "ldap_injection"
    XML_INJECTION = "xml_injection"
    XXE = "xxe"
    SSRF = "ssrf"
    RATE_LIMIT = "rate_limit"
    BOT_DETECTION = "bot_detection"
    DPI = "dpi"


@dataclass
class WAFRule:
    id: str
    name: str
    pattern: str
    attack_type: AttackType
    action: WAFAction = WAFAction.BLOCK
    severity: ThreatLevel = ThreatLevel.MEDIUM
    enabled: bool = True
    score: int = 5
    description: str = ""


@dataclass
class WAFMatch:
    rule_id: str
    rule_name: str
    attack_type: AttackType
    threat_level: ThreatLevel
    matched_value: str
    location: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class WAFRequest:
    method: str
    path: str
    headers: Dict[str, str]
    body: Optional[str]
    query_params: Dict[str, str]
    client_ip: str
    user_agent: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class WAFResponse:
    action: WAFAction
    status_code: int = 200
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    matches: List[WAFMatch] = field(default_factory=list)
    threat_level: ThreatLevel = ThreatLevel.SAFE
    score: int = 0


class AttackPattern:
    SQL_INJECTION = [
        r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|update\s+.*\s+set)",
        r"(?i)(exec\s*\(|execute\s*\(|eval\s*\(|system\s*\()",
        r"(\b(or|and)\b\s+\d+\s*=\s*\d+|'\s*(or|and)\s*'|'\s*=\s*')",
        r"(--|\#|\/\*|\*\/)",
        r"(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",
        r"(0x[0-9a-f]+|char\s*\()",
    ]
    
    XSS = [
        r"<script[^>]*>.*?</script>",
        r"javascript\s*:",
        r"on\w+\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
        r"eval\s*\(",
        r"expression\s*\(",
    ]
    
    COMMAND_INJECTION = [
        r"[;&|`$]",
        r"\b(cat|ls|dir|echo|type|rm|mv|cp|chmod|wget|curl|nc|bash|sh)\b",
        r"(\||&)\s*\w+",
        r"\$\([^)]+\)",
        r"`[^`]+`",
    ]
    
    PATH_TRAVERSAL = [
        r"\.\.[\/\\]",
        r"(\.\.%2[fF]|%2[eE])",
        r"(/etc/passwd|/etc/shadow|/windows/system32)",
    ]
    
    SSRF = [
        r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)",
        r"(?i)(metadata\.amazonaws\.com|metadata\.google)",
        r"(?i)(file://|gopher://|dict://)",
    ]
    
    LDAP_INJECTION = [
        r"(\*\)|\(\||\(&|\)\()",
        r"(\*\x00)",
    ]
    
    XXE = [
        r"<!DOCTYPE[^>]*\[",
        r"<!ENTITY",
        r"SYSTEM\s+['\"]",
    ]


class WebApplicationFirewall:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.enabled = self.config.get("enabled", True)
        
        self.default_action = WAFAction(
            self.config.get("default_action", "block")
        )
        self.blocked_status_code = self.config.get("blocked_status_code", 403)
        self.max_score = self.config.get("max_score", 10)
        
        self.rules: List[WAFRule] = []
        self._load_default_rules()
        
        self.whitelist_paths = self.config.get("whitelist_paths", [])
        self.blacklist_ips = self.config.get("blacklist_ips", [])
        
        self.request_log: List[WAFRequest] = []
        self.match_log: List[WAFMatch] = []
        self.blocked_log: List[Dict[str, Any]] = []
        
        self.lock = threading.RLock()
        
        self.callbacks: Dict[WAFAction, List[Callable]] = {
            action: [] for action in WAFAction
        }
        
        self.stats = {
            "total_requests": 0,
            "blocked_requests": 0,
            "threat_scores": defaultdict(int),
            "attack_types": defaultdict(int),
        }

    def _load_default_rules(self):
        self.rules = []
        
        for pattern in AttackPattern.SQL_INJECTION:
            self.rules.append(WAFRule(
                id=f"sql_{len(self.rules)}",
                name="SQL Injection",
                pattern=pattern,
                attack_type=AttackType.SQL_INJECTION,
                severity=ThreatLevel.HIGH,
                score=8,
                description="Detects SQL injection attempts"
            ))
        
        for pattern in AttackPattern.XSS:
            self.rules.append(WAFRule(
                id=f"xss_{len(self.rules)}",
                name="XSS Attack",
                pattern=pattern,
                attack_type=AttackType.XSS,
                severity=ThreatLevel.HIGH,
                score=7,
                description="Detects cross-site scripting attempts"
            ))
        
        for pattern in AttackPattern.COMMAND_INJECTION:
            self.rules.append(WAFRule(
                id=f"cmd_{len(self.rules)}",
                name="Command Injection",
                pattern=pattern,
                attack_type=AttackType.COMMAND_INJECTION,
                severity=ThreatLevel.CRITICAL,
                score=10,
                description="Detects command injection attempts"
            ))
        
        for pattern in AttackPattern.PATH_TRAVERSAL:
            self.rules.append(WAFRule(
                id=f"path_{len(self.rules)}",
                name="Path Traversal",
                pattern=pattern,
                attack_type=AttackType.PATH_TRAVERSAL,
                severity=ThreatLevel.HIGH,
                score=8,
                description="Detects path traversal attempts"
            ))
        
        for pattern in AttackPattern.SSRF:
            self.rules.append(WAFRule(
                id=f"ssrf_{len(self.rules)}",
                name="SSRF",
                pattern=pattern,
                attack_type=AttackType.SSRF,
                severity=ThreatLevel.HIGH,
                score=8,
                description="Detects server-side request forgery"
            ))
        
        for pattern in AttackPattern.XXE:
            self.rules.append(WAFRule(
                id=f"xxe_{len(self.rules)}",
                name="XXE",
                pattern=pattern,
                attack_type=AttackType.XXE,
                severity=ThreatLevel.CRITICAL,
                score=10,
                description="Detects XML external entity attacks"
            ))

    def inspect_request(self, request: WAFRequest) -> WAFResponse:
        if not self.enabled:
            return WAFResponse(action=WAFAction.ALLOW)
        
        with self.lock:
            self.stats["total_requests"] += 1
            
            if self._is_whitelisted(request.path):
                return WAFResponse(action=WAFAction.ALLOW)
            
            if request.client_ip in self.blacklist_ips:
                self._log_blocked(request, [], ThreatLevel.CRITICAL)
                return WAFResponse(
                    action=WAFAction.BLOCK,
                    status_code=self.blocked_status_code,
                    body="IP blocked"
                )
            
            matches = self._check_all_rules(request)
            score = sum(m.threat_level.value for m in matches)
            threat_level = self._calculate_threat_level(score)
            
            if score >= self.max_score:
                action = WAFAction.BLOCK
                self.stats["blocked_requests"] += 1
            elif score > 0:
                action = WAFAction.LOG
            else:
                action = WAFAction.ALLOW
            
            for match in matches:
                self.match_log.append(match)
                self.stats["threat_scores"][match.threat_level.value] += 1
                self.stats["attack_types"][match.attack_type.value] += 1
            
            if action == WAFAction.BLOCK:
                self._log_blocked(request, matches, threat_level)
            
            response = WAFResponse(
                action=action,
                status_code=self.blocked_status_code if action == WAFAction.BLOCK else 200,
                matches=matches,
                threat_level=threat_level,
                score=score
            )
            
            if action == WAFAction.BLOCK:
                response.body = self._generate_block_message(threat_level)
            
            return response

    def _is_whitelisted(self, path: str) -> bool:
        for pattern in self.whitelist_paths:
            if re.match(pattern, path):
                return True
        return False

    def _check_all_rules(self, request: WAFRequest) -> List[WAFMatch]:
        matches = []
        
        sources = [
            request.path,
            request.query_params.get("", ""),
            request.body or "",
        ]
        
        sources.extend(request.headers.values())
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            try:
                pattern = re.compile(rule.pattern, re.IGNORECASE)
            except re.error:
                continue
            
            for source in sources:
                if not source:
                    continue
                    
                match = pattern.search(str(source))
                if match:
                    matches.append(WAFMatch(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        attack_type=rule.attack_type,
                        threat_level=rule.severity,
                        matched_value=self._sanitize_value(match.group(0)),
                        location="body" if source == request.body else "path"
                    ))
        
        return matches

    def _calculate_threat_level(self, score: int) -> ThreatLevel:
        if score == 0:
            return ThreatLevel.SAFE
        elif score < 5:
            return ThreatLevel.LOW
        elif score < 10:
            return ThreatLevel.MEDIUM
        elif score < 20:
            return ThreatLevel.HIGH
        else:
            return ThreatLevel.CRITICAL

    def _sanitize_value(self, value: str) -> str:
        return html.escape(value[:100])

    def _log_blocked(
        self,
        request: WAFRequest,
        matches: List[WAFMatch],
        threat_level: ThreatLevel
    ):
        self.blocked_log.append({
            "timestamp": datetime.now().isoformat(),
            "client_ip": request.client_ip,
            "path": request.path,
            "method": request.method,
            "threat_level": threat_level.value,
            "matches": [
                {
                    "rule": m.rule_name,
                    "attack_type": m.attack_type.value,
                    "matched": m.matched_value
                }
                for m in matches
            ]
        })

    def _generate_block_message(self, threat_level: ThreatLevel) -> str:
        return json.dumps({
            "error": "Request blocked by WAF",
            "threat_level": threat_level.value,
            "message": "Suspicious activity detected"
        })

    def add_rule(self, rule: WAFRule):
        with self.lock:
            self.rules.append(rule)

    def remove_rule(self, rule_id: str):
        with self.lock:
            self.rules = [r for r in self.rules if r.id != rule_id]

    def enable_rule(self, rule_id: str):
        with self.lock:
            for rule in self.rules:
                if rule.id == rule_id:
                    rule.enabled = True

    def disable_rule(self, rule_id: str):
        with self.lock:
            for rule in self.rules:
                if rule.id == rule_id:
                    rule.enabled = False

    def add_to_blacklist(self, ip: str):
        if ip not in self.blacklist_ips:
            self.blacklist_ips.append(ip)

    def remove_from_blacklist(self, ip: str):
        if ip in self.blacklist_ips:
            self.blacklist_ips.remove(ip)

    def add_whitelist_path(self, path_pattern: str):
        if path_pattern not in self.whitelist_paths:
            self.whitelist_paths.append(path_pattern)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_requests": self.stats["total_requests"],
            "blocked_requests": self.stats["blocked_requests"],
            "block_rate": self.stats["blocked_requests"] / max(self.stats["total_requests"], 1),
            "threat_scores": dict(self.stats["threat_scores"]),
            "attack_types": dict(self.stats["attack_types"]),
            "active_rules": len([r for r in self.rules if r.enabled]),
        }

    def register_callback(self, action: WAFAction, callback: Callable):
        with self.lock:
            self.callbacks[action].append(callback)

    def process_callbacks(self, response: WAFResponse):
        for callback in self.callbacks.get(response.action, []):
            try:
                callback(response)
            except Exception as e:
                self.logger.error(f"Callback error: {e}")


class WAFMiddleware:
    def __init__(self, waf: WebApplicationFirewall):
        self.waf = waf

    def __call__(self, request: Dict[str, Any]) -> Dict[str, Any]:
        waf_request = WAFRequest(
            method=request.get("method", "GET"),
            path=request.get("path", "/"),
            headers=request.get("headers", {}),
            body=request.get("body"),
            query_params=request.get("query_params", {}),
            client_ip=request.get("client_ip", "0.0.0.0"),
            user_agent=request.get("user_agent", "")
        )
        
        response = self.waf.inspect_request(waf_request)
        
        if response.action == WAFAction.BLOCK:
            return {
                "status": response.status_code,
                "body": response.body,
                "headers": {"Content-Type": "application/json"},
                "blocked": True
            }
        
        return {"blocked": False, "request": request}
