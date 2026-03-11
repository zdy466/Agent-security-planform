"""Rate Limiter Module - IP-based rate limiting for DDoS protection"""

import time
import logging
from typing import Dict, Optional, Any, List
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import threading
import hashlib
import ipaddress


class RateLimitAction(Enum):
    ALLOW = "allow"
    BLOCK = "block"
    THROTTLE = "throttle"
    CHALLENGE = "challenge"


class RateLimitAlgorithm(Enum):
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    LEAKY_BUCKET = "leaky_bucket"


@dataclass
class RateLimitRule:
    name: str
    max_requests: int
    window_seconds: int
    action: RateLimitAction = RateLimitAction.BLOCK
    blocked_duration: int = 300
    priority: int = 0


@dataclass
class RequestRecord:
    timestamp: float
    client_ip: str
    path: str = ""
    user_agent: str = ""
    matched_rule: str = ""


@dataclass
class ClientProfile:
    ip: str
    request_count: int = 0
    blocked: bool = False
    blocked_until: Optional[float] = None
    challenge_passed: bool = False
    first_seen: float = field(default_factory=time.time)
    last_request: float = field(default_factory=time.time)
    total_blocked: int = 0


class TokenBucket:
    def __init__(self, rate: float, capacity: int):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.time()
        self.lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_update = now


class SlidingWindowCounter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: List[float] = []
        self.lock = threading.Lock()

    def is_allowed(self) -> bool:
        with self.lock:
            now = time.time()
            cutoff = now - self.window_seconds
            self.requests = [ts for ts in self.requests if ts > cutoff]
            
            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True
            return False

    def get_remaining(self) -> int:
        with self.lock:
            now = time.time()
            cutoff = now - self.window_seconds
            active = len([ts for ts in self.requests if ts > cutoff])
            return max(0, self.max_requests - active)


class RateLimiter:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.enabled = self.config.get("enabled", True)
        
        self.default_rate = self.config.get("default_rate", 100)
        self.default_window = self.config.get("default_window", 60)
        self.algorithm = RateLimitAlgorithm(
            self.config.get("algorithm", "sliding_window")
        )
        
        self.whitelist = self.config.get("whitelist", [])
        self.blacklist = self.config.get("blacklist", [])
        self.ipv6_support = self.config.get("ipv6_support", True)
        
        self.clients: Dict[str, ClientProfile] = {}
        self.request_history: Dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(self.default_rate, self.default_window)
        )
        self.blocked_ips: Dict[str, float] = {}
        
        self.rules: List[RateLimitRule] = []
        self._load_default_rules()
        
        self.lock = threading.Lock()
        self.cleanup_interval = self.config.get("cleanup_interval", 300)
        self._start_cleanup()

    def _load_default_rules(self):
        self.rules = [
            RateLimitRule(
                name="strict",
                max_requests=10,
                window_seconds=60,
                action=RateLimitAction.BLOCK,
                priority=100
            ),
            RateLimitRule(
                name="moderate",
                max_requests=50,
                window_seconds=60,
                action=RateLimitAction.THROTTLE,
                priority=50
            ),
            RateLimitRule(
                name="default",
                max_requests=self.default_rate,
                window_seconds=self.default_window,
                action=RateLimitAction.ALLOW,
                priority=0
            ),
        ]
        self.rules.sort(key=lambda r: r.priority, reverse=True)

    def check_rate_limit(
        self,
        client_ip: str,
        path: str = "",
        user_agent: str = ""
    ) -> Dict[str, Any]:
        if not self.enabled:
            return {"allowed": True, "action": "allowed"}

        if self._is_whitelisted(client_ip):
            return {"allowed": True, "action": "whitelisted"}

        if self._is_blacklisted(client_ip):
            self._block_ip(client_ip)
            return {
                "allowed": False,
                "action": "blacklisted",
                "message": "IP is blacklisted"
            }

        with self.lock:
            if client_ip in self.blocked_ips:
                if time.time() < self.blocked_ips[client_ip]:
                    return {
                        "allowed": False,
                        "action": "blocked",
                        "blocked_until": self.blocked_ips[client_ip]
                    }
                else:
                    del self.blocked_ips[client_ip]

            rule = self._match_rule(path)
            if rule:
                is_allowed = self.request_history[client_ip].is_allowed()
                if rule.action == RateLimitAction.BLOCK:
                    if not is_allowed:
                        self._block_ip(client_ip, rule.blocked_duration)
                        return {
                            "allowed": False,
                            "action": "blocked",
                            "rule": rule.name,
                            "blocked_duration": rule.blocked_duration
                        }
                elif rule.action == RateLimitAction.THROTTLE:
                    remaining = self.request_history[client_ip].get_remaining()
                    if remaining < rule.max_requests * 0.1:
                        return {
                            "allowed": True,
                            "action": "throttled",
                            "rule": rule.name,
                            "remaining": remaining
                        }
            
            self._update_client_profile(client_ip, path, user_agent)

        return {
            "allowed": True,
            "action": "allowed",
            "remaining": self.request_history[client_ip].get_remaining()
        }

    def _is_whitelisted(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            for entry in self.whitelist:
                if entry.startswith("/"):
                    network = ipaddress.ip_network(entry, strict=False)
                    if ip_obj in network:
                        return True
                elif entry == ip:
                    return True
        except ValueError:
            return ip in self.whitelist
        return False

    def _is_blacklisted(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            for entry in self.blacklist:
                if entry.startswith("/"):
                    network = ipaddress.ip_network(entry, strict=False)
                    if ip_obj in network:
                        return True
                elif entry == ip:
                    return True
        except ValueError:
            return ip in self.blacklist
        return False

    def _match_rule(self, path: str) -> Optional[RateLimitRule]:
        for rule in self.rules:
            if rule.name == "default":
                continue
            if path.startswith(f"/{rule.name}") or rule.name in path:
                return rule
        return self.rules[-1]

    def _block_ip(self, ip: str, duration: int = 300):
        self.blocked_ips[ip] = time.time() + duration
        if ip in self.clients:
            self.clients[ip].blocked = True
            self.clients[ip].blocked_until = time.time() + duration
            self.clients[ip].total_blocked += 1

    def _update_client_profile(
        self, ip: str, path: str, user_agent: str
    ):
        if ip not in self.clients:
            self.clients[ip] = ClientProfile(ip=ip)
        
        profile = self.clients[ip]
        profile.request_count += 1
        profile.last_request = time.time()

    def add_to_blacklist(self, ip: str, duration: Optional[int] = None):
        with self.lock:
            if duration:
                self.blocked_ips[ip] = time.time() + duration
            else:
                if ip not in self.blacklist:
                    self.blacklist.append(ip)

    def remove_from_blacklist(self, ip: str):
        with self.lock:
            if ip in self.blacklist:
                self.blacklist.remove(ip)
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]

    def add_to_whitelist(self, ip_or_network: str):
        if ip_or_network not in self.whitelist:
            self.whitelist.append(ip_or_network)

    def remove_from_whitelist(self, ip_or_network: str):
        if ip_or_network in self.whitelist:
            self.whitelist.remove(ip_or_network)

    def get_client_stats(self, ip: str) -> Optional[Dict[str, Any]]:
        if ip in self.clients:
            profile = self.clients[ip]
            return {
                "ip": profile.ip,
                "request_count": profile.request_count,
                "blocked": profile.blocked,
                "total_blocked": profile.total_blocked,
                "first_seen": profile.first_seen,
                "last_request": profile.last_request,
                "is_whitelisted": self._is_whitelisted(ip),
                "is_blacklisted": self._is_blacklisted(ip)
            }
        return None

    def _start_cleanup(self):
        def cleanup():
            while True:
                time.sleep(self.cleanup_interval)
                self._cleanup_old_entries()

        thread = threading.Thread(target=cleanup, daemon=True)
        thread.start()

    def _cleanup_old_entries(self):
        with self.lock:
            now = time.time()
            cutoff = now - 3600
            
            self.blocked_ips = {
                ip: ts for ip, ts in self.blocked_ips.items() if ts > now
            }
            
            for ip in list(self.request_history.keys()):
                profile = self.clients.get(ip)
                if profile and profile.last_request < cutoff:
                    del self.request_history[ip]
                    if ip in self.clients:
                        del self.clients[ip]


class DistributedRateLimiter:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.rate_limiter = RateLimiter(config)
        self.redis_client = None
        
        redis_config = self.config.get("redis")
        if redis_config:
            try:
                import redis
                self.redis_client = redis.Redis(
                    host=redis_config.get("host", "localhost"),
                    port=redis_config.get("port", 6379),
                    db=redis_config.get("db", 0),
                    decode_responses=True
                )
            except ImportError:
                self.logger.warning("Redis not available, using local storage")

    def check_rate_limit(self, client_ip: str, key: str = "") -> Dict[str, Any]:
        if self.redis_client:
            return self._check_distributed(client_ip, key)
        return self.rate_limiter.check_rate_limit(client_ip)

    def _check_distributed(self, client_ip: str, key: str) -> Dict[str, Any]:
        if not self.redis_client:
            return {"allowed": True}
        
        cache_key = f"ratelimit:{client_ip}:{key}"
        try:
            current = self.redis_client.get(cache_key)
            if current and int(current) >= self.rate_limiter.default_rate:
                return {
                    "allowed": False,
                    "action": "rate_limited",
                    "retry_after": self.rate_limiter.default_window
                }
            
            pipe = self.redis_client.pipeline()
            pipe.incr(cache_key)
            pipe.expire(cache_key, self.rate_limiter.default_window)
            pipe.execute()
            
            return {"allowed": True}
        except Exception as e:
            self.logger.error(f"Redis error: {e}")
            return self.rate_limiter.check_rate_limit(client_ip)
