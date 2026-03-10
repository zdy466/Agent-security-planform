"""Enhanced LLM Data Firewall with more detection patterns and caching"""

import logging
import re
import hashlib
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
import regex


class DataSensitivity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SensitiveDataMatch:
    category: str
    value: str
    start: int
    end: int
    sensitivity: DataSensitivity


class EnhancedSensitiveDataDetector:
    PATTERNS = {
        "email": {
            "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "sensitivity": DataSensitivity.MEDIUM,
            "category": "PII"
        },
        "china_phone": {
            "pattern": r"1[3-9]\d{9}",
            "sensitivity": DataSensitivity.MEDIUM,
            "category": "PII"
        },
        "us_phone": {
            "pattern": r"\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}",
            "sensitivity": DataSensitivity.MEDIUM,
            "category": "PII"
        },
        "hk_phone": {
            "pattern": r"(?:5|6|8|9)\d{7}",
            "sensitivity": DataSensitivity.MEDIUM,
            "category": "PII"
        },
        "tw_phone": {
            "pattern": r"09\d{8}",
            "sensitivity": DataSensitivity.MEDIUM,
            "category": "PII"
        },
        "api_key_sk": {
            "pattern": r"sk-[a-zA-Z0-9]{20,}",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "SECRET"
        },
        "api_key_generic": {
            "pattern": r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{16,}['\"]?",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "SECRET"
        },
        "bearer_token": {
            "pattern": r"Bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "SECRET"
        },
        "aws_access_key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "SECRET"
        },
        "aws_secret_key": {
            "pattern": r"(?i)aws\s*secret\s*access\s*key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "SECRET"
        },
        "github_token": {
            "pattern": r"ghp_[a-zA-Z0-9]{36}",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "SECRET"
        },
        "slack_token": {
            "pattern": r"xox[baprs]-[0-9a-zA-Z-]+",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "SECRET"
        },
        "private_key": {
            "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "SECRET"
        },
        "id_card_china": {
            "pattern": r"[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "PII"
        },
        "id_card_hk": {
            "pattern": r"[A-Z]\d{6}\([A-Z]\)",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "PII"
        },
        "id_card_tw": {
            "pattern": r"[A-Z]\d{9}",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "PII"
        },
        "passport": {
            "pattern": r"[A-Z]{1,2}\d{6,9}",
            "sensitivity": DataSensitivity.HIGH,
            "category": "PII"
        },
        "bank_card": {
            "pattern": r"\b(?:[0-9]{16,19})\b",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "PII"
        },
        "credit_card": {
            "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "PII"
        },
        "cvv": {
            "pattern": r"(?i)cvv\s*[:=]\s*\d{3,4}",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "PII"
        },
        "amount_cny": {
            "pattern": r"(?:人民币|RMB|￥)\s*\d+(?:\.\d{1,2})?",
            "sensitivity": DataSensitivity.HIGH,
            "category": "FINANCIAL"
        },
        "amount_usd": {
            "pattern": r"\$\s*\d+(?:,\d{3})*(?:\.\d{2})?",
            "sensitivity": DataSensitivity.HIGH,
            "category": "FINANCIAL"
        },
        "amount_eur": {
            "pattern": r"€\s*\d+(?:,\d{3})*(?:\.\d{2})?",
            "sensitivity": DataSensitivity.HIGH,
            "category": "FINANCIAL"
        },
        "bitcoin_address": {
            "pattern": r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
            "sensitivity": DataSensitivity.HIGH,
            "category": "FINANCIAL"
        },
        "ip_address": {
            "pattern": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            "sensitivity": DataSensitivity.LOW,
            "category": "NETWORK"
        },
        "mac_address": {
            "pattern": r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
            "sensitivity": DataSensitivity.LOW,
            "category": "NETWORK"
        },
        "url_with_credentials": {
            "pattern": r"https?://[^:]+:[^@]+@[^/]+",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "SECRET"
        },
        "function_def": {
            "pattern": r"def\s+\w+\s*\(",
            "sensitivity": DataSensitivity.LOW,
            "category": "CODE"
        },
        "class_def": {
            "pattern": r"class\s+\w+",
            "sensitivity": DataSensitivity.LOW,
            "category": "CODE"
        },
        "import_stmt": {
            "pattern": r"(?:import\s+\w+|from\s+\w+\s+import)",
            "sensitivity": DataSensitivity.LOW,
            "category": "CODE"
        },
        "password_in_url": {
            "pattern": r"(?i)(password|pwd|pass)\s*[:=]\s*[^\s&]+",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "SECRET"
        },
        "sql_injection": {
            "pattern": r"(?i)(union\s+select|drop\s+table|delete\s+from|insert\s+into|exec\s*\(|xp_cmdshell)",
            "sensitivity": DataSensitivity.HIGH,
            "category": "ATTACK"
        },
        "xss_pattern": {
            "pattern": r"<script[^>]*>.*?</script>|javascript:|on\w+\s*=",
            "sensitivity": DataSensitivity.HIGH,
            "category": "ATTACK"
        },
        "command_injection": {
            "pattern": r"(?i)(;\s*rm\s+|/bin/sh\s+|&\s*\w+\s*\|\||`.*`)",
            "sensitivity": DataSensitivity.HIGH,
            "category": "ATTACK"
        },
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled_categories = self.config.get("enabled_categories", list(self.PATTERNS.keys()))
        self.min_sensitivity = DataSensitivity(
            self.config.get("min_sensitivity", "low")
        )
        self.custom_patterns = self.config.get("custom_patterns", [])
        self._compile_patterns()

    def _compile_patterns(self):
        self.compiled_patterns = {}
        for pattern_name in self.enabled_categories:
            if pattern_name not in self.PATTERNS:
                continue
            pattern_info = self.PATTERNS[pattern_name]
            try:
                self.compiled_patterns[pattern_name] = {
                    "pattern": re.compile(pattern_info["pattern"], re.IGNORECASE),
                    "sensitivity": pattern_info["sensitivity"],
                    "category": pattern_info["category"]
                }
            except re.error:
                pass

        for custom in self.custom_patterns:
            try:
                self.compiled_patterns[f"custom_{len(self.compiled_patterns)}"] = {
                    "pattern": re.compile(custom["pattern"], re.IGNORECASE),
                    "sensitivity": DataSensitivity(custom.get("sensitivity", "medium")),
                    "category": custom.get("category", "CUSTOM")
                }
            except re.error:
                pass

    @lru_cache(maxsize=1000)
    def detect(self, text: str) -> List[SensitiveDataMatch]:
        matches = []
        for pattern_name, pattern_info in self.compiled_patterns.items():
            try:
                for match in pattern_info["pattern"].finditer(text):
                    sensitivity = pattern_info["sensitivity"]
                    if self._sensitivity_gte(sensitivity, self.min_sensitivity):
                        matches.append(SensitiveDataMatch(
                            category=pattern_info["category"],
                            value=match.group(),
                            start=match.start(),
                            end=match.end(),
                            sensitivity=sensitivity
                        ))
            except Exception:
                pass
        return matches

    def _sensitivity_gte(self, a: DataSensitivity, b: DataSensitivity) -> bool:
        order = [DataSensitivity.LOW, DataSensitivity.MEDIUM, DataSensitivity.HIGH, DataSensitivity.CRITICAL]
        return order.index(a) >= order.index(b)

    def get_sensitivity_level(self, matches: List[SensitiveDataMatch]) -> DataSensitivity:
        if not matches:
            return DataSensitivity.LOW
        levels = [m.sensitivity for m in matches]
        return max(levels)

    def get_category_counts(self, matches: List[SensitiveDataMatch]) -> Dict[str, int]:
        counts = {}
        for match in matches:
            counts[match.category] = counts.get(match.category, 0) + 1
        return counts


class EnhancedDataMinimizer:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.max_length = self.config.get("max_length", 1000)
        self.summary_length = self.config.get("summary_length", 200)
        self.enable_compression = self.config.get("enable_compression", True)

    def summarize_data(self, data: str) -> str:
        if len(data) <= self.max_length:
            return data
        
        sentences = re.split(r'[。！？\n]', data)
        summary_parts = []
        current_length = 0
        
        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence:
                continue
            if current_length + len(sentence) > self.summary_length:
                break
            summary_parts.append(sentence)
            current_length += len(sentence)
        
        return "。".join(summary_parts) + "..."

    def compress_data(self, data: str) -> str:
        if not self.enable_compression:
            return data
        
        import zlib
        try:
            compressed = zlib.compress(data.encode('utf-8'), level=6)
            return f"[COMPRESSED:{len(compressed)} bytes]"
        except:
            return data

    def statistics_data(self, data: str) -> Dict[str, Any]:
        words = data.split()
        return {
            "total_length": len(data),
            "word_count": len(words),
            "line_count": len(data.split('\n')),
            "char_count": len(data),
            "has_sensitive_data": False,
            "compression_available": self.enable_compression
        }


class EnhancedDataBlocker:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.block_critical = self.config.get("block_critical", True)
        self.block_high = self.config.get("block_high", True)
        self.block_medium = self.config.get("block_medium", False)
        self.block_attack_patterns = self.config.get("block_attack_patterns", True)
        self.quarantine_enabled = self.config.get("quarantine_enabled", False)
        self.quarantine_store = []

    def should_block(self, matches: List[SensitiveDataMatch]) -> bool:
        if not matches:
            return False
        
        attack_categories = ["ATTACK", "SECRET"]
        
        for match in matches:
            if match.category in attack_categories and self.block_attack_patterns:
                return True
            
            if match.sensitivity == DataSensitivity.CRITICAL and self.block_critical:
                return True
            if match.sensitivity == DataSensitivity.HIGH and self.block_high:
                return True
            if match.sensitivity == DataSensitivity.MEDIUM and self.block_medium:
                return True
        
        return False

    def get_block_reason(self, matches: List[SensitiveDataMatch]) -> str:
        if not matches:
            return ""
        
        categories = set(m.category for m in matches)
        sensitivities = set(m.sensitivity.name for m in matches)
        
        return f"Detected: {', '.join(categories)}, Sensitivity: {', '.join(sensitivities)}"

    def quarantine(self, data: str, matches: List[SensitiveDataMatch]) -> Dict[str, Any]:
        quarantine_id = hashlib.sha256(data.encode()).hexdigest()[:16]
        record = {
            "id": quarantine_id,
            "data": data,
            "matches": [{"category": m.category, "sensitivity": m.sensitivity.value} for m in matches],
            "timestamp": str(self.config.get("timestamp", "now"))
        }
        self.quarantine_store.append(record)
        return {"quarantine_id": quarantine_id, "stored": True}


class EnhancedFirewallRule:
    def __init__(self, name: str, pattern: str, action: str = "block", case_sensitive: bool = False):
        self.name = name
        self.pattern = regex.compile(pattern, flags=regex.IGNORECASE if not case_sensitive else 0)
        self.action = action
        self.hit_count = 0

    def matches(self, text: str) -> bool:
        result = bool(self.pattern.search(text))
        if result:
            self.hit_count += 1
        return result


class EnhancedLLMDataFirewall:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.enabled = self.config.get("enabled", True)
        
        self.rules: List[EnhancedFirewallRule] = []
        self.detector = EnhancedSensitiveDataDetector(self.config.get("detector", {}))
        self.minimizer = EnhancedDataMinimizer(self.config.get("minimizer", {}))
        self.blocker = EnhancedDataBlocker(self.config.get("blocker", {}))
        
        self.enable_data_minimization = self.config.get("enable_data_minimization", False)
        self.enable_caching = self.config.get("enable_caching", True)
        
        self.statistics = {
            "total_checks": 0,
            "blocked_count": 0,
            "allowed_count": 0,
            "rules_hit": {}
        }
        
        self._load_rules()

    def _load_rules(self):
        default_rules = self.config.get("rules", [])
        for rule_config in default_rules:
            rule = EnhancedFirewallRule(
                name=rule_config.get("name", "unnamed"),
                pattern=rule_config.get("pattern", ""),
                action=rule_config.get("action", "block"),
                case_sensitive=rule_config.get("case_sensitive", False)
            )
            self.rules.append(rule)

    def add_rule(self, name: str, pattern: str, action: str = "block", case_sensitive: bool = False):
        rule = EnhancedFirewallRule(name, pattern, action, case_sensitive)
        self.rules.append(rule)

    def check_input(self, data: str) -> Dict[str, Any]:
        if not self.enabled:
            return {"allowed": True, "reason": "firewall_disabled"}

        self.statistics["total_checks"] += 1
        
        for rule in self.rules:
            if rule.matches(data):
                self.statistics["rules_hit"][rule.name] = self.statistics["rules_hit"].get(rule.name, 0) + 1
                
                if rule.action == "block":
                    self.statistics["blocked_count"] += 1
                    return {"allowed": False, "reason": f"rule_matched: {rule.name}"}
                elif rule.action == "log":
                    self.logger.warning(f"Rule matched: {rule.name}")

        sensitive_matches = self.detector.detect(data)
        
        if sensitive_matches:
            if self.blocker.should_block(sensitive_matches):
                self.statistics["blocked_count"] += 1
                
                if self.blocker.quarantine_enabled:
                    quarantine_result = self.blocker.quarantine(data, sensitive_matches)
                
                return {
                    "allowed": False,
                    "reason": "sensitive_data_detected",
                    "detected_data": [
                        {"category": m.category, "sensitivity": m.sensitivity.value}
                        for m in sensitive_matches
                    ],
                    "block_reason": self.blocker.get_block_reason(sensitive_matches)
                }
            
            if self.enable_data_minimization:
                minimized_data = self.minimizer.summarize_data(data)
                return {
                    "allowed": True,
                    "reason": "data_minimized",
                    "original_length": len(data),
                    "minimized_data": minimized_data,
                    "detected_sensitive": True,
                    "categories": self.detector.get_category_counts(sensitive_matches)
                }

        self.statistics["allowed_count"] += 1
        return {"allowed": True, "reason": "passed"}

    def check_output(self, data: str) -> Dict[str, Any]:
        return self.check_input(data)

    def sanitize(self, data: str) -> str:
        sensitive_matches = self.detector.detect(data)
        if not sensitive_matches:
            return data
        
        result = data
        for match in reversed(sorted(sensitive_matches, key=lambda m: m.position)):
            replacement = f"[{match.category}]"
            result = result[:match.start] + replacement + result[match.end:]
        
        return result

    def get_statistics(self) -> Dict[str, Any]:
        return {
            **self.statistics,
            "cache_enabled": self.enable_caching,
            "rules_count": len(self.rules),
            "block_rate": f"{(self.statistics['blocked_count'] / max(self.statistics['total_checks'], 1) * 100):.2f}%"
        }

    def reset_statistics(self):
        self.statistics = {
            "total_checks": 0,
            "blocked_count": 0,
            "allowed_count": 0,
            "rules_hit": {}
        }
        for rule in self.rules:
            rule.hit_count = 0
