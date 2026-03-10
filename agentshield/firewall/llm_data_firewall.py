"""LLM Data Firewall - Filters and validates LLM input/output data"""

import logging
import regex
import re
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum


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


class SensitiveDataDetector:
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
        "id_card_china": {
            "pattern": r"[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]",
            "sensitivity": DataSensitivity.CRITICAL,
            "category": "PII"
        },
        "bank_card": {
            "pattern": r"\b(?:[0-9]{16,19})\b",
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
        }
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled_categories = self.config.get("enabled_categories", list(self.PATTERNS.keys()))
        self.min_sensitivity = DataSensitivity(
            self.config.get("min_sensitivity", "low")
        )

    def detect(self, text: str) -> List[SensitiveDataMatch]:
        matches = []
        for pattern_name in self.enabled_categories:
            if pattern_name not in self.PATTERNS:
                continue
            pattern_info = self.PATTERNS[pattern_name]
            pattern = re.compile(pattern_info["pattern"], re.IGNORECASE)
            
            for match in pattern.finditer(text):
                sensitivity = pattern_info["sensitivity"]
                if self._sensitivity_gte(sensitivity, self.min_sensitivity):
                    matches.append(SensitiveDataMatch(
                        category=pattern_info["category"],
                        value=match.group(),
                        start=match.start(),
                        end=match.end(),
                        sensitivity=sensitivity
                    ))
        return matches

    def _sensitivity_gte(self, a: DataSensitivity, b: DataSensitivity) -> bool:
        order = [DataSensitivity.LOW, DataSensitivity.MEDIUM, DataSensitivity.HIGH, DataSensitivity.CRITICAL]
        return order.index(a) >= order.index(b)

    def get_sensitivity_level(self, matches: List[SensitiveDataMatch]) -> DataSensitivity:
        if not matches:
            return DataSensitivity.LOW
        levels = [m.sensitivity for m in matches]
        return max(levels)


class DataMinimizer:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.max_length = self.config.get("max_length", 1000)
        self.summary_length = self.config.get("summary_length", 200)

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

    def statistics_data(self, data: str) -> Dict[str, Any]:
        return {
            "total_length": len(data),
            "word_count": len(data.split()),
            "line_count": len(data.split('\n')),
            "has_sensitive_data": False
        }


class DataBlocker:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.block_critical = self.config.get("block_critical", True)
        self.block_high = self.config.get("block_high", True)
        self.block_medium = self.config.get("block_medium", False)

    def should_block(self, matches: List[SensitiveDataMatch]) -> bool:
        if not matches:
            return False
        
        for match in matches:
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


class FirewallRule:
    def __init__(self, name: str, pattern: str, action: str = "block"):
        self.name = name
        self.pattern = regex.compile(pattern)
        self.action = action

    def matches(self, text: str) -> bool:
        return bool(self.pattern.search(text))


class LLMDataFirewall:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.enabled = self.config.get("enabled", True)
        
        self.rules: List[FirewallRule] = []
        self.detector = SensitiveDataDetector(self.config.get("detector", {}))
        self.minimizer = DataMinimizer(self.config.get("minimizer", {}))
        self.blocker = DataBlocker(self.config.get("blocker", {}))
        
        self.enable_data_minimization = self.config.get("enable_data_minimization", False)
        self._load_rules()

    def _load_rules(self):
        default_rules = self.config.get("rules", [])
        for rule_config in default_rules:
            rule = FirewallRule(
                name=rule_config.get("name", "unnamed"),
                pattern=rule_config.get("pattern", ""),
                action=rule_config.get("action", "block")
            )
            self.rules.append(rule)

    def add_rule(self, name: str, pattern: str, action: str = "block"):
        rule = FirewallRule(name, pattern, action)
        self.rules.append(rule)

    def check_input(self, data: str) -> Dict[str, Any]:
        if not self.enabled:
            return {"allowed": True, "reason": "firewall_disabled"}

        for rule in self.rules:
            if rule.matches(data):
                if rule.action == "block":
                    return {"allowed": False, "reason": f"rule_matched: {rule.name}"}
                elif rule.action == "log":
                    self.logger.warning(f"Rule matched: {rule.name}")

        sensitive_matches = self.detector.detect(data)
        if sensitive_matches:
            if self.blocker.should_block(sensitive_matches):
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
                    "detected_sensitive": True
                }

        return {"allowed": True, "reason": "passed"}

    def check_output(self, data: str) -> Dict[str, Any]:
        return self.check_input(data)

    def sanitize(self, data: str) -> str:
        sensitive_matches = self.detector.detect(data)
        if not sensitive_matches:
            return data
        
        result = data
        for match in reversed(sensitive_matches):
            replacement = f"[{match.category}]"
            result = result[:match.start] + replacement + result[match.end:]
        
        return result
