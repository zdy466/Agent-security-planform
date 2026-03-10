"""Prompt Injection Firewall - Detects and blocks prompt injection attacks"""

import re
import logging
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum


class InjectionType(Enum):
    DIRECT = "direct"
    INDIRECT = "indirect"
    CONTEXT_OVERRIDE = "context_override"
    ROLE_PLAYING = "role_playing"
    DELIMITER_ESCAPE = "delimiter_escape"
    CODING_INJECTION = "coding_injection"


class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class InjectionMatch:
    injection_type: InjectionType
    threat_level: ThreatLevel
    matched_text: str
    position: int
    description: str
    confidence: float


@dataclass
class InjectionResult:
    detected: bool
    threat_level: ThreatLevel
    matches: List[InjectionMatch] = field(default_factory=list)
    sanitized_text: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)


class InjectionPattern:
    PATTERNS = {
        InjectionType.DIRECT: [
            {
                "pattern": r"(?i)(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|commands?|rules?)|disregard\s+(all\s+)?(your\s+)?(instructions?|rules?))",
                "description": "Direct instruction override attempt",
                "threat": ThreatLevel.HIGH,
                "confidence": 0.9
            },
            {
                "pattern": r"(?i)(forget\s+(everything|all|your)\s+(instructions?|training|guidelines?)|reset\s+(your\s+)?(instructions?|rules?))",
                "description": "Memory reset attempt",
                "threat": ThreatLevel.HIGH,
                "confidence": 0.85
            },
            {
                "pattern": r"(?i)(new\s+instruction(s)?:|system\s*:\s*|you\s+are\s+(now|a|allowed\s+to))",
                "description": "New instruction injection",
                "threat": ThreatLevel.MEDIUM,
                "confidence": 0.7
            },
        ],
        InjectionType.INDIRECT: [
            {
                "pattern": r"(?i)(translate\s+(the\s+)?following|what\s+does\s+the\s+(following|text)\s+say)",
                "description": "Potential indirect injection",
                "threat": ThreatLevel.MEDIUM,
                "confidence": 0.6
            },
            {
                "pattern": r"<[^>]+>|\[SYSTEM\]|\[INST\]|\[AI\]",
                "description": "Special delimiter injection",
                "threat": ThreatLevel.MEDIUM,
                "confidence": 0.75
            },
        ],
        InjectionType.CONTEXT_OVERRIDE: [
            {
                "pattern": r"(?i)(instead|rather than|instead of|forget.*and)",
                "description": "Context override attempt",
                "threat": ThreatLevel.HIGH,
                "confidence": 0.8
            },
            {
                "pattern": r"(?i)(your\s+(real|actual)\s+(task|job|purpose)|your\s+(primary|main)\s+(goal|objective))",
                "description": "Goal override attempt",
                "threat": ThreatLevel.HIGH,
                "confidence": 0.85
            },
        ],
        InjectionType.ROLE_PLAYING: [
            {
                "pattern": r"(?i)(pretend\s+(to\s+be|you\s+are)|act\s+as\s+|play\s+the\s+role\s+of|imagine\s+(you\s+are|being))",
                "description": "Role playing attempt",
                "threat": ThreatLevel.MEDIUM,
                "confidence": 0.7
            },
            {
                "pattern": r"(?i)(jailbreak|bypass\s+(safety|restriction)|unrestricted\s+mode|DAN|developer\s+mode)",
                "description": "Jailbreak attempt",
                "threat": ThreatLevel.CRITICAL,
                "confidence": 0.95
            },
        ],
        InjectionType.DELIMITER_ESCAPE: [
            {
                "pattern": r"```[\s\S]*?```|%%%[\s\S]*?%%%|\*\*\*[\s\S]*?\*\*\*",
                "description": "Delimiter escape attempt",
                "threat": ThreatLevel.MEDIUM,
                "confidence": 0.65
            },
            {
                "pattern": r"(?i)(end\s+(of|your)\s+(instruction|system)\s+prompt|start\s+(of|your)\s+(instruction|system))",
                "description": "Delimiter manipulation",
                "threat": ThreatLevel.HIGH,
                "confidence": 0.8
            },
        ],
        InjectionType.CODING_INJECTION: [
            {
                "pattern": r"(?i)(execute|run|interpret)\s+(this\s+)?(code|script|command)|eval\(|exec\(|subprocess",
                "description": "Code execution attempt",
                "threat": ThreatLevel.CRITICAL,
                "confidence": 0.9
            },
            {
                "pattern": r"(?i)(sql\s+injection|drop\s+table|delete\s+from|union\s+select)",
                "description": "SQL injection pattern",
                "threat": ThreatLevel.HIGH,
                "confidence": 0.85
            },
            {
                "pattern": r"(?i)(import\s+os|import\s+sys|import\s+subprocess|from\s+os\s+import|__import__)",
                "description": "System import attempt",
                "threat": ThreatLevel.HIGH,
                "confidence": 0.8
            },
        ],
    }

    def __init__(self):
        self._compiled_patterns: Dict[InjectionType, List[Dict]] = {}
        self._compile_patterns()

    def _compile_patterns(self):
        for inj_type, patterns in self.PATTERNS.items():
            self._compiled_patterns[inj_type] = []
            for p in patterns:
                compiled = {
                    "pattern": re.compile(p["pattern"], re.IGNORECASE | re.MULTILINE),
                    "description": p["description"],
                    "threat": p["threat"],
                    "confidence": p["confidence"]
                }
                self._compiled_patterns[inj_type].append(compiled)


class PromptInjectionFirewall:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.enabled = self.config.get("enabled", True)
        
        self.pattern_matcher = InjectionPattern()
        
        self.block_threshold = ThreatLevel(
            self.config.get("block_threshold", "medium")
        )
        self.log_only = self.config.get("log_only", False)
        self.auto_sanitize = self.config.get("auto_sanitize", True)
        
        self.whitelist_sources = set(self.config.get("whitelist_sources", []))
        self.custom_patterns = self.config.get("custom_patterns", [])

    def check(self, text: str, source: str = "user_input") -> InjectionResult:
        if not self.enabled:
            return InjectionResult(detected=False, threat_level=ThreatLevel.LOW)
        
        if source in self.whitelist_sources:
            return InjectionResult(detected=False, threat_level=ThreatLevel.LOW)
        
        matches: List[InjectionMatch] = []
        
        for inj_type, patterns in self.pattern_matcher._compiled_patterns.items():
            for p in patterns:
                for match in p["pattern"].finditer(text):
                    matches.append(InjectionMatch(
                        injection_type=inj_type,
                        threat_level=p["threat"],
                        matched_text=match.group(),
                        position=match.start(),
                        description=p["description"],
                        confidence=p["confidence"]
                    ))
        
        for custom in self.custom_patterns:
            pattern = re.compile(custom.get("pattern", ""), re.IGNORECASE)
            threat = ThreatLevel(custom.get("threat", "medium"))
            for match in pattern.finditer(text):
                matches.append(InjectionMatch(
                    injection_type=InjectionType.DIRECT,
                    threat_level=threat,
                    matched_text=match.group(),
                    position=match.start(),
                    description=custom.get("description", "Custom pattern match"),
                    confidence=custom.get("confidence", 0.8)
                ))
        
        if not matches:
            return InjectionResult(detected=False, threat_level=ThreatLevel.LOW)
        
        max_threat = max(m.threat_level for m in matches)
        
        detected = max_threat.value in [h.value for h in ThreatLevel] and \
                   self._threat_gte(max_threat, self.block_threshold)
        
        sanitized = None
        if self.auto_sanitize and detected:
            sanitized = self._sanitize_text(text, matches)
        
        recommendations = self._generate_recommendations(matches)
        
        return InjectionResult(
            detected=detected,
            threat_level=max_threat,
            matches=matches,
            sanitized_text=sanitized,
            recommendations=recommendations
        )

    def check_content(self, content: str, content_type: str = "text") -> InjectionResult:
        if content_type == "url":
            return self._check_url_content(content)
        elif content_type == "file":
            return self._check_file_content(content)
        return self.check(content)

    def _check_url_content(self, url: str) -> InjectionResult:
        result = self.check(url)
        
        if result.detected:
            return result
        
        suspicious_params = ["redirect", "callback", "next", "data", "q", "search"]
        for param in suspicious_params:
            if f"{param}=" in url.lower():
                return InjectionResult(
                    detected=True,
                    threat_level=ThreatLevel.MEDIUM,
                    matches=[],
                    recommendations=["URL contains suspicious parameters that may contain injected content"]
                )
        
        return result

    def _check_file_content(self, content: str) -> InjectionResult:
        malware_indicators = [
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=",
            r"eval\(",
            r"document\.cookie",
            r"window\.location",
        ]
        
        matches = []
        for pattern in malware_indicators:
            compiled = re.compile(pattern, re.IGNORECASE)
            for match in compiled.finditer(content):
                matches.append(InjectionMatch(
                    injection_type=InjectionType.INDIRECT,
                    threat_level=ThreatLevel.HIGH,
                    matched_text=match.group(),
                    position=match.start(),
                    description="Embedded malware indicator",
                    confidence=0.9
                ))
        
        if matches:
            return InjectionResult(
                detected=True,
                threat_level=ThreatLevel.HIGH,
                matches=matches,
                recommendations=["File contains potentially malicious content"]
            )
        
        return self.check(content)

    def _sanitize_text(self, text: str, matches: List[InjectionMatch]) -> str:
        result = text
        for match in reversed(sorted(matches, key=lambda m: m.position)):
            result = result[:match.position] + "[FILTERED]" + result[match.position + len(match.matched_text):]
        return result

    def _generate_recommendations(self, matches: List[InjectionMatch]) -> List[str]:
        recommendations = []
        
        types_found = set(m.injection_type for m in matches)
        
        if InjectionType.DIRECT in types_found:
            recommendations.append("Review input for direct instruction override attempts")
        if InjectionType.ROLE_PLAYING in types_found:
            recommendations.append("Check for jailbreak or role-playing attempts")
        if InjectionType.CODING_INJECTION in types_found:
            recommendations.append("Block code execution patterns")
        if InjectionType.DELIMITER_ESCAPE in types_found:
            recommendations.append("Review delimiter usage")
        
        return recommendations

    def _threat_gte(self, a: ThreatLevel, b: ThreatLevel) -> bool:
        order = [ThreatLevel.LOW, ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        return order.index(a) >= order.index(b)

    def add_custom_pattern(self, pattern: str, description: str, threat: str = "medium", confidence: float = 0.8):
        self.custom_patterns.append({
            "pattern": pattern,
            "description": description,
            "threat": threat,
            "confidence": confidence
        })

    def add_whitelist_source(self, source: str):
        self.whitelist_sources.add(source)

    def get_attack_statistics(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
": self.block_threshold            "block_threshold.value,
            "whitelist_sources": list(self.whitelist_sources),
            "custom_patterns_count": len(self.custom_patterns)
        }
