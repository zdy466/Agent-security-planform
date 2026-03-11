import re
from typing import Any, Dict, Optional

from ..base import InputFilterPlugin, PluginMetadata
from ..manager import plugin


FILTER_METADATA = PluginMetadata(
    name="example_filter",
    version="1.0.0",
    author="AgentShield",
    description="示例输入过滤器插件，展示如何过滤和清理用户输入",
    events=["input_filter"],
    tags=["filter", "security", "example"]
)


@plugin(FILTER_METADATA)
class ExampleInputFilter(InputFilterPlugin):
    def __init__(self, metadata: PluginMetadata):
        super().__init__(metadata)
        self._blocked_patterns: list = []
        self._replace_patterns: Dict[str, str] = {}
        self._max_length: int = 10000

    def initialize(self, config: Optional[Dict[str, Any]] = None) -> None:
        if config:
            blocked = config.get("blocked_patterns", [])
            self._blocked_patterns = [re.compile(p) for p in blocked]
            
            replace = config.get("replace_patterns", {})
            self._replace_patterns = {
                re.compile(k): v for k, v in replace.items()
            }
            
            self._max_length = config.get("max_length", 10000)

    def filter(self, input_data: Any) -> Any:
        if not isinstance(input_data, str):
            return input_data

        filtered = input_data

        filtered = self._apply_replace_patterns(filtered)

        filtered = self._check_blocked_patterns(filtered)

        if len(filtered) > self._max_length:
            filtered = filtered[:self._max_length]

        filtered = filtered.strip()

        return filtered

    def _apply_replace_patterns(self, text: str) -> str:
        for pattern, replacement in self._replace_patterns.items():
            text = pattern.sub(replacement, text)
        return text

    def _check_blocked_patterns(self, text: str) -> str:
        for pattern in self._blocked_patterns:
            if pattern.search(text):
                raise ValueError(f"Input contains blocked pattern: {pattern.pattern}")
        return text

    def execute(self, input_data: Any) -> Any:
        return self.filter(input_data)


class SensitiveDataFilter(InputFilterPlugin):
    def __init__(self):
        metadata = PluginMetadata(
            name="sensitive_data_filter",
            version="1.0.0",
            author="AgentShield",
            description="过滤敏感数据，如密码、API密钥等",
            events=["input_filter"],
            tags=["filter", "security", "privacy"]
        )
        super().__init__(metadata)
        self._patterns: Dict[str, re.Pattern] = {}

    def initialize(self, config: Optional[Dict[str, Any]] = None) -> None:
        default_patterns = {
            "password": r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+',
            "api_key": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+',
            "token": r'(?i)(token|auth[_-]?token)\s*[:=]\s*\S+',
            "secret": r'(?i)(secret|private[_-]?key)\s*[:=]\s*\S+',
        }
        
        if config and "patterns" in config:
            self._patterns = {k: re.compile(v) for k, v in config["patterns"].items()}
        else:
            self._patterns = {k: re.compile(v) for k, v in default_patterns.items()}

    def filter(self, input_data: Any) -> Any:
        if not isinstance(input_data, str):
            return input_data

        filtered = input_data
        replacements = []

        for name, pattern in self._patterns.items():
            matches = pattern.finditer(filtered)
            for match in matches:
                replacements.append((match.span(), f"[{name.upper()}_REDACTED]"))

        for span, replacement in sorted(replacements, key=lambda x: x[0][0], reverse=True):
            start, end = span
            filtered = filtered[:start] + replacement + filtered[end:]

        return filtered

    def execute(self, input_data: Any) -> Any:
        return self.filter(input_data)
