from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PluginMetadata:
    name: str
    version: str
    author: str
    description: str = ""
    events: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.name:
            raise ValueError("Plugin name cannot be empty")
        if not self.version:
            raise ValueError("Plugin version cannot be empty")


class Plugin(ABC):
    def __init__(self, metadata: PluginMetadata):
        self._metadata = metadata
        self._enabled = False
        self._context: Dict[str, Any] = {}

    @property
    def metadata(self) -> PluginMetadata:
        return self._metadata

    @property
    def name(self) -> str:
        return self._metadata.name

    @property
    def version(self) -> str:
        return self._metadata.version

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def set_context(self, key: str, value: Any) -> None:
        self._context[key] = value

    def get_context(self, key: str, default: Any = None) -> Any:
        return self._context.get(key, default)

    def on_load(self) -> None:
        pass

    def on_unload(self) -> None:
        pass

    def on_enable(self) -> None:
        pass

    def on_disable(self) -> None:
        pass

    @abstractmethod
    def initialize(self, config: Optional[Dict[str, Any]] = None) -> None:
        pass

    @abstractmethod
    def execute(self, *args: Any, **kwargs: Any) -> Any:
        pass


class InputFilterPlugin(Plugin):
    def __init__(self, metadata: PluginMetadata):
        super().__init__(metadata)

    @abstractmethod
    def filter(self, input_data: Any) -> Any:
        pass

    def initialize(self, config: Optional[Dict[str, Any]] = None) -> None:
        pass

    def execute(self, input_data: Any) -> Any:
        return self.filter(input_data)


class EventHandlerPlugin(Plugin):
    def __init__(self, metadata: PluginMetadata):
        super().__init__(metadata)
        self._subscribed_events: List[str] = []

    @property
    def subscribed_events(self) -> List[str]:
        return self._subscribed_events

    @abstractmethod
    def handle(self, event: str, data: Any) -> Any:
        pass

    def initialize(self, config: Optional[Dict[str, Any]] = None) -> None:
        self._subscribed_events = self._metadata.events.copy()

    def execute(self, event: str, data: Any) -> Any:
        return self.handle(event, data)
