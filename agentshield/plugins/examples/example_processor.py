import logging
from typing import Any, Dict, Optional

from ..base import EventHandlerPlugin, PluginMetadata
from ..manager import plugin


logger = logging.getLogger(__name__)


PROCESSOR_METADATA = PluginMetadata(
    name="example_processor",
    version="1.0.0",
    author="AgentShield",
    description="示例事件处理器插件，展示如何处理系统事件",
    events=["request_received", "response_sent", "error_occurred"],
    tags=["processor", "events", "example"]
)


@plugin(PROCESSOR_METADATA)
class ExampleEventProcessor(EventHandlerPlugin):
    def __init__(self, metadata: PluginMetadata):
        super().__init__(metadata)
        self._handlers: Dict[str, callable] = {}
        self._event_count: Dict[str, int] = {}

    def initialize(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().initialize(config)
        
        self._handlers = {
            "request_received": self._handle_request,
            "response_sent": self._handle_response,
            "error_occurred": self._handle_error,
        }
        
        for event in self._subscribed_events:
            self._event_count[event] = 0

    def handle(self, event: str, data: Any) -> Any:
        self._event_count[event] = self._event_count.get(event, 0) + 1
        
        handler = self._handlers.get(event)
        if handler:
            return handler(data)
        
        logger.warning(f"No handler for event: {event}")
        return data

    def _handle_request(self, data: Any) -> Any:
        logger.info(f"Processing request: {data}")
        
        if isinstance(data, dict):
            data["processed_by"] = self.name
            data["processor_version"] = self.version
        
        return data

    def _handle_response(self, data: Any) -> Any:
        logger.info(f"Processing response: {data}")
        
        return data

    def _handle_error(self, data: Any) -> Any:
        logger.error(f"Handling error event: {data}")
        
        if isinstance(data, dict):
            data["error_handled"] = True
            data["handler"] = self.name
        
        return data

    def get_event_count(self, event: str) -> int:
        return self._event_count.get(event, 0)

    def get_all_counts(self) -> Dict[str, int]:
        return self._event_count.copy()


class LoggingProcessor(EventHandlerPlugin):
    def __init__(self):
        metadata = PluginMetadata(
            name="logging_processor",
            version="1.0.0",
            author="AgentShield",
            description="事件日志记录处理器",
            events=["*"],
            tags=["logging", "monitoring"]
        )
        super().__init__(metadata)
        self._log_file: Optional[str] = None

    def initialize(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().initialize(config)
        
        if config:
            self._log_file = config.get("log_file")

    def handle(self, event: str, data: Any) -> Any:
        log_message = f"[{self.name}] Event: {event}, Data: {data}"
        
        if self._log_file:
            try:
                with open(self._log_file, 'a') as f:
                    f.write(log_message + '\n')
            except Exception as e:
                logger.error(f"Failed to write to log file: {e}")
        else:
            logger.info(log_message)
        
        return data


class MetricsProcessor(EventHandlerPlugin):
    def __init__(self):
        metadata = PluginMetadata(
            name="metrics_processor",
            version="1.0.0",
            author="AgentShield",
            description="事件指标收集处理器",
            events=["request_received", "response_sent"],
            tags=["metrics", "monitoring"]
        )
        super().__init__(metadata)
        self._metrics: Dict[str, int] = {}

    def initialize(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().initialize(config)
        
        for event in self._subscribed_events:
            self._metrics[event] = 0

    def handle(self, event: str, data: Any) -> Any:
        self._metrics[event] = self._metrics.get(event, 0) + 1
        return data

    def get_metrics(self) -> Dict[str, int]:
        return self._metrics.copy()

    def reset_metrics(self) -> None:
        for key in self._metrics:
            self._metrics[key] = 0
