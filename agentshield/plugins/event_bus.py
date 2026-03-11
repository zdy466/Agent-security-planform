import asyncio
import logging
from collections import defaultdict
from typing import Any, Awaitable, Callable, Dict, List, Set, Union
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


EventHandler = Union[Callable[[Any], Any], Callable[[Any], Awaitable[Any]]]


@dataclass
class Subscription:
    handler: EventHandler
    priority: int = 0
    once: bool = False


class EventBus:
    def __init__(self, async_mode: bool = False):
        self._subscriptions: Dict[str, List[Subscription]] = defaultdict(list)
        self._global_handlers: List[Subscription] = []
        self._async_mode = async_mode
        self._paused_events: Set[str] = set()

    @property
    def async_mode(self) -> bool:
        return self._async_mode

    def subscribe(
        self,
        event: str,
        handler: EventHandler,
        priority: int = 0,
        once: bool = False
    ) -> None:
        subscription = Subscription(handler=handler, priority=priority, once=once)
        
        if event == "*":
            self._global_handlers.append(subscription)
            self._global_handlers.sort(key=lambda s: s.priority, reverse=True)
        else:
            self._subscriptions[event].append(subscription)
            self._subscriptions[event].sort(key=lambda s: s.priority, reverse=True)
        
        logger.debug(f"Subscribed handler to event: {event}")

    def unsubscribe(self, event: str, handler: EventHandler) -> None:
        if event == "*":
            self._global_handlers = [
                s for s in self._global_handlers if s.handler != handler
            ]
        else:
            if event in self._subscriptions:
                self._subscriptions[event] = [
                    s for s in self._subscriptions[event] if s.handler != handler
                ]
                if not self._subscriptions[event]:
                    del self._subscriptions[event]
        
        logger.debug(f"Unsubscribed handler from event: {event}")

    def publish(self, event: str, data: Any = None) -> List[Any]:
        if event in self._paused_events:
            logger.debug(f"Event '{event}' is paused, skipping")
            return []

        results = []
        
        handlers = self._subscriptions.get(event, []).copy()
        
        for global_handler in self._global_handlers:
            handlers.append(global_handler)
        
        for subscription in handlers:
            try:
                if asyncio.iscoroutinefunction(subscription.handler):
                    if asyncio.get_event_loop().is_running():
                        future = asyncio.create_task(subscription.handler(data))
                        results.append(future)
                    else:
                        result = asyncio.run(subscription.handler(data))
                        results.append(result)
                else:
                    result = subscription.handler(data)
                    results.append(result)

                if subscription.once:
                    self.unsubscribe(event, subscription.handler)

            except Exception as e:
                logger.error(f"Error in event handler for '{event}': {e}")
                results.append(e)

        return results

    async def publish_async(self, event: str, data: Any = None) -> List[Any]:
        if event in self._paused_events:
            logger.debug(f"Event '{event}' is paused, skipping")
            return []

        results = []
        
        handlers = self._subscriptions.get(event, []).copy()
        
        for global_handler in self._global_handlers:
            handlers.append(global_handler)
        
        for subscription in handlers:
            try:
                if asyncio.iscoroutinefunction(subscription.handler):
                    result = await subscription.handler(data)
                else:
                    result = subscription.handler(data)
                
                results.append(result)

                if subscription.once:
                    self.unsubscribe(event, subscription.handler)

            except Exception as e:
                logger.error(f"Error in event handler for '{event}': {e}")
                results.append(e)

        return results

    def clear(self, event: str = None) -> None:
        if event is None:
            self._subscriptions.clear()
            self._global_handlers.clear()
            logger.debug("Cleared all event subscriptions")
        else:
            if event in self._subscriptions:
                del self._subscriptions[event]
            self._global_handlers = [
                s for s in self._global_handlers 
                if s.handler.__name__ != event
            ]
            logger.debug(f"Cleared subscriptions for event: {event}")

    def pause_event(self, event: str) -> None:
        self._paused_events.add(event)
        logger.debug(f"Paused event: {event}")

    def resume_event(self, event: str) -> None:
        self._paused_events.discard(event)
        logger.debug(f"Resumed event: {event}")

    def get_subscribers(self, event: str) -> List[EventHandler]:
        handlers = [s.handler for s in self._subscriptions.get(event, [])]
        handlers.extend([s.handler for s in self._global_handlers])
        return handlers

    def has_subscribers(self, event: str) -> bool:
        return bool(self._subscriptions.get(event) or self._global_handlers)

    def get_event_names(self) -> List[str]:
        return list(self._subscriptions.keys())


class SimpleEventBus(EventBus):
    def __init__(self):
        super().__init__(async_mode=False)
        self._handlers: Dict[str, List[Callable[[Any], Any]]] = defaultdict(list)

    def subscribe(self, event: str, handler: Callable[[Any], Any]) -> None:
        self._handlers[event].append(handler)

    def unsubscribe(self, event: str, handler: Callable[[Any], Any]) -> None:
        if event in self._handlers:
            self._handlers[event].remove(handler)

    def publish(self, event: str, data: Any = None) -> List[Any]:
        results = []
        for handler in self._handlers.get(event, []):
            try:
                result = handler(data)
                results.append(result)
            except Exception as e:
                logger.error(f"Error in handler for '{event}': {e}")
        return results

    def clear(self, event: str = None) -> None:
        if event is None:
            self._handlers.clear()
        else:
            self._handlers.pop(event, None)
