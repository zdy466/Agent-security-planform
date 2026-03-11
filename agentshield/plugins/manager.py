from typing import Any, Dict, List, Optional, Set, Type
import logging

from .base import Plugin, PluginMetadata
from .event_bus import EventBus


logger = logging.getLogger(__name__)


class PluginError(Exception):
    pass


class PluginNotFoundError(PluginError):
    pass


class PluginDependencyError(PluginError):
    pass


class PluginAlreadyExistsError(PluginError):
    pass


class PluginManager:
    def __init__(self, event_bus: Optional[EventBus] = None):
        self._plugins: Dict[str, Plugin] = {}
        self._enabled_plugins: Set[str] = set()
        self._plugin_classes: Dict[str, Type[Plugin]] = {}
        self._event_bus = event_bus
        self._dependencies: Dict[str, Set[str]] = {}

    @property
    def event_bus(self) -> Optional[EventBus]:
        return self._event_bus

    @event_bus.setter
    def event_bus(self, bus: EventBus) -> None:
        self._event_bus = bus

    def register(self, plugin_class: Type[Plugin], config: Optional[Dict[str, Any]] = None) -> Plugin:
        metadata = plugin_class.__dict__.get('__plugin_metadata__')
        if not metadata:
            raise PluginError(f"Plugin class {plugin_class.__name__} missing metadata")
        
        name = metadata.name
        if name in self._plugins:
            raise PluginAlreadyExistsError(f"Plugin '{name}' already registered")

        self._plugin_classes[name] = plugin_class
        
        if metadata.dependencies:
            self._dependencies[name] = set(metadata.dependencies)

        plugin = plugin_class(metadata)
        
        try:
            plugin.on_load()
            plugin.initialize(config)
        except Exception as e:
            raise PluginError(f"Failed to initialize plugin '{name}': {e}")

        self._plugins[name] = plugin
        logger.info(f"Plugin '{name}' v{metadata.version} registered successfully")
        
        return plugin

    def unregister(self, name: str) -> None:
        plugin = self.get_plugin(name)
        if plugin is None:
            raise PluginNotFoundError(f"Plugin '{name}' not found")

        if plugin.is_enabled:
            self.disable(name)

        try:
            plugin.on_unload()
        except Exception as e:
            logger.warning(f"Error unloading plugin '{name}': {e}")

        del self._plugins[name]
        self._plugin_classes.pop(name, None)
        self._dependencies.pop(name, None)

        for deps in self._dependencies.values():
            deps.discard(name)

        logger.info(f"Plugin '{name}' unregistered")

    def enable(self, name: str) -> None:
        plugin = self.get_plugin(name)
        if plugin is None:
            raise PluginNotFoundError(f"Plugin '{name}' not found")

        if plugin.is_enabled:
            return

        unresolved = self._check_dependencies(name)
        if unresolved:
            raise PluginDependencyError(f"Plugin '{name}' has unresolved dependencies: {unresolved}")

        for dep_name in self._dependencies.get(name, set()):
            dep_plugin = self.get_plugin(dep_name)
            if dep_plugin and not dep_plugin.is_enabled:
                self.enable(dep_name)

        try:
            plugin.on_enable()
            plugin._enabled = True
            self._enabled_plugins.add(name)

            if self._event_bus:
                for event in plugin.metadata.events:
                    self._event_bus.subscribe(event, plugin)

            logger.info(f"Plugin '{name}' enabled")
        except Exception as e:
            raise PluginError(f"Failed to enable plugin '{name}': {e}")

    def disable(self, name: str) -> None:
        plugin = self.get_plugin(name)
        if plugin is None:
            raise PluginNotFoundError(f"Plugin '{name}' not found")

        if not plugin.is_enabled:
            return

        for plugin_name, deps in self._dependencies.items():
            if name in deps:
                raise PluginDependencyError(
                    f"Cannot disable plugin '{name}': required by '{plugin_name}'"
                )

        try:
            if self._event_bus:
                for event in plugin.metadata.events:
                    self._event_bus.unsubscribe(event, plugin)

            plugin.on_disable()
            plugin._enabled = False
            self._enabled_plugins.discard(name)

            logger.info(f"Plugin '{name}' disabled")
        except Exception as e:
            raise PluginError(f"Failed to disable plugin '{name}': {e}")

    def get_plugin(self, name: str) -> Optional[Plugin]:
        return self._plugins.get(name)

    def list_plugins(self, include_disabled: bool = False) -> List[Plugin]:
        plugins = list(self._plugins.values())
        if not include_disabled:
            plugins = [p for p in plugins if p.is_enabled]
        return plugins

    def get_plugin_metadata(self, name: str) -> Optional[PluginMetadata]:
        plugin = self.get_plugin(name)
        return plugin.metadata if plugin else None

    def _check_dependencies(self, name: str) -> Set[str]:
        visited: Set[str] = set()
        unresolved: Set[str] = set()
        
        def check(plugin_name: str):
            if plugin_name in visited:
                return
            visited.add(plugin_name)
            
            for dep in self._dependencies.get(plugin_name, set()):
                if dep not in self._plugins:
                    unresolved.add(dep)
                else:
                    check(dep)
        
        check(name)
        return unresolved

    def is_enabled(self, name: str) -> bool:
        return name in self._enabled_plugins


def plugin(metadata: PluginMetadata):
    def decorator(cls: Type[Plugin]) -> Type[Plugin]:
        cls.__plugin_metadata__ = metadata
        return cls
    return decorator
