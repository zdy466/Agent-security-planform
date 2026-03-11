import importlib
import importlib.util
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from .base import Plugin, PluginMetadata
from .manager import PluginManager, PluginError

logger = logging.getLogger(__name__)


class PluginLoadError(PluginError):
    pass


class PluginLoader:
    def __init__(self, manager: PluginManager):
        self._manager = manager
        self._loaded_modules: Dict[str, Any] = {}
        self._plugin_paths: List[Path] = []

    def add_search_path(self, path: str) -> None:
        path_obj = Path(path)
        if path_obj.exists() and path_obj.is_dir():
            self._plugin_paths.append(path_obj)
            logger.info(f"Added plugin search path: {path}")
        else:
            logger.warning(f"Plugin search path does not exist: {path}")

    def discover_plugins(self) -> List[Type[Plugin]]:
        discovered: List[Type[Plugin]] = []
        
        for path in self._plugin_paths:
            discovered.extend(self._discover_in_directory(path))
        
        return discovered

    def _discover_in_directory(self, directory: Path) -> List[Type[Plugin]]:
        plugins: List[Type[Plugin]] = []
        
        if not directory.exists():
            return plugins

        for item in directory.iterdir():
            if item.is_file() and item.suffix == '.py' and not item.name.startswith('_'):
                try:
                    module = self._load_module_from_file(item)
                    found = self._extract_plugins_from_module(module)
                    plugins.extend(found)
                except Exception as e:
                    logger.warning(f"Failed to load plugin from {item}: {e}")
            
            elif item.is_dir() and (item / '__init__.py').exists():
                try:
                    module = self._load_module_from_directory(item)
                    found = self._extract_plugins_from_module(module)
                    plugins.extend(found)
                except Exception as e:
                    logger.warning(f"Failed to load plugin from {item}: {e}")
        
        return plugins

    def _load_module_from_file(self, file_path: Path) -> Any:
        module_name = file_path.stem
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            raise PluginLoadError(f"Cannot load spec for {file_path}")
        
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        
        self._loaded_modules[module_name] = module
        return module

    def _load_module_from_directory(self, dir_path: Path) -> Any:
        module_name = dir_path.name
        module = importlib.import_module(module_name)
        self._loaded_modules[module_name] = module
        return module

    def _extract_plugins_from_module(self, module: Any) -> List[Type[Plugin]]:
        plugins: List[Type[Plugin]] = []
        
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (isinstance(attr, type) 
                and issubclass(attr, Plugin) 
                and attr is not Plugin
                and hasattr(attr, '__plugin_metadata__')):
                plugins.append(attr)
        
        return plugins

    def load_plugin(self, plugin_class: Type[Plugin], config: Optional[Dict[str, Any]] = None) -> Plugin:
        return self._manager.register(plugin_class, config)

    def load_directory(self, directory: str, auto_enable: bool = True) -> List[Plugin]:
        path = Path(directory)
        if not path.exists():
            raise PluginLoadError(f"Directory does not exist: {directory}")
        
        self.add_search_path(directory)
        
        discovered = self._discover_in_directory(path)
        loaded_plugins: List[Plugin] = []
        
        for plugin_class in discovered:
            try:
                plugin = self.load_plugin(plugin_class)
                if auto_enable:
                    self._manager.enable(plugin.name)
                loaded_plugins.append(plugin)
                logger.info(f"Loaded plugin: {plugin.name}")
            except Exception as e:
                logger.error(f"Failed to load plugin {plugin_class.__name__}: {e}")
        
        return loaded_plugins

    def load_from_entry_point(self, entry_point: str) -> Plugin:
        parts = entry_point.split(':')
        if len(parts) != 2:
            raise PluginLoadError(f"Invalid entry point format: {entry_point}")
        
        module_path, class_name = parts
        
        try:
            module = importlib.import_module(module_path)
            plugin_class = getattr(module, class_name)
            
            if not (isinstance(plugin_class, type) and issubclass(plugin_class, Plugin)):
                raise PluginLoadError(f"{class_name} is not a Plugin subclass")
            
            return self.load_plugin(plugin_class)
        except ImportError as e:
            raise PluginLoadError(f"Failed to import module {module_path}: {e}")
        except AttributeError:
            raise PluginLoadError(f"Class {class_name} not found in module {module_path}")

    def reload_plugin(self, name: str) -> Plugin:
        plugin = self._manager.get_plugin(name)
        if plugin is None:
            raise PluginNotFoundError(f"Plugin '{name}' not found")
        
        metadata = plugin.metadata
        
        if plugin.is_enabled:
            self._manager.disable(name)
        
        self._manager.unregister(name)
        
        plugin_class = self._plugin_classes.get(name)
        if plugin_class is None:
            raise PluginLoadError(f"Cannot reload: plugin class for '{name}' not found")
        
        new_plugin = self.load_plugin(plugin_class)
        if metadata.events:
            self._manager.enable(name)
        
        return new_plugin

    @property
    def loaded_modules(self) -> Dict[str, Any]:
        return self._loaded_modules.copy()


class PluginNotFoundError(PluginError):
    pass
