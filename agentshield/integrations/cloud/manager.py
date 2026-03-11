"""Cloud service manager for AgentShield OS"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

from .base import CloudProvider, CloudAdapter, CloudConfig, CloudResource, CloudDataResult


@dataclass
class CloudConnection:
    """Cloud connection metadata"""
    adapter: CloudAdapter
    connected_at: datetime = field(default_factory=datetime.now)
    last_used: datetime = field(default_factory=datetime.now)
    operations_count: int = 0


class CloudManager:
    """Manager for multiple cloud provider connections"""

    def __init__(self):
        self._adapters: Dict[CloudProvider, CloudConnection] = {}
        self._default_provider: Optional[CloudProvider] = None

    def register_adapter(
        self,
        provider: CloudProvider,
        adapter: CloudAdapter,
        set_default: bool = False
    ) -> None:
        """Register a cloud adapter"""
        self._adapters[provider] = CloudConnection(adapter=adapter)
        if set_default or not self._default_provider:
            self._default_provider = provider

    def unregister_adapter(self, provider: CloudProvider) -> bool:
        """Unregister a cloud adapter"""
        if provider in self._adapters:
            adapter = self._adapters[provider].adapter
            if adapter.connected:
                adapter.disconnect()
            del self._adapters[provider]
            if self._default_provider == provider:
                self._default_provider = list(self._adapters.keys())[0] if self._adapters else None
            return True
        return False

    def get_adapter(self, provider: Optional[CloudProvider] = None) -> Optional[CloudAdapter]:
        """Get cloud adapter by provider"""
        target = provider or self._default_provider
        if target and target in self._adapters:
            conn = self._adapters[target]
            conn.last_used = datetime.now()
            return conn.adapter
        return None

    def list_providers(self) -> List[CloudProvider]:
        """List all registered providers"""
        return list(self._adapters.keys())

    def connect(self, provider: CloudProvider) -> bool:
        """Connect to a cloud provider"""
        if provider in self._adapters:
            adapter = self._adapters[provider].adapter
            return adapter.connect()
        return False

    def disconnect(self, provider: CloudProvider) -> bool:
        """Disconnect from a cloud provider"""
        if provider in self._adapters:
            adapter = self._adapters[provider].adapter
            adapter.disconnect()
            return True
        return False

    def check_connection(self, provider: Optional[CloudProvider] = None) -> bool:
        """Check if connection is alive"""
        adapter = self.get_adapter(provider)
        if adapter:
            return adapter.check_connection()
        return False

    def read_data(
        self,
        bucket: str,
        key: str,
        provider: Optional[CloudProvider] = None
    ) -> Optional[CloudDataResult]:
        """Read data from cloud storage"""
        adapter = self.get_adapter(provider)
        if adapter and adapter.connected:
            self._adapters[adapter.provider].operations_count += 1
            return adapter.read_data(bucket, key)
        return None

    def write_data(
        self,
        bucket: str,
        key: str,
        data: Any,
        provider: Optional[CloudProvider] = None,
        metadata: Optional[Dict] = None
    ) -> Optional[CloudDataResult]:
        """Write data to cloud storage"""
        adapter = self.get_adapter(provider)
        if adapter and adapter.connected:
            self._adapters[adapter.provider].operations_count += 1
            return adapter.write_data(bucket, key, data, metadata)
        return None

    def delete_data(
        self,
        bucket: str,
        key: str,
        provider: Optional[CloudProvider] = None
    ) -> Optional[CloudDataResult]:
        """Delete data from cloud storage"""
        adapter = self.get_adapter(provider)
        if adapter and adapter.connected:
            self._adapters[adapter.provider].operations_count += 1
            return adapter.delete_data(bucket, key)
        return None

    def list_buckets(
        self,
        provider: Optional[CloudProvider] = None
    ) -> List[CloudResource]:
        """List storage buckets"""
        adapter = self.get_adapter(provider)
        if adapter and adapter.connected:
            return adapter.list_buckets()
        return []

    def get_stats(self) -> Dict[str, Any]:
        """Get cloud manager statistics"""
        return {
            "total_providers": len(self._adapters),
            "default_provider": self._default_provider.value if self._default_provider else None,
            "providers": {
                provider.value: {
                    "connected": conn.adapter.connected,
                    "operations": conn.operations_count,
                    "last_used": conn.last_used.isoformat()
                }
                for provider, conn in self._adapters.items()
            }
        }
