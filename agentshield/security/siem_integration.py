"""SIEM Integration Module - Splunk/ELK log forwarding"""

import os
import json
import logging
import threading
import queue
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from abc import ABC, abstractmethod
import hashlib


class SIEMProvider(Enum):
    SPLUNK = "splunk"
    ELASTICSEARCH = "elasticsearch"
    AWS_CLOUDWATCH = "aws_cloudwatch"
    AZURE_SENTINEL = "azure_sentinel"
    SUMO_LOGIC = "sumo_logic"


class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class LogEvent:
    timestamp: datetime
    level: LogLevel
    source: str
    category: str
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_data: Optional[str] = None


@dataclass
class SIEMConfig:
    provider: SIEMProvider
    endpoint: str
    api_key: Optional[str] = None
    index: str = "security"
    source_type: str = "agentshield"
    batch_size: int = 100
    flush_interval: int = 10
    retry_count: int = 3
    ssl_verify: bool = True


class BaseSIEMClient(ABC):
    def __init__(self, config: SIEMConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    @abstractmethod
    def send(self, events: List[LogEvent]) -> bool:
        pass
    
    @abstractmethod
    def test_connection(self) -> bool:
        pass


class SplunkClient(BaseSIEMClient):
    def __init__(self, config: SIEMConfig):
        super().__init__(config)
        self.session = None
    
    def _get_session(self):
        if self.session is None:
            try:
                import requests
                self.session = requests.Session()
                self.session.headers.update({
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json"
                })
            except ImportError:
                self.logger.warning("Requests library not available")
        return self.session
    
    def test_connection(self) -> bool:
        try:
            session = self._get_session()
            if not session:
                return False
            
            url = f"{self.config.endpoint}/services/server/info"
            response = session.get(url, verify=self.config.ssl_verify, timeout=10)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Splunk connection test failed: {e}")
            return False
    
    def send(self, events: List[LogEvent]) -> bool:
        try:
            session = self._get_session()
            if not session:
                return False
            
            url = f"{self.config.endpoint}/services/collector"
            
            for event in events:
                payload = {
                    "time": event.timestamp.timestamp(),
                    "host": os.environ.get("HOSTNAME", "localhost"),
                    "source": event.source,
                    "sourcetype": self.config.source_type,
                    "index": self.config.index,
                    "event": self._format_event(event)
                }
                
                response = session.post(
                    url,
                    json=payload,
                    verify=self.config.ssl_verify,
                    timeout=30
                )
                
                if response.status_code not in (200, 201):
                    self.logger.warning(f"Failed to send event: {response.text}")
            
            return True
        
        except Exception as e:
            self.logger.error(f"Splunk send failed: {e}")
            return False
    
    def _format_event(self, event: LogEvent) -> Dict[str, Any]:
        return {
            "timestamp": event.timestamp.isoformat(),
            "level": event.level.value,
            "category": event.category,
            "message": event.message,
            "metadata": event.metadata
        }


class ElasticsearchClient(BaseSIEMClient):
    def __init__(self, config: SIEMConfig):
        super().__init__(config)
        self.client = None
    
    def _get_client(self):
        if self.client is None:
            try:
                from elasticsearch import Elasticsearch
                self.client = Elasticsearch(
                    [self.config.endpoint],
                    api_key=self.config.api_key,
                    verify_certs=self.config.ssl_verify
                )
            except ImportError:
                self.logger.warning("Elasticsearch client not available")
        return self.client
    
    def test_connection(self) -> bool:
        try:
            client = self._get_client()
            if not client:
                return False
            return client.ping()
        except Exception as e:
            self.logger.error(f"Elasticsearch connection test failed: {e}")
            return False
    
    def send(self, events: List[LogEvent]) -> bool:
        try:
            client = self._get_client()
            if not client:
                return False
            
            bulk_body = []
            
            for event in events:
                doc = {
                    "@timestamp": event.timestamp.isoformat(),
                    "level": event.level.value,
                    "source": event.source,
                    "category": event.category,
                    "message": event.message,
                    "metadata": event.metadata
                }
                
                bulk_body.append({"index": {"_index": self.config.index}})
                bulk_body.append(doc)
            
            if bulk_body:
                client.bulk(body=bulk_body, refresh=True)
            
            return True
        
        except Exception as e:
            self.logger.error(f"Elasticsearch send failed: {e}")
            return False


class SIEMIntegrator:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        self.enabled = self.config.get("enabled", True)
        self.batch_size = self.config.get("batch_size", 100)
        self.flush_interval = self.config.get("flush_interval", 10)
        
        self.providers: Dict[SIEMProvider, BaseSIEMClient] = {}
        self._init_providers()
        
        self.event_queue: queue.Queue = queue.Queue()
        self.buffer: List[LogEvent] = []
        self.buffer_lock = threading.Lock()
        
        self.running = False
        self.worker_thread: Optional[threading.Thread] = None
        
        self.filters: List[Callable] = []
        self.enrichers: List[Callable] = []
        
        if self.enabled:
            self.start()

    def _init_providers(self):
        provider_configs = self.config.get("providers", [])
        
        for pc in provider_configs:
            provider_type = SIEMProvider(pc.get("type", "splunk"))
            
            siem_config = SIEMConfig(
                provider=provider_type,
                endpoint=pc.get("endpoint", ""),
                api_key=pc.get("api_key", os.getenv("SIEM_API_KEY", "")),
                index=pc.get("index", "security"),
                source_type=pc.get("source_type", "agentshield"),
                batch_size=pc.get("batch_size", self.batch_size),
                ssl_verify=pc.get("ssl_verify", True)
            )
            
            if provider_type == SIEMProvider.SPLUNK:
                client = SplunkClient(siem_config)
            elif provider_type == SIEMProvider.ELASTICSEARCH:
                client = ElasticsearchClient(siem_config)
            else:
                continue
            
            self.providers[provider_type] = client

    def start(self):
        if self.running:
            return
        
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
        self.logger.info("SIEM integrator started")

    def stop(self):
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        self._flush_buffer()
        self.logger.info("SIEM integrator stopped")

    def log_event(
        self,
        level: LogLevel,
        source: str,
        category: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None
    ):
        if not self.enabled:
            return
        
        event = LogEvent(
            timestamp=datetime.now(),
            level=level,
            source=source,
            category=category,
            message=message,
            metadata=metadata or {}
        )
        
        for enricher in self.enrichers:
            event = enricher(event)
        
        for event_filter in self.filters:
            if not event_filter(event):
                return
        
        self.event_queue.put(event)

    def _worker(self):
        while self.running:
            try:
                event = self.event_queue.get(timeout=1)
                
                with self.buffer_lock:
                    self.buffer.append(event)
                    
                    if len(self.buffer) >= self.batch_size:
                        self._flush_buffer()
            
            except queue.Empty:
                with self.buffer_lock:
                    if self.buffer:
                        self._flush_buffer()
            
            except Exception as e:
                self.logger.error(f"Worker error: {e}")

    def _flush_buffer(self):
        if not self.buffer:
            return
        
        events_to_send = self.buffer[:]
        self.buffer.clear()
        
        for provider_type, client in self.providers.items():
            try:
                client.send(events_to_send)
            except Exception as e:
                self.logger.error(f"Failed to send to {provider_type}: {e}")

    def add_filter(self, filter_func: Callable):
        self.filters.append(filter_func)

    def add_enricher(self, enricher: Callable):
        self.enrichers.append(enricher)

    def test_connections(self) -> Dict[str, bool]:
        results = {}
        for provider_type, client in self.providers.items():
            results[provider_type.value] = client.test_connection()
        return results

    def security_log(
        self,
        event_type: str,
        severity: str,
        description: str,
        source_ip: Optional[str] = None,
        user: Optional[str] = None,
        **kwargs
    ):
        level = LogLevel.ERROR if severity in ("high", "critical") else LogLevel.INFO
        
        self.log_event(
            level=level,
            source="security",
            category=event_type,
            message=description,
            metadata={
                "source_ip": source_ip,
                "user": user,
                "severity": severity,
                **kwargs
            }
        )

    def audit_log(
        self,
        action: str,
        resource: str,
        user: str,
        result: str,
        **kwargs
    ):
        self.log_event(
            level=LogLevel.INFO,
            source="audit",
            category=action,
            message=f"{action} on {resource}",
            metadata={
                "user": user,
                "resource": resource,
                "result": result,
                **kwargs
            }
        )

    def get_queue_size(self) -> int:
        return self.event_queue.qsize()

    def get_buffer_size(self) -> int:
        with self.buffer_lock:
            return len(self.buffer)


class LogFormatter:
    @staticmethod
    def format_json(event: LogEvent) -> str:
        return json.dumps({
            "timestamp": event.timestamp.isoformat(),
            "level": event.level.value,
            "source": event.source,
            "category": event.category,
            "message": event.message,
            "metadata": event.metadata
        })
    
    @staticmethod
    def format_cef(event: LogEvent) -> str:
        device_product = "AgentShield"
        device_version = "1.0"
        signature_id = hashlib.md5(
            f"{event.category}:{event.message}".encode()
        ).hexdigest()[:8]
        
        severity_map = {
            LogLevel.DEBUG: "0",
            LogLevel.INFO: "3",
            LogLevel.WARNING: "6",
            LogLevel.ERROR: "8",
            LogLevel.CRITICAL: "10"
        }
        
        return (
            f"CEF:0|{device_product}|{device_version}|{signature_id}|"
            f"{event.category}|{event.message}|{severity_map.get(event.level, '3')}"
        )
