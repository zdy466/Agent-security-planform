"""LLM Gateway - Unified LLM call interface"""

import logging
import time
import hashlib
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import threading
import json

from .llm_providers import (
    BaseLLMProvider,
    ProviderType,
    LLMRequest,
    LLMResponse,
    ModelInfo,
    LLMProviderFactory
)


class LoadBalancingStrategy(Enum):
    ROUND_ROBIN = "round_robin"
    LEAST_LATENCY = "least_latency"
    COST_OPTIMIZED = "cost_optimized"
    FAILOVER = "failover"


@dataclass
class ProviderEndpoint:
    provider_type: ProviderType
    config: Dict[str, Any]
    weight: int = 1
    enabled: bool = True
    priority: int = 0


@dataclass
class GatewayMetrics:
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_tokens: int = 0
    total_cost: float = 0.0
    avg_latency_ms: float = 0.0
    provider_stats: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class RateLimitConfig:
    requests_per_minute: int = 60
    tokens_per_minute: int = 100000
    burst_size: int = 10


class TokenBucketRateLimiter:
    def __init__(self, rate: float, capacity: int):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.time()
        self.lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_update = now


class LLMGateway:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        self.providers: Dict[str, BaseLLMProvider] = {}
        self.provider_endpoints: List[ProviderEndpoint] = []
        
        self.load_balancing = LoadBalancingStrategy(
            self.config.get("load_balancing", "round_robin")
        )
        
        self.rate_limit = RateLimitConfig(
            **self.config.get("rate_limit", {})
        )
        self.rate_limiter = TokenBucketRateLimiter(
            rate=self.rate_limit.requests_per_minute / 60,
            capacity=self.rate_limit.burst_size
        )
        
        self.cache_enabled = self.config.get("cache_enabled", True)
        self.cache_ttl = self.config.get("cache_ttl", 3600)
        self.response_cache: Dict[str, LLMResponse] = {}
        self.cache_lock = threading.Lock()
        
        self.metrics = GatewayMetrics()
        self.metrics_lock = threading.Lock()
        
        self.default_model = self.config.get("default_model", "gpt-3.5-tunnel")
        self.fallback_enabled = self.config.get("fallback_enabled", True)
        
        self.middleware: List[Callable] = []
        self.request_transformers: List[Callable] = []
        self.response_transformers: List[Callable] = []
        
        self._round_robin_index = 0
        self._init_providers()

    def _init_providers(self):
        endpoints = self.config.get("endpoints", [])
        
        for endpoint_config in endpoints:
            provider_type = ProviderType(endpoint_config.get("type", "openai"))
            endpoint = ProviderEndpoint(
                provider_type=provider_type,
                config=endpoint_config.get("config", {}),
                weight=endpoint_config.get("weight", 1),
                enabled=endpoint_config.get("enabled", True),
                priority=endpoint_config.get("priority", 0)
            )
            self.provider_endpoints.append(endpoint)
            
            try:
                provider = LLMProviderFactory.create(provider_type, endpoint.config)
                provider_id = f"{provider_type.value}_{len(self.providers)}"
                self.providers[provider_id] = provider
            except Exception as e:
                self.logger.error(f"Failed to create provider {provider_type}: {e}")
        
        if not self.providers:
            self._add_default_providers()

    def _add_default_providers(self):
        try:
            openai_provider = LLMProviderFactory.create(
                ProviderType.OPENAI, 
                {"api_key": "", "default_model": "gpt-3.5-turbo"}
            )
            self.providers["openai_default"] = openai_provider
            
            self.provider_endpoints.append(ProviderEndpoint(
                provider_type=ProviderType.OPENAI,
                config={"api_key": ""},
                weight=1,
                enabled=True,
                priority=1
            ))
        except Exception as e:
            self.logger.warning(f"Could not add default provider: {e}")

    def add_provider(self, provider_id: str, provider: BaseLLMProvider):
        self.providers[provider_id] = provider

    def remove_provider(self, provider_id: str):
        if provider_id in self.providers:
            del self.providers[provider_id]

    def _select_provider(self, request: LLMRequest) -> tuple:
        enabled_providers = [
            (pid, p) for pid, p in self.providers.items()
            if p.default_model == request.model or not request.model
        ]
        
        if not enabled_providers:
            enabled_providers = list(self.providers.items())
        
        if self.load_balancing == LoadBalancingStrategy.ROUND_ROBIN:
            with self.metrics_lock:
                provider_id = list(self.providers.keys())[
                    self._round_robin_index % len(self.providers)
                ]
                self._round_robin_index += 1
            return provider_id, self.providers[provider_id]
        
        elif self.load_balancing == LoadBalancingStrategy.LEAST_LATENCY:
            fastest = min(
                enabled_providers,
                key=lambda x: self.metrics.provider_stats.get(x[0], {}).get("avg_latency", float('inf'))
            )
            return fastest
        
        elif self.load_balancing == LoadBalancingStrategy.COST_OPTIMIZED:
            cheapest = min(
                enabled_providers,
                key=lambda x: self.metrics.provider_stats.get(x[0], {}).get("cost_per_1k", float('inf'))
            )
            return cheapest
        
        return list(self.providers.items())[0]

    def _get_cache_key(self, request: LLMRequest) -> str:
        content = json.dumps({
            "model": request.model,
            "messages": request.messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def _get_cached_response(self, cache_key: str) -> Optional[LLMResponse]:
        if not self.cache_enabled:
            return None
        
        with self.cache_lock:
            if cache_key in self.response_cache:
                cached = self.response_cache[cache_key]
                return cached
        return None

    def _cache_response(self, cache_key: str, response: LLMResponse):
        if not self.cache_enabled:
            return
        
        with self.cache_lock:
            self.response_cache[cache_key] = response
            
            if len(self.response_cache) > 1000:
                oldest_keys = list(self.response_cache.keys())[:100]
                for key in oldest_keys:
                    del self.response_cache[key]

    def _update_metrics(
        self, 
        provider_id: str, 
        response: LLMResponse, 
        success: bool
    ):
        with self.metrics_lock:
            self.metrics.total_requests += 1
            
            if success:
                self.metrics.successful_requests += 1
            else:
                self.metrics.failed_requests += 1
            
            usage = response.usage
            self.metrics.total_tokens += usage.get("total_tokens", 0)
            
            provider_stats = self.metrics.provider_stats.get(provider_id, {
                "requests": 0,
                "success": 0,
                "failure": 0,
                "total_latency": 0,
                "total_tokens": 0
            })
            
            provider_stats["requests"] += 1
            if success:
                provider_stats["success"] += 1
            else:
                provider_stats["failure"] += 1
            
            provider_stats["total_latency"] += response.latency_ms
            provider_stats["total_tokens"] += usage.get("total_tokens", 0)
            provider_stats["avg_latency"] = (
                provider_stats["total_latency"] / provider_stats["requests"]
            )
            
            self.metrics.provider_stats[provider_id] = provider_stats

    def generate(self, request: LLMRequest) -> LLMResponse:
        if not request.model:
            request.model = self.default_model
        
        for transformer in self.request_transformers:
            request = transformer(request)
        
        if not self.rate_limiter.consume():
            return LLMResponse(
                content="[Rate limit exceeded]",
                model=request.model,
                provider=ProviderType.OPENAI,
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                finish_reason="rate_limit",
                latency_ms=0
            )
        
        cache_key = self._get_cache_key(request)
        cached = self._get_cached_response(cache_key)
        if cached:
            cached.metadata["cached"] = True
            return cached
        
        errors = []
        
        if self.load_balancing == LoadBalancingStrategy.FAILOVER:
            provider_ids = sorted(
                self.providers.keys(),
                key=lambda x: self.metrics.provider_stats.get(x, {}).get("priority", 0),
                reverse=True
            )
        else:
            provider_ids = [self._select_provider(request)[0]]
        
        for provider_id in provider_ids:
            provider = self.providers[provider_id]
            
            try:
                response = provider.generate(request)
                
                self._update_metrics(provider_id, response, True)
                self._cache_cache_response(cache_key, response)
                
                for transformer in self.response_transformers:
                    response = transformer(response)
                
                return response
            
            except Exception as e:
                error_msg = f"Provider {provider_id} failed: {str(e)}"
                self.logger.warning(error_msg)
                errors.append(error_msg)
                
                self._update_metrics(
                    provider_id,
                    LLMResponse(
                        content="",
                        model=request.model,
                        provider=ProviderType.OPENAI,
                        usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                        finish_reason="error",
                        latency_ms=0
                    ),
                    False
                )
        
        return LLMResponse(
            content=f"[All providers failed: {'; '.join(errors)}]",
            model=request.model,
            provider=ProviderType.OPENAI,
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            finish_reason="error",
            latency_ms=0
        )

    def _cache_cache_response(self, cache_key: str, response: LLMResponse):
        pass

    def chat(self, messages: List[Dict[str, str]], **kwargs) -> LLMResponse:
        request = LLMRequest(
            model=kwargs.get("model", self.default_model),
            messages=messages,
            temperature=kwargs.get("temperature", 0.7),
            max_tokens=kwargs.get("max_tokens"),
            stream=kwargs.get("stream", False)
        )
        return self.generate(request)

    def add_middleware(self, middleware: Callable):
        self.middleware.append(middleware)

    def add_request_transformer(self, transformer: Callable):
        self.request_transformers.append(transformer)

    def add_response_transformer(self, transformer: Callable):
        self.response_transformers.append(transformer)

    def get_available_models(self) -> List[ModelInfo]:
        models = []
        for provider in self.providers.values():
            try:
                models.extend(provider.list_models())
            except Exception as e:
                self.logger.error(f"Failed to list models: {e}")
        return models

    def get_metrics(self) -> Dict[str, Any]:
        with self.metrics_lock:
            return {
                "total_requests": self.metrics.total_requests,
                "successful_requests": self.metrics.successful_requests,
                "failed_requests": self.metrics.failed_requests,
                "success_rate": (
                    self.metrics.successful_requests / max(self.metrics.total_requests, 1)
                ),
                "total_tokens": self.metrics.total_tokens,
                "avg_latency_ms": self.metrics.avg_latency_ms,
                "provider_stats": self.metrics.provider_stats,
                "cache_size": len(self.response_cache) if self.cache_enabled else 0
            }

    def health_check(self) -> Dict[str, Any]:
        healthy_providers = []
        unhealthy_providers = []
        
        for provider_id, provider in self.providers.items():
            try:
                if provider.validate_config():
                    healthy_providers.append(provider_id)
                else:
                    unhealthy_providers.append(provider_id)
            except Exception:
                unhealthy_providers.append(provider_id)
        
        return {
            "status": "healthy" if healthy_providers else "unhealthy",
            "healthy_providers": healthy_providers,
            "unhealthy_providers": unhealthy_providers,
            "total_providers": len(self.providers)
        }


class GatewayMiddleware:
    def __init__(self, gateway: LLMGateway):
        self.gateway = gateway
    
    def logging_middleware(self, request: LLMRequest) -> LLMRequest:
        self.gateway.logger.info(f"Gateway request: {request.model}")
        return request
    
    def metrics_middleware(self, response: LLMResponse) -> LLMResponse:
        response.metadata["gateway_processed"] = True
        return response
