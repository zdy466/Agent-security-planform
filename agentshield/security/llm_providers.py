"""LLM Providers Module - Multi-LLM provider support (OpenAI/Anthropic/Local)"""

import os
import logging
import json
import time
from typing import Dict, List, Optional, Any, Callable
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import threading
import hashlib


class ProviderType(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE_OPENAI = "azure_openai"
    GOOGLE_VERTEX = "google_vertex"
    LOCAL = "local"
    CUSTOM = "custom"


class ModelCapability(Enum):
    TEXT_GENERATION = "text_generation"
    CHAT = "chat"
    CODE_COMPLETION = "code_completion"
    EMBEDDINGS = "embeddings"
    IMAGE_UNDERSTANDING = "image_understanding"
    FUNCTION_CALLING = "function_calling"


@dataclass
class ModelInfo:
    name: str
    provider: ProviderType
    display_name: str
    context_window: int
    max_output_tokens: int
    capabilities: List[ModelCapability]
    pricing: Dict[str, float]
    latency_ms: Optional[int] = None


@dataclass
class LLMRequest:
    model: str
    messages: List[Dict[str, str]]
    temperature: float = 0.7
    max_tokens: Optional[int] = None
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    stop: Optional[List[str]] = None
    stream: bool = False
    functions: Optional[List[Dict]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    content: str
    model: str
    provider: ProviderType
    usage: Dict[str, int]
    finish_reason: str
    latency_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseLLMProvider(ABC):
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.api_key = config.get("api_key", os.getenv("API_KEY", ""))
        self.api_base = config.get("api_base", "")
        self.timeout = config.get("timeout", 60)
        self.max_retries = config.get("max_retries", 3)
        self.default_model = config.get("default_model", "")
        
    @abstractmethod
    def generate(self, request: LLMRequest) -> LLMResponse:
        pass
    
    @abstractmethod
    def list_models(self) -> List[ModelInfo]:
        pass
    
    @abstractmethod
    def validate_config(self) -> bool:
        pass
    
    def _handle_error(self, error: Exception) -> Exception:
        self.logger.error(f"LLM provider error: {error}")
        return error
    
    def _retry_with_backoff(self, func: Callable, *args, **kwargs):
        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise self._handle_error(e)
                wait_time = 2 ** attempt
                self.logger.warning(f"Retry attempt {attempt + 1}, waiting {wait_time}s")
                time.sleep(wait_time)


class OpenAIProvider(BaseLLMProvider):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.client = None
        
        if not self.api_key:
            self.api_key = os.getenv("OPENAI_API_KEY", "")
        
        self.api_base = self.api_base or os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
        self.organization = config.get("organization", os.getenv("OPENAI_ORG", ""))
        
        self._init_client()
    
    def _init_client(self):
        try:
            import openai
            openai.api_key = self.api_key
            openai.api_base = self.api_base
            if self.organization:
                openai.organization = self.organization
            self.client = openai
        except ImportError:
            self.logger.warning("OpenAI package not installed")
    
    def validate_config(self) -> bool:
        return bool(self.api_key)
    
    def generate(self, request: LLMRequest) -> LLMResponse:
        start_time = time.time()
        
        try:
            if self.client:
                response = self.client.ChatCompletion.create(
                    model=request.model,
                    messages=request.messages,
                    temperature=request.temperature,
                    max_tokens=request.max_tokens,
                    top_p=request.top_p,
                    frequency_penalty=request.frequency_penalty,
                    presence_penalty=request.presence_penalty,
                    stop=request.stop,
                    functions=request.functions
                )
                
                return LLMResponse(
                    content=response.choices[0].message.content or "",
                    model=response.model,
                    provider=ProviderType.OPENAI,
                    usage={
                        "prompt_tokens": response.usage.prompt_tokens,
                        "completion_tokens": response.usage.completion_tokens,
                        "total_tokens": response.usage.total_tokens
                    },
                    finish_reason=response.choices[0].finish_reason,
                    latency_ms=(time.time() - start_time) * 1000
                )
            
            return LLMResponse(
                content="[OpenAI client not available]",
                model=request.model,
                provider=ProviderType.OPENAI,
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                finish_reason="error",
                latency_ms=(time.time() - start_time) * 1000
            )
        
        except Exception as e:
            self._handle_error(e)
            raise
    
    def list_models(self) -> List[ModelInfo]:
        models = [
            ModelInfo(
                name="gpt-4",
                provider=ProviderType.OPENAI,
                display_name="GPT-4",
                context_window=8192,
                max_output_tokens=4096,
                capabilities=[ModelCapability.CHAT, ModelCapability.FUNCTION_CALLING],
                pricing={"prompt": 0.03, "completion": 0.06}
            ),
            ModelInfo(
                name="gpt-4-turbo",
                provider=ProviderType.OPENAI,
                display_name="GPT-4 Turbo",
                context_window=128000,
                max_output_tokens=4096,
                capabilities=[ModelCapability.CHAT, ModelCapability.FUNCTION_CALLING, ModelCapability.IMAGE_UNDERSTANDING],
                pricing={"prompt": 0.01, "completion": 0.03}
            ),
            ModelInfo(
                name="gpt-3.5-turbo",
                provider=ProviderType.OPENAI,
                display_name="GPT-3.5 Turbo",
                context_window=16385,
                max_output_tokens=4096,
                capabilities=[ModelCapability.CHAT, ModelCapability.FUNCTION_CALLING],
                pricing={"prompt": 0.0015, "completion": 0.002}
            ),
        ]
        return models


class AnthropicProvider(BaseLLMProvider):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.client = None
        
        if not self.api_key:
            self.api_key = os.getenv("ANTHROPIC_API_KEY", "")
        
        self.api_base = self.api_base or os.getenv("ANTHROPIC_API_BASE", "https://api.anthropic.com")
        self.api_version = config.get("api_version", "2023-06-01")
        
        self._init_client()
    
    def _init_client(self):
        try:
            import anthropic
            self.client = anthropic
        except ImportError:
            self.logger.warning("Anthropic package not installed")
    
    def validate_config(self) -> bool:
        return bool(self.api_key)
    
    def generate(self, request: LLMRequest) -> LLMResponse:
        start_time = time.time()
        
        try:
            if self.client:
                system_message = ""
                messages = request.messages
                
                if messages and messages[0].get("role") == "system":
                    system_message = messages[0].get("content", "")
                    messages = messages[1:]
                
                response = self.client.messages.create(
                    model=request.model,
                    system=system_message,
                    messages=messages,
                    max_tokens=request.max_tokens or 1024,
                    temperature=request.temperature,
                    top_p=request.top_p,
                    stop_sequences=request.stop
                )
                
                return LLMResponse(
                    content=response.content[0].text if response.content else "",
                    model=response.model,
                    provider=ProviderType.ANTHROPIC,
                    usage={
                        "prompt_tokens": response.usage.input_tokens,
                        "completion_tokens": response.usage.output_tokens,
                        "total_tokens": response.usage.input_tokens + response.usage.output_tokens
                    },
                    finish_reason=response.stop_reason,
                    latency_ms=(time.time() - start_time) * 1000
                )
            
            return LLMResponse(
                content="[Anthropic client not available]",
                model=request.model,
                provider=ProviderType.ANTHROPIC,
                usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                finish_reason="error",
                latency_ms=(time.time() - start_time) * 1000
            )
        
        except Exception as e:
            self._handle_error(e)
            raise
    
    def list_models(self) -> List[ModelInfo]:
        return [
            ModelInfo(
                name="claude-3-opus",
                provider=ProviderType.ANTHROPIC,
                display_name="Claude 3 Opus",
                context_window=200000,
                max_output_tokens=4096,
                capabilities=[ModelCapability.CHAT, ModelCapability.IMAGE_UNDERSTANDING],
                pricing={"prompt": 0.015, "completion": 0.075}
            ),
            ModelInfo(
                name="claude-3-sonnet",
                provider=ProviderType.ANTHROPIC,
                display_name="Claude 3 Sonnet",
                context_window=200000,
                max_output_tokens=4096,
                capabilities=[ModelCapability.CHAT, ModelCapability.IMAGE_UNDERSTANDING],
                pricing={"prompt": 0.003, "completion": 0.015}
            ),
            ModelInfo(
                name="claude-3-haiku",
                provider=ProviderType.ANTHROPIC,
                display_name="Claude 3 Haiku",
                context_window=200000,
                max_output_tokens=4096,
                capabilities=[ModelCapability.CHAT],
                pricing={"prompt": 0.00025, "completion": 0.00125}
            ),
        ]


class AzureOpenAIProvider(BaseLLMProvider):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        self.api_key = self.api_key or os.getenv("AZURE_OPENAI_API_KEY", "")
        self.api_base = self.api_base or os.getenv("AZURE_OPENAI_ENDPOINT", "")
        self.api_version = config.get("api_version", "2024-02-01")
        self.deployment_name = config.get("deployment_name", "")
        
        self.client = None
        self._init_client()
    
    def _init_client(self):
        try:
            import openai
            openai.api_type = "azure"
            openai.api_base = self.api_base
            openai.api_version = self.api_version
            openai.api_key = self.api_key
            self.client = openai
        except ImportError:
            self.logger.warning("OpenAI package not installed")
    
    def validate_config(self) -> bool:
        return bool(self.api_key and self.api_base and self.deployment_name)
    
    def generate(self, request: LLMRequest) -> LLMResponse:
        start_time = time.time()
        
        try:
            if self.client:
                response = self.client.ChatCompletion.create(
                    engine=self.deployment_name,
                    model=request.model,
                    messages=request.messages,
                    temperature=request.temperature,
                    max_tokens=request.max_tokens,
                    top_p=request.top_p
                )
                
                return LLMResponse(
                    content=response.choices[0].message.content or "",
                    model=self.deployment_name,
                    provider=ProviderType.AZURE_OPENAI,
                    usage={
                        "prompt_tokens": response.usage.prompt_tokens,
                        "completion_tokens": response.usage.completion_tokens,
                        "total_tokens": response.usage.total_tokens
                    },
                    finish_reason=response.choices[0].finish_reason,
                    latency_ms=(time.time() - start_time) * 1000
                )
        
        except Exception as e:
            self._handle_error(e)
            raise
        
        return LLMResponse(
            content="[Azure OpenAI not available]",
            model=request.model,
            provider=ProviderType.AZURE_OPENAI,
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            finish_reason="error",
            latency_ms=(time.time() - start_time) * 1000
        )
    
    def list_models(self) -> List[ModelInfo]:
        return [
            ModelInfo(
                name="gpt-4",
                provider=ProviderType.AZURE_OPENAI,
                display_name="Azure GPT-4",
                context_window=8192,
                max_output_tokens=4096,
                capabilities=[ModelCapability.CHAT, ModelCapability.FUNCTION_CALLING],
                pricing={"prompt": 0.03, "completion": 0.06}
            ),
        ]


class LocalProvider(BaseLLMProvider):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        self.api_base = self.api_base or "http://localhost:8080"
        self.model_path = config.get("model_path", "")
        
        self.client = None
        self._init_client()
    
    def _init_client(self):
        try:
            import requests
            self.client = requests
        except ImportError:
            self.logger.warning("Requests package not installed")
    
    def validate_config(self) -> bool:
        return bool(self.api_base)
    
    def generate(self, request: LLMRequest) -> LLMResponse:
        start_time = time.time()
        
        try:
            if self.client:
                payload = {
                    "model": request.model,
                    "messages": request.messages,
                    "temperature": request.temperature,
                    "max_tokens": request.max_tokens,
                    "stream": request.stream
                }
                
                response = self.client.post(
                    f"{self.api_base}/v1/chat/completions",
                    json=payload,
                    timeout=self.timeout
                )
                response.raise_for_status()
                result = response.json()
                
                return LLMResponse(
                    content=result["choices"][0]["message"]["content"],
                    model=request.model,
                    provider=ProviderType.LOCAL,
                    usage=result.get("usage", {}),
                    finish_reason=result["choices"][0].get("finish_reason", "stop"),
                    latency_ms=(time.time() - start_time) * 1000
                )
        
        except Exception as e:
            self._handle_error(e)
        
        return LLMResponse(
            content="[Local model not available]",
            model=request.model,
            provider=ProviderType.LOCAL,
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            finish_reason="error",
            latency_ms=(time.time() - start_time) * 1000
        )
    
    def list_models(self) -> List[ModelInfo]:
        return [
            ModelInfo(
                name="llama2",
                provider=ProviderType.LOCAL,
                display_name="Llama 2",
                context_window=4096,
                max_output_tokens=2048,
                capabilities=[ModelCapability.CHAT],
                pricing={"prompt": 0, "completion": 0}
            ),
            ModelInfo(
                name="mistral",
                provider=ProviderType.LOCAL,
                display_name="Mistral",
                context_window=8192,
                max_output_tokens=4096,
                capabilities=[ModelCapability.CHAT],
                pricing={"prompt": 0, "completion": 0}
            ),
        ]


class LLMProviderFactory:
    _providers: Dict[ProviderType, type] = {
        ProviderType.OPENAI: OpenAIProvider,
        ProviderType.ANTHROPIC: AnthropicProvider,
        ProviderType.AZURE_OPENAI: AzureOpenAIProvider,
        ProviderType.LOCAL: LocalProvider,
    }
    
    @classmethod
    def create(cls, provider_type: ProviderType, config: Dict[str, Any]) -> BaseLLMProvider:
        provider_class = cls._providers.get(provider_type)
        if not provider_class:
            raise ValueError(f"Unknown provider type: {provider_type}")
        
        return provider_class(config)
    
    @classmethod
    def register(cls, provider_type: ProviderType, provider_class: type):
        cls._providers[provider_type] = provider_class
