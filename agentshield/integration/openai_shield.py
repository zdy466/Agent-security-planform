import json
from typing import Any, Callable, Dict, List, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import time


@dataclass
class OpenAIRequest:
    api_key: str
    model: str
    messages: List[Dict[str, Any]]
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    top_p: Optional[float] = None
    stream: bool = False
    functions: Optional[List[Dict]] = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class OpenAIResponse:
    id: str
    object: str
    created: int
    model: str
    choices: List[Dict[str, Any]]
    usage: Optional[Dict[str, int]] = None
    filtered: bool = False
    filter_reason: Optional[str] = None


class OpenAIRequestFilter:
    def __init__(self, firewall=None):
        self.firewall = firewall

    def filter_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        if not self.firewall:
            return request_data

        messages = request_data.get("messages", [])
        filtered_messages = []

        for message in messages:
            content = message.get("content", "")
            if isinstance(content, str):
                result = self.firewall.check_input(content)
                if result.get("allowed"):
                    filtered_messages.append(message)
                else:
                    filtered_messages.append({
                        "role": message.get("role", "user"),
                        "content": "[Content filtered by AgentShield]"
                    })
            else:
                filtered_messages.append(message)

        request_data["messages"] = filtered_messages
        return request_data


class OpenAIResponseFilter:
    def __init__(self, firewall=None):
        self.firewall = firewall

    def filter_response(self, response_data: Dict[str, Any]) -> OpenAIResponse:
        choices = response_data.get("choices", [])
        filtered = False
        filter_reason = None

        if self.firewall:
            for i, choice in enumerate(choices):
                message = choice.get("message", {})
                content = message.get("content", "")

                if content:
                    result = self.firewall.sanitize(content)
                    if result != content:
                        filtered = True
                        filter_reason = "sensitive_data_filtered"
                        choice["message"]["content"] = result

        return OpenAIResponse(
            id=response_data.get("id", ""),
            object=response_data.get("object", ""),
            created=response_data.get("created", int(time.time())),
            model=response_data.get("model", ""),
            choices=choices,
            usage=response_data.get("usage"),
            filtered=filtered,
            filter_reason=filter_reason
        )


class OpenAIAPIShield:
    def __init__(
        self,
        api_key: Optional[str] = None,
        firewall=None,
        enable_request_filter: bool = True,
        enable_response_filter: bool = True,
        block_on_filter: bool = False
    ):
        self.api_key = api_key
        self.firewall = firewall
        self.enable_request_filter = enable_request_filter
        self.enable_response_filter = enable_response_filter
        self.block_on_filter = block_on_filter

        self.request_filter = OpenAIRequestFilter(firewall)
        self.response_filter = OpenAIResponseFilter(firewall)

        self._request_count = 0
        self._blocked_count = 0
        self._total_tokens = 0

    def create_secure_request(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        **kwargs
    ) -> OpenAIRequest:
        request_data = {
            "model": model,
            "messages": messages,
            **kwargs
        }

        if self.enable_request_filter and self.firewall:
            request_data = self.request_filter.filter_request(request_data)

        return OpenAIRequest(
            api_key=self.api_key or "",
            model=request_data["model"],
            messages=request_data["messages"],
            temperature=request_data.get("temperature"),
            max_tokens=request_data.get("max_tokens"),
            top_p=request_data.get("top_p"),
            stream=request_data.get("stream", False),
            functions=request_data.get("functions")
        )

    def process_response(self, response_data: Dict[str, Any]) -> OpenAIResponse:
        self._request_count += 1

        usage = response_data.get("usage", {})
        if usage:
            self._total_tokens += usage.get("total_tokens", 0)

        if self.enable_response_filter and self.firewall:
            return self.response_filter.filter_response(response_data)

        return OpenAIResponse(
            id=response_data.get("id", ""),
            object=response_data.get("object", ""),
            created=response_data.get("created", int(time.time())),
            model=response_data.get("model", ""),
            choices=response_data.get("choices", []),
            usage=response_data.get("usage")
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_requests": self._request_count,
            "blocked_requests": self._blocked_count,
            "total_tokens": self._total_tokens,
            "request_filter_enabled": self.enable_request_filter,
            "response_filter_enabled": self.enable_response_filter
        }


class SecureOpenAIClient:
    def __init__(
        self,
        api_key: str,
        firewall=None,
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 60.0
    ):
        self.api_key = api_key
        self.shield = OpenAIAPIShield(
            api_key=api_key,
            firewall=firewall
        )
        self.base_url = base_url
        self.timeout = timeout

    async def chat_completion(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        **kwargs
    ) -> Dict[str, Any]:
        request = self.shield.create_secure_request(model, messages, **kwargs)

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": request.model,
            "messages": request.messages,
        }

        if request.temperature is not None:
            payload["temperature"] = request.temperature
        if request.max_tokens is not None:
            payload["max_tokens"] = request.max_tokens
        if request.top_p is not None:
            payload["top_p"] = request.top_p
        if request.stream:
            payload["stream"] = True
        if request.functions:
            payload["functions"] = request.functions

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    response_data = await response.json()

                    if response.status != 200:
                        return response_data

                    processed = self.shield.process_response(response_data)
                    return {
                        "id": processed.id,
                        "object": processed.object,
                        "created": processed.created,
                        "model": processed.model,
                        "choices": processed.choices,
                        "usage": processed.usage,
                        "_shield": {
                            "filtered": processed.filtered,
                            "filter_reason": processed.filter_reason
                        }
                    }
        except ImportError:
            return {
                "error": "aiohttp not installed",
                "message": "Please install aiohttp: pip install aiohttp"
            }
        except Exception as e:
            return {"error": str(e)}


def wrap_openai_client(client, firewall=None):
    original_create = getattr(client, "create", None)

    def secure_create(*args, **kwargs):
        if firewall:
            messages = kwargs.get("messages", args[1] if len(args) > 1 else [])
            for message in messages:
                content = message.get("content", "")
                if content:
                    result = firewall.check_input(content)
                    if not result.get("allowed"):
                        message["content"] = "[Content filtered by AgentShield]"

        response = original_create(*args, **kwargs) if original_create else None

        if firewall and response:
            choices = response.get("choices", [])
            for choice in choices:
                message = choice.get("message", {})
                content = message.get("content", "")
                if content:
                    sanitized = firewall.sanitize(content)
                    message["content"] = sanitized

        return response

    if original_create:
        client.create = secure_create

    return client
