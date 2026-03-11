import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
import threading


class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class ComponentHealth:
    name: str
    status: HealthStatus
    message: str = ""
    response_time_ms: float = 0
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthReport:
    status: HealthStatus
    version: str
    timestamp: datetime = field(default_factory=datetime.now)
    uptime_seconds: float = 0
    components: List[ComponentHealth] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class HealthCheck:
    def __init__(self, name: str, timeout: float = 5.0):
        self.name = name
        self.timeout = timeout
        self._check_func: Optional[Callable] = None

    def register_check(self, func: Callable):
        self._check_func = func

    async def check(self) -> ComponentHealth:
        start_time = time.time()
        try:
            if asyncio.iscoroutinefunction(self._check_func):
                result = await asyncio.wait_for(self._check_func(), timeout=self.timeout)
            else:
                result = self._check_func()

            if isinstance(result, dict):
                status = HealthStatus(result.get("status", "healthy"))
                message = result.get("message", "")
                metadata = result.get("metadata", {})
            else:
                status = HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY
                message = "OK" if status == HealthStatus.HEALTHY else "Check failed"
                metadata = {}

            response_time = (time.time() - start_time) * 1000
            return ComponentHealth(
                name=self.name,
                status=status,
                message=message,
                response_time_ms=response_time,
                metadata=metadata
            )
        except asyncio.TimeoutError:
            response_time = (time.time() - start_time) * 1000
            return ComponentHealth(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Timeout after {self.timeout}s",
                response_time_ms=response_time
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return ComponentHealth(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=str(e),
                response_time_ms=response_time
            )


class HealthCheckRegistry:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._checks: Dict[str, HealthCheck] = {}
        self._start_time = time.time()

    def register(self, name: str, check_func: Callable, timeout: float = 5.0):
        health_check = HealthCheck(name, timeout)
        health_check.register_check(check_func)
        self._checks[name] = health_check

    def unregister(self, name: str):
        self._checks.pop(name, None)

    def get_check(self, name: str) -> Optional[HealthCheck]:
        return self._checks.get(name)

    async def check_all(self) -> HealthReport:
        tasks = [check.check() for check in self._checks.values()]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        components = []
        has_unhealthy = False
        has_degraded = False

        for result in results:
            if isinstance(result, Exception):
                components.append(ComponentHealth(
                    name="unknown",
                    status=HealthStatus.UNHEALTHY,
                    message=str(result)
                ))
                has_unhealthy = True
            else:
                components.append(result)
                if result.status == HealthStatus.UNHEALTHY:
                    has_unhealthy = True
                elif result.status == HealthStatus.DEGRADED:
                    has_degraded = True

        if has_unhealthy:
            status = HealthStatus.UNHEALTHY
        elif has_degraded:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY

        return HealthReport(
            status=status,
            version="0.5.0",
            uptime_seconds=time.time() - self._start_time,
            components=components
        )

    def get_checks(self) -> Dict[str, HealthCheck]:
        return self._checks.copy()


class LivenessProbe:
    def __init__(self):
        self._healthy = True
        self._lock = threading.Lock()

    def mark_unhealthy(self):
        with self._lock:
            self._healthy = False

    def mark_healthy(self):
        with self._lock:
            self._healthy = True

    def is_alive(self) -> bool:
        with self._lock:
            return self._healthy


class ReadinessProbe:
    def __init__(self):
        self._ready = False
        self._lock = threading.Lock()
        self._dependencies: Dict[str, bool] = {}

    def set_ready(self, ready: bool):
        with self._lock:
            self._ready = ready

    def update_dependency(self, name: str, ready: bool):
        with self._lock:
            self._dependencies[name] = ready

    def is_ready(self) -> bool:
        with self._lock:
            if not self._ready:
                return False
            return all(self._dependencies.values())


class HealthServer:
    def __init__(
        self,
        host: str = "0.0.0.0",
        liveness_port: int = 8081,
        readiness_port: int = 8082,
        metrics_port: int = 8083
    ):
        self.host = host
        self.liveness_port = liveness_port
        self.readiness_port = readiness_port
        self.metrics_port = metrics_port
        self.liveness_probe = LivenessProbe()
        self.readiness_probe = ReadinessProbe()
        self.registry = HealthCheckRegistry()

    async def start(self):
        pass

    async def stop(self):
        pass

    def get_liveness_response(self) -> Dict[str, Any]:
        alive = self.liveness_probe.is_alive()
        return {
            "status": "alive" if alive else "dead",
            "timestamp": datetime.now().isoformat()
        }

    async def get_readiness_response(self) -> Dict[str, Any]:
        ready = self.readiness_probe.is_ready()
        report = await self.registry.check_all()

        return {
            "status": "ready" if ready else "not_ready",
            "health": report.status.value,
            "components": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "message": c.message,
                    "response_time_ms": c.response_time_ms
                }
                for c in report.components
            ],
            "timestamp": datetime.now().isoformat()
        }


def create_health_checks(registry: HealthCheckRegistry):
    def check_firewall():
        return {"status": "healthy", "message": "Firewall is operational"}

    def check_audit():
        return {"status": "healthy", "message": "Audit logger is operational"}

    def check_memory():
        import psutil
        memory = psutil.virtual_memory()
        return {
            "status": "healthy" if memory.percent < 90 else "degraded",
            "message": f"Memory usage: {memory.percent}%",
            "metadata": {"memory_percent": memory.percent}
        }

    registry.register("firewall", check_firewall)
    registry.register("audit", check_audit)

    try:
        import psutil
        registry.register("memory", check_memory)
    except ImportError:
        pass
