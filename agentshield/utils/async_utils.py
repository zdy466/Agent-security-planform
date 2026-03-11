"""Async support utilities for AgentShield OS"""

import asyncio
import functools
from typing import Any, Callable, Optional, TypeVar, Awaitable
from concurrent.futures import ThreadPoolExecutor
import logging

T = TypeVar('T')


def async_retry(max_attempts: int = 3, delay: float = 1.0):
    """Decorator for async retry logic"""
    def decorator(func: Callable[..., Awaitable[T]]):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        await asyncio.sleep(delay * (attempt + 1))
            raise last_exception
        return wrapper
    return decorator


def async_timeout(seconds: float):
    """Decorator for async timeout"""
    def decorator(func: Callable[..., Awaitable[T]]):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=seconds)
            except asyncio.TimeoutError:
                raise TimeoutError(f"Function {func.__name__} timed out after {seconds} seconds")
        return wrapper
    return decorator


class AsyncRunner:
    """Async task runner with thread pool support"""
    
    def __init__(self, max_workers: int = 10):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.logger = logging.getLogger(__name__)
    
    async def run_in_executor(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Run blocking function in thread pool"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor,
            functools.partial(func, *args, **kwargs)
        )
    
    async def run_tasks(self, *tasks: Awaitable) -> list:
        """Run multiple async tasks concurrently"""
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    async def run_with_semaphore(self, semaphore: asyncio.Semaphore, coro: Awaitable) -> Any:
        """Run coroutine with semaphore limit"""
        async with semaphore:
            return await coro
    
    def shutdown(self):
        """Shutdown the executor"""
        self.executor.shutdown(wait=True)


class AsyncCache:
    """Async cache with TTL support"""
    
    def __init__(self, ttl: int = 300):
        self.cache: dict = {}
        self.ttl = ttl
        self.logger = logging.getLogger(__name__)
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        import time
        if key in self.cache:
            value, expiry = self.cache[key]
            if time.time() < expiry:
                return value
            else:
                del self.cache[key]
        return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set value in cache"""
        import time
        expiry = time.time() + (ttl or self.ttl)
        self.cache[key] = (value, expiry)
    
    async def delete(self, key: str):
        """Delete value from cache"""
        if key in self.cache:
            del self.cache[key]
    
    async def clear(self):
        """Clear all cache"""
        self.cache.clear()
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        return await self.get(key) is not None


class AsyncRateLimiter:
    """Async rate limiter"""
    
    def __init__(self, max_calls: int, period: float):
        self.max_calls = max_calls
        self.period = period
        self.calls: list = []
        self.semaphore = asyncio.Semaphore(max_calls)
        self.logger = logging.getLogger(__name__)
    
    async def acquire(self):
        """Acquire a rate limit slot"""
        await self.semaphore.acquire()
        import time
        self.calls.append(time.time())
        
        asyncio.create_task(self._release_after_period())
    
    async def _release_after_period(self):
        """Release after period"""
        await asyncio.sleep(self.period)
        self.semaphore.release()
    
    async def __aenter__(self):
        await self.acquire()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class AsyncBatchProcessor:
    """Async batch processor for bulk operations"""
    
    def __init__(self, batch_size: int = 100, flush_interval: float = 1.0):
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.batch: list = []
        self._running = False
        self.logger = logging.getLogger(__name__)
    
    async def add(self, item: Any):
        """Add item to batch"""
        self.batch.append(item)
        if len(self.batch) >= self.batch_size:
            await self.flush()
    
    async def flush(self):
        """Flush batch"""
        if not self.batch:
            return
        
        batch_to_process = self.batch[:self.batch_size]
        self.batch = self.batch[self.batch_size:]
        
        await self._process_batch(batch_to_process)
    
    async def _process_batch(self, batch: list):
        """Process batch - override this"""
        pass
    
    async def start(self):
        """Start background flush"""
        self._running = True
        while self._running:
            await asyncio.sleep(self.flush_interval)
            await self.flush()
    
    def stop(self):
        """Stop background flush"""
        self._running = False


class AsyncQueue:
    """Async queue with backpressure"""
    
    def __init__(self, maxsize: int = 1000):
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self.logger = logging.getLogger(__name__)
    
    async def put(self, item: Any):
        """Put item in queue"""
        await self.queue.put(item)
    
    async def get(self) -> Any:
        """Get item from queue"""
        return await self.queue.get()
    
    def qsize(self) -> int:
        """Get queue size"""
        return self.queue.qsize()
    
    def empty(self) -> bool:
        """Check if empty"""
        return self.queue.empty()


class AsyncEventBus:
    """Async event bus for pub/sub"""
    
    def __init__(self):
        self.subscribers: dict = {}
        self.logger = logging.getLogger(__name__)
    
    async def subscribe(self, event_type: str, callback: Callable):
        """Subscribe to event"""
        if event_type not in self.subscribers:
            self.subscribers[event_type] = []
        self.subscribers[event_type].append(callback)
    
    async def unsubscribe(self, event_type: str, callback: Callable):
        """Unsubscribe from event"""
        if event_type in self.subscribers:
            self.subscribers[event_type].remove(callback)
    
    async def publish(self, event_type: str, data: Any):
        """Publish event"""
        if event_type in self.subscribers:
            for callback in self.subscribers[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(data)
                    else:
                        callback(data)
                except Exception as e:
                    self.logger.error(f"Error in event callback: {e}")


class AsyncCircuitBreaker:
    """Async circuit breaker pattern"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 60.0):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "closed"
        self.logger = logging.getLogger(__name__)
    
    async def call(self, func: Callable[..., Awaitable[T]], *args, **kwargs) -> T:
        """Call function with circuit breaker"""
        import time
        
        if self.state == "open":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "half-open"
                self.logger.info("Circuit breaker entering half-open state")
            else:
                raise Exception("Circuit breaker is open")
        
        try:
            result = await func(*args, **kwargs)
            
            if self.state == "half-open":
                self.state = "closed"
                self.failure_count = 0
                self.logger.info("Circuit breaker closed")
            
            return result
            
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = "open"
                self.logger.warning(f"Circuit breaker opened after {self.failure_count} failures")
            
            raise e
    
    def get_state(self) -> str:
        """Get circuit breaker state"""
        return self.state


class AsyncHealthCheck:
    """Async health checker"""
    
    def __init__(self):
        self.checks: dict = {}
        self.logger = logging.getLogger(__name__)
    
    def register_check(self, name: str, check_func: Callable[[], Awaitable[bool]]):
        """Register health check"""
        self.checks[name] = check_func
    
    async def check_health(self) -> dict:
        """Run all health checks"""
        results = {}
        overall_healthy = True
        
        for name, check_func in self.checks.items():
            try:
                if asyncio.iscoroutinefunction(check_func):
                    is_healthy = await check_func()
                else:
                    is_healthy = check_func()
                
                results[name] = {"healthy": is_healthy}
                
                if not is_healthy:
                    overall_healthy = False
                    
            except Exception as e:
                results[name] = {"healthy": False, "error": str(e)}
                overall_healthy = False
        
        return {
            "healthy": overall_healthy,
            "checks": results
        }
