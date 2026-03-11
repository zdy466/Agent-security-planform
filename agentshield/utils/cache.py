"""Redis cache integration for AgentShield OS"""

import json
import logging
from typing import Any, Optional, Callable
from functools import wraps
import hashlib


class RedisCache:
    """Redis cache with automatic serialization"""
    
    def __init__(self, redis_client=None, prefix: str = "agentshield:", ttl: int = 300):
        self.redis = redis_client
        self.prefix = prefix
        self.ttl = ttl
        self.logger = logging.getLogger(__name__)
        self._connected = False
    
    def _make_key(self, key: str) -> str:
        return f"{self.prefix}{key}"
    
    async def connect(self, host: str = "localhost", port: int = 6379, db: int = 0, password: Optional[str] = None):
        """Connect to Redis"""
        try:
            import redis.asyncio as aioredis
            self.redis = await aioredis.from_url(
                f"redis://{':' + password + '@' if password else ''}{host}:{port}/{db}",
                encoding="utf-8",
                decode_responses=True
            )
            self._connected = True
            self.logger.info(f"Connected to Redis at {host}:{port}")
        except ImportError:
            self.logger.warning("redis package not installed, using mock cache")
            self._connected = False
        except Exception as e:
            self.logger.warning(f"Failed to connect to Redis: {e}")
            self._connected = False
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if not self._connected or not self.redis:
            return None
        
        try:
            value = await self.redis.get(self._make_key(key))
            if value:
                return json.loads(value)
        except Exception as e:
            self.logger.error(f"Cache get error: {e}")
        
        return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        if not self._connected or not self.redis:
            return False
        
        try:
            serialized = json.dumps(value, default=str)
            await self.redis.set(
                self._make_key(key),
                serialized,
                ex=ttl or self.ttl
            )
            return True
        except Exception as e:
            self.logger.error(f"Cache set error: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete value from cache"""
        if not self._connected or not self.redis:
            return False
        
        try:
            await self.redis.delete(self._make_key(key))
            return True
        except Exception as e:
            self.logger.error(f"Cache delete error: {e}")
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        if not self._connected or not self.redis:
            return False
        
        try:
            return await self.redis.exists(self._make_key(key)) > 0
        except Exception as e:
            self.logger.error(f"Cache exists error: {e}")
            return False
    
    async def clear_pattern(self, pattern: str) -> int:
        """Clear all keys matching pattern"""
        if not self._connected or not self.redis:
            return 0
        
        try:
            keys = await self.redis.keys(self._make_key(pattern))
            if keys:
                return await self.redis.delete(*keys)
        except Exception as e:
            self.logger.error(f"Cache clear error: {e}")
        
        return 0
    
    async def get_stats(self) -> dict:
        """Get cache statistics"""
        if not self._connected or not self.redis:
            return {"connected": False}
        
        try:
            info = await self.redis.info("stats")
            return {
                "connected": True,
                "keys": await self.redis.dbsize(),
                "hits": info.get("keyspace_hits", 0),
                "misses": info.get("keyspace_misses", 0)
            }
        except Exception as e:
            return {"connected": False, "error": str(e)}
    
    async def close(self):
        """Close connection"""
        if self.redis:
            await self.redis.close()
            self._connected = False


def cached(cache: RedisCache, key_func: Optional[Callable] = None, ttl: int = 300):
    """Decorator for caching function results"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                key_parts = [func.__name__]
                key_parts.extend(str(arg) for arg in args)
                key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
                cache_key = hashlib.md5("".join(key_parts).encode()).hexdigest()
            
            cached_value = await cache.get(cache_key)
            if cached_value is not None:
                return cached_value
            
            if hasattr(func, '__await__'):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            await cache.set(cache_key, result, ttl)
            return result
        
        return wrapper
    return decorator


class CacheManager:
    """Multiple cache backend support"""
    
    def __init__(self):
        self.caches: dict = {}
        self.logger = logging.getLogger(__name__)
    
    def add_cache(self, name: str, cache: RedisCache):
        """Add cache backend"""
        self.caches[name] = cache
    
    def get_cache(self, name: str = "default") -> Optional[RedisCache]:
        """Get cache by name"""
        return self.caches.get(name)
    
    async def close_all(self):
        """Close all caches"""
        for cache in self.caches.values():
            await cache.close()
    
    async def get_all_stats(self) -> dict:
        """Get stats from all caches"""
        stats = {}
        for name, cache in self.caches.items():
            stats[name] = await cache.get_stats()
        return stats
