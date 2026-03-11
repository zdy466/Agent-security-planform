"""Connection pool for AgentShield OS"""

import asyncio
import logging
from typing import Any, Callable, Optional, TypeVar, Generic
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import Enum
import time

T = TypeVar('T')


class PoolState(Enum):
    IDLE = "idle"
    ACTIVE = "active"
    CLOSED = "closed"


@dataclass
class PoolConfig:
    min_size: int = 5
    max_size: int = 20
    timeout: float = 30.0
    max_idle_time: float = 300.0
    validation_interval: float = 60.0


class Connection(Generic[T]):
    """Wrapper for pooled connection"""
    
    def __init__(self, connection: T, pool: 'ConnectionPool'):
        self.connection = connection
        self.pool = pool
        self.created_at = time.time()
        self.last_used = time.time()
        self.in_use = False
    
    async def validate(self) -> bool:
        """Validate connection"""
        return await self.pool._validate_connection(self.connection)
    
    def mark_used(self):
        """Mark connection as used"""
        self.last_used = time.time()
        self.in_use = True
    
    def mark_idle(self):
        """Mark connection as idle"""
        self.in_use = False


class ConnectionPool(Generic[T]):
    """Generic async connection pool"""
    
    def __init__(
        self,
        factory: Callable[[], Any],
        config: Optional[PoolConfig] = None
    ):
        self.factory = factory
        self.config = config or PoolConfig()
        self.pool: list[Connection[T]] = []
        self.wait_queue: asyncio.Queue = asyncio.Queue()
        self.state = PoolState.IDLE
        self.logger = logging.getLogger(self.__name__)
        self._lock = asyncio.Lock()
        self._validation_task = None
    
    async def initialize(self):
        """Initialize pool with minimum connections"""
        if self.state != PoolState.IDLE:
            return
        
        for _ in range(self.config.min_size):
            conn = await self._create_connection()
            if conn:
                self.pool.append(conn)
        
        self.state = PoolState.ACTIVE
        self._start_validation()
        
        self.logger.info(f"Pool initialized with {len(self.pool)} connections")
    
    async def _create_connection(self) -> Optional[Connection[T]]:
        """Create new connection"""
        try:
            conn = await self._create_conn()
            return Connection(conn, self) if conn else None
        except Exception as e:
            self.logger.error(f"Failed to create connection: {e}")
            return None
    
    async def _create_conn(self) -> T:
        """Create actual connection - override this"""
        return await self.factory()
    
    async def _validate_connection(self, conn: T) -> bool:
        """Validate connection - override this"""
        return True
    
    @asynccontextmanager
    async def acquire(self, timeout: Optional[float] = None):
        """Acquire connection from pool"""
        timeout = timeout or self.config.timeout
        
        connection = await asyncio.wait_for(
            self._acquire_connection(),
            timeout=timeout
        )
        
        try:
            yield connection.connection
        finally:
            await self._release_connection(connection)
    
    async def _acquire_connection(self) -> Connection[T]:
        """Internal acquire logic"""
        async with self._lock:
            for conn in self.pool:
                if not conn.in_use and await conn.validate():
                    conn.mark_used()
                    return conn
        
            if len(self.pool) < self.config.max_size:
                new_conn = await self._create_connection()
                if new_conn:
                    new_conn.mark_used()
                    self.pool.append(new_conn)
                    return new_conn
        
        await self.wait_queue.put(asyncio.Event())
        event = await self.wait_queue.get()
        
        async with self._lock:
            for conn in self.pool:
                if not conn.in_use and await conn.validate():
                    conn.mark_used()
                    return conn
        
        raise TimeoutError("No available connections")
    
    async def _release_connection(self, connection: Connection[T]):
        """Release connection back to pool"""
        async with self._lock:
            connection.mark_idle()
            
            if not await connection.validate():
                self.pool.remove(connection)
                self.logger.warning("Removed invalid connection")
            
            if not self.wait_queue.empty():
                try:
                    event = self.wait_queue.get_nowait()
                    event.set()
                except:
                    pass
    
    def _start_validation(self):
        """Start periodic validation"""
        async def validate_loop():
            while self.state == PoolState.ACTIVE:
                await asyncio.sleep(self.config.validation_interval)
                await self._validate_pool()
        
        self._validation_task = asyncio.create_task(validate_loop())
    
    async def _validate_pool(self):
        """Validate all connections in pool"""
        async with self._lock:
            to_remove = []
            
            for conn in self.pool:
                if time.time() - conn.last_used > self.config.max_idle_time:
                    to_remove.append(conn)
                elif not await conn.validate():
                    to_remove.append(conn)
            
            for conn in to_remove:
                self.pool.remove(conn)
                self.logger.debug("Removed idle/invalid connection")
            
            while len(self.pool) < self.config.min_size:
                new_conn = await self._create_connection()
                if new_conn:
                    self.pool.append(new_conn)
    
    async def close(self):
        """Close pool and all connections"""
        self.state = PoolState.CLOSED
        
        if self._validation_task:
            self._validation_task.cancel()
            try:
                await self._validation_task
            except:
                pass
        
        async with self._lock:
            self.pool.clear()
        
        self.logger.info("Pool closed")
    
    def get_stats(self) -> dict:
        """Get pool statistics"""
        in_use = sum(1 for c in self.pool if c.in_use)
        idle = len(self.pool) - in_use
        
        return {
            "total": len(self.pool),
            "in_use": in_use,
            "idle": idle,
            "max_size": self.config.max_size,
            "state": self.state.value
        }


class HTTPConnectionPool(ConnectionPool):
    """HTTP client connection pool"""
    
    async def _create_conn(self):
        import aiohttp
        return aiohttp.ClientSession()
    
    async def _validate_connection(self, session) -> bool:
        return not session.closed


class DatabaseConnectionPool(ConnectionPool):
    """Database connection pool"""
    
    def __init__(self, dsn: str, factory: Callable, config: Optional[PoolConfig] = None):
        self.dsn = dsn
        super().__init__(factory, config)
    
    async def _create_conn(self):
        import asyncpg
        return await asyncpg.connect(self.dsn)
    
    async def _validate_connection(self, conn) -> bool:
        try:
            await conn.fetchval("SELECT 1")
            return True
        except:
            return False


class PoolManager:
    """Manage multiple connection pools"""
    
    def __init__(self):
        self.pools: dict[str, ConnectionPool] = {}
        self.logger = logging.getLogger(__name__)
    
    def create_pool(
        self,
        name: str,
        factory: Callable,
        config: Optional[PoolConfig] = None
    ) -> ConnectionPool:
        """Create a new pool"""
        pool = ConnectionPool(factory, config)
        self.pools[name] = pool
        return pool
    
    async def initialize_all(self):
        """Initialize all pools"""
        for pool in self.pools.values():
            await pool.initialize()
    
    async def close_all(self):
        """Close all pools"""
        for pool in self.pools.values():
            await pool.close()
    
    def get_pool(self, name: str) -> Optional[ConnectionPool]:
        """Get pool by name"""
        return self.pools.get(name)
    
    def get_all_stats(self) -> dict:
        """Get stats from all pools"""
        return {name: pool.get_stats() for name, pool in self.pools.items()}
