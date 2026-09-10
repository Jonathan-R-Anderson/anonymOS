from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque

from fastapi import HTTPException
from redis.asyncio import Redis


class RateLimiter:
    def __init__(self, limit: int = 5, window: int = 60, redis_url: str | None = None):
        self.limit = limit
        self.window = window
        self._redis = Redis.from_url(redis_url, decode_responses=True) if redis_url else None
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(self, key: str) -> None:
        if self._redis is not None:
            bucket = int(time.time()) // self.window
            redis_key = f"gateway-register:{bucket}:{key}"
            async with self._redis.pipeline(transaction=True) as pipeline:
                pipeline.incr(redis_key)
                pipeline.expire(redis_key, self.window + 5)
                count, _ = await pipeline.execute()
            if int(count) > self.limit:
                raise HTTPException(429, "registration rate limit exceeded")
            return
        now = time.monotonic()
        async with self._lock:
            events = self._events[key]
            while events and events[0] <= now - self.window:
                events.popleft()
            if len(events) >= self.limit:
                raise HTTPException(429, "registration rate limit exceeded")
            events.append(now)

    async def close(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()
