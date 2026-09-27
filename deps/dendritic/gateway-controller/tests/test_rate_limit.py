import pytest
from fastapi import HTTPException

from backend.rate_limit import RateLimiter


@pytest.mark.asyncio
async def test_five_registrations_per_minute():
    limiter = RateLimiter(limit=5, window=60)
    for _ in range(5):
        await limiter.check("8.8.8.8")
    with pytest.raises(HTTPException) as error:
        await limiter.check("8.8.8.8")
    assert error.value.status_code == 429

