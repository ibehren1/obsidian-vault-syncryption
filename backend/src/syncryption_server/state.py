"""Process-wide state shared by the routers."""

import asyncio
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field

from fastapi import Request

from syncryption_server.config import Settings
from syncryption_server.db import Database
from syncryption_server.errors import ApiError
from syncryption_server.storage import BlobStore


class RateLimiter:
    """Sliding-window counters kept in memory (one container, one worker)."""

    # Drop idle keys every this many checks, so one-off addresses don't add up.
    PRUNE_EVERY = 1000

    def __init__(self, clock: Callable[[], float]):
        self.clock = clock
        self.hits: dict[str, deque[float]] = defaultdict(deque)
        self.windows: dict[str, float] = {}
        self.checks = 0

    def prune(self) -> None:
        now = self.clock()
        for key in [k for k, h in self.hits.items() if not h or h[-1] <= now - self.windows[k]]:
            del self.hits[key]
            del self.windows[key]

    def check(self, key: str, limit: int, window: float) -> None:
        self.checks += 1
        if self.checks % self.PRUNE_EVERY == 0:
            self.prune()
        now = self.clock()
        self.windows[key] = window
        hits = self.hits[key]
        while hits and hits[0] <= now - window:
            hits.popleft()
        if len(hits) >= limit:
            retry = max(1, int(hits[0] + window - now) + 1)
            raise ApiError(
                429,
                "rate_limited",
                "Too many requests. Try again later.",
                headers={"Retry-After": str(retry)},
            )
        hits.append(now)


@dataclass(eq=False)
class _Waiter:
    kicked: bool = False


class Notifier:
    """Wakes `/wait` long-polls when a vault's `seq` or `locksSeq` moves (architecture 2.3)."""

    MAX_WAITS_PER_DEVICE = 2

    def __init__(self) -> None:
        self.conditions: dict[str, asyncio.Condition] = {}
        self.waiters: dict[str, deque[tuple[str, _Waiter]]] = defaultdict(deque)

    def _condition(self, vault_id: str) -> asyncio.Condition:
        if vault_id not in self.conditions:
            self.conditions[vault_id] = asyncio.Condition()
        return self.conditions[vault_id]

    async def notify(self, vault_id: str) -> None:
        cond = self.conditions.get(vault_id)
        if cond is not None:
            async with cond:
                cond.notify_all()

    async def wait(
        self, vault_id: str, device_id: str, changed: Callable[[], bool], seconds: float
    ) -> bool:
        """Wait until `changed()` is true, the timeout passes, or the device opens a third
        wait (the oldest then returns). Returns `changed()` at the end."""
        cond = self._condition(vault_id)
        waiter = _Waiter()
        mine = self.waiters[device_id]
        mine.append((vault_id, waiter))
        while len(mine) > self.MAX_WAITS_PER_DEVICE:
            old_vault, old = mine.popleft()
            old.kicked = True
            await self.notify(old_vault)
        try:
            async with cond:
                await asyncio.wait_for(
                    cond.wait_for(lambda: waiter.kicked or changed()), timeout=seconds
                )
        except TimeoutError:
            pass
        finally:
            if (vault_id, waiter) in mine:
                mine.remove((vault_id, waiter))
            if not mine:
                self.waiters.pop(device_id, None)
        return not waiter.kicked and changed()


@dataclass
class AppState:
    settings: Settings
    db: Database
    store: BlobStore
    clock: Callable[[], float] = time.time
    notifier: Notifier = field(default_factory=Notifier)
    limiter: RateLimiter = field(init=False)
    # Striped locks so blob upload and garbage collection of the same blob never interleave.
    blob_locks: list[asyncio.Lock] = field(
        default_factory=lambda: [asyncio.Lock() for _ in range(64)]
    )

    def __post_init__(self) -> None:
        self.limiter = RateLimiter(lambda: self.clock())

    def blob_lock(self, blob_id: str) -> asyncio.Lock:
        return self.blob_locks[int(blob_id[:4], 16) % len(self.blob_locks)]

    def now(self) -> int:
        return int(self.clock())


async def get_state(request: Request) -> AppState:
    """All handlers and dependencies are async, so the database is only used from the
    event loop thread."""
    return request.app.state.ctx
