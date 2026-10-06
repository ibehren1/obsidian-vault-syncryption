"""Process-wide state shared by the routers."""

import asyncio
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from fastapi import Request

from syncryption_server.config import Settings
from syncryption_server.db import Database
from syncryption_server.encoding import rfc3339
from syncryption_server.errors import ApiError, maintenance
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

    def full(self, key: str, limit: int, window: float) -> bool:
        """True when `key` already has `limit` hits in the window. Doesn't add a hit."""
        now = self.clock()
        return sum(1 for t in self.hits.get(key, ()) if t > now - window) >= limit

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
        # Counts the notifications per vault, so one sent while `changed()` runs isn't lost.
        self.generations: dict[str, int] = defaultdict(int)

    def _condition(self, vault_id: str) -> asyncio.Condition:
        if vault_id not in self.conditions:
            self.conditions[vault_id] = asyncio.Condition()
        return self.conditions[vault_id]

    async def notify(self, vault_id: str) -> None:
        self.generations[vault_id] += 1
        cond = self.conditions.get(vault_id)
        if cond is not None:
            async with cond:
                cond.notify_all()

    async def notify_all(self) -> None:
        for vault_id in list(self.conditions):
            await self.notify(vault_id)

    async def wait(
        self,
        vault_id: str,
        device_id: str,
        changed: Callable[[], Awaitable[bool]],
        seconds: float,
    ) -> bool:
        """Wait until `changed()` is true, the timeout passes, or the device opens a third
        wait (the oldest then returns). `changed()` runs at the start and after each
        notification for the vault. Returns `changed()` at the end."""
        cond = self._condition(vault_id)
        deadline = asyncio.get_running_loop().time() + seconds
        waiter = _Waiter()
        mine = self.waiters[device_id]
        mine.append((vault_id, waiter))
        while len(mine) > self.MAX_WAITS_PER_DEVICE:
            old_vault, old = mine.popleft()
            old.kicked = True
            await self.notify(old_vault)
        try:
            while not waiter.kicked:
                seen = self.generations[vault_id]
                if await changed():
                    break
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                try:
                    async with cond:
                        await asyncio.wait_for(
                            cond.wait_for(
                                lambda seen=seen: (
                                    waiter.kicked or self.generations[vault_id] != seen
                                )
                            ),
                            timeout=remaining,
                        )
                except TimeoutError:
                    break
        finally:
            if (vault_id, waiter) in mine:
                mine.remove((vault_id, waiter))
            if not mine:
                self.waiters.pop(device_id, None)
        return not waiter.kicked and await changed()


@dataclass(frozen=True)
class Maintenance:
    """Maintenance mode, on since `since` (Unix seconds), with the admin's optional note."""

    since: int
    message: str | None = None


def load_maintenance(db: Database) -> Maintenance | None:
    row = db.one("SELECT since, message FROM maintenance WHERE id = 1")
    return Maintenance(row["since"], row["message"]) if row else None


@dataclass
class AppState:
    settings: Settings
    db: Database
    store: BlobStore
    clock: Callable[[], float] = time.time
    notifier: Notifier = field(default_factory=Notifier)
    limiter: RateLimiter = field(init=False)
    # A copy of the `maintenance` row, so requests don't query it. Only the admin changes it.
    maintenance: Maintenance | None = None
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

    def maintenance_error(self) -> ApiError | None:
        """The 503 every `/api/v1` request gets while maintenance is on, else None."""
        m = self.maintenance
        if m is None:
            return None
        return maintenance(self.settings.admin_contact, m.message, rfc3339(m.since))


async def get_state(request: Request) -> AppState:
    """The app's state. Handlers run their queries on the database thread (`Database.run`)."""
    return request.app.state.ctx
