"""W-TinyLFU cache for media bytes, in front of the DHT read path.

Once local shard copies are pruned, a miss costs an I2P round trip measured in
seconds, so what this cache keeps matters far more than in an ordinary web
cache. Three properties drive the design:

CAPACITY IS IN BYTES, NOT ENTRIES. Media ranges from a few KB to tens of MB. An
entry-counted cache sized for images will hold a handful of videos and blow the
process memory limit -- which is not hypothetical here: reading whole
attachments into memory is exactly what pushed the backend container from
2.78 GiB to 3.76 GiB against a 4 GiB limit during the migration.

ADMISSION, NOT JUST EVICTION. Plain LRU is defeated by scans: a crawler walking
an archive evicts the entire hot set on its way past. TinyLFU only admits a
candidate if it is estimated to be MORE frequent than the victim it would
displace, so a one-off request cannot evict a popular image.

A MISS MUST NOT MULTIPLY. Fifty people opening the same thread must produce one
fetch, not fifty (see SingleFlight), and an object that is currently
unreachable must not be retried per-request (see the negative cache) -- one
offline volunteer would otherwise turn into an I2P hammering loop.
"""
import collections
import hashlib
import struct
import threading
import time

# `shared` is imported lazily inside _configured_capacity() rather than here:
# the cache is pure data-structure code and importing it must not require a
# working Flask app, or it cannot be unit tested apart from the application.

# Segment split follows the W-TinyLFU paper: a small LRU "window" absorbs new
# arrivals so a burst cannot be rejected outright, and the main cache is an
# SLRU split into probation and protected.
_WINDOW_FRACTION = 0.01
_PROTECTED_FRACTION = 0.80
_NEGATIVE_TTL_SECONDS = 30.0
_SKETCH_DEPTH = 4


class _CountMinSketch:
    """4-bit counting sketch with periodic halving.

    Halving is what makes this track *changing* popularity instead of whatever
    was popular when the process started -- without it, yesterday's hot set
    would outrank today's forever.
    """

    def __init__(self, width):
        self._width = max(64, width)
        self._counters = bytearray(self._width * _SKETCH_DEPTH)
        self._additions = 0
        self._sample = self._width * 10

    def _positions(self, key):
        digest = hashlib.blake2b(str(key).encode("utf-8"), digest_size=16).digest()
        for index in range(_SKETCH_DEPTH):
            (value,) = struct.unpack_from("<I", digest, index * 4)
            yield index * self._width + (value % self._width)

    def increment(self, key):
        for position in self._positions(key):
            if self._counters[position] < 15:
                self._counters[position] += 1
        self._additions += 1
        if self._additions >= self._sample:
            self._halve()

    def estimate(self, key):
        return min(self._counters[position] for position in self._positions(key))

    def _halve(self):
        counters = self._counters
        for index in range(len(counters)):
            counters[index] >>= 1
        self._additions = 0


class SingleFlight:
    """Collapses concurrent misses for the same key into one fetch."""

    def __init__(self):
        self._lock = threading.Lock()
        self._inflight = {}

    def do(self, key, producer):
        with self._lock:
            event = self._inflight.get(key)
            if event is None:
                event = {"event": threading.Event(), "value": None, "error": None}
                self._inflight[key] = event
                leader = True
            else:
                leader = False
        if not leader:
            # Followers wait for the leader's result rather than issuing their
            # own fetch. Bounded so a hung I2P read cannot pin them forever.
            event["event"].wait(timeout=90)
            if event["error"]:
                raise event["error"]
            return event["value"]
        try:
            event["value"] = producer()
        except Exception as error:  # noqa: BLE001 - re-raised to every waiter
            event["error"] = error
        finally:
            with self._lock:
                self._inflight.pop(key, None)
            event["event"].set()
        if event["error"]:
            raise event["error"]
        return event["value"]


class MediaCache:
    def __init__(self, capacity_bytes):
        self.capacity = int(capacity_bytes)
        window = int(self.capacity * _WINDOW_FRACTION)
        main = self.capacity - window
        self._budgets = {
            "window": max(window, 1),
            "protected": max(int(main * _PROTECTED_FRACTION), 1),
            "probation": max(main - int(main * _PROTECTED_FRACTION), 1),
        }
        self._segments = {
            name: collections.OrderedDict() for name in self._budgets
        }
        self._sizes = {name: 0 for name in self._budgets}
        self._sketch = _CountMinSketch(width=4096)
        self._lock = threading.RLock()
        self._negative = {}
        self.hits = 0
        self.misses = 0
        self.admissions = 0
        self.rejections = 0

    # -- negative cache ---------------------------------------------------
    def mark_unavailable(self, key):
        with self._lock:
            self._negative[key] = time.monotonic() + _NEGATIVE_TTL_SECONDS

    def is_unavailable(self, key):
        with self._lock:
            expiry = self._negative.get(key)
            if expiry is None:
                return False
            if expiry < time.monotonic():
                del self._negative[key]
                return False
            return True

    def clear_unavailable(self, key):
        with self._lock:
            self._negative.pop(key, None)

    def drop(self, key):
        """Forget the bytes held for `key`. Returns whether anything was held.

        Needed by the purge path, and only by it. mark_unavailable() is NOT a
        substitute: get() searches the segments before anything consults the
        negative cache, so an entry that is merely marked unavailable keeps
        being served until it ages out. A purge that leaves the bytes in RAM has
        not purged them from this worker.
        """
        with self._lock:
            found = False
            for name in ("window", "probation", "protected"):
                segment = self._segments[name]
                if key in segment:
                    self._sizes[name] -= len(segment.pop(key))
                    found = True
            return found

    # -- reads ------------------------------------------------------------
    def get(self, key):
        with self._lock:
            self._sketch.increment(key)
            for name in ("window", "probation", "protected"):
                segment = self._segments[name]
                if key in segment:
                    value = segment.pop(key)
                    self._sizes[name] -= len(value)
                    self.hits += 1
                    # A second hit promotes into protected, so the hot set is
                    # the set that has actually been *re*-read.
                    target = "protected" if name != "window" else "window"
                    self._insert(target, key, value)
                    return value
            self.misses += 1
            return None

    # -- writes -----------------------------------------------------------
    def put(self, key, value, recent=False):
        """Admit `value`. `recent` bypasses the frequency filter.

        Recency-based admission: content from an active thread has no access
        history yet and would lose every frequency comparison against the
        established hot set, so it would never get cached at exactly the moment
        it is about to be requested most.
        """
        if not value or len(value) > self._budgets["protected"]:
            # Never let one object evict the whole cache.
            return False
        with self._lock:
            self.clear_unavailable(key)
            self._insert("window", key, value)
            if recent:
                self.admissions += 1
            self._evict(force_admit=recent)
            return True

    def _insert(self, segment_name, key, value):
        segment = self._segments[segment_name]
        segment[key] = value
        segment.move_to_end(key)
        self._sizes[segment_name] += len(value)
        self._trim_protected()

    def _trim_protected(self):
        # Protected overflow demotes to probation rather than being dropped --
        # it was hot recently and deserves to compete, not disappear.
        while self._sizes["protected"] > self._budgets["protected"]:
            key, value = self._segments["protected"].popitem(last=False)
            self._sizes["protected"] -= len(value)
            self._segments["probation"][key] = value
            self._sizes["probation"] += len(value)

    def _evict(self, force_admit=False):
        while self._sizes["window"] > self._budgets["window"]:
            key, value = self._segments["window"].popitem(last=False)
            self._sizes["window"] -= len(value)
            if not self._admit(key, force_admit):
                self.rejections += 1
                continue
            self.admissions += 1
            self._segments["probation"][key] = value
            self._sizes["probation"] += len(value)
        while self._sizes["probation"] > self._budgets["probation"]:
            _key, value = self._segments["probation"].popitem(last=False)
            self._sizes["probation"] -= len(value)

    def _admit(self, candidate_key, force_admit):
        if force_admit:
            return True
        probation = self._segments["probation"]
        if not probation:
            return True
        victim_key = next(iter(probation))
        return self._sketch.estimate(candidate_key) > self._sketch.estimate(victim_key)

    def stats(self):
        with self._lock:
            total = self.hits + self.misses
            return {
                "capacity_bytes": self.capacity,
                "used_bytes": sum(self._sizes.values()),
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": round(self.hits / total, 4) if total else None,
                "admissions": self.admissions,
                "rejections": self.rejections,
                "negative_entries": len(self._negative),
            }


def _configured_capacity():
    try:
        from shared import app

        return int(app.config.get("MEDIA_CACHE_BYTES") or 0) or (512 << 20)
    except Exception:
        return 512 << 20


_cache = None
_flight = SingleFlight()
_cache_lock = threading.Lock()


def cache():
    global _cache
    if _cache is None:
        with _cache_lock:
            if _cache is None:
                _cache = MediaCache(_configured_capacity())
    return _cache


def single_flight():
    return _flight
