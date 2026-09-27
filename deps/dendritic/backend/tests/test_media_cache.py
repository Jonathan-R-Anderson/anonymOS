import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.media_cache import MediaCache, SingleFlight  # noqa: E402


class MediaCacheTests(unittest.TestCase):
    def test_capacity_is_measured_in_bytes(self):
        """Entry-counted caches size for images and then hold two videos."""
        cache = MediaCache(capacity_bytes=100_000)
        cache.put("small", b"x" * 1_000)
        self.assertLessEqual(cache.stats()["used_bytes"], 100_000)
        # One object must never be allowed to evict everything.
        self.assertFalse(cache.put("huge", b"x" * 500_000))

    def test_scan_does_not_evict_the_hot_set(self):
        """The whole reason for an admission filter.

        A crawler walking an archive is a stream of one-off keys. Under plain
        LRU each one evicts something popular; TinyLFU should refuse to admit
        them because they are less frequent than what they would displace.
        """
        cache = MediaCache(capacity_bytes=200_000)
        hot = b"h" * 1_000
        cache.put("hot", hot, recent=True)
        for _ in range(30):          # make "hot" genuinely frequent
            cache.get("hot")
        for index in range(500):     # the scan
            cache.put("cold-%d" % index, b"c" * 1_000)
        self.assertIsNotNone(cache.get("hot"), "hot entry was evicted by a scan")
        self.assertGreater(cache.rejections, 0, "admission filter never rejected")

    def test_recent_admission_bypasses_frequency(self):
        """New content from an active thread has no history to win with."""
        cache = MediaCache(capacity_bytes=50_000)
        for index in range(200):
            cache.put("established-%d" % index, b"e" * 500)
            for _ in range(5):
                cache.get("established-%d" % index)
        cache.put("brand-new", b"n" * 500, recent=True)
        self.assertIsNotNone(cache.get("brand-new"))

    def test_negative_cache_expires(self):
        cache = MediaCache(capacity_bytes=10_000)
        cache.mark_unavailable("gone")
        self.assertTrue(cache.is_unavailable("gone"))
        # A successful put must clear the tombstone, or a recovered object
        # stays invisible for the rest of the TTL.
        cache.put("gone", b"back")
        self.assertFalse(cache.is_unavailable("gone"))

    def test_single_flight_collapses_concurrent_misses(self):
        """Fifty viewers of one thread must produce one I2P fetch."""
        flight = SingleFlight()
        calls = []
        barrier = threading.Barrier(8)

        def producer():
            calls.append(1)
            time.sleep(0.05)
            return b"value"

        def worker(results, index):
            barrier.wait()
            results[index] = flight.do("same-key", producer)

        results = [None] * 8
        threads = [threading.Thread(target=worker, args=(results, i)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(calls), 1, "producer ran more than once")
        self.assertTrue(all(value == b"value" for value in results))

    def test_single_flight_propagates_failure_to_all_waiters(self):
        """A follower must not treat the leader's failure as a cache-able miss."""
        flight = SingleFlight()
        barrier = threading.Barrier(4)

        def producer():
            raise RuntimeError("peer unreachable")

        errors = []

        def worker():
            barrier.wait()
            try:
                flight.do("failing", producer)
            except RuntimeError:
                errors.append(1)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(errors), 4)


if __name__ == "__main__":
    unittest.main()
