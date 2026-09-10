import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scraper_client  # noqa: E402


class ScraperURLResolutionTests(unittest.TestCase):
    """Guards the bug that made every scraper report "unreachable" in production.

    /.dockerenv is created by the Docker daemon and does not exist under
    k3s/containerd, so the loopback-rewrite keyed on it never fired in the
    cluster. The stale development .env values (localhost:8002-8005) were then
    used verbatim, and the admin page showed "scraper unreachable" for every
    source while all five aggregators were healthy and answering on their
    service names.
    """

    def setUp(self):
        self._saved = {
            key: os.environ.get(key)
            for key in (
                "KUBERNETES_SERVICE_HOST",
                "FOURCHAN_AGGREGATOR_URL",
                "GENERIC_AGGREGATOR_URL",
            )
        }

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_loopback_is_rewritten_to_service_name_in_kubernetes(self):
        os.environ["KUBERNETES_SERVICE_HOST"] = "10.43.0.1"
        os.environ["FOURCHAN_AGGREGATOR_URL"] = "http://localhost:8002"
        self.assertEqual(
            scraper_client._url_for("4chan"), "http://fourchan-aggregator:8000"
        )

    def test_generic_host_maps_to_the_shared_generic_scraper(self):
        """Generic chans use their HOST as source_type, so a literal lookup
        misses and they would fall through unrewritten."""
        os.environ["KUBERNETES_SERVICE_HOST"] = "10.43.0.1"
        os.environ["GENERIC_AGGREGATOR_URL"] = "http://localhost:8006"
        self.assertEqual(
            scraper_client._url_for("lainchan.org"), "http://generic-aggregator:8000"
        )

    def test_outside_kubernetes_the_configured_url_is_left_alone(self):
        """Local development must keep pointing at loopback."""
        os.environ.pop("KUBERNETES_SERVICE_HOST", None)
        os.environ["FOURCHAN_AGGREGATOR_URL"] = "http://localhost:8002"
        if os.path.exists("/.dockerenv"):
            self.skipTest("running inside Docker; rewrite is expected there")
        self.assertEqual(scraper_client._url_for("4chan"), "http://localhost:8002")

    def test_a_real_service_url_is_never_rewritten(self):
        """Only loopback is redirected -- an explicit host must win."""
        os.environ["KUBERNETES_SERVICE_HOST"] = "10.43.0.1"
        os.environ["FOURCHAN_AGGREGATOR_URL"] = "http://fourchan-aggregator:8000"
        self.assertEqual(
            scraper_client._url_for("4chan"), "http://fourchan-aggregator:8000"
        )


if __name__ == "__main__":
    unittest.main()
