import unittest

from services.source_adapters import adapter_by_id, adapter_for_source


class SourceAdapterRegistryTest(unittest.TestCase):
    def test_matches_only_exact_allowlisted_hosts(self):
        adapter = adapter_for_source(
            "4chan",
            "https://boards.4chan.org/g/thread/123456",
        )
        self.assertIsNotNone(adapter)
        self.assertEqual("fourchan", adapter.id)
        self.assertIsNone(adapter_for_source(
            "4chan",
            "https://boards.4chan.org.attacker.example/g/thread/123456",
        ))

    def test_rejects_non_tls_and_wrong_path(self):
        self.assertIsNone(adapter_for_source(
            "7chan",
            "http://7chan.org/b/res/123.html",
        ))
        self.assertIsNone(adapter_for_source(
            "7chan",
            "https://7chan.org/b/catalog.html",
        ))

    def test_adapter_version_is_part_of_lookup(self):
        self.assertIsNotNone(adapter_by_id("vichan_7chan", "1.0.0"))
        self.assertIsNone(adapter_by_id("vichan_7chan", "0.9.0"))


if __name__ == "__main__":
    unittest.main()
