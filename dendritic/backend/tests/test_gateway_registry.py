import unittest
from unittest import mock

from services import gateway_registry


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class GatewayRegistryTest(unittest.TestCase):
    def setUp(self):
        gateway_registry.reset_cache()

    def tearDown(self):
        gateway_registry.reset_cache()

    @mock.patch(
        "services.gateway_registry.latlon_for_ip",
        return_value=(45.5, -73.6, "CA"),
    )
    @mock.patch("services.gateway_registry.requests.get")
    def test_verified_gateway_is_normalized_for_green_only_map_marker(
        self, get, _geo
    ):
        get.return_value = _Response(
            [
                {
                    "node_id": "12D3KooWGatewayIdentity",
                    "hostname": "gw-example.syndichan.org",
                    "ip": "192.0.2.10",
                    "port": 443,
                    "latency": 12.5,
                    "healthy": True,
                    "verified": True,
                    "tls_valid": True,
                    "last_seen": "2026-07-28T07:00:00Z",
                    "registration_expires_at": "2026-07-28T07:05:00Z",
                }
            ]
        )

        values, error = gateway_registry.active_gateways(now=1)

        self.assertIsNone(error)
        self.assertEqual(1, len(values))
        self.assertFalse(values[0]["storage"])
        self.assertTrue(values[0]["gateway"])
        self.assertTrue(values[0]["healthy"])
        self.assertTrue(values[0]["verified"])
        self.assertEqual("https://gw-example.syndichan.org/readyz", values[0]["status_url"])

    @mock.patch(
        "services.gateway_registry.latlon_for_ip",
        return_value=(45.5, -73.6, "CA"),
    )
    @mock.patch("services.gateway_registry.requests.get")
    def test_short_cache_prevents_one_controller_request_per_map_poll(
        self, get, _geo
    ):
        get.return_value = _Response(
            [
                {
                    "node_id": "12D3KooWGatewayIdentity",
                    "hostname": "gw-example.syndichan.org",
                    "ip": "192.0.2.10",
                    "healthy": True,
                    "verified": True,
                    "tls_valid": True,
                }
            ]
        )

        gateway_registry.active_gateways(now=1)
        gateway_registry.active_gateways(now=5)

        self.assertEqual(1, get.call_count)

    @mock.patch(
        "services.gateway_registry.latlon_for_ip",
        return_value=(45.5, -73.6, "CA"),
    )
    @mock.patch("services.gateway_registry.requests.get")
    def test_legacy_controller_response_still_draws_verified_gateway(
        self, get, _geo
    ):
        get.return_value = _Response(
            [
                {
                    "hostname": "gw-example.syndichan.org",
                    "ip": "192.0.2.10",
                    "latency": 8.0,
                }
            ]
        )

        values, error = gateway_registry.active_gateways(now=1)

        self.assertIsNone(error)
        self.assertEqual("gateway:gw-example.syndichan.org", values[0]["node_id"])
        self.assertTrue(values[0]["healthy"])
        self.assertTrue(values[0]["verified"])
        self.assertTrue(values[0]["tls_valid"])

    @mock.patch(
        "services.gateway_registry.latlon_for_ip",
        return_value=(45.5, -73.6, "CA"),
    )
    @mock.patch("services.gateway_registry.requests.get")
    def test_controller_failure_keeps_last_known_marker_but_reports_stale(
        self, get, _geo
    ):
        get.return_value = _Response(
            [
                {
                    "node_id": "12D3KooWGatewayIdentity",
                    "hostname": "gw-example.syndichan.org",
                    "ip": "192.0.2.10",
                    "healthy": True,
                    "verified": True,
                    "tls_valid": True,
                }
            ]
        )
        gateway_registry.active_gateways(now=1)
        get.side_effect = RuntimeError("controller offline")

        values, error = gateway_registry.active_gateways(now=20)

        self.assertEqual(1, len(values))
        self.assertIn("controller offline", error)


if __name__ == "__main__":
    unittest.main()
