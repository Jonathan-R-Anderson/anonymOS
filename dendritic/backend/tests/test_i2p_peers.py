import io
import unittest
from unittest import mock

from services.i2p_addresses import is_i2p_host, normalize_i2p_host
from services.nntpchan.client import NNTPError, _i2p_socks_connect


DESTINATION = ("a" * 52) + ".b32.i2p"


class _FakeSocket:
    def __init__(self, response):
        self.response = io.BytesIO(response)
        self.sent = bytearray()
        self.closed = False

    def sendall(self, value):
        self.sent.extend(value)

    def recv(self, size):
        return self.response.read(size)

    def close(self):
        self.closed = True


class I2PPeerTest(unittest.TestCase):
    def test_only_base32_i2p_destinations_are_accepted(self):
        self.assertEqual(DESTINATION, normalize_i2p_host(DESTINATION.upper()))
        self.assertTrue(is_i2p_host(DESTINATION))
        for invalid in ("192.0.2.1", "peer.example", "localhost", "a" * 52):
            self.assertFalse(is_i2p_host(invalid))
            with self.assertRaises(ValueError):
                normalize_i2p_host(invalid)

    def test_nntp_connect_uses_socks_domain_request_without_dns(self):
        fake = _FakeSocket(
            b"\x05\x00"              # no-auth accepted
            b"\x05\x00\x00\x01"     # connect accepted, IPv4 bind address
            b"\x00\x00\x00\x00\x00\x00"
        )
        with mock.patch(
            "services.nntpchan.client.socket.create_connection",
            return_value=fake,
        ) as connect:
            result = _i2p_socks_connect(DESTINATION, 119, 30)
        self.assertIs(result, fake)
        connect.assert_called_once_with(("127.0.0.1", 4447), 30)
        encoded = DESTINATION.encode("ascii")
        self.assertIn(b"\x05\x01\x00\x03" + bytes((len(encoded),)) + encoded, fake.sent)

    def test_clearnet_destination_never_reaches_proxy(self):
        with mock.patch("services.nntpchan.client.socket.create_connection") as connect:
            with self.assertRaises(ValueError):
                _i2p_socks_connect("192.0.2.1", 119, 30)
        connect.assert_not_called()

    def test_proxy_failure_has_no_direct_fallback(self):
        with mock.patch(
            "services.nntpchan.client.socket.create_connection",
            side_effect=OSError("proxy unavailable"),
        ) as connect:
            with self.assertRaises(OSError):
                _i2p_socks_connect(DESTINATION, 119, 30)
        connect.assert_called_once_with(("127.0.0.1", 4447), 30)


if __name__ == "__main__":
    unittest.main()
