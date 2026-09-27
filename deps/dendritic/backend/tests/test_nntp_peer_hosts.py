"""NNTP peers may be I2P destinations or ordinary hosts, and the difference
must be decided by the address itself.

The transport is DERIVED, never configured beside the host: if it were a
separate field the two could disagree, and the failure mode of that disagreement
is dialling a peer in the clear that was written down as anonymous. Deriving it
makes that particular mistake unrepresentable.
"""

import os
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from services.nntp_hosts import (  # noqa: E402
    TRANSPORT_CLEARNET, TRANSPORT_I2P, normalize_peer_host,
)

I2P_HOST = "a" * 4 + "bcdefghijklmnopqrstuvwxyz234567" * 2 + ".b32.i2p"


class PeerHostTest(unittest.TestCase):
    def test_i2p_destination_is_recognised(self):
        host = ("abcdefghijklmnopqrstuvwxyz234567" * 2)[:52] + ".b32.i2p"
        normalized, transport = normalize_peer_host(host.upper())
        self.assertEqual(normalized, host)
        self.assertEqual(transport, TRANSPORT_I2P)

    def test_ordinary_hostname_is_clearnet(self):
        for host in ("news.tcpreset.net", "news.eternal-september.org", "example.com"):
            normalized, transport = normalize_peer_host(host)
            self.assertEqual(normalized, host)
            self.assertEqual(transport, TRANSPORT_CLEARNET)

    def test_ip_addresses_are_accepted(self):
        for host in ("192.0.2.10", "2001:db8::1"):
            _, transport = normalize_peer_host(host)
            self.assertEqual(transport, TRANSPORT_CLEARNET)

    def test_a_malformed_i2p_address_is_a_typo_not_a_hostname(self):
        # Anything ending .i2p was MEANT to be I2P. Falling back to resolving it
        # on the open internet would answer a request for anonymity by silently
        # doing the opposite.
        with self.assertRaises(ValueError):
            normalize_peer_host("tooshort.b32.i2p")
        with self.assertRaises(ValueError):
            normalize_peer_host("somenode.i2p")

    def test_junk_is_refused(self):
        for host in ("", "   ", "-leading.hyphen.net", "trailing-.net",
                     "has space.net", "a" * 300 + ".net"):
            with self.assertRaises(ValueError, msg=host):
                normalize_peer_host(host)

    def test_trailing_dot_and_case_are_normalised(self):
        normalized, _ = normalize_peer_host("  News.Example.ORG.  ")
        self.assertEqual(normalized, "news.example.org")


if __name__ == "__main__":
    unittest.main()
