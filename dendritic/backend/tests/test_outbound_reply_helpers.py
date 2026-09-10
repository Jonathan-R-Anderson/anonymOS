import unittest

from services.outbound_quote import (
    normalized_body_digest,
    normalized_idempotency_key,
    translate_source_quotes,
)


class OutboundReplyHelpersTest(unittest.TestCase):
    def test_translates_only_structured_quote_ids(self):
        self.assertEqual(
            ">>987654\nhello >>1234",
            translate_source_quotes(
                ">>5000001\nhello >>1234",
                '{"5000001":"987654"}',
            ),
        )

    def test_invalid_mapping_is_ignored(self):
        self.assertEqual(">>42", translate_source_quotes(">>42", '{"42":"bad id"}'))
        self.assertEqual(">>42", translate_source_quotes(">>42", "not-json"))

    def test_does_not_replace_a_number_prefix(self):
        self.assertEqual(
            ">>420",
            translate_source_quotes(">>420", '{"42":"999"}'),
        )

    def test_body_digest_normalizes_whitespace(self):
        self.assertEqual(
            normalized_body_digest("hello\n  world"),
            normalized_body_digest(" hello world "),
        )

    def test_valid_idempotency_key_is_preserved(self):
        key = "browser-generated_key-1234"
        self.assertEqual(key, normalized_idempotency_key(key))

    def test_invalid_idempotency_key_is_replaced(self):
        generated = normalized_idempotency_key("short")
        self.assertGreaterEqual(len(generated), 16)
        self.assertNotEqual("short", generated)


if __name__ == "__main__":
    unittest.main()
