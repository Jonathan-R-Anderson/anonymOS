import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from config_parser import parse_config


class TestParseConfig(unittest.TestCase):
    def test_comments_and_blank_lines(self):
        cfg_content = """\
# This is a comment
host = localhost

# Another comment
port=8080


username = admin
"""
        with tempfile.NamedTemporaryFile('w+', delete=False) as tmp:
            tmp.write(cfg_content)
            tmp.flush()
            path = tmp.name
        try:
            result = parse_config(path)
        finally:
            os.unlink(path)

        expected = {
            'host': 'localhost',
            'port': '8080',
            'username': 'admin',
        }
        self.assertEqual(result, expected)


if __name__ == '__main__':
    unittest.main()
