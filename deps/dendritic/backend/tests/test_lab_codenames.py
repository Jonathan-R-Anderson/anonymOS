"""Lab machines get a handle people can actually say.

`vulhub-1panel-cve-2024-39907` is a catalogue entry. Two researchers comparing
notes need a name, and a CVE number is exactly the thing nobody remembers — so
each machine gets an adjective-and-animal codename in the style Docker gives
containers.
"""

import os
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from services.lab_codenames import codename_for, wordlist_size  # noqa: E402

# The real catalogue's shape: a few hundred vulhub slugs.
SLUGS = ["vulhub-%s-cve-20%02d-%05d" % (product, year, num)
         for product in ("activemq", "adminer", "airflow", "apisix", "appweb",
                         "confluence", "django", "gitlab", "jenkins", "joomla",
                         "kibana", "nginx", "php", "redis", "solr", "struts2",
                         "tomcat", "weblogic", "wordpress", "zabbix")
         for year in range(18, 26)
         for num in range(1000, 1003)]


class CodenameTest(unittest.TestCase):
    def test_names_look_like_docker_names(self):
        name = codename_for("vulhub-1panel-cve-2024-39907")
        first, _, second = name.partition(" ")
        self.assertTrue(second, "expected two words, got %r" % name)
        self.assertTrue(first[0].isupper() and second[0].isupper(), name)
        self.assertNotIn("cve", name.lower())

    def test_the_same_slug_always_gets_the_same_name(self):
        # A machine's name is how people refer to it. If it moved between
        # deployments, or between restarts, it would not be a name.
        for slug in SLUGS[:50]:
            self.assertEqual(codename_for(slug), codename_for(slug))

    def test_names_are_unique_across_a_realistic_catalogue(self):
        seen = set()
        for slug in SLUGS:
            name = codename_for(slug, seen)
            self.assertNotIn(name.lower(), seen, "duplicate name %r" % name)
            seen.add(name.lower())
        self.assertEqual(len(seen), len(SLUGS))

    def test_collisions_do_not_produce_a_run_of_neighbours(self):
        # Walking +1 on collision would hand every colliding slug consecutive
        # animals of one adjective, which reads as a bug even when it is not.
        names = []
        taken = set()
        for slug in SLUGS[:40]:
            name = codename_for(slug, taken)
            names.append(name)
            taken.add(name.lower())
        adjectives = {n.split()[0] for n in names}
        self.assertGreater(len(adjectives), 20,
                           "names are clustering on too few adjectives: %r" % sorted(adjectives))

    def test_there_is_real_headroom(self):
        # Growth is the normal case here: vulhub gains entries constantly.
        self.assertGreater(wordlist_size(), 10000)

    def test_a_full_wordlist_degrades_visibly_rather_than_silently(self):
        # If every pair were taken, handing out a duplicate would be the one
        # unacceptable outcome. A numeric suffix is ugly on purpose: somebody
        # sees it and adds words.
        everything = {
            codename_for("seed-%d" % i).lower() for i in range(4000)
        }
        name = codename_for("one-more", everything)
        self.assertNotIn(name.lower(), everything)


if __name__ == "__main__":
    unittest.main()
