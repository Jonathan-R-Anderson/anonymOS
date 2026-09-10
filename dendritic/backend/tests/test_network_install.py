"""The one-line install command on /network.

The command is the one thing on that page a visitor is invited to paste into a
root-capable shell, and it is assembled in the browser from whatever they
clicked on the topology diagram. That combination is worth pinning down:

  * a command that is half-built, or that carries a flag the installer does not
    take, fails on a stranger's machine where nobody can see it;
  * a second listener on the selection would eventually disagree with the first,
    and the visible line would stop matching the highlighted boxes;
  * the flag shape is a contract with an installer that lives outside this
    repository, so it is written down here rather than left to be rediscovered.

These are text assertions against the template because that is where the logic
lives — there is no server-side rendering of the command to call.
"""

import os
import pathlib
import re
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

TEMPLATE = pathlib.Path(BACKEND) / "templates" / "network.html"

# The site was renamed syndichan.org -> dendritic.network. This constant was
# not followed, so both tests here failed against a template that is correct
# -- the same stale-identifier shape as the storage-client -> dendritic-node
# path in test_compute_catalogue, and it was likewise counted as an orphan
# of a deleted feature (item 4.13). templates/network.html contains no
# occurrence of the old domain at all.
INSTALL_URL = "https://dendritic.network/install.sh"
PLAIN_COMMAND = "curl -fsSL %s | sh" % INSTALL_URL


def template_source():
    return TEMPLATE.read_text()


def script_source():
    """The page's inline script, without the surrounding markup."""
    match = re.search(r"<script>\n(.*?)\n</script>", template_source(), re.S)
    assert match, "network.html has no inline script"
    return match.group(1)


class InstallCommandTest(unittest.TestCase):
    def setUp(self):
        if not TEMPLATE.exists():
            self.skipTest("network.html is not present")

    def test_the_markup_already_holds_a_runnable_command(self):
        """Before a single line of JavaScript runs, and if none ever does.

        The command is server-rendered as the plain form and then rewritten by
        the script. If the static text were a placeholder — "…", or a line with
        an empty --role — a reader with JavaScript off, or one who copied it in
        the instant before the script ran, would take away something that does
        not work.
        """
        markup = template_source()
        self.assertIn(
            '<code id="nw-install-cmd">%s</code>' % PLAIN_COMMAND, markup)
        static = re.search(r'<code id="nw-install-cmd">(.*?)</code>', markup, re.S)
        self.assertNotIn("--role", static.group(1))

    def test_the_flag_shape_is_the_documented_one(self):
        """`| sh -s -- --role a,b`.

        `sh -s --` is not decoration: without it the flags are consumed by sh
        and the installer is handed nothing, which fails silently by installing
        the wrong thing rather than loudly by erroring. The role list is one
        comma-separated value under a singular --role, matching the `role=`
        query parameter /download/node already accepts.
        """
        script = script_source()
        self.assertIn('var INSTALL_URL = "%s";' % INSTALL_URL, script)
        self.assertIn(' -s -- --role ', script)
        self.assertIn('roles.join(",")', script)

    def test_roles_are_emitted_in_a_stable_order(self):
        """Click order must not change the command.

        Two people who chose the same roles should be able to compare the lines
        they were given. Ordering by the server's ROLES keys rather than by
        Set insertion order is what makes that true.
        """
        script = script_source()
        self.assertIn("var ROLE_ORDER = Object.keys(needsPort);", script)
        self.assertIn("ROLE_ORDER.filter(", script)

    def test_one_updater_owns_the_selection(self):
        """refreshInstall is called from refresh(), and from nowhere else.

        The page already has an update path that reads the selection Set — the
        summary, the download link and the port warning all hang off it. A
        second listener on the same Set is how a page ends up showing a command
        for roles that are no longer lit up.
        """
        script = script_source()
        self.assertEqual(1, len(re.findall(r"function refreshInstall\(", script)))
        calls = [m.start() for m in re.finditer(r"(?<!function )refreshInstall\(", script)]
        self.assertEqual(1, len(calls), "refreshInstall should have exactly one call site")
        refresh_at = script.index("function refresh() {")
        self.assertGreater(calls[0], refresh_at,
                           "the only call must be inside refresh()")

    def test_the_copy_button_has_a_fallback_and_cannot_do_nothing(self):
        """Async clipboard, then execCommand, then the text left selected.

        navigator.clipboard is unavailable outside a secure context, which
        includes plain HTTP and an eepsite — both ordinary ways to reach this
        page. A copy button that quietly no-ops there is worse than no button,
        so the failure path still selects the command and says how to copy it.
        """
        script = script_source()
        self.assertIn("navigator.clipboard", script)
        self.assertIn('document.execCommand("copy")', script)
        self.assertIn("selectNodeContents", script)
        self.assertIn("Ctrl-C", script)

    def test_the_control_is_a_real_button_with_a_live_region(self):
        markup = template_source()
        self.assertIn('<button type="button"', markup)
        self.assertIn('id="nw-copy"', markup)
        self.assertRegex(markup, r'id="nw-copy-status"[^>]*aria-live="polite"')
        self.assertRegex(markup, r'id="nw-copy-status"[^>]*role="status"')

    def test_the_command_block_is_reachable_by_keyboard(self):
        """It scrolls sideways when the role list is long, so it needs focus."""
        self.assertRegex(template_source(),
                         r'<pre class="nw__cmd-text" id="nw-install-pre"\s+tabindex="0"')

    def test_it_uses_theme_variables_rather_than_fixed_colours(self):
        """The dark themes supply no --bs-* and no colour of their own.

        A hardcoded colour here is invisible text on midnight and cyberpunk, and
        Bootstrap's own <pre>/<code> rules are exactly such a colour unless they
        are overridden — which is why the block pins itself back to inherit.
        """
        markup = template_source()
        block = markup[markup.index(".nw__cmd {"):markup.index(".nw__copy-status")]
        self.assertNotIn("--bs-", block)
        self.assertIn("var(--sc-accent", block)
        self.assertIn("color: inherit", block)


if __name__ == "__main__":
    unittest.main()
