"""The admin site map, in one place.

WHY THIS IS PYTHON AND NOT MARKUP
---------------------------------
Before this, the only navigation between admin screens was a row of fifteen
buttons hardcoded into `admin-dashboard.html`. Two consequences followed from
that and both were felt daily:

* every journey went through the dashboard, because no other page linked to a
  sibling. Getting from Scrapers to Spam Blocklist meant loading a 3,300-line
  page and finding a button on it.
* a new screen was navigable only if somebody remembered to edit that row. Two
  already existed that nobody had -- the reports queue linked nowhere at all.

Defining the map here means the shell renders it on EVERY page, a new screen is
one entry, and `test_admin_nav.py` can assert that every registered admin page
appears somewhere in it. Navigation that can silently disagree with the routes
is how dead ends happen.

HOW THE GROUPS WERE CHOSEN
--------------------------
By what an operator is doing, not by which module implements it. The old layout
grouped by neither: "Lab Image Registry" sat beside "Arcade" beside "Software
update" beside "Warrant Canary" because that is the order somebody added them.

The ordering within the list is deliberate too. MODERATION is first because it
is the only group with people waiting at the other end of it; SYSTEM is last
because it is where you go when something is wrong rather than as routine work.
"""

from collections import namedtuple


# `endpoint` is a Flask endpoint name; `danger` marks a destination whose
# primary purpose is destructive, so the shell can mark it visually. It is NOT
# "important" -- a queue of civil-rights reports is important and is not
# dangerous, and conflating the two is why the old button row had six colours
# that meant nothing.
Item = namedtuple("Item", "label endpoint danger description")
Item.__new__.__defaults__ = (False, "")

Group = namedtuple("Group", "key label items")


SITE_MAP = (
    # SCOPED TO THE NETWORK AND THE CONTRACTS (2026-08-16, by request).
    #
    # Moderation, Newsroom, Sources, Analytics and Arcade were removed. That is
    # not only a scoping decision: of the fourteen entries those five groups
    # held, ELEVEN pointed at endpoints that no longer exist -- report_review,
    # news_editor, admin.scrapers, admin.analytics_*, admin.arcade,
    # admin.codeplay_content, admin.lab_challenges and admin.torrent_monitor
    # were all deleted with their blueprints. `admin_url()` returns None for a
    # missing endpoint, so the shell quietly hid them and the map went on
    # claiming they were there.
    #
    # The two that were live -- admin.purge_search and admin.spam_blocklist --
    # are content moderation, which is what this panel is no longer for. Their
    # routes still exist and are reachable by URL; only the navigation is gone.
    Group("network", "Network & storage", (
        Item("Node releases", "admin.node_releases_admin",
             description="Publish the storage-node binary"),
        Item("DHT purge", "admin.dht_purge", danger=True,
             description="Recall and delete objects from the storage network"),
        Item("Network directive", "admin.network_directive_admin", danger=True,
             description="Fleet-wide instructions to volunteer nodes"),
    )),

    # Its own group rather than an entry under Network: deploying and governing
    # contracts is irreversible in a way nothing above it is, and a seizure or a
    # genesis mint should not sit one line below "publish the binary".
    Group("contracts", "Smart contracts", (
        Item("Contracts", "admin.contracts_console",
             description="Deploy and manage the on-chain token, registry and treasury"),
    )),

    Group("system", "System", (
        Item("Status", "admin.status_admin",
             description="Software update, health and deploy state"),
    )),
)


# Sections that live ON the dashboard rather than at their own URL. Listed so the
# shell can offer them as in-page anchors: a 3,300-line page with twenty-five
# unlabelled sections is not navigable by scrolling, and the fix that does not
# require moving every one of them at once is to name them and let the reader
# jump.
#
# Ordered by how often an operator touches them -- daily first. The old order was
# the order things were added, which put "upload file types" above "sitewide
# bans".
DASHBOARD_SECTIONS = (
    # Only the sections that are about running the NETWORK. The board, slip,
    # media, ban, captcha, wordfilter and arcade sections are still PRESENT in
    # templates/admin-dashboard.html and are simply no longer offered as jump
    # targets -- removing 3,000 lines of nested cards is a separate change and
    # a riskier one than editing this tuple.
    ("software-update", "Software update"),
    ("falco", "Falco runtime security"),
)


def resolve(endpoint_name):
    """(group_key, Item) for a Flask endpoint, or (None, None).

    Used by the shell to mark the current location. A page whose endpoint is not
    in the map still renders -- it simply has nothing highlighted -- because a
    missing nav entry should not be a 500 on a working screen.
    """
    for group in SITE_MAP:
        for item in group.items:
            if item.endpoint == endpoint_name:
                return group.key, item
    return None, None


def all_endpoints():
    return {item.endpoint for group in SITE_MAP for item in group.items}
