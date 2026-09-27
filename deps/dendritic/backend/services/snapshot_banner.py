"""What a reader is told when they are looking at a snapshot.

Separate from the rewriter so the wording is in one place. A reader who cannot
tell they are seeing an hour-old copy will report it as a bug, or worse, act on
stale information — so this is not decoration, it is the difference between
degraded service and misinformation.

Styles are inline. The snapshot is served when things are broken, and a banner
that depends on a stylesheet arriving is a banner that is missing exactly when
it is needed.
"""

DISABLED_NOTICE = (
    "Unavailable while syndichan is in emergency mode — nothing you type here "
    "would be saved."
)

# The class is a contract, not styling — inline styles do all the visual work.
# A page whose own controls reach the origin (the node download, say) needs to
# be able to tell that it is being served as a snapshot and switch them off
# itself. The rewriter disables forms and buttons; it cannot know that a link
# points at something only the origin can answer.
BANNER_CLASS = "dendritic-emergency-banner"

BANNER_HTML = """
<div role="status" class="dendritic-emergency-banner"
     style="background:#4a2c00;color:#ffd9a0;padding:10px 14px;
     font:14px/1.5 system-ui,sans-serif;border-bottom:2px solid #ffb84d;
     text-align:center">
  <strong>Emergency cached copy.</strong>
  syndichan is not reachable right now, so you are reading a saved snapshot
  from <strong>%s</strong>. It is read-only: posting, logging in, purchases and
  transfers are all disabled, and newer posts are not shown.
</div>
"""
