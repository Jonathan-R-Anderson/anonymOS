"""Keep the controller's managed DNS zone pointed wherever the network is.

The controller writes `gw*.<zone>` records. If the network moves and the zone
stays baked into a ConfigMap, every gateway comes up under a name nothing points
at any more — so the zone follows the signed directive.

WHAT THIS DELIBERATELY DOES NOT DO
It does not delete the old zone's records. The Name.com client is scoped to one
domain, so when the zone changes the previous domain simply stops being managed
and its records stay exactly as they were. That is the right behaviour during a
move: the old name should keep resolving and keep handing readers forward for as
long as it still answers. Tearing it down the moment a directive lands would
strand everyone holding an old link at precisely the worst moment.

FAILING TO FETCH IS NOT A REASON TO CHANGE ANYTHING
Every failure path here returns the zone already in use. A controller that fell
back to a default because one HTTP request timed out would rewrite the DNS for
every gateway in the network over a transient error.
"""

from __future__ import annotations

import logging
import time

import httpx

from backend.directive import is_effective, sources, verify_document, zone_from

logger = logging.getLogger(__name__)

# Rarely. This changes almost never, and each check is a request to a host that
# may no longer be ours.
DEFAULT_REFRESH_SECONDS = 900


class DirectiveTracker:
    """Holds the verified directive, and the zone that follows from it."""

    def __init__(self, configured_domain: str, pinned_wallet: str,
                 extra_sources=(), refresh_seconds: int = DEFAULT_REFRESH_SECONDS,
                 client: httpx.AsyncClient | None = None):
        self.configured_domain = configured_domain
        self.pinned_wallet = (pinned_wallet or "").strip().lower()
        self.sources = sources(configured_domain, extra_sources)
        self.refresh_seconds = refresh_seconds
        self._client = client
        self._directive: dict | None = None
        self._checked_at = 0.0

    @property
    def zone(self) -> str:
        """The domain to manage right now."""
        return zone_from(self._directive, self.configured_domain)

    @property
    def sequence(self) -> int:
        try:
            return int((self._directive or {}).get("sequence") or 0)
        except (TypeError, ValueError):
            return 0

    async def refresh(self, now: float | None = None) -> str:
        """Poll for a newer directive. Returns the zone to manage."""
        now = time.time() if now is None else now
        if not self.pinned_wallet:
            # Loud once per refresh interval, then inert. A controller with no
            # pinned wallet cannot tell a real directive from anyone else's, and
            # polling anyway would mean the first plausible document rewrites
            # DNS for the whole network.
            if now - self._checked_at >= self.refresh_seconds:
                self._checked_at = now
                logger.warning(
                    "no directive wallet is pinned, so the managed zone stays %s "
                    "and directives are ignored", self.configured_domain)
            return self.zone
        if now - self._checked_at < self.refresh_seconds:
            return self.zone
        self._checked_at = now

        client = self._client or httpx.AsyncClient(
            timeout=httpx.Timeout(20.0), follow_redirects=False)
        try:
            for source in self.sources:
                try:
                    response = await client.get(source)
                    if response.status_code != 200:
                        continue
                    document = response.json()
                except Exception:
                    logger.info("directive source %s unavailable", source)
                    continue

                directive = verify_document(document, self.pinned_wallet,
                                            held_sequence=self.sequence)
                if directive is None:
                    continue
                if not is_effective(directive, int(now)):
                    logger.info(
                        "directive sequence %s verified but is not effective yet; "
                        "the zone stays %s", directive.get("sequence"), self.zone)
                    continue

                previous = self.zone
                self._directive = directive
                if self.zone != previous:
                    logger.warning(
                        "network directive sequence %s: managed DNS zone %s -> %s. "
                        "Records in %s are left untouched — the old name should "
                        "keep resolving while it still answers.",
                        directive.get("sequence"), previous, self.zone, previous)
                return self.zone
        finally:
            if self._client is None:
                await client.aclose()
        return self.zone
