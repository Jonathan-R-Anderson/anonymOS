import re
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlparse


@dataclass(frozen=True)
class SourceAdapter:
    id: str
    version: str
    source_type: str
    hosts: Tuple[str, ...]
    path_pattern: re.Pattern
    challenge_families: Tuple[str, ...]

    def matches(self, source_type, source_url):
        parsed = urlparse(source_url or "")
        host = (parsed.hostname or "").lower()
        return (
            source_type == self.source_type
            and parsed.scheme == "https"
            and host in self.hosts
            and parsed.username is None
            and parsed.password is None
            and self.path_pattern.fullmatch(parsed.path or "") is not None
        )

    def launch_descriptor(self, source_url):
        parsed = urlparse(source_url)
        return {
            "adapter_id": self.id,
            "adapter_version": self.version,
            "source_host": parsed.hostname.lower(),
            "source_url": source_url,
            "challenge_families": list(self.challenge_families),
        }


# These adapters are intentionally host-specific. A scraper source that merely looks
# like one of these engines is not enough to grant the extension access to it.
ADAPTERS = (
    SourceAdapter(
        id="fourchan",
        version="1.0.0",
        source_type="4chan",
        hosts=("boards.4chan.org", "boards.4channel.org"),
        path_pattern=re.compile(r"/[A-Za-z0-9_-]+/thread/[0-9]+(?:/)?"),
        challenge_families=("native", "recaptcha", "javascript_interstitial"),
    ),
    SourceAdapter(
        id="vichan_7chan",
        version="1.0.0",
        source_type="7chan",
        hosts=("7chan.org", "www.7chan.org"),
        path_pattern=re.compile(r"/[A-Za-z0-9_-]+/res/[0-9]+(?:\.html)?(?:/)?"),
        challenge_families=("native", "recaptcha", "hcaptcha", "javascript_interstitial"),
    ),
    SourceAdapter(
        id="lynxchan_8chan_moe",
        version="1.0.0",
        source_type="8chan",
        hosts=("8chan.moe", "www.8chan.moe"),
        path_pattern=re.compile(r"/[A-Za-z0-9_-]+/res/[0-9]+(?:\.html)?(?:/)?"),
        challenge_families=("native", "hcaptcha", "javascript_interstitial", "proof_of_work"),
    ),
)


def adapter_for_source(source_type, source_url) -> Optional[SourceAdapter]:
    for adapter in ADAPTERS:
        if adapter.matches(source_type, source_url):
            return adapter
    return None


def adapter_by_id(adapter_id, adapter_version=None) -> Optional[SourceAdapter]:
    for adapter in ADAPTERS:
        if adapter.id != adapter_id:
            continue
        if adapter_version is not None and adapter.version != adapter_version:
            continue
        return adapter
    return None
