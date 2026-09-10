"""Fetch the country-flag assets at image build time.

Downloads a CC0 IP->country database (github.com/sapics/ip-location-db, via
jsDelivr) and the Twemoji country-flag web font so emoji flags render on every
platform (Windows shows letters otherwise). Everything here is fail-soft: a
download problem prints a warning and leaves the feature dormant (no flags)
rather than breaking the build.
"""
import os
import sys
import urllib.request

# (url, destination-relative-to-backend-root)
ASSETS = [
    (
        "https://cdn.jsdelivr.net/npm/@ip-location-db/geo-whois-asn-country/geo-whois-asn-country-ipv4.csv",
        "resources/geoip/country-ipv4.csv",
    ),
    (
        "https://cdn.jsdelivr.net/npm/@ip-location-db/geo-whois-asn-country/geo-whois-asn-country-ipv6.csv",
        "resources/geoip/country-ipv6.csv",
    ),
    (
        "https://cdn.jsdelivr.net/npm/country-flag-emoji-polyfill@0.1.8/dist/TwemojiCountryFlags.woff2",
        "static/webfonts/TwemojiCountryFlags.woff2",
    ),
]


def fetch(url, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "maniwani-build"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read()
    if not data:
        raise RuntimeError("empty response")
    with open(dest, "wb") as out:
        out.write(data)
    return len(data)


def main():
    for url, dest in ASSETS:
        try:
            size = fetch(url, dest)
            sys.stderr.write("[geoip_bootstrap] %s -> %s (%d bytes)\n" % (url, dest, size))
        except Exception as exc:  # noqa: BLE001 — never fail the build
            sys.stderr.write("[geoip_bootstrap] WARNING: could not fetch %s (%s); "
                             "country flags will be unavailable until provided.\n" % (url, exc))
    # Always succeed so a network hiccup can't break the image build.
    return 0


if __name__ == "__main__":
    sys.exit(main())
