# Maniwani Remote Reply Assistant

This Manifest V3 extension fills a prepared Maniwani reply into an explicitly
allowlisted source form. It does not solve or export CAPTCHAs, read cookies or
credentials, attach files, or click the source site's final Submit control.

Supported adapter packages:

- `fourchan@1.0.0`: `boards.4chan.org` and `boards.4channel.org`;
- `vichan_7chan@1.0.0`: `7chan.org`;
- `lynxchan_8chan_moe@1.0.0`: `8chan.moe`.

The latter two are separate adapters because similarly named imageboards do not
necessarily expose identical forms. Reddit is intentionally absent: its documented
JSON API is read-only for this use, and posting belongs in a separate OAuth/API
integration.

## Build and load

Build a package for the exact Maniwani deployment origin:

```sh
cd browser-extension
MANIWANI_ORIGIN=https://boards.example npm run build
```

`MANIWANI_ORIGIN` must be only an origin—no path, query, credentials, wildcard, or
fragment. The generated unpacked extension is in `dist/`. Load that directory through
the browser's extension developer page. Rebuild per deployment origin; do not add
`<all_urls>`.

For local development the default is `http://localhost`. Run `npm test` for the pure
adapter contract tests.

## Visitor flow

1. Create a forwarded reply on Maniwani.
2. On the private handoff page, select **Fill with browser extension**.
3. The extension opens the server-validated source URL in a top-level tab.
4. A one-use capability is exchanged for the minimum draft fields.
5. The matching adapter verifies host, path, adapter version, and thread ID before
   filling text fields.
6. The visitor reviews the form, completes any CAPTCHA/login/challenge on that source,
   chooses any attachment locally, and clicks Submit.

If selectors do not match, the extension stops and the original handoff page remains
available for manual copy. Updating an adapter requires changing its version in both
`backend/services/source_adapters.py` and `src/adapter-registry.js`, adding/updating a
fixture, and reviewing the exact host permissions.

## Security properties

- Drafts and capability values never appear in source URLs.
- The capability is consumed once; a separate short-lived token authenticates
  monotonically sequenced status events.
- Only the opaque, expiring handoff capability and event state are kept in
  `chrome.storage.session`; draft text is not persisted by the extension.
- Destination checks are repeated by the backend, background worker, and source
  content script.
- The extension has no cookie, history, proxy, web-request, or broad-host permission.
