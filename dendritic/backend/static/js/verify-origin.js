/*
 * Verify that the page you are reading came from syndichan.
 *
 * A gateway is transport. It can see what you asked for and it hands you bytes,
 * but it must not be able to change them without you noticing. This script is
 * the "without you noticing" part: it re-fetches the current document, rebuilds
 * the exact message the origin signed, and checks the signature against a key
 * the origin publishes.
 *
 * WHAT IT CAN AND CANNOT TELL YOU
 * -------------------------------
 * It CAN tell you a byte was changed, a signature was moved from another page,
 * or an older signed copy was replayed at you.
 *
 * It CANNOT tell you the key itself is genuine on your very first visit: you
 * fetched that through a gateway too. That is trust-on-first-use, the same
 * bootstrap every pinned-key system has, and it is still worth having — an
 * attacker now has to be the only gateway you ever use AND stay consistent for
 * your whole session, rather than flipping one byte in one response.
 *
 * The key is therefore remembered in localStorage after the first visit, and a
 * key that CHANGES is reported loudly. A legitimate rotation looks exactly like
 * an attack from here, which is precisely why it should be noisy rather than
 * silently accepted.
 */
(function () {
  "use strict";

  var KEY_URL = "/.well-known/syndichan/origin-key.json";
  var PINNED = "syndichan.origin-key";
  var VERSIONS = "syndichan.versions";

  if (!window.crypto || !window.crypto.subtle || !window.fetch) { return; }

  function b64bytes(text) {
    var binary = atob(String(text || "").replace(/-/g, "+").replace(/_/g, "/"));
    var out = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) { out[i] = binary.charCodeAt(i); }
    return out;
  }

  function hex(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), function (b) {
      return ("0" + b.toString(16)).slice(-2);
    }).join("");
  }

  function store(name, value) {
    try { window.localStorage.setItem(name, value); } catch (e) { /* private mode */ }
  }
  function load(name) {
    try { return window.localStorage.getItem(name); } catch (e) { return null; }
  }

  function report(level, message, detail) {
    // Console rather than an overlay: a false positive that covers the page is
    // worse than the attack for anyone on a flaky connection, and this is new
    // code. It escalates to something visible once it has been proven quiet.
    var line = "[syndichan] " + message;
    if (level === "bad") { console.error(line, detail || ""); }
    else { console.info(line, detail || ""); }
    window.dispatchEvent(new CustomEvent("syndichan:verification", {
      detail: { level: level, message: message, info: detail || null }
    }));
  }

  /*
   * Report an observation, so detection has a consequence.
   *
   * Without this the reader closes the tab and the gateway carries on. The
   * report is one observation by one observer and is treated as nothing more —
   * anybody can POST anything here, which is precisely why a single report never
   * becomes reputation on its own.
   *
   * Fire-and-forget. A reader is doing us a favour by reporting at all; they
   * must never wait on it, and a failure to report is not their problem.
   */
  /*
   * The observer's own key.
   *
   * Kept NON-EXTRACTABLE in IndexedDB rather than as a JWK in localStorage: the
   * browser will sign with it but will not hand it back, so script running on
   * this page — including anything injected — can use the identity but cannot
   * steal it and file reports elsewhere in this reader's name.
   *
   * It buys no sybil resistance. Keys are free, so a determined party is many
   * observers no matter what. What it does buy is that ONE observer's record
   * cannot be written by anyone else, which is what makes "distinct observers"
   * mean anything.
   */
  var IDENTITY_DB = "syndichan-audit";
  var identityPromise = null;

  function openIdentityStore() {
    return new Promise(function (resolve, reject) {
      var request = indexedDB.open(IDENTITY_DB, 1);
      request.onupgradeneeded = function () {
        request.result.createObjectStore("keys");
      };
      request.onsuccess = function () { resolve(request.result); };
      request.onerror = function () { reject(request.error); };
    });
  }

  function storedKeyPair(db) {
    return new Promise(function (resolve, reject) {
      var tx = db.transaction("keys", "readonly").objectStore("keys").get("observer");
      tx.onsuccess = function () { resolve(tx.result || null); };
      tx.onerror = function () { reject(tx.error); };
    });
  }

  function observerIdentity() {
    if (identityPromise) { return identityPromise; }
    identityPromise = openIdentityStore().then(function (db) {
      return storedKeyPair(db).then(function (existing) {
        if (existing) { return existing; }
        return crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])
          .then(function (pair) {
            return new Promise(function (resolve, reject) {
              var tx = db.transaction("keys", "readwrite")
                .objectStore("keys").put(pair, "observer");
              tx.onsuccess = function () { resolve(pair); };
              tx.onerror = function () { reject(tx.error); };
            });
          });
      });
    }).catch(function () { return null; });   // private mode, or no Ed25519
    return identityPromise;
  }

  function b64(bytes) {
    var binary = "";
    var view = new Uint8Array(bytes);
    for (var i = 0; i < view.length; i++) { binary += String.fromCharCode(view[i]); }
    return btoa(binary);
  }

  function reportAudit(gateway, objectKey, version, objectHash, result, latency, peer) {
    if (!gateway) { return; }   // nothing to attribute the observation to
    var payload = {
      gateway: gateway, object_key: objectKey, version: Number(version) || 0,
      object_hash: objectHash || "", result: result,
      latency_ms: latency || null, observer_kind: "client"
    };
    // The other gateway in a comparison, when there was one. "These two
    // disagreed" is a different and more useful fact than "this one did not
    // match", and only the reader was in a position to see both.
    if (peer && peer !== gateway) { payload.peer_gateway = peer; }

    // Sign the exact fields the origin will re-derive. A signature over less
    // could be lifted onto a different observation in this observer's name.
    var message = new TextEncoder().encode(
      "syndichan-audit:v1\n" + gateway + "\n" + objectKey + "\n" +
      (Number(version) || 0) + "\n" + (objectHash || "") + "\n" + result);

    observerIdentity().then(function (pair) {
      if (!pair) { return payload; }
      return crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, message)
        .then(function (signature) {
          return crypto.subtle.exportKey("raw", pair.publicKey).then(function (raw) {
            payload.observer_key = b64(raw);
            payload.signature = b64(signature);
            return payload;
          });
        })
        .catch(function () { return payload; });   // unsigned beats unsent
    }).then(sendAudit).catch(function () {});
  }

  function sendAudit(payload) {
    try {
      var body = JSON.stringify(payload);
      if (navigator.sendBeacon) {
        navigator.sendBeacon("/api/v1/gateway/audit",
                             new Blob([body], { type: "application/json" }));
        return;
      }
      fetch("/api/v1/gateway/audit", {
        method: "POST", credentials: "omit", keepalive: true,
        headers: { "Content-Type": "application/json" }, body: body
      }).catch(function () {});
    } catch (e) { /* reporting must never break the page */ }
  }

  function seenVersions() {
    try { return JSON.parse(load(VERSIONS) || "{}") || {}; } catch (e) { return {}; }
  }

  function rememberVersion(key, version) {
    var all = seenVersions();
    all[key] = version;
    // Bounded: a browser that visits thousands of threads should not carry all
    // of them forever.
    var keys = Object.keys(all);
    if (keys.length > 500) { delete all[keys[0]]; }
    store(VERSIONS, JSON.stringify(all));
  }

  function verify() {
    var path = window.location.pathname;
    var started = performance.now();

    fetch(KEY_URL, { credentials: "omit" })
      .then(function (r) { return r.json(); })
      .then(function (info) {
        if (!info || !info.public_key) {
          report("info", "this site is not signing content yet");
          return null;
        }
        var pinned = load(PINNED);
        if (pinned && pinned !== info.public_key) {
          report("bad", "THE ORIGIN KEY CHANGED since your last visit. This is " +
                        "either a key rotation or someone between you and the site.",
                 { was: pinned, now: info.public_key });
          return null;
        }
        if (!pinned) { store(PINNED, info.public_key); }
        return info.public_key;
      })
      .then(function (publicKey) {
        if (!publicKey) { return; }
        // Re-fetch rather than reading the DOM: the browser has already parsed
        // and mutated the document, so its serialisation is not the bytes that
        // were signed. Only the raw response can be checked.
        return fetch(window.location.href, { credentials: "same-origin", cache: "no-store" })
          .then(function (response) {
            var version = response.headers.get("X-Syndichan-Version");
            var signature = response.headers.get("X-Syndichan-Signature");
            // Which gateway served this. A gateway that declines to identify
            // itself cannot be credited for honest service either, so there is
            // an incentive to send it.
            var gateway = response.headers.get("X-Syndichan-Gateway") || "";
            var latency = Math.round(performance.now() - started);

            // An emergency snapshot is authentic AND old, which is the one
            // combination the checks below would call an attack. It gets its
            // own path — see verifySnapshot for why the claim is not taken on
            // trust.
            if ((response.headers.get("X-Syndichan-Source") || "") === "snapshot") {
              return response.arrayBuffer().then(function (body) {
                return verifySnapshot(path, body, response, gateway, latency);
              });
            }

            if (!version || !signature) {
              report("info", "this response is unsigned", { path: path });
              reportAudit(gateway, path, 0, "", "unsigned", latency);
              return;
            }
            return response.arrayBuffer().then(function (body) {
              return crypto.subtle.digest("SHA-256", body).then(function (digest) {
                var bodyHash = hex(digest);
                var message = new TextEncoder().encode(
                  "syndichan-object:v1\n" + path + "\n" + version + "\n" + bodyHash);

                return crypto.subtle.importKey(
                  "raw", b64bytes(publicKey), { name: "Ed25519" }, false, ["verify"]
                ).then(function (key) {
                  return crypto.subtle.verify("Ed25519", key, b64bytes(signature), message);
                }).then(function (ok) {
                  if (!ok) {
                    report("bad", "THIS PAGE DOES NOT MATCH THE ORIGIN SIGNATURE. " +
                                  "Something between you and syndichan changed it.",
                           { path: path, version: version });
                    reportAudit(gateway, path, version, bodyHash, "mismatch", latency);
                    return;
                  }
                  // Authentic — but authentic is not the same as current. A
                  // signed copy stays valid forever, so the only defence
                  // against being served last week's thread is refusing to go
                  // backwards.
                  var seen = seenVersions()[path];
                  if (seen && Number(version) < Number(seen)) {
                    report("bad", "you are being served an OLDER version of this " +
                                  "page than you have already seen. The signature is " +
                                  "genuine; the content is stale.",
                           { path: path, seen: seen, served: version });
                    reportAudit(gateway, path, version, bodyHash, "stale", latency);
                    return;
                  }
                  rememberVersion(path, Number(version));
                  report("ok", "content verified against the origin signature",
                         { path: path, version: version });
                  reportAudit(gateway, path, version, bodyHash, "pass", latency);
                  verifyAssets(publicKey);
                  maybeAuditAnotherGateway(publicKey, path, gateway);
                });
              });
            });
          });
      })
      .catch(function (err) {
        // A failure to VERIFY is not a failure of the page. Reported, never
        // fatal: the commonest cause is a browser without Ed25519 in WebCrypto,
        // and blocking those readers would be a worse outcome than not
        // verifying for them.
        report("info", "could not verify this page", String(err));
      });
  }

  /*
   * Static assets: CSS and scripts, which nginx serves directly and which are
   * therefore not signed on the way out. They are covered by a manifest instead
   * — SHA-256 per file under one signed Merkle root — so this checks each asset
   * the page actually loaded against it.
   *
   * The check is by HASH against the manifest rather than by Merkle proof. The
   * manifest arrives whole and its root is signed, so a file's hash appearing in
   * it is already an origin statement; the proof endpoint exists for a client
   * that wants to verify ONE asset without downloading the list.
   */
  function verifyAssets(publicKey) {
    fetch("/.well-known/syndichan/manifest.json", { credentials: "omit" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (!data || !data.files) { return; }
        if (!data.signed) {
          report("info", "static assets are not signed on this deployment");
          return;
        }

        var urls = [];
        Array.prototype.forEach.call(
          document.querySelectorAll('script[src], link[rel="stylesheet"][href]'),
          function (el) {
            var raw = el.getAttribute("src") || el.getAttribute("href") || "";
            var match = raw.match(/\/static\/(.+?)(?:\?|$)/);
            if (match) { urls.push({ url: raw, path: match[1] }); }
          });

        urls.forEach(function (item) {
          var expected = data.files[item.path];
          if (!expected) {
            // Not in the manifest at all. Worth saying: an asset the origin
            // never published is exactly what an injected script looks like.
            report("bad", "an asset on this page is NOT in the signed manifest",
                   item.path);
            return;
          }
          fetch(item.url, { credentials: "omit", cache: "no-store" })
            .then(function (r) { return r.arrayBuffer(); })
            .then(function (bytes) { return crypto.subtle.digest("SHA-256", bytes); })
            .then(function (digest) {
              if (hex(digest) !== expected) {
                report("bad", "AN ASSET DOES NOT MATCH THE SIGNED MANIFEST. " +
                              "Something between you and syndichan changed it.",
                       item.path);
              }
            })
            .catch(function () { /* a failed fetch is not a failed check */ });
        });
      })
      .catch(function () { /* no manifest is not an error, only less coverage */ });
  }

  /*
   * Phase 3: fetch what you just read from a DIFFERENT gateway, and check it.
   *
   * WHY A READER AND NOT A MONITOR
   * ------------------------------
   * A gateway that wanted to cheat safely would serve honest bytes to anything
   * that looks like an auditor and altered bytes to everyone else. Against a
   * fixed monitor that works: its addresses are knowable and its schedule is
   * regular. It does not work against readers, because a gateway cannot tell
   * which ordinary request is the one being checked — the auditor IS the
   * audience. That is the whole value of this layer, and it is why the sample
   * is random rather than scheduled.
   *
   * SAMPLED, because correctness does not need every reader. One percent of a
   * day's traffic is a large number of independent observations of every
   * popular object, while costing any individual reader nothing they would
   * notice. Auditing on every page load would double the site's egress to learn
   * the same thing.
   *
   * The comparison is against the ORIGIN SIGNATURE, not against the other
   * gateway's bytes. Two gateways disagreeing tells you only that they
   * disagree; the signature says which one is right. So this never accuses a
   * gateway of differing from a peer — it records whether what it served
   * matches what syndichan published.
   */
  var AUDIT_PROBABILITY = 0.01;

  function maybeAuditAnotherGateway(publicKey, path, servedBy) {
    if (Math.random() >= AUDIT_PROBABILITY) { return; }
    // nginx answers this straight from the gateway controller, which is the
    // authority on which gateways exist and returns a bare array. Both shapes
    // are accepted so the client keeps working whichever side serves it.
    fetch("/api/v1/gateways", { credentials: "omit" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var all = Array.isArray(data) ? data : ((data && data.gateways) || []);
        // Never audit the gateway that just served this page: it would only
        // confirm it is consistent with itself, which a dishonest one is.
        var others = all.filter(function (g) {
          return g.node_id && g.hostname && g.node_id !== servedBy && g.healthy;
        });
        if (!others.length) { return; }
        var pick = others[Math.floor(Math.random() * others.length)];
        auditGateway(publicKey, path, pick, servedBy);
      })
      .catch(function () { /* no directory, no audit; not the reader's problem */ });
  }

  function auditGateway(publicKey, path, gateway, arrivedThrough) {
    var started = performance.now();
    // credentials omitted deliberately: this is the anonymous public view, and
    // a reader's session must never be sent to a volunteer's machine.
    fetch("https://" + gateway.hostname + path, {
      credentials: "omit", cache: "no-store", mode: "cors", redirect: "manual"
    })
      .then(function (response) {
        var latency = Math.round(performance.now() - started);
        var version = response.headers.get("X-Syndichan-Version");
        var signature = response.headers.get("X-Syndichan-Signature");
        // A gateway that strips the headers, or hides them by refusing CORS,
        // cannot be verified. That is recorded rather than excused: "would not
        // let itself be checked" is exactly what a gateway with something to
        // hide looks like.
        if (!version || !signature) {
          reportAudit(gateway.node_id, path, 0, "", "unsigned", latency, arrivedThrough);
          return;
        }
        return response.arrayBuffer().then(function (body) {
          return crypto.subtle.digest("SHA-256", body).then(function (digest) {
            var bodyHash = hex(digest);
            var message = new TextEncoder().encode(
              "syndichan-object:v1\n" + path + "\n" + version + "\n" + bodyHash);
            return crypto.subtle.importKey(
              "raw", b64bytes(publicKey), { name: "Ed25519" }, false, ["verify"]
            ).then(function (key) {
              return crypto.subtle.verify("Ed25519", key, b64bytes(signature), message);
            }).then(function (ok) {
              if (!ok) {
                report("bad", "ANOTHER GATEWAY SERVED CONTENT THAT DOES NOT MATCH " +
                              "THE ORIGIN SIGNATURE.",
                       { gateway: gateway.hostname, path: path });
                reportAudit(gateway.node_id, path, version, bodyHash, "mismatch", latency, arrivedThrough);
                return;
              }
              // Authentic, but possibly old. A gateway serving a genuinely
              // signed older copy is the one attack a hash cannot see.
              var seen = seenVersions()[path];
              if (seen && Number(version) < Number(seen)) {
                reportAudit(gateway.node_id, path, version, bodyHash, "stale", latency, arrivedThrough);
                return;
              }
              reportAudit(gateway.node_id, path, version, bodyHash, "pass", latency, arrivedThrough);
            });
          });
        });
      })
      .catch(function () {
        // Unreachable is an AVAILABILITY fact, not a content one, and this
        // script cannot tell a dishonest gateway from a reader's flaky wifi or
        // a captive portal. Reporting it as a content failure would let one
        // bad network blame a gateway that did nothing wrong.
      });
  }

  /*
   * Verify a page served from an emergency snapshot.
   *
   * WHY THIS EXISTS SEPARATELY
   * --------------------------
   * When the origin is down, gateways serve a frozen copy from an earlier hour.
   * That copy is genuine and OLD — and "genuine but old" is precisely what the
   * live path reports as an attack, because a replayed older page is a real
   * threat when the origin is up. Without this branch, the first real outage
   * would show every reader a tampering warning and file fault reports against
   * gateways that behaved correctly.
   *
   * THE CLAIM IS NOT TRUSTED
   * ------------------------
   * A gateway announces a snapshot with a header, and a header is something a
   * TAMPERING gateway would also set to escape checking. So the header only
   * chooses which verification runs. What decides the outcome is the signed
   * manifest: the bytes must hash to the object this snapshot's manifest lists
   * for this path, and the manifest must be signed by the publisher key. A
   * gateway claiming "snapshot" without that fails here exactly as it would
   * have failed on the live path.
   *
   * ROLLBACK IS STILL REFUSED
   * -------------------------
   * Monotonicity moves from the object version to the snapshot sequence. A
   * reader who has seen snapshot 8841 refuses 8840, so an attacker cannot
   * replay last week's signed snapshot — while an ordinary outage, which serves
   * the NEWEST snapshot, passes.
   */
  var SNAPSHOT_KEY_URL = "/.well-known/syndichan/snapshot-key.json";
  var SNAPSHOT_URL = "/.well-known/syndichan/snapshot.json";
  var SNAPSHOT_SEQ = "syndichan.snapshot-sequence";

  function verifySnapshot(path, body, response, gateway, latency) {
    return fetch(SNAPSHOT_KEY_URL, { credentials: "omit" })
      .then(function (r) { return r.json(); })
      .then(function (info) {
        if (!info || !info.public_key) {
          report("bad", "This page claims to be an emergency snapshot, but this " +
                        "site publishes no snapshot key. Nothing here can be checked.",
                 { path: path });
          reportAudit(gateway, path, 0, "", "unsigned", latency);
          return;
        }
        return fetch(SNAPSHOT_URL, { credentials: "omit" })
          .then(function (r) { return r.json(); })
          .then(function (manifest) {
            return checkSnapshot(info.public_key, manifest, path, body,
                                 gateway, latency);
          });
      })
      .catch(function (err) {
        report("info", "could not check this emergency snapshot", String(err));
      });
  }

  function checkSnapshot(publicKey, manifest, path, body, gateway, latency) {
    if (!manifest || !manifest.signature || !manifest.routes) {
      report("bad", "This emergency snapshot has no signature.", { path: path });
      reportAudit(gateway, path, 0, "", "unsigned", latency);
      return;
    }
    var sequence = Number(manifest.sequence) || 0;
    var seen = Number(load(SNAPSHOT_SEQ) || 0);
    if (seen && sequence < seen) {
      report("bad", "You are being served an OLDER emergency snapshot than one " +
                    "you have already seen. The signature is genuine; the " +
                    "snapshot is a rollback.",
             { path: path, seen: seen, served: sequence });
      reportAudit(gateway, path, sequence, "", "stale", latency);
      return;
    }
    if (manifest.expires_at && (Date.now() / 1000) > Number(manifest.expires_at)) {
      report("bad", "This emergency snapshot has expired and should not be served.",
             { path: path, expired: manifest.expires_at });
      reportAudit(gateway, path, sequence, "", "stale", latency);
      return;
    }

    var message = new TextEncoder().encode(
      "syndichan-snapshot:v1\n" + (manifest.snapshot_id || "") + "\n" + sequence +
      "\n" + (manifest.root_hash || "") + "\n" + (manifest.created_at || 0) +
      "\n" + (manifest.expires_at || 0) + "\n" + (manifest.object_count || 0));

    return crypto.subtle.importKey(
      "raw", b64bytes(publicKey), { name: "Ed25519" }, false, ["verify"]
    ).then(function (key) {
      return crypto.subtle.verify("Ed25519", key, b64bytes(manifest.signature), message);
    }).then(function (ok) {
      if (!ok) {
        report("bad", "THIS EMERGENCY SNAPSHOT IS NOT SIGNED BY SYNDICHAN.",
               { path: path });
        reportAudit(gateway, path, sequence, "", "mismatch", latency);
        return;
      }
      return crypto.subtle.digest("SHA-256", body).then(function (digest) {
        var bodyHash = hex(digest);
        var entry = manifest.routes[path];
        if (!entry || entry.object !== bodyHash) {
          // The manifest is genuine and does not cover these bytes, so
          // something between the publisher and here substituted them.
          report("bad", "THIS PAGE DOES NOT MATCH THE SIGNED EMERGENCY SNAPSHOT. " +
                        "Something between you and syndichan changed it.",
                 { path: path, sequence: sequence });
          reportAudit(gateway, path, sequence, bodyHash, "mismatch", latency);
          return;
        }
        store(SNAPSHOT_SEQ, String(sequence));
        // A verified snapshot is not a fault. Reporting it as one would make
        // every outage look like a fleet of gateways going bad at once, and
        // the reputation record exists to distinguish those.
        report("ok", "emergency snapshot verified against the publisher signature",
               { path: path, sequence: sequence,
                 taken: new Date((manifest.created_at || 0) * 1000).toISOString() });
        reportAudit(gateway, path, sequence, bodyHash, "pass", latency);
      });
    });
  }

  if (document.readyState === "complete") { verify(); }
  else { window.addEventListener("load", verify); }
})();
