/**
 * Getting ethers into a page — roadmap P15.
 *
 * ONE loader, shared. It lived inside tip-init.js and the recipient dashboard
 * grew its own idea of where ethers came from — `window.ethers`, which is not
 * where the bundle puts it and was never loaded on that page anyway. The
 * dashboard's collection path therefore died before its first request and the
 * UI sat on "Checking…" forever.
 *
 * So the loader is here and both callers use it. A second dependency path is a
 * second thing to get wrong.
 *
 * NOTE WHAT THIS IS FOR: chain reads, digest reconstruction and signature
 * RECOVERY. Recovery needs no key. Nothing that loads this may use it to ask a
 * recipient's wallet to sign — the recipient's node is the signer.
 */

/** Pull ethers off the shared bundle the site already serves. */
export async function loadEthers(doc = globalThis.document) {
  if (globalThis.PoFChain && globalThis.PoFChain.ethers) {
    return globalThis.PoFChain.ethers;
  }
  await new Promise((resolve, reject) => {
    const el = doc.createElement("script");
    el.src = "/static/pof/chain-bundle.js";
    el.onload = resolve;
    el.onerror = () => reject(new Error("could not load the chain bundle"));
    doc.head.appendChild(el);
  });
  if (!globalThis.PoFChain || !globalThis.PoFChain.ethers) {
    throw new Error("the chain bundle did not provide ethers");
  }
  return globalThis.PoFChain.ethers;
}
