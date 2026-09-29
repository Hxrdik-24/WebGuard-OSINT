// ================================
// IP Finder - OSINT background service worker
// content.js -> background.js -> module -> public API -> back to dashboard
// ================================
importScripts(
  "utils/validators.js", "utils/formatters.js", "utils/http.js", "utils/cache.js", "utils/api.js",
  "modules/dns.js", "modules/ip.js", "modules/asn.js", "modules/geo.js", "modules/whois.js",
  "modules/certificates.js", "modules/subdomains.js"
);

const O = self.OSINT;

// Whitelist of operations the content script may request. Each module re-validates its input.
const HANDLERS = {
  dns: (p) => O.dns.records(p.domain),
  ipv4: (p) => O.ip.v4(p.domain),
  ipv6: (p) => O.ip.v6(p.domain),
  rdns: (p) => O.ip.reverse(p.ips),
  asn: (p) => O.asn.lookup(p.ip),
  geo: (p) => O.geo.lookup(p.ip),
  rdap: (p) => O.whois.lookup(p.domain),
  certs: (p) => O.certificates.lookup(p.domain),
  subdomains: (p) => O.subdomains.discover(p.domain)
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !msg) return false;

  if (msg.type === "OSINT_RUN") {
    const handler = Object.prototype.hasOwnProperty.call(HANDLERS, msg.op) ? HANDLERS[msg.op] : null;
    if (!handler) {
      sendResponse({ ok: false, error: "Unknown operation" });
      return false;
    }
    Promise.resolve()
      .then(() => handler(msg.params || {}))
      .then((data) => sendResponse({ ok: true, data }))
      .catch((err) => sendResponse({ ok: false, error: (err && err.message) || String(err) }));
    return true; // async response
  }

  if (msg.type === "OSINT_CLEAR_CACHE") {
    O.cache.clear();
    sendResponse({ ok: true });
    return false;
  }

  if (msg.type === "OSINT_GET_CSS") {
    // Served via the background so the stylesheet is not web-accessible (avoids page fingerprinting).
    fetch(chrome.runtime.getURL("style.css"))
      .then((r) => r.text())
      .then((css) => sendResponse({ ok: true, data: css }))
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  return false;
});
