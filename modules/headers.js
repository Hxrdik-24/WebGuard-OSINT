// HTTP response headers of the current page. Same-origin, cookie-less request from the content script.
(() => {
  const O = (self.OSINT = self.OSINT || {});
  const IMPORTANT = [
    "server", "content-type", "content-length", "cache-control", "location",
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "referrer-policy", "permissions-policy"
  ];

  function fetchHeaders() {
    return O.http.withTimeout(10000, async (signal) => {
      const init = { credentials: "omit", cache: "no-store", redirect: "follow", signal };
      let method = "HEAD";
      let resp = null;
      try { resp = await fetch(location.href, { ...init, method }); }
      catch (e) { if (e.name === "AbortError") throw e; }
      if (!resp || resp.status >= 400) {
        method = "GET";
        resp = await fetch(location.href, { ...init, method });
        if (resp.body) resp.body.cancel().catch(() => {});
      }
      const headers = {};
      resp.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
      const u = new URL(resp.url || location.href);
      return {
        method, status: resp.status, statusText: resp.statusText,
        finalUrl: u.origin + u.pathname, redirected: resp.redirected, headers
      };
    });
  }

  O.headers = { IMPORTANT, fetch: fetchHeaders };
})();
