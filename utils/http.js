// Fetch helpers: every request has a timeout (AbortController) and never sends cookies.
(() => {
  const O = (self.OSINT = self.OSINT || {});

  async function withTimeout(ms, fn) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), ms);
    try {
      return await fn(ctl.signal);
    } catch (e) {
      if (e && e.name === "AbortError") throw new Error("Request timed out");
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }

  function fetchJson(url, { timeout = 10000, headers, validate } = {}) {
    return withTimeout(timeout, async (signal) => {
      const r = await fetch(url, { headers, signal, credentials: "omit" });
      if (!r.ok) {
        const err = new Error(`HTTP ${r.status}`);
        err.status = r.status;
        throw err;
      }
      const json = await r.json();
      if (validate && !validate(json)) throw new Error("Unexpected response format");
      return json;
    });
  }

  // Reads at most `max` characters of a response body, then cancels the stream.
  async function readHead(resp, max = 65536) {
    if (!resp.body) return (await resp.text()).slice(0, max);
    const reader = resp.body.getReader();
    const dec = new TextDecoder();
    let out = "";
    try {
      while (out.length < max) {
        const { done, value } = await reader.read();
        if (done) break;
        out += dec.decode(value, { stream: true });
      }
    } finally {
      reader.cancel().catch(() => {});
    }
    return out.slice(0, max);
  }

  O.http = { withTimeout, fetchJson, readHead };
})();
