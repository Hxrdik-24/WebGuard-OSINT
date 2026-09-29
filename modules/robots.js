// robots.txt: fetched and parsed only. Listed paths are never requested.
(() => {
  const O = (self.OSINT = self.OSINT || {});
  const cap = (a) => [...new Set(a)].slice(0, 500);

  function parse(text, url) {
    const agents = [], allow = [], disallow = [], sitemaps = [];
    for (const raw of text.split(/\r?\n/)) {
      const m = /^([A-Za-z-]+)\s*:\s*(.*)$/.exec(raw.replace(/#.*$/, "").trim());
      if (!m) continue;
      const key = m[1].toLowerCase(), val = m[2].trim();
      if (!val) continue;
      if (key === "user-agent") agents.push(val);
      else if (key === "allow") allow.push(val);
      else if (key === "disallow") disallow.push(val);
      else if (key === "sitemap" && /^https?:\/\//i.test(val)) sitemaps.push(val);
    }
    return { exists: true, url, userAgents: cap(agents), allow: cap(allow), disallow: cap(disallow), sitemaps: cap(sitemaps) };
  }

  function fetchRobots() {
    const url = location.origin + "/robots.txt";
    return O.http.withTimeout(8000, async (signal) => {
      const r = await fetch(url, { credentials: "omit", signal });
      if (!r.ok) return { exists: false, url, status: r.status };
      if (/html/i.test(r.headers.get("content-type") || "")) {
        return { exists: false, url, status: r.status, note: "Server returned an HTML page instead of a robots file" };
      }
      return parse(await O.http.readHead(r, 262144), url);
    });
  }

  O.robots = { fetch: fetchRobots, parse };
})();
