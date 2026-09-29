// Lists declared sitemap URLs (robots.txt) plus 3 common locations. Never crawls a sitemap.
(() => {
  const O = (self.OSINT = self.OSINT || {});
  const COMMON = ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"];

  async function discover(robots) {
    const found = [];
    const seen = new Set();
    const add = (url, source) => { if (!seen.has(url)) { seen.add(url); found.push({ url, source }); } };

    ((robots && robots.sitemaps) || []).forEach((u) => add(u, "robots.txt"));

    for (const path of COMMON) {
      const url = location.origin + path;
      if (seen.has(url)) continue;
      try {
        const ok = await O.http.withTimeout(6000, async (signal) => {
          const r = await fetch(url, { credentials: "omit", signal });
          if (!r.ok) return false;
          return /<(urlset|sitemapindex)[\s>]/i.test(await O.http.readHead(r, 2048));
        });
        if (ok) add(url, "common location");
      } catch { /* not present */ }
    }
    return { found };
  }

  O.sitemap = { discover };
})();
