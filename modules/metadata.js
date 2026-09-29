(() => {
  const O = (self.OSINT = self.OSINT || {});

  function collect() {
    const q = (s) => document.querySelector(s);
    const attr = (s, a) => { const e = q(s); return e ? e.getAttribute(a) : null; };
    const abs = (u) => { if (!u) return null; try { return new URL(u, location.href).href; } catch { return u; } };
    const icon = attr('link[rel~="icon"]', "href");
    return {
      favicon: icon ? abs(icon) : location.origin + "/favicon.ico (default location, not verified)",
      title: document.title || null,
      description: attr('meta[name="description"]', "content"),
      ogTitle: attr('meta[property="og:title"]', "content"),
      ogDescription: attr('meta[property="og:description"]', "content"),
      ogImage: abs(attr('meta[property="og:image"]', "content")),
      canonical: abs(attr('link[rel="canonical"]', "href")),
      language: document.documentElement.lang || attr('meta[http-equiv="content-language"]', "content")
    };
  }

  O.metadata = { collect };
})();
