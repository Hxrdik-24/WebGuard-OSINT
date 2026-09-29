// Inventory of resources the current page already references or has loaded.
(() => {
  const O = (self.OSINT = self.OSINT || {});
  const LIMIT = 200;
  const isHttp = (u) => /^https?:\/\//i.test(u || "");
  const uniq = (a) => [...new Set(a)];
  const FONT_RE = /\.(woff2?|ttf|otf|eot)(\?|#|$)/i;

  function inventory() {
    const scripts = uniq([...document.scripts].map((s) => s.src).filter(isHttp));
    const styles = uniq([...document.querySelectorAll('link[rel~="stylesheet"]')].map((l) => l.href).filter(isHttp));
    const images = uniq([...document.images].map((i) => i.currentSrc || i.src).filter(isHttp));
    const perf = performance.getEntriesByType("resource").map((e) => e.name).filter(isHttp);
    const fonts = uniq(
      perf.filter((u) => FONT_RE.test(u)).concat([...document.querySelectorAll('link[as="font"]')].map((l) => l.href).filter(isHttp))
    );

    const counts = {};
    for (const u of uniq([...scripts, ...styles, ...images, ...fonts, ...perf])) {
      try {
        const host = new URL(u).hostname;
        if (host !== location.hostname) counts[host] = (counts[host] || 0) + 1;
      } catch {}
    }
    const externalDomains = Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([domain, count]) => ({ domain, count }));

    return {
      totals: { scripts: scripts.length, stylesheets: styles.length, images: images.length, fonts: fonts.length, externalDomains: externalDomains.length },
      scripts: scripts.slice(0, LIMIT), stylesheets: styles.slice(0, LIMIT),
      images: images.slice(0, LIMIT), fonts: fonts.slice(0, LIMIT), externalDomains
    };
  }

  O.resources = { inventory };
})();
