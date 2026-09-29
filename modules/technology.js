// Passive technology detection from what the page already exposes. No probing.
(() => {
  const O = (self.OSINT = self.OSINT || {});

  const URL_SIGS = [
    ["WordPress", "CMS", /wp-content|wp-includes/],
    ["Drupal", "CMS", /sites\/(default|all)\/(files|modules|themes)/],
    ["Shopify", "E-commerce", /cdn\.shopify\.com/],
    ["Wix", "CMS", /parastorage\.com|wixstatic\.com/],
    ["Squarespace", "CMS", /squarespace\.com|sqspcdn/],
    ["Webflow", "CMS", /webflow\.(com|io)/],
    ["Next.js", "JavaScript framework", /\/_next\//],
    ["Nuxt", "JavaScript framework", /\/_nuxt\//],
    ["React", "JavaScript framework", /react(-dom)?(\.min|\.production)?\.js/],
    ["Vue.js", "JavaScript framework", /vue(\.runtime)?(\.min|\.global)?\.js|\/vue@/],
    ["Angular", "JavaScript framework", /angular(\.min)?\.js|@angular/],
    ["jQuery", "JavaScript library", /jquery/],
    ["Bootstrap", "CSS framework", /bootstrap/],
    ["Tailwind CSS", "CSS framework", /tailwind/],
    ["Google Analytics", "Analytics", /google-analytics\.com|googletagmanager\.com\/gtag/],
    ["Google Tag Manager", "Tag manager", /googletagmanager\.com\/gtm/],
    ["Matomo", "Analytics", /matomo|piwik/],
    ["Plausible", "Analytics", /plausible\.io/],
    ["Hotjar", "Analytics", /hotjar\.com/],
    ["Cloudflare", "CDN", /cdnjs\.cloudflare\.com|\/cdn-cgi\//],
    ["jsDelivr", "CDN", /cdn\.jsdelivr\.net/],
    ["unpkg", "CDN", /unpkg\.com/],
    ["Google Fonts", "Font service", /fonts\.(googleapis|gstatic)\.com/],
    ["Font Awesome", "Icon font", /fontawesome|font-awesome/]
  ];

  function detect(headers) {
    const found = new Map();
    const add = (name, category, evidence) => { if (!found.has(name)) found.set(name, { name, category, evidence }); };

    const urls = [...document.scripts].map((s) => s.src)
      .concat([...document.querySelectorAll("link[href]")].map((l) => l.href))
      .filter(Boolean);
    for (const [name, cat, re] of URL_SIGS) {
      const hit = urls.find((u) => re.test(u.toLowerCase()));
      if (hit) {
        let ev = hit;
        try { const u = new URL(hit); ev = u.host + u.pathname; } catch {}
        add(name, cat, "Resource URL: " + ev.slice(0, 70));
      }
    }

    const gen = document.querySelector('meta[name="generator"]');
    if (gen && gen.content) add(gen.content.slice(0, 60), "CMS / generator", "meta generator");

    const dom = [
      ["#__next", "Next.js", "JavaScript framework"], ["#__nuxt", "Nuxt", "JavaScript framework"],
      ["[data-reactroot]", "React", "JavaScript framework"], ["[data-v-app]", "Vue.js", "JavaScript framework"],
      ["[data-wf-site]", "Webflow", "CMS"]
    ];
    for (const [sel, name, cat] of dom) if (document.querySelector(sel)) add(name, cat, "DOM marker " + sel);
    const ng = document.querySelector("[ng-version]");
    if (ng) add("Angular " + ng.getAttribute("ng-version"), "JavaScript framework", "ng-version attribute");

    if (headers) {
      const h = headers;
      if (h.server) add(h.server, "Web server", "Server header");
      if (h["x-powered-by"]) add(h["x-powered-by"], "Framework / runtime", "X-Powered-By header");
      if (h["x-generator"]) add(h["x-generator"], "CMS / generator", "X-Generator header");
      if (h["x-drupal-cache"] || h["x-drupal-dynamic-cache"]) add("Drupal", "CMS", "Drupal cache header");
      if ((h.link || "").includes("wp-json")) add("WordPress", "CMS", "Link header (wp-json)");
      if (h["cf-ray"]) add("Cloudflare", "CDN", "cf-ray header");
      if (h["x-vercel-id"]) add("Vercel", "Hosting / CDN", "x-vercel-id header");
      if (h["x-amz-cf-id"] || h["x-amz-cf-pop"] || /cloudfront/i.test(h.via || "")) add("Amazon CloudFront", "CDN", "CloudFront header");
      if (h["x-fastly-request-id"]) add("Fastly", "CDN", "x-fastly-request-id header");
      if (Object.keys(h).some((k) => k.startsWith("x-akamai"))) add("Akamai", "CDN", "x-akamai header");
    }
    return [...found.values()].sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));
  }

  O.technology = { detect };
})();
