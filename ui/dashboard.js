// ================================
// OSINT dashboard (platform independent: Chrome content script AND Android WebView)
// Needs a `platform` adapter: { call, getCss, loadPosition, savePosition, clearCache }
// States per operation: IDLE, LOADING, SUCCESS, ERROR, NOT_AVAILABLE
// ================================
(() => {
  "use strict";
  const O = (self.OSINT = self.OSINT || {});
  const V = O.validators, F = O.fmt;

  const S = { IDLE: "idle", LOADING: "loading", SUCCESS: "success", ERROR: "error", NA: "not_available" };
  const AUTO = ["domain", "ipv4", "ipv6"];      // only basics run automatically
  const DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];
  const MAX_ITEMS = 60, DRAG_THRESHOLD = 5;
  const DOH = "Cloudflare DoH (cloudflare-dns.com)";

  class NotAvailable extends Error {}
  const na = (m) => new NotAvailable(m);

  let platform = null, shadow = null, panel = null, icon = null, topIp = null, topUrl = null, topHost = null;

  const call = (op, params) => platform.call(op, params);
  const tgt = () => { const host = V.stripBrackets(location.hostname); return { host, isIP: V.isIPv4(host) || V.isIPv6(host) }; };
  const needPublic = () => {
    const { host, isIP } = tgt();
    if (!(isIP ? V.isPublicIP(host) : V.isPublicDomain(host))) throw na("Local or private target - network lookups are disabled");
    return host;
  };
  const needDomain = () => {
    const host = needPublic();
    if (tgt().isIP) throw na("Target is an IP address, not a domain");
    return host;
  };

  // ---------- operations ----------
  const ipOp = (ver) => async () => {
    const host = needPublic();
    let ips;
    if (tgt().isIP) {
      if (ver === 4 ? !V.isIPv4(host) : !V.isIPv6(host)) throw na(`Target is not an IPv${ver} address`);
      ips = [host];
    } else {
      ips = (await call(ver === 4 ? "ipv4" : "ipv6", { domain: host })).ips;
    }
    if (!ips.length) return { state: S.NA, summary: `No ${ver === 4 ? "A" : "AAAA"} record found`, data: { ips: [] } };
    return { summary: ips[0] + (ips.length > 1 ? ` (+${ips.length - 1})` : ""), rows: [[`IPv${ver} addresses`, ips]], data: { ips } };
  };

  const allIps = async () => {
    const [a, b] = await Promise.all([ensure("ipv4"), ensure("ipv6")]);
    return [...((a.data && a.data.ips) || []), ...((b.data && b.data.ips) || [])];
  };
  const firstIp = async () => {
    needPublic();
    const ips = await allIps();
    if (!ips.length) throw na("No IP address resolved");
    return ips[0];
  };
  const safe = (p) => p.catch(() => null);

  const OPS = {
    domain: {
      title: "Domain Information", source: "Local (current page URL)",
      run: async () => {
        const u = V.parseUrl(location.href);
        return {
          summary: u.hostname,
          rows: [["URL", u.url], ["Protocol", u.protocol], ["Hostname", u.hostname], ["Root domain", u.rootDomain], ["Subdomain", u.subdomain],
                 ["TLD", u.tld], ["Port", u.port], ["Path", u.path], ["Query", u.query], ["Fragment", u.hash]],
          note: u.isIP ? null : "Root domain uses a built-in suffix list; it can be wrong for uncommon public suffixes.",
          data: { hostname: u.hostname, rootDomain: u.rootDomain, subdomain: u.subdomain, tld: u.tld, protocol: u.protocol, port: u.port, path: u.path, hasQuery: !!u.query, hasFragment: !!u.hash }
        };
      }
    },
    ipv4: { title: "IPv4 Lookup", source: DOH, run: ipOp(4) },
    ipv6: { title: "IPv6 Lookup", source: DOH, run: ipOp(6) },
    dns: {
      title: "DNS Records", source: DOH,
      run: async () => {
        const d = await call("dns", { domain: needDomain() });
        let n = 0;
        const rows = DNS_TYPES.map((t) => {
          const list = d.records[t] || [];
          n += list.length;
          return [t, list.length ? list : (d.errors && d.errors[t] ? "error: " + d.errors[t] : "—")];
        });
        if (!n) return { state: S.NA, summary: "No record found", data: d };
        return { summary: `${n} record(s)`, rows, data: d };
      }
    },
    rdns: {
      title: "Reverse DNS", source: DOH + " (PTR)",
      run: async () => {
        needPublic();
        const ips = await allIps();
        if (!ips.length) throw na("No IP addresses discovered");
        const d = await call("rdns", { ips });
        const has = d.results.some((x) => x.ptr.length);
        return {
          state: has ? S.SUCCESS : S.NA,
          summary: has ? d.results.find((x) => x.ptr.length).ptr[0] : "No PTR record",
          rows: d.results.map((x) => [x.ip, x.ptr.length ? x.ptr : x.error ? "error: " + x.error : "No PTR record"]),
          data: d
        };
      }
    },
    asn: {
      title: "ASN Information", source: "RIPEstat (stat.ripe.net) + ipwho.is (country)",
      run: async () => {
        const ip = await firstIp();
        const [d, g] = await Promise.all([call("asn", { ip }), safe(call("geo", { ip }))]);
        if (!d.asn) return { state: S.NA, summary: "IP not announced in BGP", data: d };
        return {
          summary: `${d.asn} ${d.holder || ""}`.trim(),
          rows: [["IP", ip], ["ASN", d.asn], ["Organization", d.holder], ["Prefix", d.prefix], ["Country", g ? `${g.country} (${g.countryCode})` : "—"], ["Description", d.description]],
          data: { ...d, country: g ? g.country : null }
        };
      }
    },
    geo: {
      title: "IP Geolocation", source: "ipwho.is",
      run: async () => {
        const ip = await firstIp();
        const g = await call("geo", { ip });
        return {
          summary: [g.city, g.country].filter(Boolean).join(", ") || "Unknown",
          rows: [["IP", ip], ["Country", g.country], ["Region", g.region], ["City", g.city], ["Latitude", g.latitude], ["Longitude", g.longitude], ["Timezone", g.timezone]],
          note: "IP geolocation is approximate. It reflects where the network is registered or routed, not a precise or physical location.",
          data: g
        };
      }
    },
    network: {
      title: "ISP / Network", source: "ipwho.is + RIPEstat",
      run: async () => {
        const ip = await firstIp();
        const [a, g] = await Promise.all([safe(call("asn", { ip })), safe(call("geo", { ip }))]);
        if (!a && !g) throw new Error("Network lookup failed");
        const data = { ip, isp: g && g.isp, organization: (g && g.org) || (a && a.holder), network: a && a.prefix, asn: (a && a.asn) || (g && g.asn), country: g && g.country };
        return {
          summary: data.isp || data.organization || "Unknown",
          rows: [["ISP", data.isp], ["Organization", data.organization], ["Network", data.network], ["ASN", data.asn], ["Country", data.country]],
          data
        };
      }
    },
    rdap: {
      title: "Domain Age (RDAP)", source: "rdap.org (RDAP)",
      run: async () => {
        const d = await call("rdap", { domain: needDomain() });
        if (!d.found) return { state: S.NA, summary: "No RDAP data for this registry", data: d };
        const age = d.ageDays != null ? `${(d.ageDays / 365.25).toFixed(1)} years` : "—";
        return {
          summary: d.registered ? `${F.date(d.registered)} (${age})` : "Registered (date unknown)",
          rows: [["Domain", d.domain], ["Registrar", d.registrar], ["Registered", F.date(d.registered)], ["Updated", F.date(d.updated)], ["Expires", F.date(d.expires)], ["Age", age], ["Status", d.status]],
          note: "Only public registry fields are shown. Contact details are never requested or displayed.",
          data: d
        };
      }
    },
    headers: {
      title: "HTTP Headers", source: "This site (same-origin request, no cookies)",
      run: async () => {
        needPublic();
        const d = await O.headers.fetch();
        const rows = [["Status", `${d.status} ${d.statusText}`.trim() + ` (${d.method})`]];
        if (d.redirected) rows.push(["Final URL", d.finalUrl]);
        for (const k of O.headers.IMPORTANT) if (d.headers[k] !== undefined) rows.push([k, F.truncate(d.headers[k], 300)]);
        rows.push(["All headers", Object.entries(d.headers).map(([k, v]) => `${k}: ${F.truncate(v, 120)}`)]);
        return {
          summary: `${d.status} · ${Object.keys(d.headers).length} headers`, rows,
          note: "Fetched fresh without cookies, so values can differ from the response your browser received.",
          data: d
        };
      }
    },
    tls: {
      title: "TLS / HTTPS", source: "Browser APIs (local)",
      run: async () => {
        const https = location.protocol === "https:";
        const nav = performance.getEntriesByType("navigation")[0];
        const proto = nav && nav.nextHopProtocol ? ({ h2: "HTTP/2", h3: "HTTP/3", "http/1.1": "HTTP/1.1" }[nav.nextHopProtocol] || nav.nextHopProtocol) : "Not exposed";
        const data = { https, httpProtocol: proto, secureContext: window.isSecureContext, tlsVersion: "Not exposed by web APIs", certificate: "Not exposed by web APIs" };
        return {
          summary: https ? `HTTPS · ${proto}` : "Not using HTTPS",
          rows: [["HTTPS enabled", https ? "Yes" : "No"], ["HTTP protocol", proto], ["Secure context", data.secureContext ? "Yes" : "No"], ["TLS version", data.tlsVersion], ["Certificate", data.certificate]],
          note: "Pages cannot read certificate or TLS details. Use the browser's padlock or DevTools > Security for those.",
          data
        };
      }
    },
    secheaders: {
      title: "Security Headers", source: "This site (uses HTTP Headers result)",
      run: async () => {
        const h = await ensure("headers");
        if (h.state !== S.SUCCESS) throw na("HTTP headers unavailable");
        const items = O.security.evaluate(h.data.headers, location.protocol);
        const label = { present: "Present", missing: "Missing", not_detectable: "Not detectable" };
        const c = (s) => items.filter((i) => i.status === s).length;
        return {
          summary: `${c("present")} present · ${c("missing")} missing`,
          rows: items.map((i) => [i.label, label[i.status] + (i.note ? ` - ${i.note}` : "")]),
          data: { items }
        };
      }
    },
    tech: {
      title: "Technology Detection", source: "Page HTML + response headers (passive)",
      run: async () => {
        const h = await ensure("headers");
        const list = O.technology.detect(h.state === S.SUCCESS ? h.data.headers : null);
        if (!list.length) return { state: S.NA, summary: "Nothing detected", data: { technologies: [] } };
        const groups = {};
        list.forEach((t) => (groups[t.category] = groups[t.category] || []).push(`${t.name}  (${t.evidence})`));
        return { summary: `${list.length} detected`, rows: Object.entries(groups), data: { technologies: list } };
      }
    },
    metadata: {
      title: "Favicon / Site Metadata", source: "Page HTML (local)",
      run: async () => {
        const m = O.metadata.collect();
        return {
          summary: m.title ? F.truncate(m.title, 40) : "No title",
          rows: [["Favicon", m.favicon], ["Title", m.title], ["Description", m.description], ["OG title", m.ogTitle], ["OG description", m.ogDescription], ["OG image", m.ogImage], ["Canonical", m.canonical], ["Language", m.language]],
          data: m
        };
      }
    },
    robots: {
      title: "robots.txt", source: "This site /robots.txt",
      run: async () => {
        needPublic();
        const d = await O.robots.fetch();
        if (!d.exists) return { state: S.NA, summary: d.status ? `Not found (HTTP ${d.status})` : "Not found", data: d };
        return {
          summary: `${d.disallow.length} disallow · ${d.allow.length} allow · ${d.sitemaps.length} sitemap`,
          rows: [["URL", d.url], ["Sitemaps", d.sitemaps], ["Disallow", d.disallow], ["Allow", d.allow], ["User-agents", d.userAgents]],
          note: "Paths are listed only. They are never requested or crawled.",
          data: d
        };
      }
    },
    sitemap: {
      title: "Sitemap Discovery", source: "robots.txt + 3 common locations",
      run: async () => {
        needPublic();
        const r = await ensure("robots");
        const d = await O.sitemap.discover(r.state === S.SUCCESS ? r.data : null);
        if (!d.found.length) return { state: S.NA, summary: "No sitemap found", data: d };
        return { summary: `${d.found.length} found`, rows: [["Sitemaps", d.found.map((f) => `${f.url}  (${f.source})`)]], note: "Sitemaps are listed only, never crawled.", data: d };
      }
    },
    resources: {
      title: "Resource Inventory", source: "Page DOM + Performance API (local)",
      run: async () => {
        const d = O.resources.inventory(), t = d.totals;
        return {
          summary: `${t.scripts} JS · ${t.stylesheets} CSS · ${t.externalDomains} external`,
          rows: [[`JavaScript (${t.scripts})`, d.scripts], [`CSS (${t.stylesheets})`, d.stylesheets], [`Images (${t.images})`, d.images], [`Fonts (${t.fonts})`, d.fonts],
                 [`External domains (${t.externalDomains})`, d.externalDomains.map((x) => `${x.domain}  (${x.count})`)]],
          data: d
        };
      }
    },
    subdomains: {
      title: "Subdomain Discovery", source: "crt.sh (CT logs) + " + DOH,
      run: async () => {
        const d = await call("subdomains", { domain: needDomain() });
        if (!d.total) return { state: S.NA, summary: "None found in CT logs", data: d };
        return {
          summary: `${d.total} found`,
          rows: [["Root domain", d.domain], ["Subdomains", d.items.map((i) => `${i.name}  [${i.status}]`)], ["Source", "crt.sh (Certificate Transparency)"]],
          note: `Passive only, no brute forcing. DNS status was checked for the first ${d.checked} names.`,
          data: d
        };
      }
    },
    certs: {
      title: "Certificate Transparency", source: "crt.sh",
      run: async () => {
        const d = await call("certs", { domain: needDomain() });
        if (!d.total) return { state: S.NA, summary: "No certificates found", data: d };
        return { summary: `${d.total} names · ${d.certificateCount} certs`, rows: [["Domain queried", d.domain], ["Certificates", d.certificateCount], ["Names", d.names]], data: d };
      }
    },
    report: { title: "OSINT Report", source: "Local (uses completed results)", custom: true }
  };

  const SECTIONS = [
    ["Target", ["domain"], true],
    ["DNS & IP", ["ipv4", "ipv6", "dns", "rdns"], true],
    ["Network", ["asn", "geo", "network", "rdap"], false],
    ["HTTP", ["headers", "tls"], false],
    ["Security", ["secheaders"], false],
    ["Technology", ["tech"], false],
    ["Metadata", ["metadata", "robots", "sitemap", "resources"], false],
    ["Subdomains", ["subdomains", "certs"], false],
    ["Report", ["report"], false]
  ];
  const OPEN_CARDS = new Set(["domain", "ipv4", "ipv6"]);

  // ---------- state ----------
  const fresh = () => ({ state: S.IDLE, result: null, promise: null });
  const store = {};
  const cards = {};
  Object.keys(OPS).forEach((id) => (store[id] = fresh()));

  function ensure(id) {
    const s = store[id];
    return s.promise || run(id);
  }

  function run(id) {
    const s = store[id];
    if (s.state === S.LOADING && s.promise) return s.promise;
    s.state = S.LOADING;
    s.result = null;
    paint(id);
    s.promise = (async () => {
      try {
        const r = await OPS[id].run();
        s.result = r;
        s.state = r.state || S.SUCCESS;
      } catch (e) {
        s.state = e instanceof NotAvailable ? S.NA : S.ERROR;
        s.result = { summary: (e && e.message) || "Failed" };
      }
      paint(id);
      return { ...s.result, state: s.state };
    })();
    return s.promise;
  }

  // ---------- DOM helpers ----------
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) el.setAttribute(k, v);
    }
    for (const kid of kids.flat()) {
      if (kid == null || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  async function copyText(text, el) {
    let ok = false;
    try { await navigator.clipboard.writeText(text); ok = true; }
    catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.cssText = "position:fixed;opacity:0;top:0;left:0";
      shadow.appendChild(ta);
      ta.select();
      try { ok = document.execCommand("copy"); } catch {}
      ta.remove();
    }
    if (el) {
      el.classList.add(ok ? "copied" : "failed");
      setTimeout(() => el.classList.remove("copied", "failed"), 900);
    }
  }

  function download(name, mime, text) {
    const url = URL.createObjectURL(new Blob([text], { type: mime }));
    const a = document.createElement("a");
    a.href = url; a.download = name;
    shadow.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  const rowsText = (rows) => rows.map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v ?? "—"}`).join("\n");
  const cardText = (id) => {
    const s = store[id];
    return `${OPS[id].title} (${OPS[id].source})\n` + (s.result && s.result.rows ? rowsText(s.result.rows) : s.result ? s.result.summary : "");
  };

  function renderRows(rows) {
    const box = h("div", { class: "rows" });
    for (const [k, v] of rows) {
      const vals = Array.isArray(v) ? (v.length ? v : ["—"]) : [v];
      const items = vals.slice(0, MAX_ITEMS).map((x) => {
        const t = x == null || x === "" ? "—" : String(x);
        const el = h("div", { class: "vi", title: "Click to copy" }, t);
        el.addEventListener("click", () => copyText(t, el));
        return el;
      });
      const more = vals.length > MAX_ITEMS ? h("div", { class: "more" }, `… +${vals.length - MAX_ITEMS} more (use Report export for the full list)`) : null;
      box.append(h("div", { class: "row" }, h("div", { class: "k" }, k), h("div", { class: "v" }, items, more)));
    }
    return box;
  }

  const ICON = { idle: "", loading: "…", success: "✓ ", error: "✕ ", not_available: "⚠ " };

  function paint(id) {
    const c = cards[id];
    if (!c) return;
    const s = store[id];
    c.root.dataset.state = s.state;
    c.summary.textContent = s.state === S.IDLE ? "" : s.state === S.LOADING ? "Loading…" : ICON[s.state] + ((s.result && s.result.summary) || "Done");
    if (!OPS[id].custom) renderBody(id);
    if (id === "ipv4" || id === "ipv6") updateTopIp();
  }

  function renderBody(id) {
    const s = store[id], b = cards[id].body, r = s.result || {};
    b.replaceChildren();
    const src = h("div", { class: "srcline" }, "Source: " + OPS[id].source);
    if (s.state === S.IDLE) b.append(h("div", { class: "msg" }, "Not run yet. Expand to query."), src);
    else if (s.state === S.LOADING) b.append(h("div", { class: "msg" }, "Loading…"), src);
    else if (s.state === S.ERROR) b.append(h("div", { class: "msg err" }, "⚠ " + r.summary), h("div", { class: "btns-row" }, h("button", { class: "btn", type: "button", onclick: () => { store[id] = fresh(); run(id); } }, "Retry")), src);
    else {
      if (s.state === S.NA) b.append(h("div", { class: "msg" }, "⚠ " + r.summary));
      if (r.rows) b.append(renderRows(r.rows));
      if (r.note) b.append(h("div", { class: "note" }, r.note));
      b.append(src);
    }
  }

  function updateTopIp() {
    if (!topIp) return;
    const ips = [...((store.ipv4.result && store.ipv4.result.data && store.ipv4.result.data.ips) || []), ...((store.ipv6.result && store.ipv6.result.data && store.ipv6.result.data.ips) || [])];
    const loading = store.ipv4.state === S.LOADING || store.ipv6.state === S.LOADING;
    topIp.textContent = ips.length ? ips[0] + (ips.length > 1 ? ` (+${ips.length - 1})` : "") : loading ? "Loading…" : "—";
    topIp.dataset.all = ips.join(", ");
  }

  // ---------- report ----------
  function buildReport() {
    const results = {}, sources = {};
    for (const id of Object.keys(OPS)) {
      const s = store[id];
      if (id !== "report" && s.state === S.SUCCESS && s.result && s.result.data !== undefined) {
        results[id] = s.result.data;
        sources[id] = OPS[id].source;
      }
    }
    const u = V.parseUrl(location.href);   // query string and fragment are deliberately excluded
    return O.report.build({ url: u.origin + u.path, hostname: u.hostname }, results, sources);
  }

  function reportUI() {
    const total = Object.keys(OPS).length - 1;
    const status = h("div", { class: "msg" }, "Includes every operation that finished successfully. Run the others first, or use Run all.");
    const stamp = () => `${new Date().toISOString().slice(0, 10)}`;
    const update = () => { status.textContent = `${Object.keys(buildReport().sources).length} of ${total} operations included in the report.`; };
    const runAll = h("button", { class: "btn", type: "button" }, "Run all operations");
    runAll.addEventListener("click", async () => {
      runAll.disabled = true; runAll.textContent = "Running…";
      await Promise.allSettled(Object.keys(OPS).filter((id) => id !== "report").map(ensure));
      runAll.disabled = false; runAll.textContent = "Run all operations"; update();
    });
    const btn = (label, fn) => h("button", { class: "btn", type: "button", onclick: (e) => { update(); fn(e.currentTarget); } }, label);
    const name = (ext) => `osint-${V.stripBrackets(location.hostname)}-${stamp()}.${ext}`;
    return h("div", {}, status, h("div", { class: "btns-row" },
      runAll,
      btn("Copy report", (b) => copyText(O.report.toText(buildReport()), b)),
      btn("Export JSON", () => download(name("json"), "application/json", JSON.stringify(buildReport(), null, 2))),
      btn("Export TXT", () => download(name("txt"), "text/plain", O.report.toText(buildReport())))));
  }

  // ---------- UI construction ----------
  function makeCard(id) {
    const op = OPS[id];
    const summary = h("span", { class: "sum" });
    const copyBtn = op.custom ? null : h("button", { class: "icon-btn", type: "button", title: "Copy", "aria-label": "Copy " + op.title, onclick: (e) => { e.stopPropagation(); copyText(cardText(id), e.currentTarget); } }, "⧉");
    const head = h("div", { class: "card-head", role: "button", tabindex: "0" },
      h("span", { class: "dot" }),
      h("div", { class: "ct" }, h("div", { class: "line1" }, h("span", { class: "name" }, op.title), summary), h("div", { class: "src" }, op.source)),
      copyBtn, h("span", { class: "chev" }, "▸"));
    const body = h("div", { class: "card-body" });
    const root = h("div", { class: "card" + (OPEN_CARDS.has(id) ? " open" : ""), "data-state": "idle" }, head, body);
    const toggle = () => {
      root.classList.toggle("open");
      if (root.classList.contains("open") && store[id].state === S.IDLE && !op.custom) run(id);
    };
    head.addEventListener("click", toggle);
    head.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
    cards[id] = { root, summary, body };
    if (op.custom) body.append(reportUI());
    paint(id);
    return root;
  }

  function makeSection([name, ids, open]) {
    const wrap = h("div", { class: "section" + (open ? " open" : "") });
    wrap.append(
      h("button", { class: "sec-head", type: "button", onclick: () => wrap.classList.toggle("open") }, h("span", { class: "chev" }, "▸"), name, h("span", { class: "count" }, String(ids.length))),
      h("div", { class: "sec-body" }, ids.map(makeCard)));
    return wrap;
  }

  const vw = () => document.documentElement.clientWidth || window.innerWidth;
  const vh = () => document.documentElement.clientHeight || window.innerHeight;
  const panelOpen = () => panel.classList.contains("show");

  function placeIcon(x, y) {
    x = Math.max(0, Math.min(x, vw() - icon.offsetWidth));
    y = Math.max(0, Math.min(y, vh() - icon.offsetHeight));
    Object.assign(icon.style, { left: x + "px", top: y + "px", right: "auto", bottom: "auto" });
  }

  function positionPanel() {
    const r = icon.getBoundingClientRect();
    const W = Math.min(380, vw() - 20);
    panel.style.width = W + "px";
    const H = panel.offsetHeight;
    const left = Math.max(10, Math.min(r.left, vw() - W - 10));
    let top = r.bottom + 10;
    if (top + H > vh() - 10) top = r.top - H - 10;
    panel.style.left = left + "px";
    panel.style.top = Math.max(10, top) + "px";
  }

  let started = false;
  function openPanel() {
    panel.classList.add("show");
    positionPanel();
    if (!started) { started = true; AUTO.forEach(run); }   // basics run on first open only
  }
  const togglePanel = () => (panelOpen() ? panel.classList.remove("show") : openPanel());

  const refresh = F.debounce(async () => {
    const reopen = Object.keys(cards).filter((id) => cards[id].root.classList.contains("open") && !OPS[id].custom);
    await platform.clearCache();
    Object.keys(OPS).forEach((id) => (store[id] = fresh()));
    updateTarget();
    Object.keys(cards).forEach(paint);
    new Set([...AUTO, ...reopen]).forEach(run);
  }, 400);

  function updateTarget() {
    topUrl.textContent = location.origin + location.pathname;
    topUrl.title = location.origin + location.pathname;
    topHost.textContent = V.stripBrackets(location.hostname);
  }

  function trow(label, valueEl, copyFn) {
    const b = h("button", { class: "icon-btn", type: "button", title: "Copy", "aria-label": "Copy " + label }, "⧉");
    b.addEventListener("click", () => copyText(copyFn(), b));
    return h("div", { class: "trow" }, h("span", { class: "k" }, label), valueEl, b);
  }

  async function init() {
    if (document.getElementById("ip-finder-host")) return;
    const host = h("div", { id: "ip-finder-host" });
    host.style.cssText = "all:initial;position:fixed;top:0;left:0;width:0;height:0;z-index:2147483647;";
    shadow = host.attachShadow({ mode: "closed" });

    icon = h("div", { class: "icon", role: "button", tabindex: "0", title: "IP Finder · OSINT", "aria-label": "Open OSINT dashboard" }, "🌐");
    topUrl = h("span", { class: "v" });
    topHost = h("span", { class: "v" });
    topIp = h("span", { class: "v" }, "—");

    const closeBtn = h("button", { class: "icon-btn", type: "button", title: "Close", "aria-label": "Close", onclick: () => panel.classList.remove("show") }, "×");
    const refreshBtn = h("button", { class: "icon-btn", type: "button", title: "Refresh", "aria-label": "Refresh", onclick: refresh }, "↻");

    panel = h("div", { class: "panel", role: "dialog", "aria-label": "OSINT dashboard" },
      h("div", { class: "hdr" },
        h("div", { class: "brand" }, h("span", {}, "🌐"), h("div", {}, h("div", { class: "ttl" }, "OSINT"), h("div", { class: "sub" }, "Passive lookups, public sources only"))),
        h("div", { class: "hbtns" }, refreshBtn, closeBtn)),
      h("div", { class: "scroll" },
        h("div", { class: "target" },
          trow("URL", topUrl, () => location.origin + location.pathname),
          trow("Hostname", topHost, () => V.stripBrackets(location.hostname)),
          trow("IP", topIp, () => topIp.dataset.all || "")),
        SECTIONS.map(makeSection)),
      h("div", { class: "foot" }, "Queries go only to the public APIs named on each card. Nothing is sent to the extension developer."));

    updateTarget();

    let css = "";
    try { css = await platform.getCss(); } catch {}
    shadow.append(h("style", {}, css), icon, panel);
    document.documentElement.appendChild(host);

    // ---- drag (pointer events: mouse, touch, pen) ----
    let drag = null;
    icon.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      const r = icon.getBoundingClientRect();
      drag = { sx: e.clientX, sy: e.clientY, ox: e.clientX - r.left, oy: e.clientY - r.top, moved: false };
      icon.setPointerCapture(e.pointerId);
      icon.classList.add("dragging");
      e.preventDefault();
    });
    icon.addEventListener("pointermove", (e) => {
      if (!drag) return;
      if (!drag.moved && Math.abs(e.clientX - drag.sx) <= DRAG_THRESHOLD && Math.abs(e.clientY - drag.sy) <= DRAG_THRESHOLD) return;
      drag.moved = true;
      placeIcon(e.clientX - drag.ox, e.clientY - drag.oy);
      if (panelOpen()) positionPanel();
    });
    const endDrag = (e, cancelled) => {
      if (!drag) return;
      const moved = drag.moved;
      drag = null;
      icon.classList.remove("dragging");
      try { icon.releasePointerCapture(e.pointerId); } catch {}
      if (moved) {
        const r = icon.getBoundingClientRect();
        platform.savePosition({ left: r.left, top: r.top });
      } else if (!cancelled) togglePanel();
    };
    icon.addEventListener("pointerup", (e) => endDrag(e, false));
    icon.addEventListener("pointercancel", (e) => endDrag(e, true));
    icon.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); togglePanel(); } });

    window.addEventListener("resize", () => {
      if (icon.style.left) { const r = icon.getBoundingClientRect(); placeIcon(r.left, r.top); }
      if (panelOpen()) positionPanel();
    });
    if (typeof ResizeObserver !== "undefined") new ResizeObserver(() => { if (panelOpen()) positionPanel(); }).observe(panel);

    const pos = await Promise.resolve(platform.loadPosition()).catch(() => null);
    if (pos && Number.isFinite(pos.left) && Number.isFinite(pos.top)) placeIcon(pos.left, pos.top);
  }

  O.mountDashboard = (p) => { platform = p; return init(); };
})();
