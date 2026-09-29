// Centralised API layer (background only). All external requests go through here.
// Providers can be overridden (https only) via chrome.storage.local key "osintProviders",
// e.g. {"geo":"https://my-provider.example/"}. The host must also be added to
// host_permissions in manifest.json. No API keys are hardcoded anywhere.
(() => {
  const O = (self.OSINT = self.OSINT || {});
  const { fetchJson } = O.http;
  const cached = O.cache.get;

  const DEFAULTS = {
    doh: "https://cloudflare-dns.com/dns-query",
    geo: "https://ipwho.is/",
    asn: "https://stat.ripe.net/data/prefix-overview/data.json",
    rdap: "https://rdap.org/domain/",
    ct: "https://crt.sh/"
  };
  const SOURCES = {
    dns: "Cloudflare DNS-over-HTTPS (cloudflare-dns.com)",
    geo: "ipwho.is",
    asn: "RIPEstat (stat.ripe.net)",
    rdap: "rdap.org (RDAP bootstrap)",
    certificates: "crt.sh (Certificate Transparency)"
  };
  const DNS_TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28 };
  const MIN = 60 * 1000;

  let overrides = {};
  const ready = chrome.storage.local
    .get("osintProviders")
    .then((r) => { overrides = r.osintProviders || {}; })
    .catch(() => {});
  const base = (k) => (typeof overrides[k] === "string" && overrides[k].startsWith("https://") ? overrides[k] : DEFAULTS[k]);

  async function dns(name, type) {
    if (!(type in DNS_TYPES)) throw new Error("Unsupported DNS type");
    await ready;
    return cached(`dns:${type}:${name}`, 5 * MIN, async () => {
      const j = await fetchJson(`${base("doh")}?name=${encodeURIComponent(name)}&type=${type}`, {
        headers: { Accept: "application/dns-json" },
        timeout: 8000,
        validate: (x) => x && typeof x === "object" && "Status" in x
      });
      const answers = (j.Answer || [])
        .filter((a) => a.type === DNS_TYPES[type])
        .map((a) => (type === "TXT" ? String(a.data).replace(/^"|"$/g, "") : String(a.data)));
      return { nxdomain: j.Status === 3, answers };
    });
  }

  async function ip(domain) {
    return (await dns(domain, "A")).answers;
  }

  async function asn(addr) {
    await ready;
    return cached(`asn:${addr}`, 30 * MIN, async () => {
      const j = await fetchJson(`${base("asn")}?resource=${encodeURIComponent(addr)}`, {
        timeout: 10000,
        validate: (x) => x && x.status === "ok" && x.data
      });
      const d = j.data;
      const first = (d.asns || [])[0];
      return {
        ip: addr,
        asn: first ? `AS${first.asn}` : null,
        holder: first ? first.holder : null,
        prefix: d.resource || null,
        description: (d.block && (d.block.desc || d.block.name)) || null
      };
    });
  }

  async function geo(addr) {
    await ready;
    return cached(`geo:${addr}`, 30 * MIN, async () => {
      const j = await fetchJson(base("geo") + encodeURIComponent(addr), {
        timeout: 10000,
        validate: (x) => x && typeof x === "object"
      });
      if (j.success === false) throw new Error(j.message || "Geolocation lookup failed");
      const c = j.connection || {};
      return {
        ip: j.ip, country: j.country, countryCode: j.country_code, region: j.region, city: j.city,
        latitude: j.latitude, longitude: j.longitude, timezone: j.timezone && j.timezone.id,
        isp: c.isp, org: c.org, asn: c.asn ? `AS${c.asn}` : null, domain: c.domain
      };
    });
  }

  async function rdap(domain) {
    await ready;
    return cached(`rdap:${domain}`, 6 * 60 * MIN, async () => {
      try {
        return await fetchJson(base("rdap") + encodeURIComponent(domain), {
          timeout: 12000,
          headers: { Accept: "application/rdap+json, application/json" },
          validate: (x) => x && typeof x === "object"
        });
      } catch (e) {
        if (e.status === 404) return null;
        throw e;
      }
    });
  }

  async function certificates(domain) {
    await ready;
    return cached(`ct:${domain}`, 30 * MIN, async () => {
      const rows = await fetchJson(`${base("ct")}?q=${encodeURIComponent("%." + domain)}&output=json`, {
        timeout: 25000,
        validate: Array.isArray
      });
      const names = new Set();
      for (const row of rows) {
        for (const n of `${row.name_value || ""}\n${row.common_name || ""}`.split("\n")) {
          const s = n.trim().toLowerCase().replace(/^\*\./, "");
          if (s) names.add(s);
        }
      }
      return { certificateCount: rows.length, names: [...names].sort() };
    });
  }

  O.api = { dns, ip, asn, geo, rdap, certificates, SOURCES };
})();
