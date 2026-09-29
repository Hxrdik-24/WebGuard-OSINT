// DNS records via DoH (background).
(() => {
  const O = (self.OSINT = self.OSINT || {});
  const TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"];

  async function records(domain) {
    domain = O.validators.assertPublicDomain(domain);
    const out = { domain, records: {}, errors: {} };
    await Promise.all(TYPES.map(async (t) => {
      try { out.records[t] = (await O.api.dns(domain, t)).answers; }
      catch (e) { out.records[t] = []; out.errors[t] = e.message; }
    }));
    if (Object.keys(out.errors).length === TYPES.length) throw new Error("DNS service unreachable");
    return out;
  }

  O.dns = { TYPES, records };
})();
