// Domain age via RDAP. Only registrar name, dates and status are surfaced (no contacts).
(() => {
  const O = (self.OSINT = self.OSINT || {});
  const V = O.validators;

  async function lookup(domain) {
    domain = V.assertPublicDomain(domain);
    const root = V.parseDomain(domain).rootDomain;
    const j = await O.api.rdap(root);
    if (!j) return { domain: root, found: false };

    const ev = {};
    for (const e of j.events || []) ev[e.eventAction] = e.eventDate;

    let registrar = null;
    const reg = (j.entities || []).find((e) => (e.roles || []).includes("registrar"));
    if (reg && reg.vcardArray && Array.isArray(reg.vcardArray[1])) {
      const fn = reg.vcardArray[1].find((x) => x[0] === "fn");
      registrar = fn ? fn[3] : null;
    }
    const registered = ev.registration || null;
    const ageDays = registered ? Math.floor((Date.now() - Date.parse(registered)) / 86400000) : null;

    return {
      domain: root, found: true, registrar, registered,
      updated: ev["last changed"] || null,
      expires: ev.expiration || null,
      ageDays: Number.isFinite(ageDays) ? ageDays : null,
      status: j.status || []
    };
  }

  O.whois = { lookup };
})();
