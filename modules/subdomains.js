// Passive subdomain discovery from Certificate Transparency. No brute forcing.
(() => {
  const O = (self.OSINT = self.OSINT || {});
  const V = O.validators;
  const MAX_STATUS_CHECKS = 25;
  const SOURCE = "crt.sh (Certificate Transparency)";

  async function discover(domain) {
    const root = V.parseDomain(V.assertPublicDomain(domain)).rootDomain;
    const ct = await O.api.certificates(root);
    const names = ct.names
      .filter((n) => n !== root && n.endsWith("." + root) && V.isValidHostname(n))
      .slice(0, 300);

    const items = names.map((name) => ({ name, source: SOURCE, status: "not checked" }));
    const toCheck = items.slice(0, MAX_STATUS_CHECKS);
    for (let i = 0; i < toCheck.length; i += 5) {
      await Promise.all(toCheck.slice(i, i + 5).map(async (it) => {
        try {
          const r = await O.api.dns(it.name, "A");
          it.status = r.answers.length ? "resolves" : "no A record";
        } catch { it.status = "unknown"; }
      }));
    }
    return { domain: root, total: items.length, checked: toCheck.length, items };
  }

  O.subdomains = { discover };
})();
