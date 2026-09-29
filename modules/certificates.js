(() => {
  const O = (self.OSINT = self.OSINT || {});
  const V = O.validators;

  async function lookup(domain) {
    const root = V.parseDomain(V.assertPublicDomain(domain)).rootDomain;
    const r = await O.api.certificates(root);
    return { domain: root, certificateCount: r.certificateCount, total: r.names.length, names: r.names.slice(0, 1000) };
  }

  O.certificates = { lookup };
})();
