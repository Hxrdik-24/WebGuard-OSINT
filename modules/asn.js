(() => {
  const O = (self.OSINT = self.OSINT || {});
  O.asn = { lookup: (ip) => O.api.asn(O.validators.assertPublicIP(ip)) };
})();
