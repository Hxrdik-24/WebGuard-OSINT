(() => {
  const O = (self.OSINT = self.OSINT || {});
  O.geo = { lookup: (ip) => O.api.geo(O.validators.assertPublicIP(ip)) };
})();
