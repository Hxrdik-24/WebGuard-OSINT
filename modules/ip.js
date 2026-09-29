// IPv4 / IPv6 lookup and reverse DNS (background).
(() => {
  const O = (self.OSINT = self.OSINT || {});
  const V = O.validators;

  async function v4(domain) {
    domain = V.assertPublicDomain(domain);
    const r = await O.api.dns(domain, "A");
    return { domain, ips: r.answers.filter(V.isIPv4), nxdomain: r.nxdomain };
  }

  async function v6(domain) {
    domain = V.assertPublicDomain(domain);
    const r = await O.api.dns(domain, "AAAA");
    return { domain, ips: r.answers.filter(V.isIPv6), nxdomain: r.nxdomain };
  }

  function expandV6(ip) {
    const [head, tail] = ip.toLowerCase().split("::");
    const h = head ? head.split(":") : [];
    const t = tail ? tail.split(":") : [];
    const mid = ip.includes("::") ? Array(8 - h.length - t.length).fill("0") : [];
    return [...h, ...mid, ...t].map((x) => x.padStart(4, "0")).join("");
  }

  function ptrName(ip) {
    if (V.isIPv4(ip)) return ip.split(".").reverse().join(".") + ".in-addr.arpa";
    return expandV6(ip).split("").reverse().join(".") + ".ip6.arpa";
  }

  async function reverse(ips) {
    if (!Array.isArray(ips)) throw new Error("ips must be an array");
    const list = [...new Set(ips.map(V.assertPublicIP))].slice(0, 6);
    const results = await Promise.all(list.map(async (ip) => {
      try {
        const r = await O.api.dns(ptrName(ip), "PTR");
        return { ip, ptr: r.answers.map((s) => s.replace(/\.$/, "")) };
      } catch (e) {
        return { ip, ptr: [], error: e.message };
      }
    }));
    return { results };
  }

  O.ip = { v4, v6, reverse, ptrName };
})();
