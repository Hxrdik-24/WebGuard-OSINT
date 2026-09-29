// Input validation. Every domain / IP is validated before any request is made.
(() => {
  const O = (self.OSINT = self.OSINT || {});

  // Small heuristic list. For exact results swap in the Public Suffix List.
  const MULTI_PART_TLDS = new Set([
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "co.jp", "ne.jp", "or.jp", "co.in", "net.in", "org.in", "co.za", "com.br",
    "com.cn", "com.mx", "com.tr", "com.sg", "com.hk", "com.tw", "co.kr", "com.ar",
    "com.ua", "co.il", "com.my", "com.ph", "com.pk", "com.eg"
  ]);

  const NON_PUBLIC_SUFFIXES = [
    ".local", ".localhost", ".internal", ".lan", ".home", ".home.arpa",
    ".intranet", ".corp", ".private", ".test", ".invalid"
  ];

  const stripBrackets = (s) => String(s || "").replace(/^\[|\]$/g, "");

  function isIPv4(s) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s));
    return !!m && m.slice(1).every((n) => Number(n) <= 255);
  }

  function isIPv6(s) {
    s = String(s);
    if (!s.includes(":") || !/^[0-9a-f:]+$/i.test(s)) return false;
    try { new URL(`http://[${s}]/`); return true; } catch { return false; }
  }

  function isPrivateIPv4(s) {
    const [a, b] = s.split(".").map(Number);
    return (
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 198 && (b === 18 || b === 19))
    );
  }

  function isPrivateIPv6(s) {
    s = s.toLowerCase();
    const first = parseInt(s.split(":")[0] || "0", 16);
    return (
      first === 0 ||                       // ::, ::1, ::ffff:x (mapped), etc.
      (first & 0xfe00) === 0xfc00 ||       // fc00::/7 unique local
      (first & 0xffc0) === 0xfe80 ||       // fe80::/10 link local
      (first & 0xff00) === 0xff00 ||       // multicast
      s.startsWith("64:ff9b:") ||          // NAT64
      s.startsWith("2001:db8")             // documentation
    );
  }

  function isPublicIP(s) {
    s = stripBrackets(s);
    if (isIPv4(s)) return !isPrivateIPv4(s);
    if (isIPv6(s)) return !isPrivateIPv6(s);
    return false;
  }

  function isValidHostname(h) {
    h = String(h || "").toLowerCase();
    if (!h || h.length > 253) return false;
    const labels = h.split(".");
    if (labels.length < 2) return false;
    if (!labels.every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) return false;
    return !/^\d+$/.test(labels[labels.length - 1]);
  }

  function isPublicDomain(h) {
    h = String(h || "").toLowerCase().replace(/\.$/, "");
    if (!isValidHostname(h) || isIPv4(h) || isIPv6(h)) return false;
    return !NON_PUBLIC_SUFFIXES.some((s) => h.endsWith(s));
  }

  function assertPublicDomain(h) {
    if (!isPublicDomain(h)) throw new Error("Not a public domain name");
    return String(h).toLowerCase().replace(/\.$/, "");
  }

  function assertPublicIP(ip) {
    if (!isPublicIP(ip)) throw new Error("Not a public IP address");
    return stripBrackets(ip);
  }

  function parseDomain(hostname) {
    const h = stripBrackets(hostname || "").toLowerCase().replace(/\.$/, "");
    if (isIPv4(h) || isIPv6(h)) {
      return { hostname: h, isIP: true, rootDomain: null, subdomain: null, tld: null };
    }
    const labels = h.split(".");
    if (labels.length < 2) return { hostname: h, isIP: false, rootDomain: h, subdomain: "", tld: h };
    const tldLen = MULTI_PART_TLDS.has(labels.slice(-2).join(".")) ? 2 : 1;
    const tld = labels.slice(-tldLen).join(".");
    if (labels.length <= tldLen) return { hostname: h, isIP: false, rootDomain: h, subdomain: "", tld };
    return {
      hostname: h,
      isIP: false,
      rootDomain: labels.slice(-(tldLen + 1)).join("."),
      subdomain: labels.slice(0, -(tldLen + 1)).join("."),
      tld
    };
  }

  function parseUrl(href) {
    const u = new URL(href);
    return {
      url: u.href,
      origin: u.origin,
      protocol: u.protocol.replace(":", ""),
      port: u.port || "(default)",
      path: u.pathname,
      query: u.search,
      hash: u.hash,
      ...parseDomain(u.hostname)
    };
  }

  O.validators = {
    stripBrackets, isIPv4, isIPv6, isPublicIP, isValidHostname, isPublicDomain,
    assertPublicDomain, assertPublicIP, parseDomain, parseUrl
  };
})();
