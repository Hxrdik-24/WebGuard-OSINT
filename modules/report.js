// Builds the structured OSINT report from operations that completed successfully.
(() => {
  const O = (self.OSINT = self.OSINT || {});

  const TITLES = [
    ["target", "Target"], ["domain", "Domain"], ["ips", "IPs"], ["dns", "DNS"], ["asn", "ASN"],
    ["network", "Network"], ["approximateLocation", "Approximate location (IP geolocation is approximate)"],
    ["rdap", "WHOIS / RDAP"], ["httpHeaders", "HTTP headers"], ["securityHeaders", "Security headers"],
    ["technologies", "Technologies"], ["robots", "Robots.txt"], ["sitemap", "Sitemap"], ["metadata", "Metadata"],
    ["externalResources", "External resources"], ["subdomains", "Subdomains"],
    ["certificateTransparency", "Certificate Transparency"]
  ];

  function build(target, r, sources) {
    const ips = {};
    if (r.ipv4) ips.ipv4 = r.ipv4.ips;
    if (r.ipv6) ips.ipv6 = r.ipv6.ips;
    if (r.rdns) ips.reverseDns = r.rdns.results;
    return {
      tool: "IP Finder - OSINT Web Intelligence Assistant",
      generatedAt: new Date().toISOString(),
      note: "Passive, publicly available information only. IP geolocation is approximate.",
      target,
      domain: r.domain,
      ips: Object.keys(ips).length ? ips : undefined,
      dns: r.dns, asn: r.asn, network: r.network, approximateLocation: r.geo, rdap: r.rdap,
      httpHeaders: r.headers, securityHeaders: r.secheaders, technologies: r.tech,
      robots: r.robots, sitemap: r.sitemap, metadata: r.metadata, externalResources: r.resources,
      subdomains: r.subdomains, certificateTransparency: r.certs,
      sources
    };
  }

  function toText(rep) {
    const out = [`${rep.tool}`, `Generated: ${rep.generatedAt}`, rep.note];
    for (const [key, title] of TITLES) {
      if (rep[key] === undefined) continue;
      out.push("", `== ${title} ==`, O.fmt.toText(rep[key], 1));
    }
    out.push("", "== Data sources ==", O.fmt.toText(rep.sources, 1));
    return out.join("\n");
  }

  O.report = { build, toText };
})();
