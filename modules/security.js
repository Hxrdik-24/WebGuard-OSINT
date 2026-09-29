// Security-header summary. Intentionally no overall score.
(() => {
  const O = (self.OSINT = self.OSINT || {});

  const CHECKS = [
    { key: "strict-transport-security", label: "Strict-Transport-Security", httpsOnly: true },
    { key: "content-security-policy", label: "Content-Security-Policy", reportOnly: "content-security-policy-report-only" },
    { key: "x-frame-options", label: "X-Frame-Options",
      alt: (h) => /frame-ancestors/i.test(h["content-security-policy"] || "") && "Covered by CSP frame-ancestors" },
    { key: "x-content-type-options", label: "X-Content-Type-Options" },
    { key: "referrer-policy", label: "Referrer-Policy" },
    { key: "permissions-policy", label: "Permissions-Policy" },
    { key: "cross-origin-opener-policy", label: "Cross-Origin-Opener-Policy" },
    { key: "cross-origin-resource-policy", label: "Cross-Origin-Resource-Policy" },
    { key: "cross-origin-embedder-policy", label: "Cross-Origin-Embedder-Policy" }
  ];

  function evaluate(headers, protocol) {
    return CHECKS.map((c) => {
      const base = { header: c.key, label: c.label };
      if (c.httpsOnly && protocol !== "https:") {
        return { ...base, status: "not_detectable", note: "Only sent over HTTPS" };
      }
      if (headers[c.key] !== undefined) return { ...base, status: "present", value: String(headers[c.key]).slice(0, 200) };
      const alt = c.alt && c.alt(headers);
      if (alt) return { ...base, status: "present", note: alt };
      if (c.reportOnly && headers[c.reportOnly] !== undefined) {
        return { ...base, status: "missing", note: "Only the Report-Only variant is present" };
      }
      return { ...base, status: "missing" };
    });
  }

  O.security = { evaluate };
})();
