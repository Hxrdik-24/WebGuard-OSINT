// Small formatting helpers shared by the dashboard, report and modules.
(() => {
  const O = (self.OSINT = self.OSINT || {});

  function debounce(fn, ms) {
    let t;
    return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
  }

  const truncate = (s, n = 300) => {
    s = String(s ?? "");
    return s.length > n ? s.slice(0, n) + "…" : s;
  };

  const date = (iso) => (iso ? String(iso).slice(0, 10) : "—");

  // Plain-text rendering of nested data (used for copy + TXT export).
  function toText(v, ind = 0) {
    const pad = "  ".repeat(ind);
    if (v === null || v === undefined) return pad + "-";
    if (typeof v !== "object") return pad + String(v);
    if (Array.isArray(v)) {
      if (!v.length) return pad + "(none)";
      return v.map((x) => (x && typeof x === "object" ? pad + "-\n" + toText(x, ind + 1) : pad + "- " + x)).join("\n");
    }
    const entries = Object.entries(v).filter(([, x]) => x !== undefined);
    if (!entries.length) return pad + "(empty)";
    return entries
      .map(([k, x]) => (x && typeof x === "object" ? `${pad}${k}:\n${toText(x, ind + 1)}` : `${pad}${k}: ${x ?? "-"}`))
      .join("\n");
  }

  O.fmt = { debounce, truncate, date, toText };
})();
