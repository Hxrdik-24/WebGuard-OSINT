// ================================
// IP Finder - Chrome adapter
// Connects the platform-independent dashboard (ui/dashboard.js) to Chrome APIs.
// content.js -> background.js -> OSINT module -> public API -> dashboard
// ================================
(() => {
  const O = self.OSINT;

  const send = (msg) =>
    new Promise((resolve, reject) => {
      try {
        chrome.runtime.sendMessage(msg, (r) => {
          if (chrome.runtime.lastError) return reject(new Error("Extension background unavailable"));
          resolve(r);
        });
      } catch {
        reject(new Error("Extension was reloaded - refresh this page"));
      }
    });

  O.mountDashboard({
    async call(op, params) {
      const r = await send({ type: "OSINT_RUN", op, params });
      if (!r || !r.ok) throw new Error((r && r.error) || "Request failed");
      return r.data;
    },
    async getCss() {
      const r = await send({ type: "OSINT_GET_CSS" });
      return r && r.ok ? r.data : "";
    },
    loadPosition: () =>
      new Promise((resolve) => chrome.storage.local.get("ipFinderPosition", (r) => resolve(r.ipFinderPosition || null))),
    savePosition: (pos) => chrome.storage.local.set({ ipFinderPosition: pos }),
    clearCache: () => send({ type: "OSINT_CLEAR_CACHE" }).catch(() => {})
  });
})();
