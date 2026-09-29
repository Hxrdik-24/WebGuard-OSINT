// Android platform adapter: same dashboard, but network calls go through the native bridge.
// __TOKEN__ (per page load) and __CSS__ are substituted by MainActivity before injection.
(function () {
  var TOKEN = "__TOKEN__";
  var CSS = __CSS__;
  var pending = {}, seq = 0;

  // Non-enumerable, token-named callback: page scripts cannot discover it by simple enumeration.
  Object.defineProperty(window, "__osint_" + TOKEN, {
    enumerable: false, configurable: true,
    value: function (id, ok, payload) {
      var p = pending[id]; if (!p) return; delete pending[id];
      if (ok) { try { p.resolve(JSON.parse(payload)); } catch (e) { p.reject(new Error("Bad response")); } }
      else p.reject(new Error(payload || "Request failed"));
    }
  });

  var O = self.OSINT;
  O.mountDashboard({
    call: function (op, params) {
      return new Promise(function (resolve, reject) {
        var id = ++seq;
        pending[id] = { resolve: resolve, reject: reject };
        OsintNative.request(TOKEN, id, op, JSON.stringify(params || {}));
        setTimeout(function () { if (pending[id]) { delete pending[id]; reject(new Error("Request timed out")); } }, 35000);
      });
    },
    getCss: function () { return Promise.resolve(CSS); },
    loadPosition: function () {
      try { var s = OsintNative.getPosition(TOKEN); return Promise.resolve(s ? JSON.parse(s) : null); }
      catch (e) { return Promise.resolve(null); }
    },
    savePosition: function (pos) { OsintNative.setPosition(TOKEN, pos.left, pos.top); },
    clearCache: function () { OsintNative.clearCache(TOKEN); return Promise.resolve(); }
  });
  try { delete window.OSINT; } catch (e) {}   // hide the module namespace from the page
})();
