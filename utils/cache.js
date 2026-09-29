// In-memory TTL cache with in-flight de-duplication. Failed requests are never cached.
(() => {
  const O = (self.OSINT = self.OSINT || {});
  const store = new Map();

  function get(key, ttlMs, fn) {
    const hit = store.get(key);
    if (hit && hit.exp > Date.now()) return hit.p;
    if (store.size > 500) store.clear();
    const p = Promise.resolve().then(fn);
    store.set(key, { p, exp: Date.now() + ttlMs });
    p.catch(() => store.delete(key));
    return p;
  }

  O.cache = { get, clear: () => store.clear() };
})();
