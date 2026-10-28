// In-memory stand-in for a Netlify Blobs store, including version tags and conditional writes,
// so the tests exercise the same compare-and-swap paths the real store uses.
export function memoryStore({ slow = false } = {}) {
  const m = new Map();
  let version = 0;
  const tick = () => (slow ? new Promise((r) => setImmediate(r)) : Promise.resolve());
  return {
    async list({ prefix }) { await tick(); return { blobs: [...m.keys()].filter((k) => k.startsWith(prefix)).map((key) => ({ key, etag: m.get(key).etag })) }; },
    async get(key) { await tick(); return m.has(key) ? JSON.parse(m.get(key).v) : null; },
    async getWithMetadata(key) {
      await tick();
      if (!m.has(key)) return null;
      const e = m.get(key);
      return { data: JSON.parse(e.v), etag: e.etag, metadata: {} };
    },
    async setJSON(key, value, opts = {}) {
      await tick();
      const cur = m.get(key); // from here to the write there is no await: the check and the write are one step
      if (opts.onlyIfNew && cur) return { modified: false };
      if (opts.onlyIfMatch !== undefined && (!cur || cur.etag !== opts.onlyIfMatch)) return { modified: false };
      const etag = `"${++version}"`;
      m.set(key, { v: JSON.stringify(value), etag });
      return { modified: true, etag };
    },
    async delete(key) { await tick(); m.delete(key); },
    keys() { return [...m.keys()]; },
  };
}
