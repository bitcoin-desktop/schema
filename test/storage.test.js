// IdbStorage lifecycle: close() must release the cached connection so a
// deleteDatabase is never blocked by us, and a later operation reopens.
// Node has no IndexedDB, so a minimal counting fake stands in — it tracks
// exactly what the contract cares about: connections opened and closed.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { IdbStorage, MemoryStorage } from '../codec/node.js';

function fakeIndexedDB() {
  const stats = { opened: 0, closed: 0 };
  const kv = new Map();
  globalThis.indexedDB = {
    open() {
      stats.opened++;
      const db = {
        close: () => { stats.closed++; },
        createObjectStore: () => {},
        transaction: () => ({
          objectStore: () => ({
            get(k) { const r = {}; queueMicrotask(() => { r.result = kv.get(k); r.onsuccess?.(); }); return r; },
            put(v, k) { kv.set(k, v); },
          }),
          set oncomplete(fn) { queueMicrotask(fn); },
        }),
      };
      const req = { result: db };
      queueMicrotask(() => req.onsuccess?.());
      return req;
    },
  };
  return stats;
}

test('close() releases the connection; the next operation reopens', async () => {
  const stats = fakeIndexedDB();
  try {
    const s = new IdbStorage('t');
    await s.set('a', '1');
    assert.equal(await s.get('a'), '1');
    assert.equal(stats.opened, 1);

    s.close();
    assert.equal(stats.closed, 1, 'cached connection actually closed');
    s.close(); // idempotent
    assert.equal(stats.closed, 1);

    assert.equal(await s.get('a'), '1', 'reopens cleanly after close');
    assert.equal(stats.opened, 2);
  } finally { delete globalThis.indexedDB; }
});

test('MemoryStorage.close() exists for interface symmetry', () => {
  const s = new MemoryStorage();
  s.close();
  s.close();
});
