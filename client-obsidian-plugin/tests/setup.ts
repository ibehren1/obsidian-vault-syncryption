import { IDBKeyRange } from "fake-indexeddb";

// The plugin calls timers through `window` (Obsidian popout windows); the tests run in Node.
(globalThis as { window?: unknown }).window ??= globalThis;
// IndexedDB key ranges are globals in Obsidian; the tests use fake-indexeddb's.
(globalThis as { IDBKeyRange?: unknown }).IDBKeyRange ??= IDBKeyRange;
