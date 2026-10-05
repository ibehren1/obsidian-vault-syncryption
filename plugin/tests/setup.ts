// The plugin calls timers through `window` (Obsidian popout windows); the tests run in Node.
(globalThis as { window?: unknown }).window ??= globalThis;
