// The admin page's Activity tab (protocol.md 14.3). Polls /admin/activity.json with the
// session cookie and adds up each device's requests since the tab opened. Writes text
// only, never HTML.
"use strict";

(() => {
  const SOURCE = "/admin/activity.json";
  const STORE = "syncryption-admin-interval";
  const GROUP_STORE = "syncryption-admin-groupby";
  const FIELDS = [
    "requests",
    "waits",
    "errors4xx",
    "errors5xx",
    "requestBytes",
    "responseBytes",
  ];
  const DASH = "–";

  const $ = (id) => document.getElementById(id);
  const select = $("interval");
  const groupBy = $("groupby");
  const opened = new Date();
  // Per device: names, the totals added up since the tab opened, and the last interval's.
  const tally = new Map();
  let previous = null;
  let timer = null;

  restore(select, STORE);
  restore(groupBy, GROUP_STORE);
  $("since").textContent =
    `(since ${opened.toLocaleTimeString()}, when this tab opened)`;

  select.addEventListener("change", () => {
    remember(STORE, select.value);
    clearTimeout(timer);
    if (Number(select.value) > 0) tick();
  });
  groupBy.addEventListener("change", () => {
    remember(GROUP_STORE, groupBy.value);
    render();
  });

  function restore(el, key) {
    try {
      const saved = localStorage.getItem(key);
      if (saved !== null && [...el.options].some((o) => o.value === saved)) {
        el.value = saved;
      }
    } catch {
      // Storage blocked: keep the default.
    }
  }

  function remember(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch {
      // Not remembered, still applied.
    }
  }

  function schedule(seconds) {
    clearTimeout(timer);
    if (seconds > 0) timer = setTimeout(tick, seconds * 1000);
  }

  async function tick() {
    try {
      const r = await fetch(SOURCE, {
        credentials: "same-origin",
        cache: "no-store",
      });
      if (r.status === 401) {
        $("updated").textContent =
          "Logged out. Reload the page to log in again.";
        return;
      }
      if (!r.ok) throw new Error(String(r.status));
      const first = previous === null;
      add(await r.json());
      render();
      // Rates need two answers, so the first one is followed quickly by a second.
      schedule(
        first ? Math.min(Number(select.value), 1) : Number(select.value),
      );
    } catch {
      $("updated").textContent = "Update failed, retrying.";
      schedule(Number(select.value));
    }
  }

  // Add the change since the previous answer to the tally. The first answer is only the
  // starting point. After a restart, or for a device the previous answer didn't have, the
  // totals themselves are the change.
  function add(snap) {
    const restarted = previous && previous.startedAt !== snap.startedAt;
    const old = new Map(
      previous && !restarted
        ? previous.devices.map((d) => [d.deviceId, d])
        : [],
    );
    const dt = previous ? snap.time - previous.time : 0;
    for (const d of snap.devices) {
      let t = tally.get(d.deviceId);
      if (!t) {
        t = { routes: new Map(), rate: null };
        for (const f of FIELDS) t[f] = 0;
        tally.set(d.deviceId, t);
      }
      Object.assign(t, {
        deviceId: d.deviceId,
        username: d.username,
        vaultName: d.vaultName,
        deviceName: d.deviceName,
        fingerprint: d.fingerprint,
        status: d.status,
      });
      if (!previous) continue;
      const o = old.get(d.deviceId);
      const delta = (f) => Math.max(0, d[f] - (o ? o[f] : 0));
      for (const f of FIELDS) t[f] += delta(f);
      t.rate = dt > 0 ? delta("requests") / dt : null;
      for (const [route, n] of Object.entries(d.routes)) {
        const change = Math.max(0, n - (o ? o.routes[route] || 0 : 0));
        if (change > 0)
          t.routes.set(route, (t.routes.get(route) || 0) + change);
      }
    }
    // A device gone from the answer (deleted, or idle for an hour) keeps its tally.
    const present = new Set(snap.devices.map((d) => d.deviceId));
    for (const [id, t] of tally)
      if (!present.has(id)) t.rate = previous ? 0 : null;
    previous = snap;
    $("updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
  }

  function render() {
    const mode = groupBy.value;
    const groups = new Map();
    for (const t of tally.values()) {
      const key = groupKey(t, mode);
      let g = groups.get(key);
      if (!g) {
        g = { ...labels(t, mode), routes: new Map(), rate: null };
        for (const f of FIELDS) g[f] = 0;
        groups.set(key, g);
      }
      for (const f of FIELDS) g[f] += t[f];
      if (t.rate !== null) g.rate = (g.rate || 0) + t.rate;
      for (const [route, n] of t.routes)
        g.routes.set(route, (g.routes.get(route) || 0) + n);
    }
    const rows = [...groups.values()]
      .sort(
        (a, b) =>
          b.requests - a.requests ||
          b.responseBytes +
            b.requestBytes -
            (a.responseBytes + a.requestBytes) ||
          b.waits - a.waits ||
          a.sortName.localeCompare(b.sortName),
      )
      .map((g) => {
        const route = [...g.routes].sort((a, b) => b[1] - a[1])[0];
        return [
          g.user,
          g.vault,
          g.device,
          count(g.requests),
          g.rate === null ? DASH : g.rate.toFixed(1),
          count(g.waits),
          count(g.errors4xx + g.errors5xx),
          size(g.requestBytes),
          size(g.responseBytes),
          route ? route[0] : DASH,
        ];
      });
    if (rows.length === 0)
      rows.push([DASH, "", "", "", "", "", "", "", "", ""]);
    $("activity").replaceChildren(
      ...rows.map((cells) => {
        const tr = document.createElement("tr");
        cells.forEach((text, i) => {
          const td = document.createElement("td");
          if (i >= 3 && i <= 8) td.className = "num";
          td.textContent = text;
          tr.append(td);
        });
        return tr;
      }),
    );
  }

  // Requests without a session form one group in every mode, as does each deleted device.
  function groupKey(t, mode) {
    if (t.deviceId === null) return "anonymous";
    if (t.username === null || mode === "device") return `device:${t.deviceId}`;
    if (mode === "user") return `user:${t.username}`;
    return `vault:${t.username}/${t.vaultName}`;
  }

  function labels(t, mode) {
    if (t.deviceId === null)
      return { user: "Not logged in", vault: "", device: "", sortName: "" };
    if (t.username === null) {
      const device = `Deleted device ${t.deviceId.slice(0, 8)}`;
      return { user: DASH, vault: DASH, device, sortName: device };
    }
    const short = t.fingerprint ? ` (${t.fingerprint.slice(7, 15)})` : "";
    const pending = t.status === "pending" ? ", pending" : "";
    const vault = mode === "user" ? "" : t.vaultName;
    const device =
      mode === "device" ? `${t.deviceName || "Unnamed"}${short}${pending}` : "";
    return {
      user: t.username,
      vault,
      device,
      sortName: `${t.username}/${vault}/${device}`,
    };
  }

  function count(n) {
    return n.toLocaleString("en-US");
  }

  function size(n) {
    let value = n;
    for (const unit of ["B", "KB", "MB", "GB"]) {
      if (value < 1024 || unit === "GB") {
        return unit === "B"
          ? `${value.toFixed(0)} B`
          : `${value.toFixed(1)} ${unit}`;
      }
      value /= 1024;
    }
    return `${n} B`;
  }

  tick();
})();
