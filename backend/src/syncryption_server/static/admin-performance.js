// The admin page's Performance tab (protocol.md 14.2). Polls /admin/performance.json with
// the session cookie and turns two snapshots into rates. Writes text only, never HTML.
"use strict";

(() => {
  const SOURCE = "/admin/performance.json";
  const STORE = "syncryption-admin-interval";
  const TOP_ROUTES = 8;
  const DASH = "–";

  const $ = (id) => document.getElementById(id);
  const select = $("interval");
  let previous = null;
  let timer = null;

  try {
    const saved = localStorage.getItem(STORE);
    if (saved !== null && [...select.options].some((o) => o.value === saved)) {
      select.value = saved;
    }
  } catch {
    // Storage blocked: keep the default.
  }

  select.addEventListener("change", () => {
    try {
      localStorage.setItem(STORE, select.value);
    } catch {
      // Not remembered, still applied.
    }
    clearTimeout(timer);
    if (Number(select.value) > 0) tick();
  });

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
      const snap = await r.json();
      // A restart resets the counters: start over.
      const before =
        previous && previous.startedAt === snap.startedAt ? previous : null;
      show(snap, before);
      previous = snap;
      // Rates need two snapshots, so the first one is followed quickly by a second.
      schedule(
        before ? Number(select.value) : Math.min(Number(select.value), 1),
      );
    } catch {
      $("updated").textContent = "Update failed, retrying.";
      schedule(Number(select.value));
    }
  }

  function set(id, text) {
    $(id).textContent = text;
  }

  function show(snap, before) {
    const dt = before ? snap.time - before.time : 0;
    const rate = (now, then) => (dt > 0 ? (now - then) / dt : null);

    set(
      "updated",
      `Updated ${new Date().toLocaleTimeString()} · up ${duration(snap.time - snap.startedAt)}`,
    );

    // Requests per second matching `keep`, from the change in their counts.
    const total = (s, keep) =>
      s.requests.filter(keep).reduce((sum, r) => sum + r.count, 0);
    const perSecond = (keep) =>
      before ? rate(total(snap, keep), total(before, keep)) : null;
    const status = (prefix) => (r) => r.status.startsWith(prefix);
    const route =
      (method, path, prefix = "") =>
      (r) =>
        r.method === method && r.route === path && r.status.startsWith(prefix);
    const showRate = (id, keep) => {
      const value = perSecond(keep);
      set(id, number(value, 1));
      trend(id, value);
    };

    showRate("rps", () => true);
    showRate("e5", status("5"));
    showRate("e4", status("4"));

    const files = "/api/v1/vaults/{vault_id}/files/{file_id}";
    const blob = "/api/v1/vaults/{vault_id}/blobs/{blob_id}";
    showRate("commits", route("PUT", files, "2"));
    showRate("conflicts", route("PUT", files, "409"));
    showRate("uploads", route("PUT", blob, "2"));
    showRate("downloads", route("GET", blob, "2"));
    showRate("logins", route("POST", "/api/v1/auth/verify", "2"));
    showRate("s401", status("401"));
    showRate("s429", status("429"));

    // Latency from the histogram buckets that filled up between the two snapshots.
    const deltas = new Map();
    if (before) {
      const old = new Map(
        before.durations.map((d) => [`${d.method} ${d.route}`, d.buckets]),
      );
      for (const d of snap.durations) {
        const then =
          old.get(`${d.method} ${d.route}`) || d.buckets.map(() => 0);
        deltas.set(`${d.method} ${d.route}`, {
          route: d.route,
          buckets: d.buckets.map((n, i) => n - then[i]),
        });
      }
    }
    const merged = snap.buckets.concat([Infinity]).map(() => 0);
    for (const d of deltas.values()) {
      if (d.route.endsWith("/wait")) continue; // long-polls wait on purpose
      d.buckets.forEach((n, i) => (merged[i] += n));
    }
    const p95 = quantile(0.95, merged, snap.buckets);
    set("p50", latency(quantile(0.5, merged, snap.buckets)));
    set("p95", latency(p95));
    set("p99", latency(quantile(0.99, merged, snap.buckets)));
    trend("p95", p95 === Infinity ? null : p95);

    routes(snap, before, deltas, dt);

    const bytesIn = before
      ? rate(snap.requestBytes, before.requestBytes)
      : null;
    const bytesOut = before
      ? rate(snap.responseBytes, before.responseBytes)
      : null;
    set("bin", bytesIn === null ? DASH : `${size(bytesIn)}/s`);
    set("bout", bytesOut === null ? DASH : `${size(bytesOut)}/s`);
    trend("bin", bytesIn);
    trend("bout", bytesOut);
    const inFlight = Math.max(snap.inFlight - snap.longpolls, 0);
    set("inflight", String(inFlight));
    trend("inflight", inFlight);
    set("longpolls", String(snap.longpolls));
    trend("longpolls", snap.longpolls);
    set("lag", latency(snap.loopLagSeconds));
    trend("lag", snap.loopLagSeconds);

    const p = snap.process;
    const c = snap.container;
    const cpu = (id, now, then) => {
      const value =
        now !== null && then !== null && dt > 0
          ? ((now - then) / dt) * 100
          : null;
      set(id, value === null ? DASH : `${number(value, 1)} %`);
      trend(id, value);
    };
    cpu("cpu", p.cpuSeconds, before ? before.process.cpuSeconds : null);
    set("mem", p.memoryBytes !== null ? size(p.memoryBytes) : DASH);
    trend("mem", p.memoryBytes);
    set("fds", p.openFds !== null ? String(p.openFds) : DASH);
    $("row-ccpu").hidden = c.cpuSeconds === null;
    cpu("ccpu", c.cpuSeconds, before ? before.container.cpuSeconds : null);
    $("row-cmem").hidden = c.memoryBytes === null;
    if (c.memoryBytes !== null) {
      set(
        "cmem",
        c.memoryLimitBytes !== null
          ? `${size(c.memoryBytes)} / ${size(c.memoryLimitBytes)}`
          : size(c.memoryBytes),
      );
      trend("cmem", c.memoryBytes);
    }
    set("locks", String(snap.locks));
    set("maintenance", snap.maintenance ? "on" : "off");
    set(
      "failures",
      `${snap.adminTokenFailures} / ${snap.sharedSecretFailures}`,
    );

    const disk = snap.disk;
    $("row-disk").hidden = disk.freeBytes === null;
    if (disk.freeBytes !== null) {
      const share = disk.totalBytes
        ? (disk.freeBytes / disk.totalBytes) * 100
        : 0;
      set(
        "disk",
        `${size(disk.freeBytes)} of ${size(disk.totalBytes)} (${share.toFixed(0)} %)`,
      );
    }
    $("row-db").hidden = snap.dbBytes === null;
    if (snap.dbBytes !== null) set("db", size(snap.dbBytes));
    $("row-wal").hidden = snap.dbWalBytes === null;
    if (snap.dbWalBytes !== null) set("wal", size(snap.dbWalBytes));
    const failed = Object.values(snap.gcFailures).reduce((a, b) => a + b, 0);
    set(
      "gc",
      `${snap.gcRuns.retention ?? 0} / ${snap.gcRuns.blobs ?? 0}, ${failed} failed`,
    );
    const runs = Object.values(snap.gcLastRun).filter((t) => t !== null);
    set(
      "gclast",
      runs.length
        ? `${duration(snap.time - Math.max(...runs))} ago`
        : "not yet",
    );
    set("pruned", count(snap.prunedRevisions));
    set("deleted", count(snap.deletedBlobs));

    const dev = snap.devices;
    set("users", count(snap.users));
    set("vaults", count(snap.vaults));
    set(
      "keys",
      `${count(dev.active ?? 0)} active, ${count(dev.pending ?? 0)} pending, ${count(dev.revoked ?? 0)} revoked`,
    );
    set("files", count(snap.files));
    set("revisions", count(snap.revisions));
    set("blobs", count(snap.blobs));
    set("stored", size(snap.blobBytes));
    trend("stored", snap.blobBytes);
  }

  // The last readings of each value with a sparkline, drawn as a small SVG line.
  const SPARK_POINTS = 60;
  const SPARK_WIDTH = 80;
  const SPARK_HEIGHT = 18;
  const SVG = "http://www.w3.org/2000/svg";
  const history = new Map();

  function trend(id, value) {
    const box = $(`spark-${id}`);
    if (!box || value === null || value === undefined || !isFinite(value))
      return;
    const values = history.get(id) || [];
    values.push(value);
    if (values.length > SPARK_POINTS) values.shift();
    history.set(id, values);
    if (values.length < 2) return;
    const low = Math.min(0, ...values);
    const high = Math.max(...values);
    const span = high - low || 1;
    const step = SPARK_WIDTH / (SPARK_POINTS - 1);
    const offset = (SPARK_POINTS - values.length) * step;
    const points = values
      .map((v, i) => {
        const x = offset + i * step;
        const y = SPARK_HEIGHT - 1 - ((v - low) / span) * (SPARK_HEIGHT - 2);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
    let svg = box.firstElementChild;
    if (!svg) {
      svg = document.createElementNS(SVG, "svg");
      svg.setAttribute("width", String(SPARK_WIDTH));
      svg.setAttribute("height", String(SPARK_HEIGHT));
      svg.setAttribute("aria-hidden", "true");
      const line = document.createElementNS(SVG, "polyline");
      line.setAttribute("fill", "none");
      line.setAttribute("stroke", "#2d2f31");
      line.setAttribute("stroke-width", "1.5");
      line.setAttribute("stroke-linejoin", "round");
      svg.append(line);
      box.append(svg);
    }
    svg.firstElementChild.setAttribute("points", points);
    box.title = `Last ${values.length} readings`;
  }

  function routes(snap, before, deltas, dt) {
    const body = $("routes");
    const sums = new Map();
    if (before && dt > 0) {
      const old = new Map();
      for (const r of before.requests) {
        const key = `${r.method} ${r.route}`;
        old.set(key, (old.get(key) || 0) + r.count);
      }
      for (const r of snap.requests) {
        const key = `${r.method} ${r.route}`;
        sums.set(key, (sums.get(key) || 0) + r.count);
      }
      for (const [key, n] of sums)
        sums.set(key, (n - (old.get(key) || 0)) / dt);
    }
    const top = [...sums]
      .filter(([, r]) => r > 0)
      .sort((a, b) => b[1] - a[1])
      .slice(0, TOP_ROUTES);
    const rows = top.map(([key, r]) => {
      const d = deltas.get(key);
      const p95 = d ? latency(quantile(0.95, d.buckets, snap.buckets)) : DASH;
      return [key, number(r, 1), p95];
    });
    if (rows.length === 0)
      rows.push([before ? "No requests in this interval." : DASH, "", ""]);
    body.replaceChildren(
      ...rows.map((cells) => {
        const tr = document.createElement("tr");
        cells.forEach((text, i) => {
          const td = document.createElement("td");
          if (i > 0) td.className = "num";
          td.textContent = text;
          tr.append(td);
        });
        return tr;
      }),
    );
  }

  // Like Prometheus' histogram_quantile: linear within the bucket. `counts` are cumulative
  // per bound in `bounds`, then +Inf. Returns seconds, Infinity past the last bound, or null.
  function quantile(q, counts, bounds) {
    const total = counts[counts.length - 1];
    if (!total) return null;
    const rank = q * total;
    const i = counts.findIndex((n) => n >= rank);
    if (i >= bounds.length) return Infinity;
    const low = i === 0 ? 0 : bounds[i - 1];
    const below = i === 0 ? 0 : counts[i - 1];
    const inside = counts[i] - below;
    return inside > 0
      ? low + ((bounds[i] - low) * (rank - below)) / inside
      : bounds[i];
  }

  function latency(seconds) {
    if (seconds === null) return DASH;
    if (seconds === Infinity) return "> 60 s";
    return seconds < 1
      ? `${Math.round(seconds * 1000)} ms`
      : `${seconds.toFixed(1)} s`;
  }

  function number(value, digits) {
    return value === null ? DASH : value.toFixed(digits);
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

  function duration(seconds) {
    const s = Math.max(0, Math.floor(seconds));
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m ${s % 60}s`;
  }

  tick();
})();
