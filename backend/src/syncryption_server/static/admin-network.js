// The admin page's Network tab (protocol.md 14.4). Fetches /admin/network.json and
// /admin/network-totals.json with the session cookie and draws the recorded traffic as
// stacked areas per group, with totals per range and per period. Writes text only, never
// HTML.
"use strict";

(() => {
  const SOURCE = "/admin/network.json";
  const TOTALS = "/admin/network-totals.json";
  const RANGE_STORE = "syncryption-admin-network-range";
  const GROUP_STORE = "syncryption-admin-network-groupby";
  const PERIOD_STORE = "syncryption-admin-network-period";
  const REFRESH = 30;
  const DASH = "–";
  const SVG = "http://www.w3.org/2000/svg";
  // Categorical slots in a fixed order (each group keeps its slot while the tab is open),
  // and "Other".
  const PALETTE = [
    "#2a78d6",
    "#eb6834",
    "#1baf7a",
    "#eda100",
    "#e87ba4",
    "#008300",
    "#6250d6",
    "#e34948",
  ];
  const OTHER = "#8a8d90";
  const CHARTS = ["web_in", "web_out", "s3_in", "s3_out"];
  const FIELDS = ["web_in", "web_out", "requests", "s3_in", "s3_out", "s3_ops"];
  const WINDOWS = {
    hour: "Last hour",
    day: "Last 24 hours",
    week: "Last 7 days",
    month: "Last 30 days",
    all: "All monitored time",
  };
  const GROUP_NAMES = {
    device: "device",
    vault: "vault",
    user: "user",
    client: "client",
  };
  const HEIGHT = 200;
  const PAD = { left: 64, right: 8, top: 8, bottom: 22 };

  const $ = (id) => document.getElementById(id);
  const range = $("range");
  const groupBy = $("groupby");
  const period = $("period");
  const tooltip = $("tooltip");
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  const slots = new Map();
  let filter = "";
  let data = null;
  let timer = null;
  // The period table's rows, and whether only its first page is shown.
  let periodRows = [];
  let firstPageOnly = true;

  restore(range, RANGE_STORE);
  restore(groupBy, GROUP_STORE);
  restore(period, PERIOD_STORE);
  $("tz").textContent = `(${tz})`;

  range.addEventListener("change", () => {
    remember(RANGE_STORE, range.value);
    refresh();
  });
  groupBy.addEventListener("change", () => {
    remember(GROUP_STORE, groupBy.value);
    refresh(true);
  });
  period.addEventListener("change", () => {
    remember(PERIOD_STORE, period.value);
    loadPeriods(true);
  });
  $("filter-clear").addEventListener("click", () => {
    filter = "";
    refresh(true);
  });
  $("older").addEventListener("click", () => loadPeriods(false));
  window.addEventListener("resize", () => {
    if (data) drawCharts();
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

  async function get(url) {
    const r = await fetch(url, { credentials: "same-origin", cache: "no-store" });
    if (r.status === 401) {
      $("updated").textContent = "Logged out. Reload the page to log in again.";
      throw new Error("logged out");
    }
    if (!r.ok) throw new Error(String(r.status));
    return r.json();
  }

  function query(extra) {
    const q = new URLSearchParams({ group: groupBy.value, filter, ...extra });
    return q.toString();
  }

  async function refresh(withPeriods) {
    clearTimeout(timer);
    try {
      const extra = {};
      if (range.value === "mtd") {
        // From the 1st of this month, in the browser's time zone.
        const now = new Date();
        const first = new Date(now.getFullYear(), now.getMonth(), 1);
        extra.start = String(Math.floor(first.getTime() / 1000));
      } else if (range.value !== "all") {
        extra.start = String(Math.floor(Date.now() / 1000) - Number(range.value));
      }
      data = await get(`${SOURCE}?${query(extra)}`);
      render();
      if (withPeriods || firstPageOnly) await loadPeriods(true);
      $("updated").textContent =
        `Updated ${new Date().toLocaleTimeString()}, every ${REFRESH} s`;
    } catch (e) {
      if (e.message !== "logged out") {
        $("updated").textContent = `Update failed (${e.message}), retrying`;
      }
    }
    timer = setTimeout(() => refresh(false), REFRESH * 1000);
  }

  // Colours

  function colour(key) {
    if (key === "other") return OTHER;
    if (!slots.has(key)) {
      const used = new Set(slots.values());
      let slot = PALETTE.findIndex((_, i) => !used.has(i));
      if (slot < 0) {
        // Every slot is taken: free one whose group isn't on screen.
        const shown = new Set(data.series.map((s) => s.key));
        const [gone] = [...slots].find(([k]) => !shown.has(k)) || [];
        slot = gone === undefined ? 0 : slots.get(gone);
        slots.delete(gone);
      }
      slots.set(key, slot);
    }
    return PALETTE[slots.get(key)];
  }

  // Rendering

  function render() {
    const f = $("filter");
    f.hidden = !data.filter;
    $("filter-label").textContent = data.filterLabel || "";
    $("group-name").textContent = GROUP_NAMES[data.group];
    $("summary-scope").textContent = data.filter ? `(only ${data.filterLabel})` : "";
    renderSummary();
    renderLegend();
    drawCharts();
    renderGroups();
    renderFlow();
  }

  function cells(row, item) {
    for (const field of FIELDS) {
      const td = row.insertCell();
      td.className = "num";
      const v = item[field];
      td.textContent =
        field === "requests" || field === "s3_ops" ? count(v) : size(v);
    }
  }

  function renderSummary() {
    const body = $("summary");
    body.replaceChildren();
    for (const item of data.summary) {
      const row = body.insertRow();
      row.insertCell().textContent = WINDOWS[item.window];
      cells(row, item);
    }
  }

  function renderLegend() {
    const legend = $("legend");
    legend.replaceChildren();
    for (const s of data.series) {
      legend.append(key(colour(s.key), s.label));
    }
    if (data.series.length) {
      const gap = document.createElement("span");
      gap.className = "key";
      const box = document.createElement("span");
      box.className = "swatch gapkey";
      gap.append(box, "Not monitoring");
      legend.append(gap);
    }
  }

  function key(fill, label) {
    const k = document.createElement("span");
    k.className = "key";
    const box = document.createElement("span");
    box.className = "swatch";
    box.style.background = fill;
    k.append(box, label);
    return k;
  }

  function renderGroups() {
    const body = $("groups");
    body.replaceChildren();
    if (!data.totals.length) {
      const row = body.insertRow();
      const td = row.insertCell();
      td.colSpan = 8;
      td.className = "muted";
      td.textContent = "No traffic recorded in this range.";
      return;
    }
    for (const item of data.totals) {
      const row = body.insertRow();
      const name = row.insertCell();
      const shown = data.series.some((s) => s.key === item.key);
      name.append(key(shown ? colour(item.key) : OTHER, item.label));
      row.insertCell().textContent = item.client || DASH;
      cells(row, item);
      row.title = `Show only ${item.label}`;
      row.addEventListener("click", () => {
        filter = item.key;
        refresh(true);
      });
    }
  }

  // The flow diagram: clients, the server and S3, with the range's totals on the arrows
  // (only the shown group's while a filter is on).

  function renderFlow() {
    const sum = {};
    for (const f of FIELDS) sum[f] = data.totals.reduce((a, t) => a + t[f], 0);
    const W = 760;
    const H = 190;
    const BW = 150;
    const BH = 80;
    const y = (H - BH) / 2;
    const xs = [10, (W - BW) / 2, W - BW - 10];
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.setAttribute("role", "img");
    const defs = el("defs", {});
    const marker = el("marker", {
      id: "flow-head",
      viewBox: "0 0 10 10",
      refX: 9,
      refY: 5,
      markerWidth: 7,
      markerHeight: 7,
      orient: "auto-start-reverse",
    });
    marker.append(el("path", { class: "head", d: "M0,0L10,5L0,10Z" }));
    defs.append(marker);
    svg.append(defs);
    const who = data.filter ? data.filterLabel : "All clients";
    const boxes = [
      ["Client", who],
      ["Server", "this server"],
      ["S3", s3Label()],
    ];
    boxes.forEach(([name, sub], i) => {
      svg.append(el("rect", { class: "box", x: xs[i], y, width: BW, height: BH, rx: 8 }));
      svg.append(text("name", xs[i] + BW / 2, y + 34, name));
      svg.append(text("who", xs[i] + BW / 2, y + 54, clip(sub, 22)));
    });
    // Upper arrows point right, lower ones left.
    const arrow = (x1, x2, yy, value, note, above) => {
      svg.append(el("line", {
        class: "arrow",
        x1,
        x2,
        y1: yy,
        y2: yy,
        "marker-end": "url(#flow-head)",
      }));
      const mid = (x1 + x2) / 2;
      const off = above ? -24 : 22;
      svg.append(text("val", mid, yy + off, value));
      svg.append(text("sub", mid, yy + off + (above ? 13 : 13), note));
    };
    const a1 = xs[0] + BW + 6;
    const b1 = xs[1] - 6;
    const a2 = xs[1] + BW + 6;
    const b2 = xs[2] - 6;
    const up = y + 24;
    const down = y + BH - 24;
    arrow(a1, b1, up, size(sum.web_in), `web in, ${count(sum.requests)} requests`, true);
    arrow(b1, a1, down, size(sum.web_out), "web out", false);
    arrow(a2, b2, up, size(sum.s3_out), `uploaded, ${count(sum.s3_ops)} S3 calls`, true);
    arrow(b2, a2, down, size(sum.s3_in), "downloaded", false);
    $("flow").replaceChildren(svg);
  }

  function s3Label() {
    return data.totals.some((t) => t.s3_ops) ? "bucket" : "no S3 calls";
  }

  function text(cls, x, yy, content) {
    const t = el("text", { class: cls, x, y: yy, "text-anchor": "middle" });
    t.textContent = content;
    return t;
  }

  function clip(s, n) {
    return s.length > n ? `${s.slice(0, n - 1)}…` : s;
  }

  // Charts

  function monitored(t, step) {
    return data.periods.some(
      (p) => p.start < t + step && (p.end === null || p.end > t),
    );
  }

  function drawCharts() {
    for (const field of CHARTS) drawChart(field);
  }

  function drawChart(field) {
    const box = $(`chart-${field}`);
    const width = Math.max(box.clientWidth, 280);
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", `0 0 ${width} ${HEIGHT}`);
    svg.setAttribute("role", "img");
    box.replaceChildren(svg);
    const n = data.times.length;
    const plotW = width - PAD.left - PAD.right;
    const plotH = HEIGHT - PAD.top - PAD.bottom;
    const step = data.step;
    const xOf = (i) => PAD.left + (i / Math.max(n, 1)) * plotW;
    // Rates in bytes per second, stacked in the order of the series (busiest at the base).
    const stacks = [];
    const top = new Array(n).fill(0);
    for (const s of data.series) {
      const lower = top.slice();
      for (let i = 0; i < n; i++) top[i] += s[field][i] / step;
      stacks.push({ s, lower, upper: top.slice() });
    }
    const max = niceMax(Math.max(0, ...top));
    const yOf = (v) => PAD.top + plotH - (v / max) * plotH;

    // Not monitored: shaded behind everything.
    for (let i = 0; i < n; ) {
      if (monitored(data.times[i], step)) {
        i++;
        continue;
      }
      let j = i;
      while (j < n && !monitored(data.times[j], step)) j++;
      svg.append(el("rect", {
        class: "gap",
        x: xOf(i),
        y: PAD.top,
        width: xOf(j) - xOf(i),
        height: plotH,
      }));
      i = j;
    }
    for (const t of [0, 0.5, 1]) {
      const y = yOf(max * t);
      svg.append(el("line", {
        class: t === 0 ? "base" : "grid",
        x1: PAD.left,
        x2: width - PAD.right,
        y1: y,
        y2: y,
      }));
      const label = el("text", {
        class: "axis",
        x: PAD.left - 6,
        y: y + 4,
        "text-anchor": "end",
      });
      label.textContent = rate(max * t);
      svg.append(label);
    }
    for (const tick of timeTicks(n, plotW)) {
      const x = xOf(tick) + (xOf(1) - xOf(0)) / 2;
      // A label that would run past the right edge is left out.
      if (x > width - PAD.right - 60) continue;
      const label = el("text", {
        class: "axis",
        x,
        y: HEIGHT - 6,
        "text-anchor": "middle",
      });
      label.textContent = timeLabel(data.times[tick]);
      svg.append(label);
    }
    if (!n || !top.some((v) => v > 0)) {
      const empty = el("text", {
        class: "empty",
        x: PAD.left + plotW / 2,
        y: PAD.top + plotH / 2,
        "text-anchor": "middle",
      });
      empty.textContent = "No traffic in this range";
      svg.append(empty);
    }
    // Each bucket is drawn flat across its width, so a spike reads as one bucket.
    for (const { s, lower, upper } of stacks) {
      if (!upper.some((v, i) => v > lower[i])) continue;
      let d = "";
      for (let i = 0; i < n; i++) {
        d += `${i ? "L" : "M"}${xOf(i)},${yOf(upper[i])}L${xOf(i + 1)},${yOf(upper[i])}`;
      }
      for (let i = n - 1; i >= 0; i--) {
        d += `L${xOf(i + 1)},${yOf(lower[i])}L${xOf(i)},${yOf(lower[i])}`;
      }
      svg.append(el("path", {
        d: `${d}Z`,
        fill: colour(s.key),
        stroke: "#fff",
        "stroke-width": 1,
        "stroke-linejoin": "round",
      }));
    }
    const cross = el("line", {
      class: "cross",
      y1: PAD.top,
      y2: PAD.top + plotH,
      visibility: "hidden",
    });
    svg.append(cross);
    const hit = el("rect", {
      x: PAD.left,
      y: 0,
      width: plotW,
      height: HEIGHT,
      fill: "transparent",
    });
    svg.append(hit);
    hit.addEventListener("mousemove", (ev) => {
      const r = svg.getBoundingClientRect();
      const x = ((ev.clientX - r.left) / r.width) * width;
      const i = Math.min(n - 1, Math.max(0, Math.floor(((x - PAD.left) / plotW) * n)));
      if (i < 0 || !n) return;
      const cx = (xOf(i) + xOf(i + 1)) / 2;
      cross.setAttribute("x1", cx);
      cross.setAttribute("x2", cx);
      cross.setAttribute("visibility", "visible");
      showTip(ev, field, i);
    });
    hit.addEventListener("mouseleave", () => {
      cross.setAttribute("visibility", "hidden");
      tooltip.hidden = true;
    });
  }

  function showTip(ev, field, i) {
    const t = data.times[i];
    tooltip.replaceChildren();
    const head = document.createElement("div");
    const end = new Date((t + data.step) * 1000);
    head.textContent = `${fullTime(t)} – ${end.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    })}`;
    const sub = document.createElement("div");
    sub.className = "muted";
    sub.textContent = monitored(t, data.step)
      ? "Average per second (bytes in the bucket)"
      : "Not monitoring";
    tooltip.append(head, sub);
    let total = 0;
    // Top of the stack first, as drawn.
    for (const s of [...data.series].reverse()) {
      const v = s[field][i];
      total += v;
      if (!v) continue;
      tooltip.append(tipRow(colour(s.key), s.label, v));
    }
    tooltip.append(tipRow(null, "Total", total));
    tooltip.hidden = false;
    const pad = 14;
    const w = tooltip.offsetWidth;
    const h = tooltip.offsetHeight;
    let left = ev.clientX + pad;
    if (left + w > window.innerWidth - 4) left = ev.clientX - pad - w;
    let topY = ev.clientY + pad;
    if (topY + h > window.innerHeight - 4) topY = ev.clientY - pad - h;
    tooltip.style.left = `${Math.max(4, left)}px`;
    tooltip.style.top = `${Math.max(4, topY)}px`;
  }

  function tipRow(fill, label, bytes) {
    const row = document.createElement("div");
    row.className = "row";
    if (fill) {
      const box = document.createElement("span");
      box.className = "swatch";
      box.style.background = fill;
      row.append(box);
    }
    const name = document.createElement(fill ? "span" : "b");
    name.textContent = label;
    const v = document.createElement("span");
    v.className = "v";
    v.textContent = `${rate(bytes / data.step)} (${size(bytes)})`;
    row.append(name, v);
    return row;
  }

  function el(name, attrs) {
    const e = document.createElementNS(SVG, name);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
    return e;
  }

  function niceMax(v) {
    if (v <= 0) return 1;
    const p = 10 ** Math.floor(Math.log10(v));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  }

  function timeTicks(n, plotW) {
    if (!n) return [];
    const count = Math.max(2, Math.min(6, Math.floor(plotW / 110)));
    const every = Math.max(1, Math.round(n / count));
    const ticks = [];
    for (let i = 0; i < n; i += every) ticks.push(i);
    return ticks;
  }

  function timeLabel(t) {
    const d = new Date(t * 1000);
    const span = data.end - data.start;
    if (data.step >= 86400) {
      return d.toLocaleDateString([], { month: "short", day: "numeric" });
    }
    const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    if (span <= 86400) return time;
    return `${d.toLocaleDateString([], { month: "short", day: "numeric" })} ${time}`;
  }

  function fullTime(t) {
    return new Date(t * 1000).toLocaleString([], {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  // Totals by period

  async function loadPeriods(first) {
    const extra = { period: period.value, tz };
    if (!first && periodRows.length) {
      extra.before = String(periodRows[periodRows.length - 1].start);
    }
    let page;
    try {
      page = await get(`${TOTALS}?${query(extra)}`);
    } catch {
      return;
    }
    periodRows = first ? page.periods : periodRows.concat(page.periods);
    firstPageOnly = first;
    $("older").hidden = !page.more;
    renderPeriods();
  }

  function renderPeriods() {
    const body = $("periods");
    body.replaceChildren();
    if (!periodRows.length) {
      const row = body.insertRow();
      const td = row.insertCell();
      td.colSpan = 8;
      td.className = "muted";
      td.textContent = "No traffic recorded.";
      return;
    }
    for (const p of periodRows) {
      const row = body.insertRow();
      row.insertCell().textContent = periodLabel(p.start);
      cells(row, p);
      const busiest = p.groups[0];
      row.insertCell().textContent = busiest ? busiest.label : DASH;
      const subs = [];
      for (const g of p.groups) {
        const sub = body.insertRow();
        sub.className = "sub";
        sub.hidden = true;
        sub.insertCell().textContent = g.label;
        cells(sub, g);
        sub.insertCell();
        subs.push(sub);
      }
      if (subs.length) {
        row.title = "Show the groups of this period";
        row.addEventListener("click", () => {
          for (const sub of subs) sub.hidden = !sub.hidden;
        });
      }
    }
  }

  function periodLabel(t) {
    const d = new Date(t * 1000);
    switch (period.value) {
      case "hour":
        return d.toLocaleString([], {
          weekday: "short",
          month: "short",
          day: "numeric",
          hour: "2-digit",
          minute: "2-digit",
        });
      case "day":
        return d.toLocaleDateString([], {
          weekday: "short",
          year: "numeric",
          month: "short",
          day: "numeric",
        });
      case "week":
        return `Week of ${d.toLocaleDateString([], {
          year: "numeric",
          month: "short",
          day: "numeric",
        })}`;
      default:
        return d.toLocaleDateString([], { year: "numeric", month: "long" });
    }
  }

  // Numbers

  function count(n) {
    return n.toLocaleString("en-US");
  }

  function size(n) {
    let value = n;
    for (const unit of ["B", "KB", "MB", "GB", "TB"]) {
      if (value < 1024 || unit === "TB") {
        return unit === "B"
          ? `${value.toFixed(0)} B`
          : `${value.toFixed(1)} ${unit}`;
      }
      value /= 1024;
    }
    return `${n} B`;
  }

  function rate(bytesPerSecond) {
    return `${size(bytesPerSecond)}/s`;
  }

  refresh(true);
})();
