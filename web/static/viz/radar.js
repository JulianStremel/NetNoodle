// Radar: an attack-surface sonar screen. The center is "you are here".
// The riskiest, most exposed devices sit closest to the center; clean
// devices drift to the rim. Sectors are networks. Guests share a spoke
// with their hypervisor host. Layout code: radar-layout.js (no DOM).
import { fill } from "../map-kit.js";
import * as L from "./radar-layout.js";

export const meta = {
  id: "radar",
  title: "Radar",
  description: "Attack-surface radar: the closer to the center, the higher the risk. Sectors are networks. Click a blip for its blast radius; arrow keys step by risk.",
};

const TAU = Math.PI * 2;
const OMEGA = TAU / 6; // sweep: one turn in 6 s
const FRAME_MS = 32; // about 30 frames per second while the sweep turns
const LIST_PAGE = 300;
const GCELL = 0.05; // hit-test grid cell (world units)

const norm = (a) => ((a % TAU) + TAU) % TAU;
const fmt = (r) => (Math.round((r || 0) * 10) / 10).toFixed(1);

function withAlpha(c, a) {
  let m = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(c || "");
  if (m) {
    let h = m[1];
    if (h.length === 3) h = h.split("").map((x) => x + x).join("");
    const v = parseInt(h, 16);
    return `rgba(${(v >> 16) & 255},${(v >> 8) & 255},${v & 255},${a})`;
  }
  m = /^rgba?\(([^)]+)\)$/.exec(c || "");
  if (m) return `rgba(${m[1].split(/[\s,/]+/).filter(Boolean).slice(0, 3).join(",")},${a})`;
  return c;
}

function shapePath(ctx, kind, x, y, r) {
  ctx.beginPath();
  if (kind === "host") {
    const s = r * 0.88;
    ctx.rect(x - s, y - s, 2 * s, 2 * s);
  } else if (kind === "vm") {
    const s = r * 1.2;
    ctx.moveTo(x, y - s);
    ctx.lineTo(x + s, y);
    ctx.lineTo(x, y + s);
    ctx.lineTo(x - s, y);
    ctx.closePath();
  } else if (kind === "container") {
    const s = r * 1.25;
    ctx.moveTo(x, y - s);
    ctx.lineTo(x + s * 0.95, y + s * 0.62);
    ctx.lineTo(x - s * 0.95, y + s * 0.62);
    ctx.closePath();
  } else {
    ctx.arc(x, y, r, 0, TAU);
  }
}

export function mount(container, graph, kit) {
  kit.loadCSS("viz/radar.css");
  const { el } = kit;
  const mqReduce = matchMedia("(prefers-reduced-motion: reduce)");
  const mqDark = matchMedia("(prefers-color-scheme: dark)");

  const st = {
    graph,
    lay: null,
    f: { kev: false, exposed: false, kinds: new Set(L.KINDS) },
    network: "",
    q: "",
    vis: new Set(), // passes the chip filters
    hit: new Set(), // matches the search
    order: [], // visible + matching, ranked by risk
    drawOrder: [],
    sel: null,
    blast: null,
    hover: null,
    peek: null,
    hoverSector: null,
    mode: "radar",
    sweep: !mqReduce.matches,
    k: 1,
    panX: 0,
    panY: 0,
    w: 1,
    h: 1,
    dpr: 1,
    R: 100,
    listLimit: LIST_PAGE,
  };
  let P = palette();
  let raf = 0;
  let lastFrame = 0;
  let dirty = true;
  let destroyed = false;
  let grid = new Map();
  let drag = null;

  function palette() {
    return {
      bg: kit.cssVar("--bg") || "#f6f7f9",
      card: kit.cssVar("--card") || "#ffffff",
      fg: kit.cssVar("--fg") || "#1d2129",
      muted: kit.cssVar("--muted") || "#667085",
      line: kit.cssVar("--line") || "#e4e7ec",
      accent: kit.cssVar("--accent") || "#2f6fdb",
      risk: [0, 2, 5, 8, 9.5].map((r) => kit.riskColor(r)),
    };
  }
  const colorOf = (r) => P.risk[4 - L.bandOf(r)];
  const kindOf = L.kindOf;
  const glyph = (n) => kit.kindGlyph[kindOf(n)] || "?";

  // ---- DOM ---------------------------------------------------------------
  const search = el("input", {
    type: "search", class: "rd-search", placeholder: "Search name, IP, CVE",
    "aria-label": "Search devices by name, IP or CVE", spellcheck: "false", autocomplete: "off",
  });
  const chip = (label, title, onclick) =>
    el("button", { type: "button", class: "rd-chip", title, "aria-pressed": "false", onclick }, label);
  const kevChip = chip("✛ KEV", "Only devices with a known exploited vulnerability (CISA KEV)", () => {
    st.f.kev = !st.f.kev;
    applyFilters();
  });
  const expChip = chip("◎ Exposed", "Only devices with findings in a package that listens on the network", () => {
    st.f.exposed = !st.f.exposed;
    applyFilters();
  });
  const kindChips = L.KINDS.map((k) => {
    const b = chip(`${kit.kindGlyph[k]} ${k}`, `Show or hide ${k} devices`, () => {
      if (st.f.kinds.has(k)) st.f.kinds.delete(k);
      else st.f.kinds.add(k);
      applyFilters();
    });
    b.dataset.kind = k;
    return b;
  });
  const netSel = el("select", { class: "rd-net", "aria-label": "Network", title: "Show one network on the whole radar" });
  netSel.addEventListener("change", () => {
    st.network = netSel.value;
    relayout();
    resetView();
  });
  const countEl = el("span", { class: "rd-count muted" });
  const modeBtn = el("button", { type: "button", class: "rd-btn", title: "Switch between radar and ranked list (L)", onclick: () => setMode(st.mode === "radar" ? "list" : "radar") });
  const sweepBtn = el("button", { type: "button", class: "rd-btn", title: "Start or stop the sweep", onclick: () => { st.sweep = !st.sweep; syncButtons(); requestDraw(); } });
  const bar = el("div", { class: "rd-bar" },
    search, kevChip, expChip, el("span", { class: "rd-sep" }), ...kindChips, netSel,
    el("span", { class: "rd-spacer" }), countEl, sweepBtn, modeBtn);

  const canvas = el("canvas", { class: "rd-canvas", role: "img", "aria-label": "Radar of devices by risk. Use the triage list for a text view." });
  const ctx = canvas.getContext("2d");
  const tip = el("div", { class: "rd-tip", hidden: true });
  const legendBody = el("div", { class: "rd-legend-body" });
  const legend = el("details", { class: "rd-legend", open: true }, el("summary", {}, "Legend"), legendBody);
  const zoomBtn = (label, title, fn) => el("button", { type: "button", class: "rd-zbtn", title, "aria-label": title, onclick: fn }, label);
  const zoomCtl = el("div", { class: "rd-zoom" },
    zoomBtn("+", "Zoom in", () => zoomAt(st.w / 2, st.h / 2, 1.4)),
    zoomBtn("−", "Zoom out", () => zoomAt(st.w / 2, st.h / 2, 1 / 1.4)),
    zoomBtn("⟲", "Reset view", () => resetView()));
  const list = el("div", { class: "rd-list", hidden: true });
  const main = el("div", { class: "rd-main" }, canvas, tip, legend, zoomCtl, list);
  const panel = el("aside", { class: "rd-panel", "aria-label": "Details" });
  const root = el("div", { class: "rd", tabindex: "0" }, bar, el("div", { class: "rd-body" }, main, panel));
  container.append(root);

  // ---- data --------------------------------------------------------------
  function buildNetOptions() {
    const nodes = st.graph.nodes || [];
    const nets = st.graph.networks || [];
    const noIp = nodes.filter((n) => !(n.networks || []).length).length;
    const opts = [el("option", { value: "" }, `All networks (${nodes.length})`),
      ...nets.map((x) => el("option", { value: x.id }, `${x.id} (${(x.devices || []).length})`))];
    if (noIp) opts.push(el("option", { value: L.NONET }, `${L.NONET} (${noIp})`));
    netSel.replaceChildren(...opts);
    if (st.network && !opts.some((o) => o.value === st.network)) st.network = "";
    netSel.value = st.network;
  }

  function relayout() {
    st.lay = L.layout(st.graph, { network: st.network });
    st.drawOrder = [...st.lay.blips].sort((a, b) => (a.n.risk || 0) - (b.n.risk || 0) || a.n.kev - b.n.kev);
    grid = new Map();
    for (const b of st.lay.blips) {
      const key = `${Math.floor(b.x / GCELL)},${Math.floor(b.y / GCELL)}`;
      let c = grid.get(key);
      if (!c) grid.set(key, (c = []));
      c.push(b);
    }
    applyFilters();
  }

  function applyFilters() {
    const q = st.q.trim();
    st.vis = new Set();
    st.hit = new Set();
    const ranked = [];
    for (const b of st.lay.blips) {
      if (!L.passes(b.n, st.f)) continue;
      st.vis.add(b.id);
      if (q && L.matches(b.n, q)) st.hit.add(b.id);
      if (!q || st.hit.has(b.id)) ranked.push(b.n);
    }
    st.order = L.rank(ranked);
    if (st.sel != null && !st.lay.byId.has(st.sel)) setSel(null);
    st.listLimit = LIST_PAGE;
    syncButtons();
    renderPanel();
    renderList();
    requestDraw();
  }

  function syncButtons() {
    kevChip.setAttribute("aria-pressed", String(st.f.kev));
    expChip.setAttribute("aria-pressed", String(st.f.exposed));
    for (const b of kindChips) b.setAttribute("aria-pressed", String(st.f.kinds.has(b.dataset.kind)));
    modeBtn.textContent = st.mode === "radar" ? "☰ Triage list" : "◎ Radar";
    sweepBtn.hidden = mqReduce.matches || st.mode !== "radar";
    sweepBtn.textContent = st.sweep ? "Sweep: on" : "Sweep: off";
    sweepBtn.setAttribute("aria-pressed", String(st.sweep));
    const total = st.lay ? st.lay.count : 0;
    countEl.textContent = st.order.length === total ? `${total} devices` : `${st.order.length} of ${total} shown`;
  }

  function setSel(id) {
    st.sel = id;
    st.blast = id == null ? null : kit.blast(st.graph, id);
    root.classList.toggle("rd-has-sel", id != null);
  }

  function select(id, opts = {}) {
    if (id != null && !st.lay.byId.has(id)) id = null;
    setSel(id);
    renderPanel();
    if (st.mode === "list") {
      const i = st.order.findIndex((n) => n.id === id);
      if (i >= st.listLimit) st.listLimit = i + LIST_PAGE;
      renderList();
      if (opts.reveal && id != null) list.querySelector("tr.rd-sel")?.scrollIntoView({ block: "nearest" });
    } else if (opts.reveal && id != null) {
      reveal(st.lay.byId.get(id));
    }
    requestDraw();
  }

  function step(d) {
    if (!st.order.length) return;
    let i = st.order.findIndex((n) => n.id === st.sel);
    i = i < 0 ? (d > 0 ? 0 : st.order.length - 1) : Math.min(st.order.length - 1, Math.max(0, i + d));
    select(st.order[i].id, { reveal: true });
  }

  // ---- view --------------------------------------------------------------
  const origin = () => ({ ox: st.w / 2 + st.panX, oy: st.h / 2 + st.panY });
  const sizeFactor = () => Math.min(1.4, Math.max(0.7, st.R / L.NOMINAL_R)) * Math.min(3, Math.sqrt(st.k));
  const blipR = (b, sf) => Math.max(1.3, b.px * sf);

  function resetView() {
    st.k = 1;
    st.panX = 0;
    st.panY = 0;
    requestDraw();
  }

  function zoomAt(mx, my, f) {
    const k = Math.min(40, Math.max(0.6, st.k * f));
    const g = k / st.k;
    const { ox, oy } = origin();
    st.panX = mx - (mx - ox) * g - st.w / 2;
    st.panY = my - (my - oy) * g - st.h / 2;
    st.k = k;
    requestDraw();
  }

  function reveal(b) {
    if (!b) return;
    const { ox, oy } = origin();
    const Rk = st.R * st.k;
    const sx = ox + b.x * Rk;
    const sy = oy + b.y * Rk;
    const m = 50;
    if (sx < m || sx > st.w - m || sy < m || sy > st.h - m) {
      st.panX = -b.x * Rk;
      st.panY = -b.y * Rk;
    }
  }

  function resize() {
    const r = main.getBoundingClientRect();
    st.w = Math.max(1, Math.round(r.width));
    st.h = Math.max(1, Math.round(r.height));
    st.dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = Math.round(st.w * st.dpr);
    canvas.height = Math.round(st.h * st.dpr);
    canvas.style.width = `${st.w}px`;
    canvas.style.height = `${st.h}px`;
    st.R = Math.max(60, Math.min(st.w, st.h) / 2 - (st.w < 520 ? 36 : 60));
    const narrow = container.clientWidth < 760;
    if (narrow && !root.classList.contains("rd-narrow") && !st.sized) legend.open = false;
    st.sized = true;
    root.classList.toggle("rd-narrow", narrow);
    requestDraw();
  }

  // ---- hit testing -------------------------------------------------------
  function local(e) {
    const r = canvas.getBoundingClientRect();
    return { mx: e.clientX - r.left, my: e.clientY - r.top };
  }

  function hitTest(mx, my) {
    if (!st.lay) return null;
    const Rk = st.R * st.k;
    const { ox, oy } = origin();
    const wx = (mx - ox) / Rk;
    const wy = (my - oy) / Rk;
    const sf = sizeFactor();
    const wr = (16 * sf + 6) / Rk;
    const x0 = Math.floor((wx - wr) / GCELL);
    const x1 = Math.floor((wx + wr) / GCELL);
    const y0 = Math.floor((wy - wr) / GCELL);
    const y1 = Math.floor((wy + wr) / GCELL);
    let best = null;
    let bd = Infinity;
    for (let gx = x0; gx <= x1; gx++) {
      for (let gy = y0; gy <= y1; gy++) {
        const c = grid.get(`${gx},${gy}`);
        if (!c) continue;
        for (const b of c) {
          if (!st.vis.has(b.id)) continue;
          const d = Math.hypot(ox + b.x * Rk - mx, oy + b.y * Rk - my);
          if (d <= blipR(b, sf) + 4 && d < bd) {
            bd = d;
            best = b;
          }
        }
      }
    }
    return best;
  }

  function sectorAt(mx, my) {
    if (!st.lay || st.lay.sectors.length < 2) return null;
    const Rk = st.R * st.k;
    const { ox, oy } = origin();
    const dx = mx - ox;
    const dy = my - oy;
    const r = Math.hypot(dx, dy);
    if (r < Rk * 0.99 || r > Rk + 48) return null;
    const a = norm(Math.atan2(dx, -dy));
    const g = st.lay.gap / 2;
    return st.lay.sectors.find((s) => a >= s.a0 - g && a <= s.a1 + g) || null;
  }

  // ---- tooltip -----------------------------------------------------------
  function riskPill(r) {
    const dot = el("span", { class: "rd-dot" });
    dot.style.background = colorOf(r);
    const p = el("span", { class: "rd-pill" }, dot, `${kit.riskLabel(r)} ${fmt(r)}`);
    p.style.borderColor = colorOf(r);
    return p;
  }

  function showTip(b, mx, my, rebuild) {
    if (rebuild) fillTip(b);
    tip.hidden = false;
    const tw = tip.offsetWidth;
    const th = tip.offsetHeight;
    let x = mx + 16;
    let y = my + 16;
    if (x + tw > st.w - 6) x = Math.max(6, mx - tw - 12);
    if (y + th > st.h - 6) y = Math.max(6, my - th - 12);
    tip.style.left = `${x}px`;
    tip.style.top = `${y}px`;
  }

  function fillTip(b) {
    const n = b.n;
    const ips = n.ips || [];
    const v = (n.top || [])[0];
    fill(tip,
      el("div", { class: "rd-tip-name" }, `${glyph(n)} ${n.name}`),
      el("div", { class: "rd-tip-row muted" }, `${kindOf(n)}${ips.length ? " · " + ips.slice(0, 3).join(", ") + (ips.length > 3 ? ` +${ips.length - 3}` : "") : ""}`),
      el("div", { class: "rd-tip-row" }, riskPill(n.risk), ` ${n.kev ? `✛ ${n.kev} KEV · ` : "no KEV · "}${n.findings} findings`),
      v ? el("div", { class: "rd-tip-row" }, `Top: ${v.id} (${fmt(v.score)}${v.kev ? ", KEV" : ""}${v.exposed ? ", exposed" : ""}) ${v.package}`) : null,
      n.related_risk > n.risk ? el("div", { class: "rd-tip-row muted" }, `Blast radius up to ${kit.riskLabel(n.related_risk)} ${fmt(n.related_risk)}`) : null,
    );
  }

  function setHover(b, mx, my) {
    const changed = (b ? b.id : null) !== (st.hover ? st.hover.id : null);
    st.hover = b;
    if (b) showTip(b, mx, my, changed || tip.hidden);
    else tip.hidden = true;
    const s = b ? null : sectorAt(mx, my);
    const sc = (s ? s.id : null) !== st.hoverSector;
    st.hoverSector = s ? s.id : null;
    canvas.style.cursor = b || s ? "pointer" : drag ? "grabbing" : "grab";
    if (changed || sc) requestDraw();
  }

  // ---- drawing -----------------------------------------------------------
  function requestDraw() {
    dirty = true;
    if (!raf && !destroyed) raf = requestAnimationFrame(frame);
  }
  const animating = () => st.sweep && !mqReduce.matches && st.mode === "radar" && !destroyed;

  function frame(t) {
    raf = 0;
    if (destroyed) return;
    if (st.mode !== "radar") return;
    if (animating()) {
      if (dirty || t - lastFrame >= FRAME_MS) {
        draw(t);
        lastFrame = t;
        dirty = false;
      }
      raf = requestAnimationFrame(frame);
    } else {
      draw(t);
      dirty = false;
    }
  }

  function annulus(ox, oy, r0, r1) {
    ctx.beginPath();
    ctx.arc(ox, oy, r1, 0, TAU);
    ctx.arc(ox, oy, r0, 0, TAU, true);
  }

  function draw(now) {
    const { w, h } = st;
    const lay = st.lay;
    ctx.setTransform(st.dpr, 0, 0, st.dpr, 0, 0);
    ctx.globalAlpha = 1;
    ctx.setLineDash([]);
    ctx.fillStyle = P.card;
    ctx.fillRect(0, 0, w, h);
    if (!lay) return;
    const { ox, oy } = origin();
    const Rk = st.R * st.k;
    const sf = sizeFactor();
    const sweeping = animating();
    const th = sweeping ? norm((now / 1000) * OMEGA) : 0;

    // Disk and risk bands (the hot center is tinted).
    ctx.beginPath();
    ctx.arc(ox, oy, Rk, 0, TAU);
    ctx.fillStyle = P.bg;
    ctx.fill();
    const tints = [0.13, 0.08, 0.05, 0.025];
    for (let i = 0; i < 4; i++) {
      const b = L.BANDS[i];
      annulus(ox, oy, (i === 0 ? 0 : b.lo) * Rk, b.hi * Rk);
      ctx.fillStyle = withAlpha(P.risk[4 - i], tints[i]);
      ctx.fill("evenodd");
    }
    ctx.lineWidth = 1;
    ctx.strokeStyle = P.line;
    for (let i = 0; i < 4; i++) {
      ctx.beginPath();
      ctx.arc(ox, oy, L.BANDS[i].hi * Rk, 0, TAU);
      ctx.stroke();
    }
    ctx.beginPath();
    ctx.arc(ox, oy, Rk, 0, TAU);
    ctx.strokeStyle = P.muted;
    ctx.stroke();

    // Sectors: separators, rim arcs colored by the worst device, labels.
    const S = lay.sectors.length;
    for (const s of lay.sectors) {
      if (S > 1) {
        const a = s.a0 - lay.gap / 2;
        ctx.beginPath();
        ctx.moveTo(ox + Math.sin(a) * L.BANDS[0].lo * Rk, oy - Math.cos(a) * L.BANDS[0].lo * Rk);
        ctx.lineTo(ox + Math.sin(a) * Rk, oy - Math.cos(a) * Rk);
        ctx.strokeStyle = P.line;
        ctx.lineWidth = 1;
        ctx.stroke();
      }
      if (st.hoverSector === s.id) {
        ctx.beginPath();
        ctx.moveTo(ox, oy);
        ctx.arc(ox, oy, Rk, s.a0 - Math.PI / 2, s.a1 - Math.PI / 2);
        ctx.closePath();
        ctx.fillStyle = withAlpha(P.accent, 0.07);
        ctx.fill();
      }
      ctx.beginPath();
      ctx.arc(ox, oy, Rk + 4, s.a0 - Math.PI / 2, s.a1 - Math.PI / 2);
      ctx.strokeStyle = colorOf(s.risk);
      ctx.lineWidth = st.hoverSector === s.id ? 6 : 4;
      ctx.stroke();
    }
    drawSectorLabels(ox, oy, Rk);
    drawRingLabels(ox, oy, Rk);

    // Sweep with a fading trail.
    if (sweeping) {
      const ca = th - Math.PI / 2;
      const trail = 1.1;
      ctx.beginPath();
      ctx.moveTo(ox, oy);
      ctx.arc(ox, oy, Rk, ca - trail, ca);
      ctx.closePath();
      if (typeof ctx.createConicGradient === "function") {
        const g = ctx.createConicGradient(ca - trail, ox, oy);
        g.addColorStop(0, withAlpha(P.accent, 0));
        g.addColorStop(trail / TAU, withAlpha(P.accent, 0.22));
        g.addColorStop(Math.min(1, trail / TAU + 0.0005), withAlpha(P.accent, 0));
        g.addColorStop(1, withAlpha(P.accent, 0));
        ctx.fillStyle = g;
      } else {
        ctx.fillStyle = withAlpha(P.accent, 0.08);
      }
      ctx.fill();
      ctx.beginPath();
      ctx.moveTo(ox, oy);
      ctx.lineTo(ox + Math.cos(ca) * Rk, oy + Math.sin(ca) * Rk);
      ctx.strokeStyle = withAlpha(P.accent, 0.75);
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }

    // "You are here".
    ctx.strokeStyle = P.muted;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(ox - 9, oy);
    ctx.lineTo(ox + 9, oy);
    ctx.moveTo(ox, oy - 9);
    ctx.lineTo(ox, oy + 9);
    ctx.stroke();
    ctx.beginPath();
    ctx.arc(ox, oy, 3, 0, TAU);
    ctx.fillStyle = P.fg;
    ctx.fill();

    const visible = (b) => {
      const x = ox + b.x * Rk;
      const y = oy + b.y * Rk;
      return x > -40 && x < w + 40 && y > -40 && y < h + 40;
    };
    const q = st.q.trim();
    const alphaOf = (b) => {
      if (st.blast) return st.blast.has(b.id) ? 1 : 0.13;
      if (q) return st.hit.has(b.id) ? 1 : 0.16;
      return 1;
    };

    // Host-guest tethers (spokes).
    const many = st.vis.size > 600 && st.k < 2;
    ctx.lineWidth = 1;
    for (const b of lay.blips) {
      if (!b.guest || !st.vis.has(b.id)) continue;
      const hb = lay.byId.get(b.root);
      if (!hb || !st.vis.has(hb.id)) continue;
      const fam = (st.hover && (st.hover.root === b.root)) || (st.blast && st.blast.has(b.id) && st.blast.has(hb.id));
      if (many && !fam) continue;
      if (!visible(b) && !visible(hb)) continue;
      ctx.globalAlpha = fam ? 0.9 : Math.min(alphaOf(b), alphaOf(hb)) * 0.8;
      ctx.strokeStyle = fam ? P.muted : P.line;
      ctx.beginPath();
      ctx.moveTo(ox + hb.x * Rk, oy + hb.y * Rk);
      ctx.lineTo(ox + b.x * Rk, oy + b.y * Rk);
      ctx.stroke();
    }
    ctx.globalAlpha = 1;

    // Blast radius tethers of the selection.
    const sb = st.sel != null ? lay.byId.get(st.sel) : null;
    if (sb) {
      const sx = ox + sb.x * Rk;
      const sy = oy + sb.y * Rk;
      for (const id of sb.n.related || []) {
        const rb = lay.byId.get(id);
        if (!rb) continue;
        const rel = L.relation(sb.n, rb.n);
        ctx.setLineDash(rel === "same host" ? [5, 4] : []);
        ctx.lineDashOffset = sweeping ? -(now / 60) % 9 : 0;
        ctx.lineWidth = rel === "same host" ? 1.4 : 2.2;
        ctx.strokeStyle = colorOf(Math.max(rb.n.risk, sb.n.risk));
        ctx.beginPath();
        ctx.moveTo(sx, sy);
        // A slight bend toward the center keeps lines on one spoke apart.
        const mx2 = (sx + ox + rb.x * Rk) / 2;
        const my2 = (sy + oy + rb.y * Rk) / 2;
        ctx.quadraticCurveTo(mx2 + (ox - mx2) * 0.12, my2 + (oy - my2) * 0.12, ox + rb.x * Rk, oy + rb.y * Rk);
        ctx.stroke();
      }
      ctx.setLineDash([]);
    }

    // Blips, low risk first so hot blips are on top.
    for (const b of st.drawOrder) {
      if (!visible(b)) continue;
      const x = ox + b.x * Rk;
      const y = oy + b.y * Rk;
      if (!st.vis.has(b.id)) {
        ctx.globalAlpha = 0.15;
        ctx.fillStyle = P.muted;
        ctx.fillRect(x - 1, y - 1, 2, 2);
        continue;
      }
      const n = b.n;
      const a = alphaOf(b);
      const r = blipR(b, sf);
      const col = colorOf(n.risk);
      if (sweeping && a === 1 && n.risk > 0) {
        const f = Math.exp(-(norm(th - b.a) / OMEGA) * 1.3);
        if (f > 0.04) {
          ctx.globalAlpha = 0.45 * f;
          ctx.beginPath();
          ctx.arc(x, y, r + 3 + (b.band <= 1 ? 9 : 5) * f, 0, TAU);
          ctx.fillStyle = col;
          ctx.fill();
        }
      }
      ctx.globalAlpha = a;
      if (r < 2.6) {
        ctx.fillStyle = col;
        ctx.fillRect(x - r, y - r, 2 * r, 2 * r);
      } else {
        const kind = kindOf(n);
        shapePath(ctx, kind, x, y, r);
        ctx.fillStyle = col;
        ctx.fill();
        ctx.lineWidth = 1;
        ctx.strokeStyle = P.card;
        ctx.stroke();
        if (kind === "unknown" && r >= 4.5) {
          ctx.fillStyle = P.card;
          ctx.font = `700 ${Math.round(r * 1.5)}px system-ui, sans-serif`;
          ctx.textAlign = "center";
          ctx.textBaseline = "middle";
          ctx.fillText("?", x, y + 0.5);
        }
      }
      if (n.exposed > 0) {
        ctx.beginPath();
        ctx.arc(x, y, r + 3, 0, TAU);
        ctx.strokeStyle = col;
        ctx.lineWidth = 1.2;
        ctx.stroke();
      }
      if (n.kev > 0) {
        const r0 = r + (n.exposed > 0 ? 4 : 2.5);
        const r1 = r0 + Math.max(3, r * 0.6);
        ctx.beginPath();
        ctx.moveTo(x, y - r0); ctx.lineTo(x, y - r1);
        ctx.moveTo(x, y + r0); ctx.lineTo(x, y + r1);
        ctx.moveTo(x - r0, y); ctx.lineTo(x - r1, y);
        ctx.moveTo(x + r0, y); ctx.lineTo(x + r1, y);
        ctx.strokeStyle = P.fg;
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }
    }
    ctx.globalAlpha = 1;

    // Selection, hover and peek rings.
    const ring = (b, color, extra, width) => {
      if (!b) return;
      const r = blipR(b, sf) + extra;
      ctx.beginPath();
      ctx.arc(ox + b.x * Rk, oy + b.y * Rk, r, 0, TAU);
      ctx.strokeStyle = color;
      ctx.lineWidth = width;
      ctx.stroke();
    };
    if (sb) {
      const pulse = sweeping ? 2 * Math.sin(now / 220) : 0;
      ring(sb, P.accent, 10 + pulse, 2.5);
    }
    if (st.hover && st.hover !== sb) ring(st.hover, P.fg, 6, 1.5);
    if (st.peek != null) ring(lay.byId.get(st.peek), P.accent, 8, 2);
    drawLabels(ox, oy, Rk, sf, sb, q, visible);
  }

  function haloText(text, x, y) {
    ctx.lineWidth = 3;
    ctx.strokeStyle = P.card;
    ctx.strokeText(text, x, y);
    ctx.fillText(text, x, y);
  }

  function drawSectorLabels(ox, oy, Rk) {
    const lay = st.lay;
    const many = lay.sectors.length;
    for (const s of lay.sectors) {
      const arc = (s.a1 - s.a0) * Rk;
      if (many > 1 && arc < 36 && st.hoverSector !== s.id) continue;
      const mid = many > 1 ? (s.a0 + s.a1) / 2 : 0;
      const sn = Math.sin(mid);
      const cs = Math.cos(mid);
      const x = ox + sn * (Rk + 13);
      const y = oy - cs * (Rk + 13);
      if (x < -60 || x > st.w + 60 || y < -30 || y > st.h + 30) continue;
      ctx.textAlign = sn > 0.3 ? "left" : sn < -0.3 ? "right" : "center";
      const up = cs > 0.3;
      const down = cs < -0.3;
      const line2 = `${s.count} dev${s.kev ? ` · ✛${s.kev}` : ""}`;
      ctx.textBaseline = "middle";
      const y1 = up ? y - 14 : down ? y + 2 : y - 6;
      ctx.font = "600 11px system-ui, sans-serif";
      ctx.fillStyle = st.network ? P.accent : P.fg;
      haloText(s.id, x, y1);
      ctx.font = "10px system-ui, sans-serif";
      ctx.fillStyle = P.muted;
      haloText(line2, x, y1 + 12);
    }
  }

  function drawRingLabels(ox, oy, Rk) {
    ctx.font = "10px system-ui, sans-serif";
    ctx.textAlign = "left";
    ctx.textBaseline = "top";
    for (const b of L.BANDS) {
      const y = oy - b.hi * Rk + 3;
      if (y < -10 || y > st.h) continue;
      ctx.fillStyle = P.muted;
      haloText(b.label, ox + 5, y);
    }
  }

  function drawLabels(ox, oy, Rk, sf, sb, q, visible) {
    const lay = st.lay;
    const cands = [];
    const seen = new Set();
    const push = (b, strong) => {
      if (!b || seen.has(b.id) || !st.vis.has(b.id)) return;
      seen.add(b.id);
      cands.push([b, strong]);
    };
    if (sb) {
      push(sb, true);
      for (const id of sb.n.related || []) push(lay.byId.get(id), false);
    }
    if (st.hover) push(st.hover, true);
    if (st.peek != null) push(lay.byId.get(st.peek), true);
    if (q) {
      for (const n of st.order.slice(0, 80)) push(lay.byId.get(n.id), false);
    } else if (!sb) {
      const budget = lay.count <= 80 ? 80 : Math.round(12 + 20 * st.k);
      let k = 0;
      for (const n of st.order) {
        if (k >= budget) break;
        const b = lay.byId.get(n.id);
        if (b && visible(b)) {
          push(b, false);
          k++;
        }
      }
    }
    const rects = [];
    const overlaps = (r) => rects.some((o) => r.x < o.x + o.w && r.x + r.w > o.x && r.y < o.y + o.h && r.y + r.h > o.y);
    ctx.textBaseline = "middle";
    for (const [b, strong] of cands) {
      if (!visible(b)) continue;
      const x = ox + b.x * Rk;
      const y = oy + b.y * Rk;
      const r = blipR(b, sf) + (b.n.kev > 0 ? 6 : 3);
      ctx.font = strong ? "600 12px system-ui, sans-serif" : "11px system-ui, sans-serif";
      const text = String(b.n.name);
      const tw = ctx.measureText(text).width;
      const hgt = strong ? 15 : 13;
      let rect = { x: x + r + 2, y: y - hgt / 2, w: tw + 4, h: hgt };
      let align = "left";
      if (!strong && overlaps(rect)) {
        rect = { x: x - r - 6 - tw, y: y - hgt / 2, w: tw + 4, h: hgt };
        align = "right";
        if (overlaps(rect)) continue;
      }
      rects.push(rect);
      ctx.textAlign = align;
      ctx.fillStyle = strong ? P.fg : P.muted;
      haloText(text, align === "left" ? x + r + 4 : x - r - 4, y);
    }
  }

  // ---- panel -------------------------------------------------------------
  function section(title, ...body) {
    return el("section", { class: "rd-sec" }, el("h4", {}, title), ...body);
  }

  function deviceRow(n, extra) {
    return el("button", {
      type: "button", class: "rd-dev", title: "Select",
      onclick: () => select(n.id, { reveal: true }),
      onmouseenter: () => { st.peek = n.id; requestDraw(); },
      onmouseleave: () => { st.peek = null; requestDraw(); },
    }, el("span", { class: "rd-glyph" }, glyph(n)), el("span", { class: "rd-dev-name" }, n.name),
    extra ? el("span", { class: "rd-dev-extra muted" }, extra) : null, riskPill(n.risk));
  }

  function renderPanel() {
    st.peek = null;
    const n = st.sel != null ? st.lay.byId.get(st.sel)?.n : null;
    if (!n) {
      renderOverview();
      return;
    }
    const byNode = kit.index(st.graph);
    const head = el("div", { class: "rd-head" },
      el("span", { class: "rd-glyph rd-big" }, glyph(n)),
      el("div", { class: "rd-title" }, el("h3", {}, n.name), el("div", { class: "muted" }, `${kindOf(n)}${n.agent ? " · agent" : ""}`)),
      el("button", { type: "button", class: "rd-x", title: "Clear selection (Esc)", "aria-label": "Clear selection", onclick: () => select(null) }, "×"));
    const facts = el("div", { class: "rd-facts" }, riskPill(n.risk),
      el("span", { class: "rd-fact" }, n.kev ? `✛ ${n.kev} KEV` : "no KEV"),
      el("span", { class: "rd-fact" }, `${n.findings} findings`),
      n.exposed ? el("span", { class: "rd-fact" }, `◎ ${n.exposed} exposed`) : null);
    const ids = el("div", { class: "rd-ids muted" }, [...(n.ips || []), ...(n.networks || []).map((x) => `net ${x}`)].join(" · ") || "no IP");
    const open = el("button", { type: "button", class: "rd-open", onclick: () => kit.openDevice(n.id) }, "Open device →");
    const blastNote = n.related_risk > n.risk
      ? el("p", { class: "rd-note" }, `Blast radius reaches ${kit.riskLabel(n.related_risk)} ${fmt(n.related_risk)}.`) : null;

    // Top vulnerabilities: KEV first, then exposed, then score.
    const top = [...(n.top || [])].sort((a, b) => (b.kev - a.kev) || (b.exposed - a.exposed) || (b.score - a.score));
    const vulns = top.length ? el("ul", { class: "rd-vulns" }, top.map((v) => {
      const fill = el("span", { class: "rd-epss-fill" });
      fill.style.width = `${Math.max(1, Math.round((v.epss || 0) * 100))}%`;
      fill.style.background = (v.epss || 0) >= 0.5 ? P.risk[4] : (v.epss || 0) >= 0.1 ? P.risk[3] : P.muted;
      return el("li", {},
        el("div", { class: "rd-v-head" },
          v.kev ? el("span", { class: "rd-tag rd-kev" }, "✛ KEV") : null,
          el("span", { class: "rd-v-id" }, v.id),
          el("span", { class: "rd-v-score" }, `CVSS ${fmt(v.score)}`),
          v.exposed ? el("span", { class: "rd-tag" }, "exposed") : null),
        el("div", { class: "rd-v-pkg muted" }, `${v.package} ${v.version}${v.fixed ? ` → ${v.fixed}` : ""}`),
        el("div", { class: "rd-epss", title: "EPSS: probability of exploitation in the next 30 days" },
          el("span", { class: "rd-epss-bar" }, fill), el("span", { class: "rd-epss-val muted" }, `EPSS ${Math.round((v.epss || 0) * 100)}%`)),
        v.summary ? el("div", { class: "rd-v-sum muted" }, v.summary) : null);
    })) : el("p", { class: "muted" }, "No open findings.");

    const svcs = (n.services || []).filter((s) => s.exposed)
      .sort((a, b) => (b.kev - a.kev) || (b.vulns - a.vulns) || (a.port - b.port));
    const local = (n.services || []).length - svcs.length;
    const services = svcs.length ? el("ul", { class: "rd-svcs" }, svcs.map((s) => el("li", {},
      el("span", { class: "rd-port" }, `${s.proto}/${s.port}`),
      el("span", { class: "rd-proc" }, s.process || s.product || "unknown process"),
      s.address ? el("span", { class: "muted" }, ` ${s.address}`) : null,
      s.vulns ? el("span", { class: s.kev ? "rd-tag rd-kev" : "rd-tag" }, `${s.kev ? "✛ " : ""}${s.vulns} vuln${s.vulns > 1 ? "s" : ""}`) : null)))
      : el("p", { class: "muted" }, (n.services || []).length ? "No service listens on the network." : "No service data.");

    const rel = (n.related || []).map((id) => byNode.get(id)).filter(Boolean).sort(L.rankCompare);
    const offRadar = rel.filter((r) => !st.lay.byId.has(r.id)).length;
    const related = rel.length ? el("div", { class: "rd-devs" }, rel.map((r) => deviceRow(r, L.relation(n, r))),
      offRadar ? el("p", { class: "muted" }, `${offRadar} not in this network view.`) : null)
      : el("p", { class: "muted" }, "No host or guests: nothing shares this device.");

    panel.replaceChildren(head, facts, ids, open, blastNote,
      section(`Top vulnerabilities (${n.findings})`, vulns),
      section(`Exposed services (${svcs.length}${local ? `, ${local} local` : ""})`, services),
      section(`Blast radius (${rel.length})`, related));
    panel.scrollTop = 0;
  }

  function renderOverview() {
    const counts = [0, 0, 0, 0, 0];
    for (const nd of st.order) counts[L.bandOf(nd.risk)]++;
    const max = Math.max(1, ...counts);
    const bands = el("div", { class: "rd-bands" }, L.BANDS.map((b, i) => {
      const fill = el("span", { class: "rd-band-fill" });
      fill.style.width = `${(counts[i] / max) * 100}%`;
      fill.style.background = P.risk[4 - i];
      return el("div", { class: "rd-band" }, el("span", { class: "rd-band-name" }, b.label),
        el("span", { class: "rd-band-bar" }, fill), el("span", { class: "rd-band-n" }, String(counts[i])));
    }));
    const kev = st.order.filter((x) => x.kev > 0).length;
    const top = st.order.slice(0, 10);
    panel.replaceChildren(
      el("div", { class: "rd-head" }, el("div", { class: "rd-title" }, el("h3", {}, "Attack surface"),
        el("div", { class: "muted" }, `${st.order.length} devices · ${kev} with KEV${st.network ? ` · ${st.network}` : ""}`))),
      section("By risk band", bands),
      section("Riskiest", top.length ? el("div", { class: "rd-devs" }, top.map((x) => deviceRow(x, x.kev ? `✛${x.kev}` : ""))) : el("p", { class: "muted" }, "No devices match.")),
      section("Keys", el("p", { class: "muted rd-keys" },
        "↑ ↓ step by risk · Enter open · Esc clear · / search · + − zoom · L list · Click a network name at the rim to show only it.")));
  }

  // ---- triage list -------------------------------------------------------
  function renderList() {
    if (st.mode !== "list") return;
    const rows = st.order.slice(0, st.listLimit).map((n, i) => {
      const v = (n.top || [])[0];
      const tr = el("tr", { class: n.id === st.sel ? "rd-row rd-sel" : "rd-row", "data-id": String(n.id) },
        el("td", { class: "rd-num muted" }, String(i + 1)),
        el("td", {}, riskPill(n.risk)),
        el("td", { class: "rd-name" }, el("span", { class: "rd-glyph" }, glyph(n)), ` ${n.name}`),
        el("td", { class: "muted" }, kindOf(n)),
        el("td", { class: "rd-num" }, n.kev ? `✛ ${n.kev}` : ""),
        el("td", { class: "rd-num" }, n.exposed ? `◎ ${n.exposed}` : ""),
        el("td", { class: "rd-num" }, n.findings ? String(n.findings) : ""),
        el("td", { class: "muted" }, (n.ips || [])[0] || ""),
        el("td", {}, v ? `${v.id}${v.kev ? " ✛" : ""}` : ""),
        el("td", { class: "rd-num" }, (n.related || []).length ? String(n.related.length) : ""));
      tr.style.borderLeftColor = colorOf(n.risk);
      return tr;
    });
    const head = el("thead", {}, el("tr", {}, ["#", "Risk", "Device", "Kind", "KEV", "Exposed", "Findings", "IP", "Top finding", "Blast"]
      .map((t) => el("th", {}, t))));
    const more = st.order.length > st.listLimit
      ? el("button", { type: "button", class: "rd-btn rd-more", onclick: () => { st.listLimit = st.order.length; renderList(); } },
        `Show all ${st.order.length}`) : null;
    list.replaceChildren(el("table", { class: "rd-table" }, head, el("tbody", {}, rows)), more,
      st.order.length ? null : el("p", { class: "muted rd-empty" }, "No devices match."));
  }
  list.addEventListener("click", (e) => {
    const tr = e.target.closest("tr[data-id]");
    if (tr) select(Number(tr.dataset.id));
  });
  list.addEventListener("dblclick", (e) => {
    const tr = e.target.closest("tr[data-id]");
    if (tr) kit.openDevice(Number(tr.dataset.id));
  });

  function setMode(m) {
    st.mode = m;
    list.hidden = m !== "list";
    canvas.hidden = m === "list";
    legend.hidden = m === "list";
    zoomCtl.hidden = m === "list";
    tip.hidden = true;
    syncButtons();
    renderList();
    if (m === "list") list.querySelector("tr.rd-sel")?.scrollIntoView({ block: "nearest" });
    requestDraw();
  }

  // ---- legend ------------------------------------------------------------
  function renderLegend() {
    const sw = (r, label) => {
      const s = el("span", { class: "rd-sw" });
      s.style.background = colorOf(r);
      return el("span", { class: "rd-lg" }, s, label);
    };
    legendBody.replaceChildren(
      el("div", { class: "rd-lg-row" }, "Closer to the center = higher risk. Sector = network."),
      el("div", { class: "rd-lg-row" }, sw(9.5, "critical"), sw(8, "high"), sw(5, "medium"), sw(2, "low"), sw(0, "none")),
      el("div", { class: "rd-lg-row" }, L.KINDS.map((k) => el("span", { class: "rd-lg" }, `${kit.kindGlyph[k]} ${k}`))),
      el("div", { class: "rd-lg-row" }, el("span", { class: "rd-lg" }, "✛ KEV"), el("span", { class: "rd-lg" }, "◎ exposed vulns"),
        el("span", { class: "rd-lg" }, "size = findings"), el("span", { class: "rd-lg" }, "— host↔guest")));
  }

  // ---- events ------------------------------------------------------------
  let searchTimer = 0;
  search.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      st.q = search.value;
      applyFilters();
    }, 120);
  });

  canvas.addEventListener("pointerdown", (e) => {
    if (e.button !== 0) return;
    drag = { x: e.clientX, y: e.clientY, px: st.panX, py: st.panY, moved: false };
    try { canvas.setPointerCapture(e.pointerId); } catch { /* ignore */ }
    root.focus({ preventScroll: true });
  });
  canvas.addEventListener("pointermove", (e) => {
    const { mx, my } = local(e);
    if (drag) {
      const dx = e.clientX - drag.x;
      const dy = e.clientY - drag.y;
      if (!drag.moved && Math.hypot(dx, dy) > 4) drag.moved = true;
      if (drag.moved) {
        st.panX = drag.px + dx;
        st.panY = drag.py + dy;
        tip.hidden = true;
        canvas.style.cursor = "grabbing";
        requestDraw();
        return;
      }
    }
    setHover(hitTest(mx, my), mx, my);
  });
  canvas.addEventListener("pointerup", (e) => {
    if (!drag) return;
    const moved = drag.moved;
    drag = null;
    try { canvas.releasePointerCapture(e.pointerId); } catch { /* ignore */ }
    if (moved) return;
    const { mx, my } = local(e);
    const b = hitTest(mx, my);
    if (b) {
      select(b.id);
      return;
    }
    const s = sectorAt(mx, my);
    if (s) {
      st.network = s.id;
      netSel.value = s.id;
      relayout();
      resetView();
      return;
    }
    select(null);
  });
  canvas.addEventListener("pointercancel", () => { drag = null; });
  canvas.addEventListener("pointerleave", () => {
    if (drag) return;
    st.hover = null;
    st.hoverSector = null;
    tip.hidden = true;
    requestDraw();
  });
  canvas.addEventListener("dblclick", (e) => {
    const { mx, my } = local(e);
    const b = hitTest(mx, my);
    if (b) kit.openDevice(b.id);
    else if (!sectorAt(mx, my)) resetView();
  });
  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const { mx, my } = local(e);
    const d = e.deltaMode === 1 ? e.deltaY * 16 : e.deltaY;
    zoomAt(mx, my, Math.exp(-d * 0.0015));
  }, { passive: false });

  root.addEventListener("keydown", (e) => {
    const t = e.target;
    const typing = t === search || t.tagName === "SELECT" || t.tagName === "INPUT";
    if (e.key === "Escape") {
      if (t === search && search.value) {
        search.value = "";
        clearTimeout(searchTimer);
        st.q = "";
        applyFilters();
      } else if (st.sel != null) {
        select(null);
      } else if (st.network) {
        st.network = "";
        netSel.value = "";
        relayout();
        resetView();
      }
      if (t === search) root.focus({ preventScroll: true });
      e.preventDefault();
      return;
    }
    if (typing) {
      if (t === search && (e.key === "Enter" || e.key === "ArrowDown")) {
        clearTimeout(searchTimer);
        st.q = search.value;
        applyFilters();
        if (st.order.length) select(st.order[0].id, { reveal: true });
        root.focus({ preventScroll: true });
        e.preventDefault();
      }
      return;
    }
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    // Buttons and the legend keep their own Enter and Space.
    if (t !== root && (e.key === "Enter" || e.key === " ")) return;
    switch (e.key) {
      case "ArrowDown": case "ArrowRight": step(1); break;
      case "ArrowUp": case "ArrowLeft": step(-1); break;
      case "Home": if (st.order.length) select(st.order[0].id, { reveal: true }); break;
      case "End": if (st.order.length) select(st.order[st.order.length - 1].id, { reveal: true }); break;
      case "Enter": if (st.sel != null) kit.openDevice(st.sel); else return; break;
      case "/": search.focus(); break;
      case "+": case "=": zoomAt(st.w / 2, st.h / 2, 1.4); break;
      case "-": case "_": zoomAt(st.w / 2, st.h / 2, 1 / 1.4); break;
      case "0": resetView(); break;
      case "l": case "L": setMode(st.mode === "radar" ? "list" : "radar"); break;
      default: return;
    }
    e.preventDefault();
  });

  const onTheme = () => {
    P = palette();
    renderLegend();
    renderPanel();
    renderList();
    requestDraw();
  };
  const onMotion = () => {
    st.sweep = !mqReduce.matches;
    syncButtons();
    requestDraw();
  };
  mqDark.addEventListener("change", onTheme);
  mqReduce.addEventListener("change", onMotion);
  const ro = new ResizeObserver(() => resize());
  ro.observe(main);

  // ---- start -------------------------------------------------------------
  buildNetOptions();
  renderLegend();
  relayout();
  resize();
  root.focus({ preventScroll: true });

  return {
    update(g) {
      st.graph = g;
      buildNetOptions();
      const sel = st.sel;
      relayout();
      if (sel != null && st.lay.byId.has(sel)) select(sel);
      else select(null);
    },
    destroy() {
      destroyed = true;
      if (raf) cancelAnimationFrame(raf);
      raf = 0;
      clearTimeout(searchTimer);
      ro.disconnect();
      mqDark.removeEventListener("change", onTheme);
      mqReduce.removeEventListener("change", onMotion);
      container.replaceChildren();
    },
  };
}
