// City: an isometric 2.5D city of the inventory on a canvas.
//
// Districts are networks (/24), buildings are devices. Facade color is
// the risk, height is the number of packages (log), footprint is the
// number of services. A hypervisor host is a tower with its guests on the
// same block, joined by skybridges. Antennas are exposed services, a red
// beacon is a known exploited vulnerability (KEV), a striped base means a
// device on the same host has a higher risk. Wireframe buildings have no
// package data (no agent).
import { layoutCity, rotateLayout, rotPoint, unrotPoint, PAD } from "./city-layout.js";

export const meta = {
  id: "city",
  title: "City",
  description: "Networks are districts, devices are buildings: color = risk, height = packages, red beacon = known exploited. Click a building to light its blast radius.",
};

const NIGHT_KEY = "nn.city.night";
const MIN_K = 1.5;
const MAX_K = 150;

// ---------- colors ----------

const rgbCache = new Map();
function rgb(c) {
  let v = rgbCache.get(c);
  if (v) return v;
  v = [128, 128, 128];
  if (c && c[0] === "#") {
    let h = c.slice(1);
    if (h.length === 3) h = h.split("").map((x) => x + x).join("");
    const n = parseInt(h.slice(0, 6), 16);
    v = [(n >> 16) & 255, (n >> 8) & 255, n & 255];
  } else if (c) {
    const m = c.match(/[\d.]+/g);
    if (m && m.length >= 3) v = [+m[0], +m[1], +m[2]];
  }
  if (rgbCache.size > 2000) rgbCache.clear();
  rgbCache.set(c, v);
  return v;
}
const mixCache = new Map();
function mix(a, b, t) {
  if (!t) return a;
  const key = a + "|" + b + "|" + t;
  let v = mixCache.get(key);
  if (v) return v;
  const A = rgb(a);
  const B = rgb(b);
  v = `rgb(${Math.round(A[0] + (B[0] - A[0]) * t)},${Math.round(A[1] + (B[1] - A[1]) * t)},${Math.round(A[2] + (B[2] - A[2]) * t)})`;
  if (mixCache.size > 6000) mixCache.clear();
  mixCache.set(key, v);
  return v;
}

function palette(night) {
  if (night) {
    return {
      night: true,
      sky: ["#050813", "#161d36"],
      ground: "#0c1020", plate: "#1b2235", plateLine: "#2b3552", plateSide: "#121726", outskirts: "#221f2c",
      campus: "#232b42", campusLine: "#3b4769",
      text: "#7d89ad", textStrong: "#c8d1ef",
      fog: "#141a2b", dim: 0.32, none: "#4b5572",
      winLit: "#ffd36b", winGlow: "rgba(255,190,70,0.35)", winDark: "rgba(8,10,20,0.55)",
      edge: "rgba(0,0,0,0.55)",
      antenna: "#8f9cc4", tip: "#79dcff", tipVuln: "#ffb347",
      leaf: "#1c4a3b", leaf2: "#2a6650", trunk: "#4a3a30",
      bridge: "#8ea3d8", bridgeTop: "#c7d4f7", conduit: "rgba(120,170,255,0.6)",
      accent: "#7fb2ff", label: "rgba(16,20,36,0.9)", labelText: "#e8edff", labelLine: "#34415f",
      hazard: "#f4c430", hazardDark: "#1a1a1a",
    };
  }
  return {
    night: false,
    sky: ["#b9d5f1", "#eef4fb"],
    ground: "#c9d2dd", plate: "#eef1f4", plateLine: "#d3dae3", plateSide: "#b3bdc9", outskirts: "#ece5d6",
    campus: "#e1e7ee", campusLine: "#b4c1d2",
    text: "#677386", textStrong: "#262e3d",
    fog: "#dfe5ec", dim: 0, none: null,
    winLit: "#fff3b8", winGlow: null, winDark: "rgba(20,30,50,0.28)",
    edge: "rgba(20,30,50,0.38)",
    antenna: "#596378", tip: "#2f6fdb", tipVuln: "#e07b00",
    leaf: "#7cbf7a", leaf2: "#5ea65e", trunk: "#8a6a4f",
    bridge: "#7f90b4", bridgeTop: "#b6c3dc", conduit: "rgba(47,111,219,0.5)",
    accent: "#2f6fdb", label: "rgba(255,255,255,0.93)", labelText: "#1d2129", labelLine: "#c3ccd8",
    hazard: "#f2b705", hazardDark: "#222222",
  };
}

// ---------- geometry ----------

// corners fills p with the screen points of a box: A1 B1 C1 D1 (top:
// back, right, front, left) then A0 B0 C0 D0 (bottom).
function corners(V, x0, y0, x1, y1, z0, z1, p) {
  const k = V.k;
  const h = k * 0.5;
  const ax = V.ox + (x0 - y0) * k, ay = V.oy + (x0 + y0) * h;
  const bx = V.ox + (x1 - y0) * k, by = V.oy + (x1 + y0) * h;
  const cx = V.ox + (x1 - y1) * k, cy = V.oy + (x1 + y1) * h;
  const dx = V.ox + (x0 - y1) * k, dy = V.oy + (x0 + y1) * h;
  const t = z1 * k;
  const b = z0 * k;
  p[0] = ax; p[1] = ay - t; p[2] = bx; p[3] = by - t; p[4] = cx; p[5] = cy - t; p[6] = dx; p[7] = dy - t;
  p[8] = ax; p[9] = ay - b; p[10] = bx; p[11] = by - b; p[12] = cx; p[13] = cy - b; p[14] = dx; p[15] = dy - b;
  return p;
}

function poly(ctx, p, idx) {
  ctx.beginPath();
  ctx.moveTo(p[idx[0] * 2], p[idx[0] * 2 + 1]);
  for (let i = 1; i < idx.length; i++) ctx.lineTo(p[idx[i] * 2], p[idx[i] * 2 + 1]);
  ctx.closePath();
}
const TOP = [0, 1, 2, 3];
const LEFT = [3, 2, 6, 7];
const RIGHT = [2, 1, 5, 6];
const HULL = [0, 1, 5, 6, 7, 3];

function fillBox(ctx, p, top, left, right) {
  ctx.fillStyle = left;
  poly(ctx, p, LEFT);
  ctx.fill();
  ctx.fillStyle = right;
  poly(ctx, p, RIGHT);
  ctx.fill();
  ctx.fillStyle = top;
  poly(ctx, p, TOP);
  ctx.fill();
}

function edgeBox(ctx, p, color, w) {
  ctx.strokeStyle = color;
  ctx.lineWidth = w;
  poly(ctx, p, HULL);
  ctx.moveTo(p[4], p[5]);
  ctx.lineTo(p[12], p[13]);
  ctx.moveTo(p[6], p[7]);
  ctx.lineTo(p[4], p[5]);
  ctx.lineTo(p[2], p[3]);
  ctx.stroke();
}

function inHull(p, x, y) {
  let sign = 0;
  for (let i = 0; i < HULL.length; i++) {
    const a = HULL[i];
    const b = HULL[(i + 1) % HULL.length];
    const ax = p[a * 2], ay = p[a * 2 + 1], bx = p[b * 2], by = p[b * 2 + 1];
    const c = (bx - ax) * (y - ay) - (by - ay) * (x - ax);
    if (c !== 0) {
      const s = c > 0 ? 1 : -1;
      if (sign === 0) sign = s;
      else if (s !== sign) return false;
    }
  }
  return true;
}

const hash = (a, b) => ((Math.imul(a | 0, 2654435761) ^ Math.imul(b | 0, 40503)) >>> 0) % 1009 / 1009;

// ---------- module ----------

export function mount(container, graph, kit) {
  kit.loadCSS("viz/city.css");
  const el = kit.el;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  const scheme = matchMedia("(prefers-color-scheme: dark)");

  let night = kit.dark();
  try {
    const v = localStorage.getItem(NIGHT_KEY);
    if (v === "1" || v === "0") night = v === "1";
  } catch { /* private mode */ }
  let pal = palette(night);

  // State.
  let G = graph;
  let byId = new Map();
  let L = null;
  let R = null;
  let rot = 0;
  const V = { k: 20, ox: 0, oy: 0 };
  let W = 0, H = 0, dpr = 1;
  let hover = -1;
  let selected = null;
  let blastSet = null;
  let query = "";
  let matches = null;
  let sceneDirty = true;
  let raf = 0;
  let tween = null;
  let fitted = false;
  let destroyed = false;
  let hits = [];
  let beacons = [];
  let panelOpen = (container.clientWidth || 1000) >= 760;
  const P16 = new Float64Array(16);

  // DOM.
  const canvas = el("canvas", { class: "city-canvas", tabindex: "0", role: "img", "aria-label": "Isometric city of the inventory. Use the search box and the side panel for a text view." });
  const ctx = canvas.getContext("2d");
  const scene = document.createElement("canvas");
  const sctx = scene.getContext("2d");
  const tip = el("div", { class: "city-tip", hidden: true });
  const search = el("input", { class: "city-search", type: "search", placeholder: "Search name, IP, CVE…", "aria-label": "Search buildings by name, IP, CVE or service" });
  const found = el("span", { class: "city-found" });
  const nightBtn = el("button", { class: "city-btn", type: "button", title: "Night mode (independent of the page theme)" }, "☾ Night");
  const panelBtn = el("button", { class: "city-btn", type: "button", title: "Show or hide the side panel" }, "Panel");
  const bar = el("div", { class: "city-bar" },
    search, found,
    el("button", { class: "city-btn", type: "button", title: "Rotate left", "aria-label": "Rotate left", onclick: () => rotate(-1) }, "⟲"),
    el("button", { class: "city-btn", type: "button", title: "Rotate right", "aria-label": "Rotate right", onclick: () => rotate(1) }, "⟳"),
    el("button", { class: "city-btn", type: "button", title: "Show the whole city", onclick: () => fit(true) }, "Fit"),
    nightBtn, panelBtn);
  const panelBody = el("div", { class: "city-panel-body" });
  const putPanel = (...xs) => panelBody.replaceChildren(...xs.flat(Infinity).filter((x) => x !== null && x !== undefined && x !== false));
  const panel = el("aside", { class: "city-panel", "aria-label": "City details" }, panelBody);
  const legendBody = el("div", { class: "city-legend-body" });
  const legend = el("details", { class: "city-legend" }, el("summary", {}, "Legend"), legendBody);
  if ((container.clientWidth || 0) >= 1000 && (container.clientHeight || 0) >= 560) legend.open = true;
  const hint = el("div", { class: "city-hint muted" }, "drag: pan · wheel: zoom · click: blast radius · double-click: open · Esc: clear");
  const root = el("div", { class: "city" }, canvas, bar, panel, legend, hint, tip);
  container.append(root);

  // ---------- data ----------

  function setGraph(g) {
    G = g || { nodes: [], networks: [] };
    byId = new Map((G.nodes || []).map((n) => [n.id, n]));
    L = layoutCity(G);
    R = rotateLayout(L, rot);
    if (selected != null && !byId.has(selected)) selected = null;
    blastSet = selected != null ? new Set([selected, ...(byId.get(selected).related || [])]) : null;
    hover = -1;
    computeMatches();
  }

  function computeMatches() {
    const q = query.trim().toLowerCase();
    if (!q) {
      matches = null;
      found.textContent = "";
      return;
    }
    matches = new Set();
    for (const n of G.nodes || []) {
      const hay = [n.name, n.kind, ...(n.ips || []), ...(n.macs || []), ...(n.networks || []),
        ...(n.top || []).map((v) => v.id + " " + v.package),
        ...(n.services || []).map((s) => `${s.port}/${s.proto} ${s.process || ""} ${s.product || ""}`)];
      if (hay.some((h) => h && String(h).toLowerCase().includes(q))) matches.add(n.id);
    }
    found.textContent = matches.size ? `${matches.size} found` : "none";
  }

  const riskOf = (n) => +n.risk || 0;
  const facade = (n) => {
    const r = riskOf(n);
    if (!r && pal.none) return pal.none;
    const c = kit.riskColor(r);
    return pal.dim ? mix(c, "#0a0f1f", pal.dim) : c;
  };
  const fogOf = (id) => {
    if (blastSet) return blastSet.has(id) ? 0 : 0.8;
    if (matches) return matches.has(id) ? 0 : 0.68;
    return 0;
  };

  // ---------- view ----------

  function rightInset() {
    return panelOpen && W >= 760 ? 320 : 0;
  }

  function fit(animate) {
    if (!R || !L.buildings.length || !W) return;
    let x0 = Infinity, x1 = -Infinity, y0 = Infinity, y1 = -Infinity;
    const add = (x, y, z) => {
      const sx = x - y;
      const sy = (x + y) / 2 - z;
      x0 = Math.min(x0, sx); x1 = Math.max(x1, sx); y0 = Math.min(y0, sy); y1 = Math.max(y1, sy);
    };
    for (const d of R.districts) {
      add(d.x0, d.y0, 0); add(d.x1, d.y0, 0); add(d.x1, d.y1, -0.25); add(d.x0, d.y1, -0.25);
    }
    R.buildings.forEach((b, i) => add(b.x0, b.y0, L.buildings[i].top + 0.8));
    const aw = W - rightInset() - 40;
    const ah = H - 90;
    const k = Math.max(MIN_K, Math.min(60, aw / Math.max(1, x1 - x0), ah / Math.max(1, y1 - y0)));
    const target = { k, ox: 20 + (aw - (x1 - x0) * k) / 2 - x0 * k, oy: 60 + (ah - (y1 - y0) * k) / 2 - y0 * k };
    flyTo(target, animate);
  }

  function flyTo(target, animate) {
    if (!animate || reduced.matches) {
      Object.assign(V, target);
      tween = null;
      invalidate();
      return;
    }
    tween = { from: { ...V }, to: target, t0: performance.now(), dur: 420 };
    schedule();
  }

  function focusBuilding(i) {
    const b = R.buildings[i];
    const lb = L.buildings[i];
    const k = Math.min(MAX_K, Math.max(V.k, 34));
    const cx = (b.x0 + b.x1) / 2;
    const cy = (b.y0 + b.y1) / 2;
    const sx = (W - rightInset()) / 2;
    const sy = H / 2 + 20;
    flyTo({ k, ox: sx - (cx - cy) * k, oy: sy - ((cx + cy) / 2 - lb.top / 2) * k }, true);
  }

  function rotate(d) {
    if (!L) return;
    const sx = (W - rightInset()) / 2;
    const sy = H / 2;
    const a = (sx - V.ox) / V.k;
    const b = ((sy - V.oy) * 2) / V.k;
    const [wx, wy] = unrotPoint(L, rot, (a + b) / 2, (b - a) / 2);
    rot = (rot + d + 4) % 4;
    R = rotateLayout(L, rot);
    const k = V.k;
    const [rx, ry] = rotPoint(L, rot, wx, wy);
    V.ox = sx - (rx - ry) * k;
    V.oy = sy - ((rx + ry) / 2) * k;
    hover = -1;
    tip.hidden = true;
    invalidate();
  }

  function resize() {
    const w = container.clientWidth;
    const h = container.clientHeight;
    const r = window.devicePixelRatio || 1;
    if (w === W && h === H && r === dpr) return;
    W = w; H = h; dpr = r;
    for (const c of [canvas, scene]) {
      c.width = Math.max(1, Math.round(W * dpr));
      c.height = Math.max(1, Math.round(H * dpr));
    }
    if (!fitted && W > 0) {
      fitted = true;
      fit(false);
    }
    invalidate();
  }

  // ---------- render ----------

  function invalidate() {
    sceneDirty = true;
    schedule();
  }
  function schedule() {
    if (!raf && !destroyed) raf = requestAnimationFrame(frame);
  }
  function animating() {
    return !reduced.matches && !document.hidden && V.k >= 8 && beacons.length > 0 && beacons.length <= 250;
  }
  function frame(t) {
    raf = 0;
    if (destroyed) return;
    if (tween) {
      const u = Math.min(1, (t - tween.t0) / tween.dur);
      const e = u < 0.5 ? 2 * u * u : 1 - (-2 * u + 2) ** 2 / 2;
      const kf = tween.from.k * Math.pow(tween.to.k / tween.from.k, e);
      // Keep the zoom and the pan in step: interpolate the world point at the center.
      V.k = kf;
      V.ox = tween.from.ox + (tween.to.ox - tween.from.ox) * e;
      V.oy = tween.from.oy + (tween.to.oy - tween.from.oy) * e;
      sceneDirty = true;
      if (u >= 1) tween = null;
    }
    if (sceneDirty) {
      renderScene();
      sceneDirty = false;
    }
    present(t);
    if (tween || animating()) schedule();
  }

  function renderScene() {
    const c = sctx;
    c.setTransform(dpr, 0, 0, dpr, 0, 0);
    const g = c.createLinearGradient(0, 0, 0, H);
    g.addColorStop(0, pal.sky[0]);
    g.addColorStop(1, pal.sky[1]);
    c.fillStyle = g;
    c.fillRect(0, 0, W, H);
    hits = [];
    beacons = [];
    if (!L || !L.buildings.length) {
      c.fillStyle = pal.textStrong;
      c.font = "15px system-ui, sans-serif";
      c.textAlign = "center";
      c.fillText("No devices yet.", W / 2, H / 2);
      c.textAlign = "start";
      return;
    }
    if (pal.night) drawStars(c);
    const k = V.k;
    const vis = (sx0, sx1, sy0, sy1) => sx1 >= -40 && sx0 <= W + 40 && sy1 >= -40 && sy0 <= H + 40;

    // Ground under the whole city.
    corners(V, -0.6, -0.6, R.w + 0.6, R.h + 0.6, -0.5, -0.3, P16);
    fillBox(c, P16, pal.ground, mix(pal.ground, "#000000", 0.18), mix(pal.ground, "#000000", 0.3));

    // District plates.
    R.districts.forEach((d, i) => {
      const D = L.districts[i];
      corners(V, d.x0, d.y0, d.x1, d.y1, -0.22, 0, P16);
      if (!vis(P16[14], P16[10], P16[1], P16[13])) return;
      const curb = mix(D.risk ? kit.riskColor(D.risk) : pal.plateSide, pal.plateSide, 0.45);
      fillBox(c, P16, D.outskirts ? pal.outskirts : pal.plate, curb, mix(curb, "#000000", 0.18));
      if (k >= 4) {
        c.save();
        if (D.outskirts) c.setLineDash([6, 4]);
        c.strokeStyle = pal.plateLine;
        c.lineWidth = 1;
        poly(c, P16, TOP);
        c.stroke();
        c.restore();
      }
    });
    // Blocks of a host and its guests.
    R.blocks.forEach((b) => {
      corners(V, b.x0 + 0.06, b.y0 + 0.06, b.x1 - 0.06, b.y1 - 0.06, 0, 0.05, P16);
      if (!vis(P16[14], P16[10], P16[1], P16[13])) return;
      fillBox(c, P16, pal.campus, pal.campusLine, mix(pal.campusLine, "#000000", 0.15));
    });
    // Ground labels.
    if (k * 0.5 >= 9) {
      let lit = null;
      if (blastSet) {
        lit = new Set();
        for (const id of blastSet) if (L.index.has(id)) lit.add(L.buildings[L.index.get(id)].district);
      }
      R.districts.forEach((d, i) => groundLabel(c, d, L.districts[i], lit && !lit.has(i)));
    }
    // Ground conduits of guests that are not next to their host.
    if (k >= 5) {
      c.save();
      c.setLineDash([Math.max(2, k * 0.12), Math.max(2, k * 0.1)]);
      c.lineWidth = Math.max(1, k * 0.05);
      for (const br of L.bridges) {
        if (br.adjacent) continue;
        const a = R.buildings[L.index.get(br.from)];
        const b = R.buildings[L.index.get(br.to)];
        const ax = (a.x0 + a.x1) / 2, ay = (a.y0 + a.y1) / 2, bx = (b.x0 + b.x1) / 2, by = (b.y0 + b.y1) / 2;
        const hot = blastSet && blastSet.has(br.from) && blastSet.has(br.to);
        c.strokeStyle = hot ? pal.accent : blastSet ? mix(pal.campusLine, pal.fog, 0.5) : pal.conduit;
        c.beginPath();
        c.moveTo(V.ox + (ax - ay) * k, V.oy + (ax + ay) * k * 0.5 - 0.06 * k);
        c.lineTo(V.ox + (bx - ay) * k, V.oy + (bx + ay) * k * 0.5 - 0.06 * k);
        c.lineTo(V.ox + (bx - by) * k, V.oy + (bx + by) * k * 0.5 - 0.06 * k);
        c.stroke();
      }
      c.restore();
    }

    // Buildings and trees, back to front.
    for (const it of R.order) {
      if (it.t === 1) {
        if (k >= 6) drawTree(c, R.trees[it.i], L.trees[it.i]);
        continue;
      }
      const i = it.i;
      const bb = R.buildings[i];
      const lb = L.buildings[i];
      const sx0 = V.ox + (bb.x0 - bb.y1) * k, sx1 = V.ox + (bb.x1 - bb.y0) * k;
      const sy1 = V.oy + (bb.x1 + bb.y1) * k * 0.5, sy0 = V.oy + (bb.x0 + bb.y0) * k * 0.5 - (lb.top + 1) * k;
      if (!vis(sx0, sx1, sy0, sy1)) continue;
      const br = R.before.get(i);
      if (br && k >= 4) for (const x of br) drawBridge(c, x);
      drawBuilding(c, i);
    }
    labelsPass(c);
  }

  function drawStars(c) {
    c.fillStyle = "rgba(220,230,255,0.7)";
    for (let i = 0; i < 90; i++) {
      const x = hash(i, 7) * W;
      const y = hash(i, 13) * H * 0.7;
      const s = hash(i, 29) < 0.15 ? 1.6 : 1;
      c.fillRect(x, y, s, s);
    }
  }

  function groundLabel(c, d, D, fogged) {
    const k = V.k;
    c.save();
    c.setTransform(dpr * k, dpr * k * 0.5, -dpr * k, dpr * k * 0.5, dpr * V.ox, dpr * V.oy);
    const maxW = d.x1 - d.x0 - 0.8;
    const line = (text, size, y, color, weight) => {
      c.font = `${weight} 40px system-ui, -apple-system, "Segoe UI", sans-serif`;
      const w40 = c.measureText(text).width || 1;
      const s = Math.min(size / 40, maxW / w40);
      c.save();
      c.scale(s, s);
      c.fillStyle = color;
      c.fillText(text, (d.x0 + 0.42) / s, y / s);
      c.restore();
    };
    const main = fogged ? mix(pal.textStrong, pal.plate, 0.6) : pal.textStrong;
    const sub = fogged ? mix(pal.text, pal.plate, 0.6) : pal.text;
    line(D.outskirts ? "outskirts (no network)" : D.label, 0.5, d.y1 - PAD * 0.45, main, 700);
    const bits = [`${D.devices} device${D.devices === 1 ? "" : "s"}`];
    if (D.kev) bits.push(`${D.kev} KEV`);
    bits.push(`worst ${kit.riskLabel(D.risk)}${D.risk ? " " + D.risk.toFixed(1) : ""}`);
    line(bits.join(" · "), 0.27, d.y1 - PAD * 0.12, sub, 500);
    c.restore();
  }

  function drawTree(c, t, lt) {
    const k = V.k;
    const sx = V.ox + (t.x - t.y) * k;
    const sy = V.oy + (t.x + t.y) * k * 0.5 - 0.05 * k;
    const s = lt.s;
    const fog = blastSet || matches ? 0.6 : 0;
    c.strokeStyle = mix(pal.trunk, pal.fog, fog);
    c.lineWidth = Math.max(1, k * 0.05);
    c.beginPath();
    c.moveTo(sx, sy);
    c.lineTo(sx, sy - 0.3 * k * s);
    c.stroke();
    c.fillStyle = mix(pal.leaf2, pal.fog, fog);
    c.beginPath();
    c.arc(sx, sy - 0.42 * k * s, 0.2 * k * s, 0, Math.PI * 2);
    c.fill();
    c.fillStyle = mix(pal.leaf, pal.fog, fog);
    c.beginPath();
    c.arc(sx - 0.05 * k * s, sy - 0.48 * k * s, 0.13 * k * s, 0, Math.PI * 2);
    c.fill();
  }

  function drawBridge(c, br) {
    const k = V.k;
    const a = R.buildings[L.index.get(br.from)];
    const b = R.buildings[L.index.get(br.to)];
    const ax = (a.x0 + a.x1) / 2, ay = (a.y0 + a.y1) / 2, bx = (b.x0 + b.x1) / 2, by = (b.y0 + b.y1) / 2;
    const hot = blastSet && blastSet.has(br.from) && blastSet.has(br.to);
    const fog = blastSet ? (hot ? 0 : 0.8) : matches ? 0.6 : 0;
    const p0x = V.ox + (ax - ay) * k, p0y = V.oy + (ax + ay) * k * 0.5 - br.z * k;
    const p1x = V.ox + (bx - by) * k, p1y = V.oy + (bx + by) * k * 0.5 - br.z * k;
    c.lineCap = "round";
    c.strokeStyle = hot ? pal.accent : mix(pal.bridge, pal.fog, fog);
    c.lineWidth = Math.max(2, k * 0.16);
    c.beginPath();
    c.moveTo(p0x, p0y);
    c.lineTo(p1x, p1y);
    c.stroke();
    c.strokeStyle = hot ? mix(pal.accent, "#ffffff", 0.5) : mix(pal.bridgeTop, pal.fog, fog);
    c.lineWidth = Math.max(1, k * 0.05);
    c.beginPath();
    c.moveTo(p0x, p0y - k * 0.04);
    c.lineTo(p1x, p1y - k * 0.04);
    c.stroke();
    c.lineCap = "butt";
  }

  function drawBuilding(c, i) {
    const k = V.k;
    const bb = R.buildings[i];
    const lb = L.buildings[i];
    const n = lb.node;
    const fog = fogOf(n.id);
    const col = mix(facade(n), pal.fog, fog);
    const top = mix(col, "#ffffff", pal.night ? 0.12 : 0.24);
    const right = mix(col, "#000000", 0.22);
    const p = corners(V, bb.x0, bb.y0, bb.x1, bb.y1, 0.05, lb.h, P16);
    const hull = Float64Array.from(p);
    const detail = fog < 0.5;

    if (lb.known) {
      fillBox(c, p, top, col, right);
      if (k >= 16 && detail) drawWindows(c, bb, lb, col, right);
      if (lb.hazard && k >= 6) drawHazard(c, bb, lb);
      if (k >= 7) edgeBox(c, p, pal.edge, 1);
    } else {
      // Unknown interior: translucent faces and a dashed wire frame.
      c.save();
      c.globalAlpha = 0.28;
      fillBox(c, p, top, col, right);
      c.globalAlpha = 1;
      if (lb.hazard && k >= 6) drawHazard(c, bb, lb);
      c.setLineDash([Math.max(2, k * 0.08), Math.max(2, k * 0.06)]);
      c.strokeStyle = mix(right, pal.textStrong, pal.night ? 0.35 : 0.1);
      c.lineWidth = 1;
      c.beginPath();
      c.moveTo(p[0], p[1]); c.lineTo(p[8], p[9]); // back edge
      c.moveTo(p[8], p[9]); c.lineTo(p[10], p[11]);
      c.moveTo(p[8], p[9]); c.lineTo(p[14], p[15]);
      c.stroke();
      c.setLineDash([]);
      edgeBox(c, p, mix(right, pal.textStrong, pal.night ? 0.45 : 0.2), k >= 10 ? 1.4 : 1);
      if (k >= 14) {
        const sx = (p[0] + p[4]) / 2, sy = (p[1] + p[5]) / 2;
        c.fillStyle = mix(pal.textStrong, pal.fog, fog);
        c.font = `700 ${Math.round(Math.min(22, k * 0.32))}px system-ui, sans-serif`;
        c.textAlign = "center";
        c.textBaseline = "middle";
        c.fillText("?", sx, sy);
        c.textAlign = "start";
        c.textBaseline = "alphabetic";
      }
      c.restore();
    }

    // Roof: crown of a tower.
    let rx0 = bb.x0, ry0 = bb.y0, rx1 = bb.x1, ry1 = bb.y1, rz = lb.h;
    if (lb.role === "host") {
      const inset = (bb.x1 - bb.x0) * 0.2;
      rx0 += inset; ry0 += inset; rx1 -= inset; ry1 -= inset;
      const cp = corners(V, rx0, ry0, rx1, ry1, lb.h, lb.top, P16);
      fillBox(c, cp, mix(top, "#ffffff", 0.1), mix(col, "#000000", 0.06), mix(right, "#000000", 0.08));
      if (k >= 7) edgeBox(c, cp, pal.edge, 1);
      // Make the hull cover the crown: use the outer box at crown height.
      corners(V, bb.x0, bb.y0, bb.x1, bb.y1, 0.05, lb.top, P16);
      hull[0] = P16[0]; hull[1] = P16[1]; hull[2] = P16[2]; hull[3] = P16[3]; hull[6] = P16[6]; hull[7] = P16[7];
      rz = lb.top;
      if (k >= 9 && detail) {
        // Spire.
        const sx = V.ox + ((rx0 + rx1) / 2 - (ry0 + ry1) / 2) * k;
        const sy = V.oy + ((rx0 + rx1 + ry0 + ry1) / 4) * k - rz * k;
        if (!(n.kev > 0)) {
          c.strokeStyle = pal.antenna;
          c.lineWidth = Math.max(1, k * 0.04);
          c.beginPath();
          c.moveTo(sx, sy);
          c.lineTo(sx, sy - 0.55 * k);
          c.stroke();
        }
      }
    }

    // Antennas: one per exposed service (max 4); amber tip when it has findings.
    if (k >= 9 && lb.exposed > 0) {
      const svc = (n.services || []).filter((s) => s.exposed).sort((a, b) => (b.vulns > 0) - (a.vulns > 0)).slice(0, 4);
      const spots = [[0.22, 0.22], [0.78, 0.22], [0.22, 0.78], [0.78, 0.78]];
      const hgt = 0.42 * k;
      svc.forEach((s, j) => {
        const [u, v] = spots[j];
        const x = rx0 + (rx1 - rx0) * u;
        const y = ry0 + (ry1 - ry0) * v;
        const sx = V.ox + (x - y) * k;
        const sy = V.oy + (x + y) * k * 0.5 - rz * k;
        c.strokeStyle = mix(pal.antenna, pal.fog, fog);
        c.lineWidth = Math.max(1, k * 0.035);
        c.beginPath();
        c.moveTo(sx, sy);
        c.lineTo(sx, sy - hgt);
        c.stroke();
        c.fillStyle = mix(s.vulns > 0 ? pal.tipVuln : pal.tip, pal.fog, fog);
        c.beginPath();
        c.arc(sx, sy - hgt, Math.max(1.4, k * 0.05), 0, Math.PI * 2);
        c.fill();
      });
    }

    // KEV beacon position (drawn now when static, else in the overlay).
    if (n.kev > 0) {
      const cx = (rx0 + rx1) / 2, cy = (ry0 + ry1) / 2;
      const sx = V.ox + (cx - cy) * k;
      const sy = V.oy + (cx + cy) * k * 0.5 - rz * k;
      beacons.push({ sx, sy, fog, phase: hash(n.id, 3) * Math.PI * 2 });
    }

    // Selection and blast outline.
    if (blastSet && blastSet.has(n.id)) {
      c.strokeStyle = pal.accent;
      c.lineWidth = n.id === selected ? 3 : 2;
      poly(c, hull, HULL);
      c.stroke();
      if (n.id === selected) drawPin(c, (bb.x0 + bb.x1) / 2, (bb.y0 + bb.y1) / 2, lb.top + (n.kev > 0 ? 1.1 : 0.85));
    } else if (matches && matches.has(n.id)) {
      c.save();
      c.setLineDash([4, 3]);
      c.strokeStyle = pal.accent;
      c.lineWidth = 2;
      poly(c, hull, HULL);
      c.stroke();
      c.restore();
    }
    hits.push({ i, hull });
  }

  function drawPin(c, x, y, z) {
    const k = V.k;
    const sx = V.ox + (x - y) * k;
    const sy = V.oy + (x + y) * k * 0.5 - z * k;
    const s = Math.max(7, Math.min(16, k * 0.3));
    c.fillStyle = pal.accent;
    c.strokeStyle = pal.night ? "#0b1020" : "#ffffff";
    c.lineWidth = 2;
    c.beginPath();
    c.moveTo(sx, sy);
    c.lineTo(sx - s * 0.7, sy - s);
    c.lineTo(sx + s * 0.7, sy - s);
    c.closePath();
    c.stroke();
    c.fill();
  }

  function drawWindows(c, bb, lb, col, right) {
    const k = V.k;
    const n = lb.node;
    const svc = (n.services || []).length;
    const frac = svc ? lb.exposed / svc : 0;
    const rows = Math.max(1, Math.min(16, Math.floor((lb.h - 0.2) / 0.3)));
    const f = bb.x1 - bb.x0;
    const cols = Math.max(1, Math.min(4, Math.round(f / 0.2)));
    const ww = (f / cols) * 0.5;
    const wh = 0.13;
    const lit = new Path2D();
    const dark = new Path2D();
    const quad = (path, ax, ay, bx, by, z0, z1) => {
      path.moveTo(V.ox + (ax - ay) * k, V.oy + (ax + ay) * k * 0.5 - z0 * k);
      path.lineTo(V.ox + (bx - by) * k, V.oy + (bx + by) * k * 0.5 - z0 * k);
      path.lineTo(V.ox + (bx - by) * k, V.oy + (bx + by) * k * 0.5 - z1 * k);
      path.lineTo(V.ox + (ax - ay) * k, V.oy + (ax + ay) * k * 0.5 - z1 * k);
      path.closePath();
    };
    let idx = 0;
    for (let r = 0; r < rows; r++) {
      const z0 = 0.22 + r * 0.3 + (lb.hazard ? 0.06 : 0);
      if (z0 + wh > lb.h - 0.05) break;
      for (let j = 0; j < cols; j++) {
        const u0 = (j + 0.25) * (f / cols);
        // Left face (y = y1), then right face (x = x1).
        let on = hash(n.id, idx++) < frac;
        quad(on ? lit : dark, bb.x0 + u0, bb.y1, bb.x0 + u0 + ww, bb.y1, z0, z0 + wh);
        on = hash(n.id, idx++) < frac;
        quad(on ? lit : dark, bb.x1, bb.y1 - u0, bb.x1, bb.y1 - u0 - ww, z0, z0 + wh);
      }
    }
    c.fillStyle = pal.winDark;
    c.fill(dark);
    if (pal.winGlow) {
      c.strokeStyle = pal.winGlow;
      c.lineWidth = Math.max(2, k * 0.08);
      c.stroke(lit);
    }
    c.fillStyle = pal.winLit;
    c.fill(lit);
  }

  function drawHazard(c, bb, lb) {
    const k = V.k;
    const hb = Math.min(0.2, lb.h * 0.35);
    const p = corners(V, bb.x0, bb.y0, bb.x1, bb.y1, 0.05, 0.05 + hb, new Float64Array(16));
    c.save();
    c.beginPath();
    c.moveTo(p[6], p[7]); c.lineTo(p[4], p[5]); c.lineTo(p[2], p[3]);
    c.lineTo(p[10], p[11]); c.lineTo(p[12], p[13]); c.lineTo(p[14], p[15]);
    c.closePath();
    c.clip();
    c.fillStyle = pal.hazard;
    c.fill();
    c.strokeStyle = pal.hazardDark;
    const step = Math.max(4, k * 0.16);
    c.lineWidth = step * 0.45;
    const xa = p[14] - 20, xb = p[10] + 20, ya = Math.min(p[3], p[7]) - 4, yb = p[13] + 4;
    c.beginPath();
    for (let x = xa - (yb - ya); x < xb; x += step) {
      c.moveTo(x, yb);
      c.lineTo(x + (yb - ya), ya);
    }
    c.stroke();
    c.restore();
  }

  function drawBeacon(c, b, t) {
    const k = V.k;
    const r = Math.max(3, Math.min(9, k * 0.1));
    const cx = b.sx;
    const cy = b.sy - r * 0.4;
    c.save();
    if (b.fog >= 0.5) c.globalAlpha = 0.35;
    if (t != null) {
      const a0 = t / 650 + b.phase;
      const R0 = Math.min(140, k * 1.9);
      const g = c.createRadialGradient(cx, cy, 0, cx, cy, R0);
      g.addColorStop(0, "rgba(255,40,64,0.55)");
      g.addColorStop(1, "rgba(255,40,64,0)");
      c.fillStyle = g;
      for (const a of [a0, a0 + Math.PI]) {
        c.beginPath();
        c.moveTo(cx, cy);
        for (let s = -0.3; s <= 0.301; s += 0.15) c.lineTo(cx + Math.cos(a + s) * R0, cy + Math.sin(a + s) * R0 * 0.5);
        c.closePath();
        c.fill();
      }
    } else if (k >= 9) {
      c.strokeStyle = "#ff2944";
      c.lineWidth = Math.max(1, r * 0.28);
      c.beginPath();
      for (const a of [-2.7, -1.57, -0.44]) {
        c.moveTo(cx + Math.cos(a) * r * 1.6, cy + Math.sin(a) * r * 1.6);
        c.lineTo(cx + Math.cos(a) * r * 2.5, cy + Math.sin(a) * r * 2.5);
      }
      c.stroke();
    }
    c.fillStyle = "#4a0a14";
    c.fillRect(cx - r, cy, r * 2, r * 0.45);
    c.beginPath();
    c.arc(cx, cy, r, Math.PI, 0);
    c.closePath();
    c.fillStyle = "#ff2944";
    c.fill();
    c.strokeStyle = pal.night ? "#ffd0d6" : "#ffffff";
    c.lineWidth = 1.2;
    c.stroke();
    c.fillStyle = "rgba(255,255,255,0.85)";
    c.beginPath();
    c.arc(cx - r * 0.35, cy - r * 0.45, r * 0.25, 0, Math.PI * 2);
    c.fill();
    c.restore();
  }

  function labelsPass(c) {
    const k = V.k;
    const placed = [];
    const overlaps = (x0, y0, x1, y1) => placed.some((r) => x0 < r[2] && r[0] < x1 && y0 < r[3] && r[1] < y1);
    c.font = "600 11px system-ui, -apple-system, 'Segoe UI', sans-serif";
    c.textBaseline = "middle";
    // Upright district labels when the ground text is too small.
    if (k * 0.5 < 9) {
      R.districts.forEach((d, i) => {
        const D = L.districts[i];
        const x = (d.x0 + d.x1) / 2, y = d.y1 - 0.3;
        const sx = V.ox + (x - y) * k, sy = V.oy + (x + y) * k * 0.5 + 12;
        const t = `${D.outskirts ? "outskirts" : D.label} · ${D.devices}${D.kev ? ` · ${D.kev} KEV` : ""}`;
        const w = c.measureText(t).width + 12;
        const r = [sx - w / 2, sy - 9, sx + w / 2, sy + 9];
        if (r[2] < 0 || r[0] > W || r[3] < 0 || r[1] > H || overlaps(...r)) return;
        placed.push(r);
        c.fillStyle = pal.label;
        c.strokeStyle = D.risk ? kit.riskColor(D.risk) : pal.labelLine;
        c.lineWidth = 1.5;
        pill(c, r[0], r[1], w, 18);
        c.fill();
        c.stroke();
        c.fillStyle = pal.labelText;
        c.fillText(t, r[0] + 6, sy);
      });
    }
    // Building labels: selection and blast radius first, then by risk.
    const cand = [];
    for (const h of hits) {
      const n = L.buildings[h.i].node;
      let pri = -1;
      if (n.id === selected) pri = 1000;
      else if (blastSet && blastSet.has(n.id)) pri = 500 + riskOf(n);
      else if (matches && matches.has(n.id)) pri = 400 + riskOf(n);
      else if (!blastSet && !matches && k >= 16) pri = riskOf(n) + (n.kev > 0 ? 5 : 0);
      else if (!blastSet && !matches && k >= 6 && (riskOf(n) >= 9 || n.kev > 0)) pri = 100 + riskOf(n);
      if (pri >= 0) cand.push({ h, pri });
    }
    cand.sort((a, b) => b.pri - a.pri);
    let count = 0;
    for (const { h, pri } of cand) {
      if (count >= 140) break;
      const r = labelAt(c, h.i, pri >= 500, placed);
      if (r) count++;
    }
    c.textBaseline = "alphabetic";
  }

  function labelText(n) {
    const r = riskOf(n);
    let t = n.name || `#${n.id}`;
    if (r) t += `  ${r.toFixed(1)}`;
    if (n.kev > 0) t += " · KEV";
    return t;
  }

  function labelAt(c, i, force, placed) {
    const k = V.k;
    const bb = R.buildings[i];
    const lb = L.buildings[i];
    const n = lb.node;
    const x = (bb.x0 + bb.x1) / 2, y = (bb.y0 + bb.y1) / 2;
    const extra = n.kev > 0 ? 0.75 : lb.exposed ? 0.55 : 0.25;
    const sx = V.ox + (x - y) * k;
    const sy = V.oy + (x + y) * k * 0.5 - (lb.top + extra) * k - (n.id === selected ? Math.max(18, k * 0.5) : 10);
    const t = labelText(n);
    const w = c.measureText(t).width + 18;
    const r = [sx - w / 2, sy - 9, sx + w / 2, sy + 9];
    if (r[2] < 0 || r[0] > W || r[3] < 0 || r[1] > H) return null;
    if (placed && !force && placed.some((q) => r[0] < q[2] && q[0] < r[2] && r[1] < q[3] && q[1] < r[3])) return null;
    if (placed) placed.push(r);
    c.fillStyle = pal.label;
    c.strokeStyle = n.id === selected ? pal.accent : pal.labelLine;
    c.lineWidth = n.id === selected ? 2 : 1;
    pill(c, r[0], r[1], w, 18);
    c.fill();
    c.stroke();
    c.fillStyle = riskOf(n) ? kit.riskColor(riskOf(n)) : pal.labelLine;
    c.fillRect(r[0] + 5, sy - 4, 7, 8);
    c.fillStyle = pal.labelText;
    c.fillText(t, r[0] + 15, sy);
    return r;
  }

  function pill(c, x, y, w, h) {
    c.beginPath();
    if (c.roundRect) c.roundRect(x, y, w, h, h / 2);
    else c.rect(x, y, w, h);
  }

  function present(t) {
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.drawImage(scene, 0, 0);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const anim = animating();
    for (const b of beacons) drawBeacon(ctx, b, anim ? t : null);
    if (hover >= 0) {
      const h = hits.find((x) => x.i === hover);
      if (h) {
        ctx.save();
        ctx.fillStyle = pal.night ? "rgba(255,255,255,0.10)" : "rgba(255,255,255,0.22)";
        poly(ctx, h.hull, HULL);
        ctx.fill();
        ctx.strokeStyle = pal.accent;
        ctx.lineWidth = 2;
        ctx.stroke();
        ctx.font = "600 11px system-ui, -apple-system, 'Segoe UI', sans-serif";
        ctx.textBaseline = "middle";
        labelAt(ctx, hover, true, null);
        ctx.restore();
      }
    }
  }

  // ---------- picking and interaction ----------

  function pick(x, y) {
    for (let j = hits.length - 1; j >= 0; j--) if (inHull(hits[j].hull, x, y)) return hits[j].i;
    return -1;
  }

  function select(id, fly) {
    if (id == null || !byId.has(id)) {
      selected = null;
      blastSet = null;
    } else {
      selected = id;
      blastSet = new Set([id, ...(byId.get(id).related || [])]);
      if (!panelOpen) {
        panelOpen = true;
        syncPanel();
      }
      if (fly) focusBuilding(L.index.get(id));
    }
    renderPanel();
    invalidate();
  }

  function showTip(i, mx, my) {
    const n = L.buildings[i].node;
    const lb = L.buildings[i];
    const r = riskOf(n);
    const top = (n.top || [])[0];
    const rows = [
      el("div", { class: "city-tip-title" }, `${kit.kindGlyph[n.kind] || "?"} ${n.name || "#" + n.id}`),
      el("div", { class: "muted" }, roleText(n)),
    ];
    if ((n.ips || []).length) rows.push(el("div", {}, n.ips.slice(0, 3).join(", ") + (n.ips.length > 3 ? ` +${n.ips.length - 3}` : "")));
    rows.push(el("div", {}, chip(r), ` Risk ${kit.riskLabel(r)}${r ? " " + r.toFixed(1) : ""}`, n.kev > 0 ? el("span", { class: "city-kev" }, `KEV ${n.kev}`) : null));
    if (top) rows.push(el("div", {}, `Top: ${top.id} (${(+top.score || 0).toFixed(1)}) ${top.package || ""}`, top.kev ? " · KEV" : ""));
    if (lb.exposed) rows.push(el("div", { class: "muted" }, `${lb.exposed} exposed service${lb.exposed === 1 ? "" : "s"}`));
    if (lb.hazard) rows.push(el("div", { class: "city-warn" }, `Same host has risk ${(+n.related_risk).toFixed(1)}`));
    if (!lb.known) rows.push(el("div", { class: "muted" }, "No package data (no agent)"));
    tip.replaceChildren(...rows);
    tip.hidden = false;
    const tw = tip.offsetWidth;
    const th = tip.offsetHeight;
    let x = mx + 16;
    let y = my + 16;
    if (x + tw > W - 8) x = mx - tw - 12;
    if (y + th > H - 8) y = my - th - 12;
    tip.style.left = Math.max(4, x) + "px";
    tip.style.top = Math.max(4, y) + "px";
  }

  function roleText(n) {
    const parent = n.parent ? byId.get(n.parent) : null;
    const kids = (n.children || []).length;
    const parts = [n.kind || "unknown"];
    if (kids) parts.push(`host of ${kids} guest${kids === 1 ? "" : "s"}`);
    if (parent) parts.push(`guest of ${parent.name}`);
    return parts.join(" · ");
  }

  function chip(r) {
    const s = el("span", { class: "city-chip" });
    s.style.background = kit.riskColor(r);
    return s;
  }

  let down = null;
  const local = (e) => {
    const r = canvas.getBoundingClientRect();
    return [e.clientX - r.left, e.clientY - r.top];
  };
  function onDown(e) {
    if (e.button !== 0) return;
    const [x, y] = local(e);
    down = { x, y, ox: V.ox, oy: V.oy, drag: false, id: e.pointerId };
    canvas.setPointerCapture(e.pointerId);
    tween = null;
  }
  function onMove(e) {
    const [x, y] = local(e);
    if (down) {
      if (!down.drag && Math.hypot(x - down.x, y - down.y) > 4) {
        down.drag = true;
        canvas.classList.add("is-drag");
        tip.hidden = true;
        hover = -1;
      }
      if (down.drag) {
        V.ox = down.ox + (x - down.x);
        V.oy = down.oy + (y - down.y);
        invalidate();
      }
      return;
    }
    const i = pick(x, y);
    if (i !== hover) {
      hover = i;
      canvas.classList.toggle("is-hover", i >= 0);
      schedule();
    }
    if (i >= 0) showTip(i, x, y);
    else tip.hidden = true;
  }
  function onUp(e) {
    if (!down) return;
    const wasDrag = down.drag;
    try { canvas.releasePointerCapture(down.id); } catch { /* already released */ }
    down = null;
    canvas.classList.remove("is-drag");
    if (wasDrag) return;
    const [x, y] = local(e);
    const i = pick(x, y);
    if (i >= 0) select(L.buildings[i].id, false);
    else if (selected != null) select(null);
  }
  function onCancel() {
    if (down) {
      try { canvas.releasePointerCapture(down.id); } catch { /* already released */ }
    }
    down = null;
    canvas.classList.remove("is-drag");
  }
  function onLeave() {
    if (down) return;
    hover = -1;
    tip.hidden = true;
    canvas.classList.remove("is-hover");
    schedule();
  }
  function onDbl(e) {
    const [x, y] = local(e);
    const i = pick(x, y);
    if (i >= 0) kit.openDevice(L.buildings[i].id);
  }
  function onWheel(e) {
    e.preventDefault();
    const [x, y] = local(e);
    const d = e.deltaMode === 1 ? e.deltaY * 16 : e.deltaY;
    const f = Math.exp(-d * 0.0015);
    const k = Math.max(MIN_K, Math.min(MAX_K, V.k * f));
    const g = k / V.k;
    V.ox = x - (x - V.ox) * g;
    V.oy = y - (y - V.oy) * g;
    V.k = k;
    tween = null;
    tip.hidden = true;
    hover = -1;
    invalidate();
  }
  function onKey(e) {
    if (e.key !== "Escape") return;
    if (!root.isConnected) return;
    if (selected != null) {
      select(null);
    } else if (query) {
      search.value = "";
      query = "";
      computeMatches();
      invalidate();
    }
  }
  function onScheme() {
    if (!userNight) {
      night = kit.dark();
      pal = palette(night);
    }
    syncNight();
    renderLegend();
    renderPanel();
    invalidate();
  }
  let userNight = false;
  try { userNight = localStorage.getItem(NIGHT_KEY) != null; } catch { /* private mode */ }
  function syncNight() {
    nightBtn.setAttribute("aria-pressed", String(night));
  }
  nightBtn.addEventListener("click", () => {
    night = !night;
    userNight = true;
    try { localStorage.setItem(NIGHT_KEY, night ? "1" : "0"); } catch { /* private mode */ }
    pal = palette(night);
    syncNight();
    renderLegend();
    invalidate();
  });
  panelBtn.addEventListener("click", () => {
    panelOpen = !panelOpen;
    syncPanel();
  });
  function syncPanel() {
    panel.hidden = !panelOpen;
    panelBtn.setAttribute("aria-pressed", String(panelOpen));
    bar.classList.toggle("with-panel", panelOpen);
  }
  search.addEventListener("input", () => {
    query = search.value;
    computeMatches();
    invalidate();
  });
  search.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && matches && matches.size) {
      const best = [...matches].map((id) => byId.get(id)).sort((a, b) => riskOf(b) - riskOf(a) || (b.kev || 0) - (a.kev || 0))[0];
      select(best.id, true);
    }
  });
  const onVisible = () => schedule();
  const onMotion = () => invalidate();

  canvas.addEventListener("pointerdown", onDown);
  canvas.addEventListener("pointermove", onMove);
  canvas.addEventListener("pointerup", onUp);
  canvas.addEventListener("pointercancel", onCancel);
  canvas.addEventListener("pointerleave", onLeave);
  canvas.addEventListener("dblclick", onDbl);
  canvas.addEventListener("wheel", onWheel, { passive: false });
  document.addEventListener("keydown", onKey);
  document.addEventListener("visibilitychange", onVisible);
  scheme.addEventListener("change", onScheme);
  reduced.addEventListener("change", onMotion);
  const ro = new ResizeObserver(() => resize());
  ro.observe(container);

  // ---------- panel ----------

  function deviceButton(n) {
    return el("button", { class: "city-row", type: "button", onclick: () => select(n.id, true) },
      chip(riskOf(n)),
      el("span", { class: "city-row-name" }, `${kit.kindGlyph[n.kind] || "?"} ${n.name || "#" + n.id}`),
      el("span", { class: "city-row-risk" }, riskOf(n) ? `${kit.riskLabel(riskOf(n))} ${riskOf(n).toFixed(1)}` : "none"),
      n.kev > 0 ? el("span", { class: "city-kev" }, "KEV") : null);
  }

  function renderPanel() {
    const nodes = G.nodes || [];
    if (selected == null) {
      const hot = nodes.filter((n) => riskOf(n) > 0).sort((a, b) => riskOf(b) - riskOf(a) || (b.kev || 0) - (a.kev || 0)).slice(0, 12);
      const noPkg = nodes.filter((n) => !(n.agent && n.components > 0)).length;
      const kev = nodes.filter((n) => n.kev > 0).length;
      putPanel(
        el("h3", {}, "Hot spots"),
        el("p", { class: "muted" }, `${nodes.length} buildings in ${L.districts.length} district${L.districts.length === 1 ? "" : "s"} · ${kev} with a KEV beacon · ${noPkg} without package data`),
        hot.length ? el("div", { class: "city-list" }, hot.map(deviceButton)) : el("p", { class: "muted" }, "No open findings."),
        el("p", { class: "muted city-small" }, "Click a building or a row to light its blast radius (its host and the other guests)."));
      return;
    }
    const n = byId.get(selected);
    const r = riskOf(n);
    const lb = L.buildings[L.index.get(n.id)];
    const vulns = [...(n.top || [])].sort((a, b) => (b.kev ? 1 : 0) - (a.kev ? 1 : 0));
    const exp = (n.services || []).filter((s) => s.exposed).sort((a, b) => (b.kev ? 1 : 0) - (a.kev ? 1 : 0) || b.vulns - a.vulns || a.port - b.port);
    const rel = (n.related || []).map((id) => byId.get(id)).filter(Boolean).sort((a, b) => riskOf(b) - riskOf(a));
    const D = L.districts[lb.district];
    putPanel(
      el("h3", {}, `${kit.kindGlyph[n.kind] || "?"} ${n.name || "#" + n.id}`),
      el("p", { class: "muted" }, roleText(n), " · ", D.outskirts ? "outskirts" : D.label),
      (n.ips || []).length ? el("p", { class: "city-mono" }, n.ips.join(", ")) : null,
      el("p", { class: "city-risk" }, chip(r), ` ${kit.riskLabel(r)}${r ? " " + r.toFixed(1) : ""}`,
        n.kev > 0 ? el("span", { class: "city-kev" }, `KEV ${n.kev}`) : null,
        el("span", { class: "muted" }, ` · ${n.findings || 0} finding${n.findings === 1 ? "" : "s"}`)),
      lb.hazard ? el("p", { class: "city-warn" }, `⚠ A device on the same host has risk ${(+n.related_risk).toFixed(1)}.`) : null,
      !lb.known ? el("p", { class: "muted" }, "No package data: install the agent to see the inside.") : null,
      el("div", { class: "city-actions" },
        el("button", { class: "city-btn primary", type: "button", onclick: () => kit.openDevice(n.id) }, "Open device"),
        el("button", { class: "city-btn", type: "button", onclick: () => focusBuilding(lb ? L.index.get(n.id) : 0) }, "Go to"),
        el("button", { class: "city-btn", type: "button", onclick: () => select(null) }, "Clear")),
      el("h4", {}, "Top vulnerabilities"),
      vulns.length ? el("ul", { class: "city-vulns" }, vulns.map((v) => el("li", {},
        el("div", {}, v.kev ? el("span", { class: "city-kev" }, "KEV") : null, el("strong", {}, ` ${v.id}`), ` ${(+v.score || 0).toFixed(1)}`, v.exposed ? el("span", { class: "city-tag" }, "exposed") : null),
        el("div", { class: "muted city-small" }, `${v.package || ""} ${v.version || ""}${v.fixed ? " → " + v.fixed : ""}`),
        v.summary ? el("div", { class: "city-small" }, v.summary) : null))) : el("p", { class: "muted" }, "None open."),
      el("h4", {}, "Exposed services"),
      exp.length ? el("ul", { class: "city-svcs" }, exp.map((s) => el("li", {},
        el("span", { class: "city-mono" }, `${s.port}/${s.proto}`), ` ${s.process || s.product || ""}`,
        s.vulns ? el("span", { class: "city-tag" }, `${s.vulns} vuln${s.vulns === 1 ? "" : "s"}`) : null,
        s.kev ? el("span", { class: "city-kev" }, "KEV") : null))) : el("p", { class: "muted" }, "None."),
      el("h4", {}, "Blast radius (same host)"),
      rel.length ? el("div", { class: "city-list" }, rel.map(deviceButton)) : el("p", { class: "muted" }, "No host or guests."));
  }

  // ---------- legend ----------

  function miniCanvas(draw) {
    const cv = el("canvas", { class: "city-mini", width: "84", height: "84" });
    const r = window.devicePixelRatio || 1;
    cv.width = 42 * r;
    cv.height = 42 * r;
    const c = cv.getContext("2d");
    c.setTransform(r, 0, 0, r, 0, 0);
    draw(c);
    return cv;
  }

  function miniBuilding(c, opt) {
    const saveV = { ...V };
    const saved = { L, R, blastSet, matches, hits, beacons, selected };
    V.k = opt.k || 13;
    V.ox = 21;
    V.oy = 30 - (opt.lift || 0);
    const node = { id: opt.id || 1, name: "", kind: "host", risk: opt.risk ?? 8, kev: opt.kev || 0, related_risk: opt.hazard ? 10 : 0, services: opt.services || [], children: [] };
    const h = opt.h ?? 1.3;
    const f = opt.f ?? 0.7;
    const lb = { id: node.id, node, role: opt.role || "solo", known: opt.known !== false, f, h, top: opt.role === "host" ? h + 0.32 : h, hazard: !!opt.hazard, exposed: (opt.services || []).filter((s) => s.exposed).length };
    const bb = { x0: -f / 2, y0: -f / 2, x1: f / 2, y1: f / 2 };
    L = { buildings: [lb], index: new Map([[node.id, 0]]) };
    R = { buildings: [bb] };
    blastSet = null;
    matches = null;
    hits = [];
    beacons = [];
    selected = null;
    drawBuilding(c, 0);
    for (const b of beacons) drawBeacon(c, b, null);
    ({ L, R, blastSet, matches, hits, beacons, selected } = saved);
    Object.assign(V, saveV);
  }

  function renderLegend() {
    const svc = (n, vuln) => Array.from({ length: n }, (_, i) => ({ exposed: true, vulns: vuln && i === 0 ? 1 : 0 }));
    const item = (icon, text) => el("div", { class: "city-legend-item" }, icon, el("span", {}, text));
    const swatches = el("div", { class: "city-swatches" }, [0, 2, 5, 8, 9.5].map((r) => el("span", { class: "city-swatch" }, chip(r), kit.riskLabel(r))));
    legendBody.replaceChildren(
      el("div", { class: "city-legend-title" }, "Facade color = risk"),
      swatches,
      item(miniCanvas((c) => {
        const save = { ...V };
        V.k = 11; V.ox = 12; V.oy = 32;
        const a = { x0: 0, y0: 0, x1: 0.5, y1: 0.5 };
        corners(V, a.x0, a.y0, a.x1, a.y1, 0, 0.6, P16);
        fillBox(c, P16, mix(pal.plateLine, "#ffffff", 0.3), mix(pal.text, pal.plate, 0.4), mix(pal.text, pal.plate, 0.1));
        V.ox = 28;
        corners(V, -0.2, -0.2, 0.7, 0.7, 0, 2, P16);
        fillBox(c, P16, mix(pal.plateLine, "#ffffff", 0.3), mix(pal.text, pal.plate, 0.4), mix(pal.text, pal.plate, 0.1));
        Object.assign(V, save);
      }), "Height = packages (log), width = services"),
      item(miniCanvas((c) => miniBuilding(c, { known: false, risk: 0, h: 0.5, f: 0.75, k: 18 })), "Wire frame = no package data (no agent)"),
      item(miniCanvas((c) => miniBuilding(c, { risk: 5, services: svc(3, true), h: 1, k: 16 })), "Antenna = exposed service (amber tip: has findings)"),
      item(miniCanvas((c) => miniBuilding(c, { risk: 9.5, kev: 1, h: 1, k: 16 })), "Red beacon = known exploited (KEV)"),
      item(miniCanvas((c) => miniBuilding(c, { risk: 2, hazard: true, h: 1, k: 16 })), "Striped base = riskier device on the same host"),
      item(miniCanvas((c) => miniBuilding(c, { risk: 7.5, role: "host", h: 1.4, f: 0.66, k: 12 })), "Tower = hypervisor; skybridges join its guests"),
      el("div", { class: "muted city-small" }, "Curb color = worst risk in the network. Lit windows = share of exposed services."));
  }

  // ---------- start ----------

  setGraph(graph);
  syncNight();
  syncPanel();
  renderPanel();
  renderLegend();
  resize();

  return {
    update(g) {
      setGraph(g);
      renderPanel();
      invalidate();
    },
    destroy() {
      destroyed = true;
      if (raf) cancelAnimationFrame(raf);
      raf = 0;
      ro.disconnect();
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("visibilitychange", onVisible);
      scheme.removeEventListener("change", onScheme);
      reduced.removeEventListener("change", onMotion);
      root.remove();
    },
  };
}
