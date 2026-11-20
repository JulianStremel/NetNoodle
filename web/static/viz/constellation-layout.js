// Constellation: data model, force layout and geometry. No DOM here, so
// Node can run it (tests, timing). The view is in constellation.js.
//
// Model: one cluster per network (/24 or /64) plus a "no address" cluster.
// A device sits in the cluster of its networks; a device without an
// address sits with its host. A device in several networks is a bridge:
// its anchor is between the clusters. Guests orbit their host.

export const KINDS = new Set(["host", "vm", "container", "network-device", "unknown"]);
export const NOADDR = "no address";
const GOLDEN = Math.PI * (3 - Math.sqrt(5));
const PAD = 7; // free space between two stars (world units)

// bucket maps a risk 0-10 to the 5 steps of kit.riskColor.
export function bucket(r) {
  if (!r) return 0;
  if (r >= 9) return 4;
  if (r >= 7) return 3;
  if (r >= 4) return 2;
  return 1;
}

// starRadius grows with the log of the component count.
export function starRadius(g) {
  const c = Math.max(0, +g.components || 0);
  return Math.min(16, 3.2 + 1.5 * Math.log2(1 + c));
}

function seedOf(id) {
  const s = String(id);
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return (h >>> 0) / 4294967296;
}

// sortVulns puts KEV first, then exposed, then the highest score.
export function sortVulns(top) {
  return [...(top || [])].sort((a, b) => (b.kev - a.kev) || (b.exposed - a.exposed) || ((b.score || 0) - (a.score || 0)));
}

// buildModel turns GET /api/graph into the layout model. With prev (an
// earlier model), positions and pins of known devices stay.
export function buildModel(graph, prev) {
  const src = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const nodes = [];
  const byId = new Map();
  for (const g of src) {
    if (!g || g.id == null || byId.has(g.id)) continue;
    const risk = Math.max(0, Math.min(10, +g.risk || 0));
    const p = prev?.byId.get(g.id);
    const n = {
      i: nodes.length, id: g.id, g, name: String(g.name ?? g.id),
      kind: KINDS.has(g.kind) ? g.kind : "unknown",
      r: starRadius(g), risk, b: bucket(risk), kev: +g.kev || 0,
      exposed: (g.services || []).filter((s) => s && s.exposed),
      parent: -1, children: [], related: [], nets: [], home: [],
      x: p && Number.isFinite(p.x) ? p.x : NaN, y: p && Number.isFinite(p.y) ? p.y : NaN,
      vx: 0, vy: 0, fx: p ? p.fx : null, fy: p ? p.fy : null,
      ax: 0, ay: 0, orbit: 0, seed: seedOf(g.id),
    };
    n.cr = n.r + (n.kev ? 6 : n.exposed.length ? 3 : 0); // room for rings and spikes
    nodes.push(n);
    byId.set(g.id, n);
  }
  for (const n of nodes) {
    const p = n.g.parent ? byId.get(n.g.parent) : null;
    if (p && p !== n) {
      n.parent = p.i;
      p.children.push(n.i);
    }
  }
  for (const n of nodes) {
    const rel = new Set();
    for (const id of n.g.related || []) {
      const m = byId.get(id);
      if (m && m !== n) rel.add(m.i);
    }
    n.related = [...rel];
  }

  const clusters = [];
  const cById = new Map();
  const cluster = (id) => {
    let c = cById.get(id);
    if (!c) {
      c = { i: clusters.length, id, risk: 0, members: [], core: [], x: NaN, y: NaN, R: 0, noaddr: id === NOADDR };
      clusters.push(c);
      cById.set(id, c);
    }
    return c;
  };
  for (const nw of graph?.networks || []) {
    if (nw && nw.id) cluster(String(nw.id)).risk = Math.max(0, Math.min(10, +nw.risk || 0));
  }
  for (const n of nodes) {
    for (const k of n.g.networks || []) {
      const c = cluster(String(k));
      if (n.nets.includes(c.i)) continue;
      n.nets.push(c.i);
      c.members.push(n.i);
      c.risk = Math.max(c.risk, n.risk);
    }
  }
  // home: the clusters that anchor a device.
  for (const n of nodes) {
    if (n.nets.length) {
      n.home = n.nets;
      continue;
    }
    let p = n.parent;
    for (let guard = 0; p >= 0 && !nodes[p].nets.length && guard < 32; guard++) p = nodes[p].parent;
    if (p >= 0 && nodes[p].nets.length) {
      n.home = [nodes[p].nets[0]];
    } else {
      const c = cluster(NOADDR);
      c.members.push(n.i);
      c.risk = Math.max(c.risk, n.risk);
      n.home = [c.i];
    }
  }
  for (const n of nodes) if (n.home.length === 1) clusters[n.home[0]].core.push(n.i);

  const links = [];
  let maxR = 4;
  for (const n of nodes) {
    maxR = Math.max(maxR, n.cr);
    if (n.parent >= 0) links.push({ s: n.parent, t: n.i });
    if (n.children.length) {
      let cr = 0;
      for (const c of n.children) cr = Math.max(cr, nodes[c].cr);
      n.orbit = n.r + 12 + Math.max(cr + 6, (n.children.length * (2 * cr + 5)) / (2 * Math.PI));
    }
  }
  const model = { nodes, byId, clusters, cById, links, maxR };
  layoutClusters(model, prev);
  placeNodes(model);
  return model;
}

// layoutClusters places the cluster disks: riskiest near the center,
// clusters with shared (bridge) devices close together, no overlap.
export function layoutClusters(model, prev) {
  const C = model.clusters;
  if (!C.length) return;
  const { nodes } = model;
  // Slots: every root device (with the guests in the same network) gets a
  // disk on a sunflower spiral. Area-weighted radii keep big systems apart.
  let sumR = 0;
  for (const c of C) {
    const local = (n) => n.home.length === 1 && n.home[0] === c.i;
    const items = c.core.filter((i) => {
      const n = nodes[i];
      return n.parent < 0 || !local(nodes[n.parent]);
    });
    const size = new Map();
    for (const i of items) {
      const n = nodes[i];
      let kr = 0;
      for (const k of n.children) if (local(nodes[k])) kr = Math.max(kr, nodes[k].cr);
      size.set(i, kr ? n.orbit + kr + 5 : n.cr + 5);
    }
    items.sort((a, b) => (size.get(b) - size.get(a)) || (nodes[b].risk - nodes[a].risk) || (a - b));
    let acc = 0, ext = 0;
    items.forEach((i, j) => {
      const n = nodes[i];
      const s = size.get(i);
      const rho = j ? 1.05 * Math.sqrt(acc) + 0.6 * s : 0;
      acc += s * s;
      const a = j * GOLDEN + c.i;
      n.slot = true;
      n.sx = Math.cos(a) * rho;
      n.sy = Math.sin(a) * rho;
      ext = Math.max(ext, rho + s);
    });
    c.R = Math.max(30, ext + 12);
    sumR += c.R;
  }
  const pairs = new Map();
  for (const n of model.nodes) {
    if (n.home.length < 2) continue;
    for (let a = 0; a < n.home.length; a++) {
      for (let b = a + 1; b < n.home.length; b++) {
        const lo = Math.min(n.home[a], n.home[b]), hi = Math.max(n.home[a], n.home[b]);
        const k = lo * C.length + hi;
        pairs.set(k, (pairs.get(k) || 0) + 1);
      }
    }
  }
  const order = C.map((c) => c.i).sort((a, b) => (C[b].risk - C[a].risk) || (C[b].R - C[a].R) || (C[a].id < C[b].id ? -1 : 1));
  const gap = 40;
  const step = (sumR / C.length + gap) * 1.25;
  let reused = 0;
  order.forEach((ci, rank) => {
    const c = C[ci];
    const pc = prev?.cById.get(c.id);
    if (pc && Number.isFinite(pc.x)) {
      c.x = pc.x;
      c.y = pc.y;
      reused++;
    } else {
      const a = rank * GOLDEN, d = step * Math.sqrt(rank) * 1.6;
      c.x = Math.cos(a) * d;
      c.y = Math.sin(a) * d;
    }
  });
  const iters = reused === C.length ? 20 : Math.max(30, Math.min(240, Math.floor(6e6 / (C.length * C.length + 1))));
  for (let it = 0; it < iters + 4; it++) {
    const alpha = it < iters ? 1 - it / iters : 0;
    if (alpha > 0) {
      for (const c of C) {
        c.x -= c.x * 0.04 * alpha;
        c.y -= c.y * 0.04 * alpha;
      }
      for (const [k, w] of pairs) {
        const a = C[Math.floor(k / C.length)], b = C[k % C.length];
        const dx = b.x - a.x, dy = b.y - a.y;
        const d = Math.hypot(dx, dy) || 1;
        const want = a.R + b.R + gap * 1.5;
        if (d <= want) continue;
        const f = ((d - want) / d) * Math.min(0.3, 0.06 * w) * alpha;
        a.x += dx * f; a.y += dy * f;
        b.x -= dx * f; b.y -= dy * f;
      }
    }
    for (let i = 0; i < C.length; i++) {
      const a = C[i];
      for (let j = i + 1; j < C.length; j++) {
        const b = C[j];
        let dx = b.x - a.x, dy = b.y - a.y;
        const min = a.R + b.R + gap;
        if (Math.abs(dx) >= min || Math.abs(dy) >= min) continue;
        let d2 = dx * dx + dy * dy;
        if (d2 >= min * min) continue;
        if (d2 < 1e-6) {
          dx = Math.cos(i + j) * 0.5;
          dy = Math.sin(i + j) * 0.5;
          d2 = 0.25;
        }
        const d = Math.sqrt(d2);
        const push = (min - d) / d;
        const wa = (b.R * b.R) / (a.R * a.R + b.R * b.R);
        a.x -= dx * push * wa; a.y -= dy * push * wa;
        b.x += dx * push * (1 - wa); b.y += dy * push * (1 - wa);
      }
    }
  }
}

// anchors sets the anchor of each device: its slot in the cluster, the
// anchor of its host (guests), or the mean of its clusters (bridges).
export function anchors(model) {
  const C = model.clusters, nodes = model.nodes;
  for (const n of nodes) {
    let x = 0, y = 0;
    for (const h of n.home) {
      x += C[h].x;
      y += C[h].y;
    }
    n.ax = x / n.home.length;
    n.ay = y / n.home.length;
    if (n.slot) {
      n.ax += n.sx;
      n.ay += n.sy;
    }
  }
  for (let pass = 0; pass < 8; pass++) {
    for (const n of nodes) {
      if (n.slot || n.parent < 0 || n.home.length !== 1) continue;
      const p = nodes[n.parent];
      if (p.home.length === 1 && p.home[0] === n.home[0]) {
        n.ax = p.ax;
        n.ay = p.ay;
      }
    }
  }
}

// placeNodes gives a start position to devices without one: roots on a
// sunflower spiral in their cluster, guests on the orbit of their host.
export function placeNodes(model) {
  anchors(model);
  const { nodes } = model;
  for (const n of nodes) {
    if (Number.isFinite(n.x)) continue;
    if (n.slot) {
      n.x = n.ax;
      n.y = n.ay;
    } else if (n.parent < 0) {
      n.x = n.ax + (n.seed - 0.5) * 20;
      n.y = n.ay + (seedOf(n.id + "y") - 0.5) * 20;
    }
  }
  for (let pass = 0; pass < 32; pass++) {
    let left = 0;
    for (const n of nodes) {
      if (Number.isFinite(n.x)) continue;
      const p = nodes[n.parent];
      if (!Number.isFinite(p.x)) {
        left++;
        continue;
      }
      const k = p.children.indexOf(n.i);
      const a = (2 * Math.PI * k) / p.children.length + p.seed * 6.283;
      n.x = p.x + Math.cos(a) * p.orbit;
      n.y = p.y + Math.sin(a) * p.orbit;
    }
    if (!left) break;
  }
  for (const n of nodes) {
    if (!Number.isFinite(n.x) || !Number.isFinite(n.y)) {
      n.x = n.ax + (n.seed - 0.5) * 30;
      n.y = n.ay + (seedOf(n.id + "y") - 0.5) * 30;
    }
  }
}

// tick runs one step of the force simulation: anchor gravity, host-guest
// springs, collision on a uniform grid (O(n)), velocity decay.
let gridHead = new Int32Array(0), gridNext = new Int32Array(0), gridCell = new Int32Array(0);
export function tick(model, alpha) {
  const { nodes, links } = model;
  const N = nodes.length;
  if (!N) return;
  for (const n of nodes) {
    const k = n.parent >= 0 ? 0.012 : n.home.length > 1 ? 0.05 : 0.035;
    n.vx += (n.ax - n.x) * k * alpha;
    n.vy += (n.ay - n.y) * k * alpha;
  }
  for (const l of links) {
    const s = nodes[l.s], t = nodes[l.t];
    const dx = t.x - s.x, dy = t.y - s.y;
    const d = Math.hypot(dx, dy) || 0.01;
    const f = ((d - s.orbit) / d) * alpha * 0.4;
    const hs = 0.12 / Math.sqrt(s.children.length);
    t.vx -= dx * f * (1 - hs); t.vy -= dy * f * (1 - hs);
    s.vx += dx * f * hs; s.vy += dy * f * hs;
  }
  // Collision grid.
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of nodes) {
    if (!Number.isFinite(n.x) || !Number.isFinite(n.y)) {
      n.x = n.ax; n.y = n.ay; n.vx = 0; n.vy = 0;
    }
    if (n.x < minX) minX = n.x;
    if (n.x > maxX) maxX = n.x;
    if (n.y < minY) minY = n.y;
    if (n.y > maxY) maxY = n.y;
  }
  let cell = 2 * model.maxR + PAD + 2;
  let gw = Math.floor((maxX - minX) / cell) + 1, gh = Math.floor((maxY - minY) / cell) + 1;
  const cap = 8 * N + 4096;
  if (gw * gh > cap) {
    cell *= Math.sqrt((gw * gh) / cap) * 1.05;
    gw = Math.floor((maxX - minX) / cell) + 1;
    gh = Math.floor((maxY - minY) / cell) + 1;
  }
  const cells = gw * gh;
  if (gridHead.length < cells) gridHead = new Int32Array(cells * 2);
  if (gridNext.length < N) {
    gridNext = new Int32Array(N * 2);
    gridCell = new Int32Array(N * 2);
  }
  gridHead.fill(-1, 0, cells);
  for (let i = 0; i < N; i++) {
    const n = nodes[i];
    const cx = Math.floor((n.x - minX) / cell), cy = Math.floor((n.y - minY) / cell);
    const c = cy * gw + cx;
    gridCell[i] = c;
    gridNext[i] = gridHead[c];
    gridHead[c] = i;
  }
  for (let i = 0; i < N; i++) {
    const a = nodes[i];
    const c = gridCell[i];
    const cx = c % gw, cy = (c - cx) / gw;
    const ax = a.x + a.vx, ay = a.y + a.vy;
    for (let y = cy - 1; y <= cy + 1; y++) {
      if (y < 0 || y >= gh) continue;
      for (let x = cx - 1; x <= cx + 1; x++) {
        if (x < 0 || x >= gw) continue;
        for (let j = gridHead[y * gw + x]; j >= 0; j = gridNext[j]) {
          if (j <= i) continue;
          const b = nodes[j];
          let dx = b.x + b.vx - ax, dy = b.y + b.vy - ay;
          const min = a.cr + b.cr + PAD;
          let d2 = dx * dx + dy * dy;
          if (d2 >= min * min) continue;
          if (d2 < 1e-9) {
            dx = Math.cos(i * 7 + j) * 0.1;
            dy = Math.sin(i * 7 + j) * 0.1;
            d2 = 0.01;
          }
          const d = Math.sqrt(d2);
          const push = ((min - d) / d) * 0.6;
          const ra = a.cr * a.cr, rb = b.cr * b.cr;
          let wa = rb / (ra + rb);
          if (a.fx != null && b.fx == null) wa = 0;
          else if (b.fx != null && a.fx == null) wa = 1;
          a.vx -= dx * push * wa; a.vy -= dy * push * wa;
          b.vx += dx * push * (1 - wa); b.vy += dy * push * (1 - wa);
        }
      }
    }
  }
  for (const n of nodes) {
    if (n.fx != null) {
      n.x = n.fx; n.y = n.fy; n.vx = 0; n.vy = 0;
      continue;
    }
    n.vx *= 0.6;
    n.vy *= 0.6;
    n.x += n.vx;
    n.y += n.vy;
  }
}

// createSim wraps tick with an alpha that cools to zero; the view stops
// stepping when sim.active() is false and re-heats it on drag.
export function createSim(model) {
  const s = { alpha: 1, alphaTarget: 0, alphaMin: 0.004, decay: 1 - Math.pow(0.004, 1 / 260), ticks: 0 };
  s.active = () => s.alpha >= s.alphaMin || s.alphaTarget > 0;
  s.step = () => {
    s.alpha += (s.alphaTarget - s.alpha) * s.decay;
    tick(model, s.alpha);
    s.ticks++;
    return s.active();
  };
  s.reheat = (a) => { s.alpha = Math.max(s.alpha, a); };
  s.run = (maxTicks, until = s.alphaMin) => {
    let k = 0;
    while (k < maxTicks && s.alpha >= until) {
      s.step();
      k++;
    }
    return k;
  };
  return s;
}

// hull returns the convex hull (monotone chain) of flat points [x,y,...].
export function hull(pts) {
  const n = pts.length / 2;
  if (n < 3) return pts.slice();
  const idx = Array.from({ length: n }, (_, i) => i);
  idx.sort((a, b) => (pts[2 * a] - pts[2 * b]) || (pts[2 * a + 1] - pts[2 * b + 1]));
  const cross = (o, a, b) => (pts[2 * a] - pts[2 * o]) * (pts[2 * b + 1] - pts[2 * o + 1]) - (pts[2 * a + 1] - pts[2 * o + 1]) * (pts[2 * b] - pts[2 * o]);
  const lo = [], up = [];
  for (const i of idx) {
    while (lo.length >= 2 && cross(lo[lo.length - 2], lo[lo.length - 1], i) <= 0) lo.pop();
    lo.push(i);
  }
  for (let k = idx.length - 1; k >= 0; k--) {
    const i = idx[k];
    while (up.length >= 2 && cross(up[up.length - 2], up[up.length - 1], i) <= 0) up.pop();
    up.push(i);
  }
  lo.pop();
  up.pop();
  const out = [];
  for (const i of lo.concat(up)) out.push(pts[2 * i], pts[2 * i + 1]);
  return out;
}

// computeHulls returns per cluster a soft outline around its devices:
// { pts, cx, cy, rad, x0, y0, x1, y1 }. Bridges do not stretch the outline.
export function computeHulls(model, pad = 16) {
  const { nodes } = model;
  const ring = [];
  for (let k = 0; k < 8; k++) ring.push(Math.cos((k * Math.PI) / 4), Math.sin((k * Math.PI) / 4));
  return model.clusters.map((c) => {
    const ids = c.core.length ? c.core : c.members;
    const pts = [];
    let cx = 0, cy = 0;
    for (const i of ids) {
      const n = nodes[i];
      cx += n.x;
      cy += n.y;
      const rr = n.r + pad;
      for (let k = 0; k < 16; k += 2) pts.push(n.x + ring[k] * rr, n.y + ring[k + 1] * rr);
    }
    if (!ids.length) return null;
    cx /= ids.length;
    cy /= ids.length;
    const h = hull(pts);
    let rad = 0, x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (let k = 0; k < h.length; k += 2) {
      rad = Math.max(rad, Math.hypot(h[k] - cx, h[k + 1] - cy));
      x0 = Math.min(x0, h[k]); x1 = Math.max(x1, h[k]);
      y0 = Math.min(y0, h[k + 1]); y1 = Math.max(y1, h[k + 1]);
    }
    return { pts: h, cx, cy, rad, x0, y0, x1, y1 };
  });
}

// pick returns the device at world point (x, y) or -1.
export function pick(model, x, y, tol) {
  let best = -1, bd = Infinity;
  for (const n of model.nodes) {
    const dx = n.x - x, dy = n.y - y;
    const rr = n.r + tol;
    const d2 = dx * dx + dy * dy;
    if (d2 <= rr * rr && d2 < bd) {
      bd = d2;
      best = n.i;
    }
  }
  return best;
}

// matchNodes returns the devices that match a search text (name, IP, MAC,
// CVE, kind, network, service), optionally KEV only; null = no filter.
export function matchNodes(model, q, kevOnly) {
  q = String(q || "").trim().toLowerCase();
  if (!q && !kevOnly) return null;
  const out = new Set();
  for (const n of model.nodes) {
    if (kevOnly && !n.kev) continue;
    if (q) {
      const g = n.g;
      const hay = [n.name, n.kind, ...(g.ips || []), ...(g.macs || []), ...(g.networks || []),
        ...(g.top || []).map((v) => `${v.id} ${v.package || ""}`),
        ...(g.services || []).map((s) => `${s.port}/${s.proto || ""} ${s.process || ""} ${s.product || ""}`)];
      if (!hay.some((h) => String(h).toLowerCase().includes(q))) continue;
    }
    out.add(n.i);
  }
  return out;
}

// worstOrder lists the devices with risk, riskiest first.
export function worstOrder(model) {
  return model.nodes.filter((n) => n.risk > 0)
    .sort((a, b) => (b.risk - a.risk) || (b.kev - a.kev) || ((+b.g.related_risk || 0) - (+a.g.related_risk || 0)) ||
      ((+b.g.findings || 0) - (+a.g.findings || 0)) || (a.name < b.name ? -1 : 1))
    .map((n) => n.i);
}

// blastSet is the device and its related devices (host, guests, siblings).
export function blastSet(model, i) {
  const n = model.nodes[i];
  if (!n) return new Set();
  return new Set([i, ...n.related, ...n.children, ...(n.parent >= 0 ? [n.parent] : [])]);
}

// blastPaths returns the filament paths a problem travels on, as lists of
// device indices: guest -> host -> other guests, host -> guests.
export function blastPaths(model, i, max = 160) {
  const { nodes } = model;
  const n = nodes[i];
  const paths = [];
  if (!n) return paths;
  if (n.parent >= 0) {
    paths.push([i, n.parent]);
    for (const s of nodes[n.parent].children) if (s !== i && paths.length < max) paths.push([i, n.parent, s]);
  }
  for (const c of n.children) if (paths.length < max) paths.push([i, c]);
  return paths;
}

// along returns the point at fraction t (0-1) of a path, with direction.
export function along(model, path, t) {
  const { nodes } = model;
  let total = 0;
  const seg = [];
  for (let k = 1; k < path.length; k++) {
    const a = nodes[path[k - 1]], b = nodes[path[k]];
    const d = Math.hypot(b.x - a.x, b.y - a.y);
    seg.push(d);
    total += d;
  }
  let want = Math.max(0, Math.min(1, t)) * total;
  for (let k = 1; k < path.length; k++) {
    const a = nodes[path[k - 1]], b = nodes[path[k]];
    const d = seg[k - 1];
    if (want <= d || k === path.length - 1) {
      const f = d ? Math.min(1, want / d) : 0;
      return { x: a.x + (b.x - a.x) * f, y: a.y + (b.y - a.y) * f, a: Math.atan2(b.y - a.y, b.x - a.x) };
    }
    want -= d;
  }
  const a = nodes[path[0]];
  return a ? { x: a.x, y: a.y, a: 0 } : { x: 0, y: 0, a: 0 };
}

// bounds returns the world box of all devices.
export function bounds(model) {
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  for (const n of model.nodes) {
    x0 = Math.min(x0, n.x - n.r); x1 = Math.max(x1, n.x + n.r);
    y0 = Math.min(y0, n.y - n.r); y1 = Math.max(y1, n.y + n.r);
  }
  if (!Number.isFinite(x0)) return { x0: -100, y0: -100, x1: 100, y1: 100 };
  return { x0, y0, x1, y1 };
}
