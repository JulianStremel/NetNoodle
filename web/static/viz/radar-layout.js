// Pure layout and data helpers for the Radar visualization (radar.js).
// No DOM access: the functions run in Node for tests.
//
// World coordinates: the radar is the unit disk. Angle 0 is north and
// angles grow clockwise (like a radar screen): x = sin(a) * r, y = -cos(a) * r.

export const KINDS = ["host", "vm", "container", "network-device", "unknown"];
export const NONET = "no IP";
const TAU = Math.PI * 2;

// Risk bands from the center to the rim. Higher risk = closer to the center.
// lo/hi are radii; top/bottom are the risk range that maps onto them.
export const BANDS = [
  { key: "critical", label: "critical ≥9", top: 10, bottom: 9, lo: 0.06, hi: 0.27 },
  { key: "high", label: "high ≥7", top: 9, bottom: 7, lo: 0.27, hi: 0.49 },
  { key: "medium", label: "medium ≥4", top: 7, bottom: 4, lo: 0.49, hi: 0.70 },
  { key: "low", label: "low", top: 4, bottom: 0, lo: 0.70, hi: 0.86 },
  { key: "clean", label: "clean", top: 0, bottom: 0, lo: 0.86, hi: 0.985 },
];

export function bandOf(risk) {
  if (!risk) return 4;
  if (risk >= 9) return 0;
  if (risk >= 7) return 1;
  if (risk >= 4) return 2;
  return 3;
}

export const kindOf = (n) => (KINDS.includes(n.kind) ? n.kind : "unknown");

// riskRadius maps a risk 0-10 to a radius (before jitter and nudges).
export function riskRadius(risk) {
  const b = BANDS[bandOf(risk)];
  if (!risk) return (b.lo + b.hi) / 2;
  const t = Math.min(1, Math.max(0, (risk - b.bottom) / (b.top - b.bottom)));
  return b.hi - t * (b.hi - b.lo);
}

// nodeScale shrinks blips when there are many devices.
export const nodeScale = (count) => Math.min(1, Math.max(0.42, Math.sqrt(500 / Math.max(1, count))));

// blipPx is the blip radius in pixels at the nominal radar radius (NOMINAL_R)
// and zoom 1. Size grows with the number of open findings.
export const NOMINAL_R = 320;
export function blipPx(n, scale = 1) {
  const base = n.findings > 0 ? Math.min(13, 3.6 + 1.9 * Math.sqrt(n.findings)) : 3;
  return base * (n.parent ? 0.85 : 1) * scale;
}

// hash01 is a stable pseudo-random number in [0, 1) for an ID.
export function hash01(id, salt = 0) {
  let h = Math.imul((Number(id) | 0) ^ salt, 2654435761) >>> 0;
  h ^= h >>> 15;
  h = Math.imul(h, 2246822519) >>> 0;
  h ^= h >>> 13;
  return (h >>> 0) / 4294967296;
}

// rankCompare orders devices by urgency: risk, KEV, exposed findings,
// findings, EPSS, then name.
export function rankCompare(a, b) {
  return (b.risk - a.risk) || (b.kev - a.kev) || (b.exposed - a.exposed) ||
    (b.findings - a.findings) || ((b.max_epss || 0) - (a.max_epss || 0)) ||
    natCompare(String(a.name), String(b.name)) || (a.id - b.id);
}

// natCompare compares strings with embedded numbers naturally ("ws-2" < "ws-10").
// Plain code: Intl.Collator is slow to start in some runtimes.
export function natCompare(a, b) {
  const ra = a.toLowerCase().match(/\d+|\D+/g) || [];
  const rb = b.toLowerCase().match(/\d+|\D+/g) || [];
  for (let i = 0; i < Math.min(ra.length, rb.length); i++) {
    const x = ra[i];
    const y = rb[i];
    if (x === y) continue;
    const nx = x.charCodeAt(0) <= 57 && x.charCodeAt(0) >= 48;
    const ny = y.charCodeAt(0) <= 57 && y.charCodeAt(0) >= 48;
    if (nx && ny) return Number(x) - Number(y) || x.length - y.length;
    return x < y ? -1 : 1;
  }
  return ra.length - rb.length || (a < b ? -1 : a > b ? 1 : 0);
}

export const rank = (nodes) => [...nodes].sort(rankCompare);

// searchText is the lower-case text a query matches: name, IPs, MACs,
// networks, kind, CVE IDs and packages of the top findings, processes.
const textCache = new WeakMap();
export function searchText(n) {
  let s = textCache.get(n);
  if (s === undefined) {
    s = [n.name, n.kind, ...(n.ips || []), ...(n.macs || []), ...(n.networks || []),
      ...(n.top || []).flatMap((v) => [v.id, v.package]),
      ...(n.services || []).map((x) => x.process || x.product || "")].join(" ").toLowerCase();
    textCache.set(n, s);
  }
  return s;
}

// matches is true when every word of the query is in the search text.
export function matches(n, q) {
  if (!q) return true;
  const t = searchText(n);
  return q.toLowerCase().split(/\s+/).filter(Boolean).every((w) => t.includes(w));
}

// passes applies the chip filters (KEV only, exposed only, kinds).
export function passes(n, f) {
  if (f.kev && !(n.kev > 0)) return false;
  if (f.exposed && !(n.exposed > 0)) return false;
  if (f.kinds && !f.kinds.has(kindOf(n))) return false;
  return true;
}

// relation names the link between device n and a related device r.
export function relation(n, r) {
  if (n.parent && r.id === n.parent) return "host";
  if (r.parent && r.parent === n.id) return "guest";
  return "same host";
}

function clampAngle(a, a0, a1) {
  if (a >= a0 && a <= a1) return a;
  const d0 = Math.min(Math.abs(a - a0), TAU - Math.abs(a - a0));
  const d1 = Math.min(Math.abs(a - a1), TAU - Math.abs(a - a1));
  return d0 <= d1 ? a0 : a1;
}

const norm = (a) => ((a % TAU) + TAU) % TAU;

// layout places every device of the graph (or of one network) on the radar.
// opts.network: show only the devices of this network (one full-circle sector).
// Returns { blips, byId, sectors, scale, count, gap }.
export function layout(graph, opts = {}) {
  const net = opts.network || "";
  const all = graph.nodes || [];
  const byNode = new Map(all.map((n) => [n.id, n]));
  const nodes = net
    ? all.filter((n) => (net === NONET ? (n.networks || []).length === 0 : (n.networks || []).includes(net)))
    : all;
  const inSet = new Set(nodes.map((n) => n.id));
  const count = nodes.length;
  const scale = nodeScale(count);

  // Group: a host with its guests (kept on one spoke) or a single device.
  const rootOf = (n) => (n.parent && inSet.has(n.parent) ? n.parent : n.id);
  const sectorKey = (n) => {
    if (net) return net;
    const r = byNode.get(rootOf(n));
    return (r.networks && r.networks[0]) || NONET;
  };
  const sectorMap = new Map();
  for (const n of nodes) {
    const k = sectorKey(n);
    let s = sectorMap.get(k);
    if (!s) {
      s = { id: k, groups: new Map(), count: 0, risk: 0, kev: 0 };
      sectorMap.set(k, s);
    }
    s.count++;
    s.risk = Math.max(s.risk, n.risk || 0);
    if (n.kev > 0) s.kev++;
    const g = rootOf(n);
    if (!s.groups.has(g)) s.groups.set(g, []);
    s.groups.get(g).push(n);
  }
  // Sector order: the order of graph.networks, then the rest by name.
  const netOrder = new Map((graph.networks || []).map((x, i) => [x.id, i]));
  const sectors = [...sectorMap.values()].sort((a, b) => {
    const ia = netOrder.has(a.id) ? netOrder.get(a.id) : 1e9;
    const ib = netOrder.has(b.id) ? netOrder.get(b.id) : 1e9;
    return ia - ib || (a.id === NONET) - (b.id === NONET) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  });

  const S = sectors.length;
  const gap = S > 1 ? Math.min(0.05, (TAU * 0.12) / S) : 0;
  const minShare = Math.max(1, count * 0.035);
  const W = sectors.reduce((t, s) => t + Math.max(s.count, minShare), 0) || 1;
  const avail = TAU - S * gap;
  const blips = [];
  let cursor = 0;
  for (const [si, s] of sectors.entries()) {
    s.index = si;
    s.a0 = cursor + gap / 2;
    s.a1 = s.a0 + (avail * Math.max(s.count, minShare)) / W;
    cursor = s.a1 + gap / 2;
    const groups = [...s.groups.entries()].map(([root, members]) => ({
      root, members, name: String((byNode.get(root) || members[0]).name || ""),
    })).sort((a, b) => natCompare(a.name, b.name) || a.root - b.root);
    const gw = (g) => 1 + 0.6 * (g.members.length - 1);
    const GW = groups.reduce((t, g) => t + gw(g), 0) || 1;
    const span = s.a1 - s.a0;
    const pad = S > 1 ? Math.min(0.02, span * 0.04) : 0;
    let ga = s.a0 + pad;
    const inner = span - 2 * pad;
    for (const g of groups) {
      const w = (inner * gw(g)) / GW;
      const mid = ga + w / 2;
      const guests = g.members.filter((m) => m.id !== g.root)
        .sort((a, b) => natCompare(String(a.name), String(b.name)));
      for (const m of g.members) {
        let a = mid;
        const gi = guests.indexOf(m);
        if (gi >= 0) a = ga + (w * (gi + 1)) / (guests.length + 1);
        const bi = bandOf(m.risk);
        const b = BANDS[bi];
        let r = riskRadius(m.risk);
        if (bi === 4) {
          r = b.lo + 0.015 + hash01(m.id, 7) * (b.hi - b.lo - 0.03);
        } else {
          r += (hash01(m.id, 3) - 0.5) * 0.024;
          if (m.kev > 0) r -= 0.02;
          if (m.exposed > 0) r -= 0.015;
        }
        r = Math.min(b.hi - 0.004, Math.max(b.lo + 0.004, r));
        blips.push({
          id: m.id, n: m, a, r, x: 0, y: 0,
          px: blipPx(m, scale), wr: blipPx(m, scale) / NOMINAL_R,
          band: bi, sector: s.id, si: s.index, root: g.root, guest: m.id !== g.root,
        });
      }
      ga += w;
    }
  }
  for (const b of blips) {
    b.x = Math.sin(b.a) * b.r;
    b.y = -Math.cos(b.a) * b.r;
  }
  relax(blips, sectors, S);

  const byId = new Map(blips.map((b) => [b.id, b]));
  return {
    blips, byId, count, scale, gap,
    sectors: sectors.map((s) => ({ id: s.id, a0: s.a0, a1: s.a1, count: s.count, risk: s.risk, kev: s.kev })),
  };
}

// relax pushes overlapping blips apart. Blips stay in their risk band and
// their sector. A uniform grid keeps it near O(n).
function relax(blips, sectors, S, iterations = 8) {
  if (blips.length < 2) return;
  let maxWr = 0;
  for (const b of blips) maxWr = Math.max(maxWr, b.wr);
  const cell = Math.max(0.01, maxWr * 2 + 0.006);
  const sec = sectors.map((s) => [s.a0, s.a1]);
  for (let it = 0; it < iterations; it++) {
    const grid = new Map();
    for (let i = 0; i < blips.length; i++) {
      const b = blips[i];
      const key = (Math.floor(b.x / cell) + 512) * 4096 + (Math.floor(b.y / cell) + 512);
      let c = grid.get(key);
      if (!c) grid.set(key, (c = []));
      c.push(i);
    }
    let moved = 0;
    for (let i = 0; i < blips.length; i++) {
      const p = blips[i];
      const cx = Math.floor(p.x / cell) + 512;
      const cy = Math.floor(p.y / cell) + 512;
      for (let dx = -1; dx <= 1; dx++) {
        for (let dy = -1; dy <= 1; dy++) {
          const c = grid.get((cx + dx) * 4096 + (cy + dy));
          if (!c) continue;
          for (const j of c) {
            if (j <= i) continue;
            const q = blips[j];
            let ex = q.x - p.x;
            let ey = q.y - p.y;
            const d = Math.hypot(ex, ey);
            const min = p.wr + q.wr + 0.004;
            if (d >= min) continue;
            if (d < 1e-9) {
              const ang = hash01(p.id + q.id, it) * TAU;
              ex = Math.cos(ang);
              ey = Math.sin(ang);
            } else {
              ex /= d;
              ey /= d;
            }
            const push = (min - d) * 0.45;
            p.x -= ex * push;
            p.y -= ey * push;
            q.x += ex * push;
            q.y += ey * push;
            moved++;
          }
        }
      }
    }
    // Constrain to band and sector.
    for (const b of blips) {
      const band = BANDS[b.band];
      let r = Math.hypot(b.x, b.y);
      let a = r > 1e-9 ? norm(Math.atan2(b.x, -b.y)) : b.a;
      r = Math.min(band.hi - 0.004, Math.max(band.lo + 0.004, r));
      if (S > 1) {
        const [a0, a1] = sec[b.si];
        a = clampAngle(a, a0 + 0.004, a1 - 0.004);
      }
      b.r = r;
      b.a = a;
      b.x = Math.sin(a) * r;
      b.y = -Math.cos(a) * r;
    }
    if (moved === 0) break;
  }
}
