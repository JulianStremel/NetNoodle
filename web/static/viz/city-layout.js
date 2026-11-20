// Pure layout of the City visualization (no DOM, testable in Node).
//
// World units: one cell = one building lot. The ground is the x/y plane,
// z is up. Each network (/24) is a district plate; districts are placed
// with a squarified treemap. Each top-level device and all of its
// descendants (hypervisor host with guests) form a block of s x s cells;
// blocks are packed into the district grid, riskiest first (back rows).

export const PAD = 1.2; // margin inside a district plate (label strip)
export const STREET = 0.9; // street between two district plates
export const OUTSKIRTS = "";

export const hasPackages = (n) => !!n.agent && (n.components || 0) > 0;
export const exposedCount = (n) => {
  let c = 0;
  for (const s of n.services || []) if (s.exposed) c++;
  return c;
};

// buildingShape gives the footprint side f (0-1 of a cell), the body
// height h and the total height top (with the crown of a tower).
export function buildingShape(n, role) {
  const svc = (n.services || []).length;
  let f = Math.min(0.86, 0.42 + 0.13 * Math.sqrt(svc));
  const known = hasPackages(n);
  let h = known ? 0.5 + 0.5 * Math.log1p(n.components) : 0.42;
  let top = h;
  if (role === "host") {
    f = Math.max(f, 0.64);
    h = h * 1.25 + 0.55;
    top = h + 0.32;
  } else if (role === "guest") {
    f *= 0.84;
    top = h;
  }
  return { f, h, top, known };
}

const risk = (n) => +n.risk || 0;

function cmpNode(a, b) {
  return risk(b) - risk(a) || (b.kev || 0) - (a.kev || 0) || String(a.name).localeCompare(String(b.name)) || a.id - b.id;
}

// squarify places values (sorted descending, sum = w*h) into the
// rectangle and returns one {x, y, w, h} per value.
export function squarify(values, x, y, w, h) {
  const out = new Array(values.length);
  let i = 0;
  const worst = (sum, mn, mx, side) => {
    const s2 = side * side;
    const q = sum * sum;
    return Math.max((s2 * mx) / q, q / (s2 * mn));
  };
  while (i < values.length) {
    const side = Math.max(1e-9, Math.min(w, h));
    let sum = values[i];
    let mn = sum;
    let mx = sum;
    let cur = worst(sum, mn, mx, side);
    let j = i + 1;
    while (j < values.length) {
      const v = values[j];
      const nw = worst(sum + v, Math.min(mn, v), Math.max(mx, v), side);
      if (nw > cur) break;
      sum += v;
      mn = Math.min(mn, v);
      mx = Math.max(mx, v);
      cur = nw;
      j++;
    }
    const thick = sum / side;
    if (w >= h) {
      let yy = y;
      for (let k = i; k < j; k++) {
        const hh = values[k] / thick;
        out[k] = { x, y: yy, w: thick, h: hh };
        yy += hh;
      }
      x += thick;
      w -= thick;
    } else {
      let xx = x;
      for (let k = i; k < j; k++) {
        const ww = values[k] / thick;
        out[k] = { x: xx, y, w: ww, h: thick };
        xx += ww;
      }
      y += thick;
      h -= thick;
    }
    i = j;
  }
  return out;
}

// pack places square blocks (side b.s) into a grid with cols columns,
// first fit in the given order. It returns the cell of each block, the
// number of rows and the number of columns in use.
export function pack(blocks, cols) {
  const grid = [];
  const pos = new Array(blocks.length);
  let first = 0;
  let usedCols = 0;
  let rows = 0;
  const row = (r) => {
    while (grid.length <= r) grid.push(new Uint8Array(cols));
    return grid[r];
  };
  const fits = (r, c, s) => {
    for (let y = r; y < r + s; y++) {
      const g = row(y);
      for (let x = c; x < c + s; x++) if (g[x]) return false;
    }
    return true;
  };
  for (let i = 0; i < blocks.length; i++) {
    const s = Math.min(blocks[i].s, cols);
    let done = false;
    for (let r = first; !done; r++) {
      const g = row(r);
      for (let c = 0; c + s <= cols; c++) {
        if (g[c]) continue;
        if (fits(r, c, s)) {
          for (let y = r; y < r + s; y++) row(y).fill(1, c, c + s);
          pos[i] = { c, r };
          usedCols = Math.max(usedCols, c + s);
          rows = Math.max(rows, r + s);
          done = true;
          break;
        }
      }
    }
    while (first < grid.length && grid[first].every((v) => v)) first++;
  }
  return { pos, rows, cols: usedCols };
}

function blockCells(s) {
  const cc = s <= 2 ? 0 : Math.floor((s - 1) / 2);
  const cells = [];
  for (let y = 0; y < s; y++) for (let x = 0; x < s; x++) cells.push({ x, y, d: Math.max(Math.abs(x - cc), Math.abs(y - cc)), m: Math.abs(x - cc) + Math.abs(y - cc) });
  cells.sort((a, b) => a.d - b.d || a.m - b.m || a.y - b.y || a.x - b.x);
  return cells;
}

// layoutCity computes the whole city for a graph of GET /api/graph.
export function layoutCity(graph) {
  const nodes = (graph && graph.nodes) || [];
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const kids = (n) => (n.children || []).map((c) => byId.get(c)).filter(Boolean).sort(cmpNode);

  // Blocks: a root device and all its descendants.
  const seen = new Set();
  const blocks = [];
  const makeBlock = (root) => {
    const members = [];
    const depth = new Map();
    const q = [root];
    seen.add(root.id);
    depth.set(root.id, 0);
    for (let qi = 0; qi < q.length; qi++) {
      const n = q[qi];
      members.push(n);
      for (const c of kids(n)) {
        if (seen.has(c.id)) continue;
        seen.add(c.id);
        depth.set(c.id, depth.get(n.id) + 1);
        q.push(c);
      }
    }
    let r = 0;
    let kev = 0;
    for (const m of members) {
      r = Math.max(r, risk(m));
      kev += m.kev || 0;
    }
    let net = OUTSKIRTS;
    for (const m of members) {
      if (m.networks && m.networks.length) {
        net = m.networks[0];
        break;
      }
    }
    blocks.push({ root, members, s: members.length <= 1 ? 1 : Math.ceil(Math.sqrt(members.length)), risk: r, kev, net });
  };
  for (const n of nodes) if (!n.parent || !byId.has(n.parent)) if (!seen.has(n.id)) makeBlock(n);
  for (const n of nodes) if (!seen.has(n.id)) makeBlock(n); // parent cycles

  // Districts.
  const netRisk = new Map(((graph && graph.networks) || []).map((w) => [w.id, +w.risk || 0]));
  const dmap = new Map();
  for (const b of blocks) {
    let d = dmap.get(b.net);
    if (!d) {
      d = { key: b.net, label: b.net || "outskirts", outskirts: b.net === OUTSKIRTS, blocks: [], area: 0, maxS: 1, risk: 0, kev: 0, devices: 0 };
      dmap.set(b.net, d);
    }
    d.blocks.push(b);
    d.area += b.s * b.s;
    d.maxS = Math.max(d.maxS, b.s);
    d.risk = Math.max(d.risk, b.risk);
    d.kev += b.kev;
    d.devices += b.members.length;
  }
  const districts = [...dmap.values()];
  for (const d of districts) {
    if (netRisk.has(d.key)) d.risk = Math.max(d.risk, netRisk.get(d.key));
    d.blocks.sort((a, b) => b.risk - a.risk || b.kev - a.kev || b.s - a.s || cmpNode(a.root, b.root));
  }
  districts.sort((a, b) => (a.outskirts ? 1 : 0) - (b.outskirts ? 1 : 0) || String(a.key).localeCompare(String(b.key)));

  const fixed = 2 * PAD + STREET;
  const weights = districts.map((d) => {
    const side = Math.max(d.maxS, Math.sqrt(d.area * 1.12), 3);
    return (side + fixed) * (side + fixed);
  });

  // Treemap with retries: grow a district that does not fit.
  let rects = null;
  let packs = null;
  for (let iter = 0; iter < 14 && districts.length; iter++) {
    const order = districts.map((_, i) => i).sort((a, b) => weights[b] - weights[a]);
    const total = weights.reduce((a, b) => a + b, 0);
    const L = Math.sqrt(total);
    const rs = squarify(order.map((i) => weights[i]), 0, 0, L, L);
    const cand = new Array(districts.length);
    order.forEach((di, k) => (cand[di] = rs[k]));
    const pk = new Array(districts.length);
    let ok = true;
    for (let i = 0; i < districts.length; i++) {
      const d = districts[i];
      const iw = cand[i].w - fixed;
      const ih = cand[i].h - fixed;
      const cols = Math.floor(iw + 1e-6);
      if (cols < d.maxS) {
        ok = false;
        weights[i] *= Math.max(1.12, ((d.maxS + fixed) / Math.max(0.5, cand[i].w)) ** 2 * 1.05);
        continue;
      }
      const p = pack(d.blocks, cols);
      if (p.rows > Math.floor(ih + 1e-6)) {
        ok = false;
        weights[i] *= Math.max(1.08, ((p.rows + fixed) / Math.max(0.5, cand[i].h)) * 1.04);
        continue;
      }
      pk[i] = p;
    }
    if (ok) {
      rects = cand;
      packs = pk;
      break;
    }
  }
  const treemap = !!rects;
  if (!rects) {
    // Fallback: shelf layout of near-square districts.
    packs = districts.map((d) => pack(d.blocks, Math.max(d.maxS, Math.ceil(Math.sqrt(d.area * 1.1)))));
    const dims = packs.map((p) => ({ w: p.cols + fixed, h: p.rows + fixed }));
    const target = Math.sqrt(dims.reduce((a, r) => a + r.w * r.h, 0)) * 1.15;
    rects = [];
    let x = 0;
    let y = 0;
    let rowH = 0;
    for (const r of dims) {
      if (x > 0 && x + r.w > target) {
        x = 0;
        y += rowH;
        rowH = 0;
      }
      rects.push({ x, y, w: r.w, h: r.h });
      x += r.w;
      rowH = Math.max(rowH, r.h);
    }
  }

  // Place districts, blocks and buildings.
  const outD = [];
  const buildings = [];
  const multi = [];
  const trees = [];
  const bridges = [];
  const index = new Map();
  let W = 0;
  let H = 0;
  for (let i = 0; i < districts.length; i++) {
    const d = districts[i];
    const r = rects[i];
    const p = packs[i];
    const x0 = r.x + STREET / 2;
    const y0 = r.y + STREET / 2;
    const x1 = r.x + r.w - STREET / 2;
    const y1 = r.y + r.h - STREET / 2;
    W = Math.max(W, r.x + r.w);
    H = Math.max(H, r.y + r.h);
    const gx = x0 + PAD + Math.max(0, (x1 - x0 - 2 * PAD - p.cols) / 2);
    const gy = y0 + PAD + Math.max(0, (y1 - y0 - 2 * PAD - p.rows) / 2);
    outD.push({ key: d.key, label: d.label, outskirts: d.outskirts, x0, y0, x1, y1, risk: d.risk, kev: d.kev, devices: d.devices, blocks: d.blocks.length });
    d.blocks.forEach((b, bi) => {
      const bx = gx + p.pos[bi].c;
      const by = gy + p.pos[bi].r;
      const cells = blockCells(b.s);
      const cellOf = new Map();
      const ids = new Set(b.members.map((m) => m.id));
      b.members.forEach((m, mi) => {
        const cell = cells[mi];
        let role = "solo";
        if (b.members.length > 1) role = m === b.root || (m.children || []).some((c) => ids.has(c)) ? "host" : "guest";
        const sh = buildingShape(m, role);
        const cx = bx + cell.x;
        const cy = by + cell.y;
        const off = (1 - sh.f) / 2;
        cellOf.set(m.id, cell);
        index.set(m.id, buildings.length);
        buildings.push({
          id: m.id, node: m, role, known: sh.known, f: sh.f, h: sh.h, top: sh.top,
          x0: cx + off, y0: cy + off, x1: cx + off + sh.f, y1: cy + off + sh.f,
          district: i, block: multi.length, cellX: cx, cellY: cy,
          hazard: (+m.related_risk || 0) > risk(m), exposed: exposedCount(m),
        });
      });
      if (b.members.length > 1) {
        multi.push({ x0: bx, y0: by, x1: bx + b.s, y1: by + b.s, root: b.root.id, members: b.members.length, district: i });
        for (let k = b.members.length; k < cells.length; k++) {
          const c = cells[k];
          const seed = (b.root.id * 31 + k * 17) % 7;
          trees.push({ x: bx + c.x + 0.5, y: by + c.y + 0.5, s: 0.7 + seed * 0.06, seed });
        }
        for (const m of b.members) {
          if (m === b.root || !cellOf.has(m.parent)) continue;
          const par = m.parent;
          const a = cellOf.get(par);
          const c = cellOf.get(m.id);
          bridges.push({ from: par, to: m.id, adjacent: Math.max(Math.abs(a.x - c.x), Math.abs(a.y - c.y)) <= 1 });
        }
      } else {
        // Mark solo buildings with no block.
        buildings[buildings.length - 1].block = -1;
      }
    });
  }
  for (const b of bridges) {
    const A = buildings[index.get(b.from)];
    const B = buildings[index.get(b.to)];
    b.z = Math.min(A.h, B.h) * 0.62;
  }
  return { width: W, height: H, treemap, districts: outD, buildings, blocks: multi, trees, bridges, index };
}

// rotPoint turns a ground point by rot * 90 degrees (rot 0-3); the
// rotated city is again in the positive quadrant.
export function rotPoint(L, rot, x, y) {
  const W = L.width;
  const H = L.height;
  if (rot === 1) return [H - y, x];
  if (rot === 2) return [W - x, H - y];
  if (rot === 3) return [y, W - x];
  return [x, y];
}

// unrotPoint is the inverse of rotPoint.
export function unrotPoint(L, rot, x, y) {
  const W = L.width;
  const H = L.height;
  if (rot === 1) return [y, H - x];
  if (rot === 2) return [W - x, H - y];
  if (rot === 3) return [W - y, x];
  return [x, y];
}

// rotateLayout gives the rotated boxes and the back-to-front draw order
// of buildings and trees (painter's algorithm). An adjacent skybridge is
// drawn just before the first of its two buildings, so that both
// buildings cover its ends.
export function rotateLayout(L, rot) {
  const box = (o) => {
    const [a, b] = rotPoint(L, rot, o.x0, o.y0);
    const [c, d] = rotPoint(L, rot, o.x1, o.y1);
    return { x0: Math.min(a, c), y0: Math.min(b, d), x1: Math.max(a, c), y1: Math.max(b, d) };
  };
  const buildings = L.buildings.map(box);
  const districts = L.districts.map(box);
  const blocks = L.blocks.map(box);
  const trees = L.trees.map((t) => {
    const [x, y] = rotPoint(L, rot, t.x, t.y);
    return { x, y };
  });
  const order = [];
  buildings.forEach((b, i) => order.push({ t: 0, i, key: b.x0 + b.x1 + b.y0 + b.y1 }));
  trees.forEach((t, i) => order.push({ t: 1, i, key: 2 * (t.x + t.y) }));
  order.sort((a, b) => a.key - b.key || a.t - b.t || a.i - b.i);
  const pos = new Int32Array(buildings.length);
  order.forEach((it, p) => {
    if (it.t === 0) pos[it.i] = p;
  });
  const before = new Map();
  for (const br of L.bridges) {
    if (!br.adjacent) continue;
    const a = L.index.get(br.from);
    const b = L.index.get(br.to);
    const first = pos[a] < pos[b] ? a : b;
    if (!before.has(first)) before.set(first, []);
    before.get(first).push(br);
  }
  const w = rot % 2 ? L.height : L.width;
  const h = rot % 2 ? L.width : L.height;
  return { rot, buildings, districts, blocks, trees, order, before, w, h };
}
