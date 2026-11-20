// Constellation: canvas drawing. Uses only the 2D context it gets, so a
// stub context can run it in Node. State comes from constellation.js.
import { along } from "./constellation-layout.js";

const TAU = Math.PI * 2;
const FONT = "system-ui, -apple-system, 'Segoe UI', sans-serif";

export function hexRGB(hex) {
  const h = String(hex || "").replace("#", "").trim();
  const v = h.length === 3 ? h.split("").map((c) => c + c).join("") : h.padEnd(6, "0").slice(0, 6);
  const n = parseInt(v, 16);
  return Number.isFinite(n) ? [(n >> 16) & 255, (n >> 8) & 255, n & 255] : [128, 128, 128];
}
export const rgba = (rgb, a) => `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${Math.max(0, Math.min(1, a)).toFixed(3)})`;

// palette builds the colors from the map kit (theme aware).
export function palette(kit) {
  const dark = kit.dark();
  const risk = [0, 2, 5, 8, 9.5].map((r) => kit.riskColor(r));
  const accent = kit.cssVar("--accent") || (dark ? "#6c9cf0" : "#2f6fdb");
  const fg = kit.cssVar("--fg") || (dark ? "#e6e8eb" : "#1d2129");
  const muted = kit.cssVar("--muted") || "#667085";
  const neb = risk.map(hexRGB);
  neb[0] = hexRGB(accent);
  neb[1] = hexRGB(dark ? "#4fb3bf" : "#3a8f9a");
  return {
    dark, risk, riskRGB: risk.map(hexRGB), neb, accent, fg, muted, fgRGB: hexRGB(fg),
    bg0: dark ? "#070a12" : "#eef2f8",
    bg1: dark ? "#131b30" : "#fdfdff",
    halo: dark ? "rgba(7,10,18,0.85)" : "rgba(246,248,252,0.9)",
    outline: dark ? "rgba(255,255,255,0.55)" : "rgba(20,24,33,0.6)",
    grid: dark ? "rgba(140,160,210,0.07)" : "rgba(40,60,110,0.07)",
    kev: dark ? "#ffd60a" : "#111318",
    kevRGB: hexRGB(dark ? "#ffd60a" : "#111318"),
    plain: dark ? "rgba(170,185,215,0.55)" : "rgba(80,90,110,0.5)",
  };
}

// sprites makes one soft glow image per risk step (and a white one).
export function sprites(makeCanvas, pal) {
  const out = [];
  const cols = [...pal.riskRGB, [255, 255, 255]];
  for (const c of cols) {
    const cv = makeCanvas(64, 64);
    const x = cv.getContext("2d");
    const g = x.createRadialGradient(32, 32, 0, 32, 32, 32);
    g.addColorStop(0, rgba(c, 0.95));
    g.addColorStop(0.18, rgba(c, 0.5));
    g.addColorStop(0.45, rgba(c, 0.14));
    g.addColorStop(1, rgba(c, 0));
    x.fillStyle = g;
    x.fillRect(0, 0, 64, 64);
    out.push(cv);
  }
  return out;
}

// dust makes a 512 px tile of faint background stars.
export function dust(makeCanvas, pal) {
  const cv = makeCanvas(512, 512);
  const x = cv.getContext("2d");
  let s = 1234567;
  const rnd = () => ((s = (Math.imul(s, 1103515245) + 12345) >>> 0) / 4294967296);
  const base = pal.dark ? [200, 215, 255] : [60, 75, 110];
  for (let i = 0; i < 230; i++) {
    const r = 0.3 + rnd() ** 3 * 1.2;
    x.fillStyle = rgba(base, (pal.dark ? 0.15 : 0.06) + rnd() * (pal.dark ? 0.5 : 0.12));
    x.beginPath();
    x.arc(rnd() * 512, rnd() * 512, r, 0, TAU);
    x.fill();
  }
  return cv;
}

// glyph adds the outline of a device kind to the current path.
export function glyph(ctx, kind, x, y, r) {
  switch (kind) {
    case "host": {
      const s = r * 0.86;
      ctx.moveTo(x - s, y - s);
      ctx.lineTo(x + s, y - s);
      ctx.lineTo(x + s, y + s);
      ctx.lineTo(x - s, y + s);
      ctx.closePath();
      break;
    }
    case "vm": {
      const s = r * 1.18;
      ctx.moveTo(x, y - s);
      ctx.lineTo(x + s, y);
      ctx.lineTo(x, y + s);
      ctx.lineTo(x - s, y);
      ctx.closePath();
      break;
    }
    case "container": {
      const s = r * 1.3;
      ctx.moveTo(x, y - s);
      ctx.lineTo(x + s * 0.866, y + s * 0.5);
      ctx.lineTo(x - s * 0.866, y + s * 0.5);
      ctx.closePath();
      break;
    }
    default:
      ctx.moveTo(x + r, y);
      ctx.arc(x, y, r, 0, TAU);
  }
}

// smoothPath adds a closed rounded curve through hull points.
function smoothPath(ctx, p) {
  const n = p.length / 2;
  if (n < 2) return;
  const mx = (i) => (p[2 * (i % n)] + p[2 * ((i + 1) % n)]) / 2;
  const my = (i) => (p[2 * (i % n) + 1] + p[2 * ((i + 1) % n) + 1]) / 2;
  ctx.moveTo(mx(0), my(0));
  for (let i = 1; i <= n; i++) ctx.quadraticCurveTo(p[2 * (i % n)], p[2 * (i % n) + 1], mx(i), my(i));
  ctx.closePath();
}

function filament(ctx, a, b) {
  const dx = b.x - a.x, dy = b.y - a.y;
  const mx = (a.x + b.x) / 2 - dy * 0.12, my = (a.y + b.y) / 2 + dx * 0.12;
  ctx.moveTo(a.x, a.y);
  ctx.quadraticCurveTo(mx, my, b.x, b.y);
}

// curvePoint follows the same bend as filament (for pulses).
function curvePoint(a, b, t) {
  const dx = b.x - a.x, dy = b.y - a.y;
  const mx = (a.x + b.x) / 2 - dy * 0.12, my = (a.y + b.y) / 2 + dx * 0.12;
  const u = 1 - t;
  return { x: u * u * a.x + 2 * u * t * mx + t * t * b.x, y: u * u * a.y + 2 * u * t * my + t * t * b.y };
}

// pathPoint returns a point at fraction t of a multi-hop path, on the curves.
function pathPoint(model, path, t) {
  const hops = path.length - 1;
  if (hops < 1) return along(model, path, 0);
  const f = Math.max(0, Math.min(0.9999, t)) * hops;
  const k = Math.floor(f);
  const a = model.nodes[path[k]], b = model.nodes[path[k + 1]];
  // Filaments always bend from host to guest; walk them in that direction.
  if (b.parent === a.i) return curvePoint(a, b, f - k);
  return curvePoint(b, a, 1 - (f - k));
}

// draw renders one frame. S: { W, H, dpr, cam, model, hulls, pal, sprites,
// dust, time, motion, sel, focus, match, hover, paths }. Returns
// { kevVisible } so the view can stop the pulse loop when none is visible.
export function draw(ctx, S) {
  const { W, H, dpr, cam, model, pal } = S;
  const k = cam.k;
  const nodes = model.nodes;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.globalAlpha = 1;
  ctx.globalCompositeOperation = "source-over";
  // Sky.
  const sky = ctx.createRadialGradient(W * 0.5, H * 0.42, 0, W * 0.5, H * 0.42, Math.max(W, H) * 0.8);
  sky.addColorStop(0, pal.bg1);
  sky.addColorStop(1, pal.bg0);
  ctx.fillStyle = sky;
  ctx.fillRect(0, 0, W, H);
  if (S.dust) {
    S.dustPattern ||= ctx.createPattern(S.dust, "repeat");
    if (S.dustPattern) {
      const ox = ((-cam.x * k * 0.15) % 512 + 512) % 512, oy = ((-cam.y * k * 0.15) % 512 + 512) % 512;
      ctx.save();
      ctx.translate(ox, oy);
      ctx.fillStyle = S.dustPattern;
      ctx.fillRect(-ox, -oy, W, H);
      ctx.restore();
    }
  }
  const tx = W / 2 - cam.x * k, ty = H / 2 - cam.y * k;
  ctx.setTransform(dpr * k, 0, 0, dpr * k, dpr * tx, dpr * ty);
  const vx0 = cam.x - W / 2 / k, vx1 = cam.x + W / 2 / k, vy0 = cam.y - H / 2 / k, vy1 = cam.y + H / 2 / k;
  const px = 1 / k; // one screen pixel in world units
  const vis = (x, y, m) => x + m >= vx0 && x - m <= vx1 && y + m >= vy0 && y - m <= vy1;
  const focus = S.focus;
  const dim = (i) => !!focus && !focus.has(i);

  // Graticule: rings and spokes like a star chart.
  {
    const step = 220 * Math.pow(2, Math.round(Math.log2(1 / k)));
    const far = Math.hypot(Math.max(Math.abs(vx0), Math.abs(vx1)), Math.max(Math.abs(vy0), Math.abs(vy1)));
    const near = vx0 <= 0 && vx1 >= 0 && vy0 <= 0 && vy1 >= 0 ? 0 : Math.hypot(Math.max(0, vx0, -vx1), Math.max(0, vy0, -vy1));
    ctx.strokeStyle = pal.grid;
    ctx.lineWidth = px;
    ctx.beginPath();
    let rings = 0;
    for (let r = Math.max(step, Math.floor(near / step) * step); r <= far && rings < 80; r += step, rings++) {
      ctx.moveTo(r, 0);
      ctx.arc(0, 0, r, 0, TAU);
    }
    for (let a = 0; a < 12; a++) {
      ctx.moveTo(Math.cos((a * TAU) / 12) * step, Math.sin((a * TAU) / 12) * step);
      ctx.lineTo(Math.cos((a * TAU) / 12) * far, Math.sin((a * TAU) / 12) * far);
    }
    ctx.stroke();
  }

  // Nebulae (networks).
  const hulls = S.hulls || [];
  const netFocus = focus ? new Set() : null;
  if (focus) for (const i of focus) for (const h of nodes[i].home) netFocus.add(h);
  for (const c of model.clusters) {
    const h = hulls[c.i];
    if (!h || h.x1 < vx0 || h.x0 > vx1 || h.y1 < vy0 || h.y0 > vy1) continue;
    const col = pal.neb[c.noaddr ? 0 : bucketOf(c.risk)];
    const f = netFocus && !netFocus.has(c.i) ? 0.3 : 1;
    const strong = pal.dark ? 1 : 0.8;
    ctx.beginPath();
    smoothPath(ctx, h.pts);
    const g = ctx.createRadialGradient(h.cx, h.cy, 0, h.cx, h.cy, Math.max(10, h.rad));
    g.addColorStop(0, rgba(col, 0.2 * f * strong));
    g.addColorStop(0.65, rgba(col, 0.1 * f * strong));
    g.addColorStop(1, rgba(col, 0.04 * f * strong));
    ctx.fillStyle = g;
    ctx.fill();
    if (c.noaddr) ctx.setLineDash([6 * px, 5 * px]);
    ctx.strokeStyle = rgba(col, 0.05 * f);
    ctx.lineWidth = 22 * px;
    ctx.stroke();
    ctx.strokeStyle = rgba(col, 0.08 * f);
    ctx.lineWidth = 9 * px;
    ctx.stroke();
    ctx.strokeStyle = rgba(col, 0.5 * f);
    ctx.lineWidth = 1.2 * px;
    ctx.stroke();
    ctx.setLineDash([]);
  }

  // Orbits of hosts with guests.
  ctx.lineWidth = Math.max(0.6, 0.8 * px);
  ctx.strokeStyle = rgba(pal.fgRGB, pal.dark ? 0.12 : 0.13);
  ctx.setLineDash([2 * px, 4 * px]);
  ctx.beginPath();
  for (const n of nodes) {
    if (!n.orbit || dim(n.i) || !vis(n.x, n.y, n.orbit) || n.orbit * k < 6) continue;
    ctx.moveTo(n.x + n.orbit, n.y);
    ctx.arc(n.x, n.y, n.orbit, 0, TAU);
  }
  ctx.stroke();
  ctx.setLineDash([]);

  // Filaments host -> guest, grouped by color and dim state.
  const groups = Array.from({ length: 10 }, () => []);
  for (const l of model.links) {
    const a = nodes[l.s], b = nodes[l.t];
    if (Math.max(a.x, b.x) < vx0 || Math.min(a.x, b.x) > vx1 || Math.max(a.y, b.y) < vy0 || Math.min(a.y, b.y) > vy1) continue;
    const d = dim(l.s) || dim(l.t) ? 5 : 0;
    groups[d + Math.max(a.b, b.b)].push(l);
  }
  ctx.lineCap = "round";
  for (let gi = 0; gi < 10; gi++) {
    const list = groups[gi];
    if (!list.length) continue;
    const dimmed = gi >= 5;
    ctx.strokeStyle = rgba(pal.riskRGB[gi % 5], dimmed ? 0.07 : pal.dark ? 0.55 : 0.6);
    ctx.lineWidth = Math.max(1.1, 0.8 * px);
    ctx.beginPath();
    for (const l of list) filament(ctx, nodes[l.s], nodes[l.t]);
    ctx.stroke();
  }

  // Bridges: dashed lines from a multi-network device to each nebula.
  ctx.setLineDash([4 * px, 4 * px]);
  ctx.lineWidth = Math.max(0.8, 1 * px);
  for (const n of nodes) {
    if (n.home.length < 2 || !n.nets.length) continue;
    ctx.strokeStyle = rgba(pal.fgRGB, dim(n.i) ? 0.06 : 0.35);
    ctx.beginPath();
    for (const h of n.home) {
      const hh = hulls[h];
      if (!hh) continue;
      ctx.moveTo(n.x, n.y);
      ctx.lineTo(hh.cx, hh.cy);
    }
    ctx.stroke();
  }
  ctx.setLineDash([]);

  // Visible devices.
  const visible = [];
  for (const n of nodes) if (vis(n.x, n.y, n.r * 4 + 24)) visible.push(n);

  // Glow.
  ctx.globalCompositeOperation = pal.dark ? "lighter" : "source-over";
  for (const n of visible) {
    if (!n.risk && !n.kev) continue;
    const s = n.r * (2.2 + n.risk * 0.28) * (n.i === S.sel ? 1.35 : 1);
    if (s * k < 3) continue;
    ctx.globalAlpha = (dim(n.i) ? 0.06 : 0.3 + n.risk * 0.05) * (pal.dark ? 1 : 0.55);
    ctx.drawImage(S.sprites[n.b], n.x - s, n.y - s, s * 2, s * 2);
  }
  ctx.globalAlpha = 1;
  ctx.globalCompositeOperation = "source-over";

  // Rays: one spike per exposed service. Longer for KEV or vulnerable.
  const rays = [[], [], [], [], [], [], []]; // 0-4 vulnerable by risk step, 5 KEV, 6 plain
  for (const n of visible) {
    const cnt = Math.min(16, n.exposed.length);
    if (!cnt || n.r * k < 2.5) continue;
    const base = n.seed * TAU;
    for (let j = 0; j < cnt; j++) {
      const s = n.exposed[j];
      const a = base + (j * TAU) / cnt;
      const cat = s.kev ? 5 : s.vulns > 0 ? n.b : 6;
      const len = n.r + (s.kev ? 11 : s.vulns > 0 ? 8 : 5);
      rays[cat].push(n, a, len);
    }
  }
  for (let ci = 0; ci < 7; ci++) {
    const list = rays[ci];
    if (!list.length) continue;
    for (const dm of [false, true]) {
      ctx.fillStyle = ci === 5 ? rgba(pal.kevRGB, dm ? 0.1 : 0.95) : ci === 6 ? (dm ? rgba(pal.fgRGB, 0.06) : pal.plain) : rgba(pal.riskRGB[ci], dm ? 0.08 : 0.9);
      ctx.beginPath();
      let any = false;
      for (let q = 0; q < list.length; q += 3) {
        const n = list[q];
        if (dim(n.i) !== dm) continue;
        any = true;
        const a = list[q + 1], len = list[q + 2];
        const w = Math.max(0.9, n.r * 0.22);
        const ca = Math.cos(a), sa = Math.sin(a);
        const r0 = n.r * 0.7;
        ctx.moveTo(n.x + ca * r0 - sa * w, n.y + sa * r0 + ca * w);
        ctx.lineTo(n.x + ca * len, n.y + sa * len);
        ctx.lineTo(n.x + ca * r0 + sa * w, n.y + sa * r0 - ca * w);
        ctx.closePath();
      }
      if (any) ctx.fill();
    }
  }

  // Star cores: glyph by kind, fill by risk, outline for contrast.
  for (const dm of [false, true]) {
    ctx.globalAlpha = dm ? 0.16 : 1;
    for (let b = 0; b < 5; b++) {
      ctx.fillStyle = pal.risk[b];
      ctx.beginPath();
      let any = false;
      for (const n of visible) {
        if (n.b !== b || dim(n.i) !== dm || n.kind === "unknown") continue;
        any = true;
        if (n.r * k < 1.4) {
          const s = Math.max(1.6 * px, n.r * 0.9);
          ctx.rect(n.x - s, n.y - s, s * 2, s * 2);
        } else glyph(ctx, n.kind, n.x, n.y, n.r);
      }
      if (!any) continue;
      ctx.fill();
      if (k >= 0.4) {
        ctx.strokeStyle = pal.outline;
        ctx.lineWidth = Math.max(0.5, 0.9 * px);
        ctx.stroke();
      }
    }
    // Unknown devices: hollow circles.
    ctx.beginPath();
    let anyU = false;
    for (const n of visible) {
      if (n.kind !== "unknown" || dim(n.i) !== dm) continue;
      anyU = true;
      ctx.moveTo(n.x + n.r, n.y);
      ctx.arc(n.x, n.y, Math.max(n.r, 1.6 * px), 0, TAU);
    }
    if (anyU) {
      ctx.fillStyle = pal.bg0;
      ctx.fill();
      ctx.strokeStyle = pal.plain;
      ctx.lineWidth = Math.max(1, 1.4 * px);
      ctx.stroke();
    }
  }
  ctx.globalAlpha = 1;
  // Bright center (looks like a star).
  ctx.fillStyle = pal.dark ? "rgba(255,255,255,0.85)" : "rgba(255,255,255,0.7)";
  ctx.beginPath();
  for (const n of visible) {
    if (!n.risk || dim(n.i) || n.r * k < 4 || n.kind === "unknown") continue;
    ctx.moveTo(n.x + n.r * 0.28, n.y);
    ctx.arc(n.x, n.y, n.r * 0.28, 0, TAU);
  }
  ctx.fill();

  // KEV: a double ring; the outer ring pulses when motion is allowed.
  ctx.lineWidth = Math.max(1, 1.4 * px);
  let kevVisible = 0;
  for (const n of visible) {
    if (!n.kev) continue;
    const a = dim(n.i) ? 0.12 : 1;
    if (a === 1) kevVisible++;
    ctx.strokeStyle = rgba(pal.kevRGB, 0.9 * a);
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.r + 4, 0, TAU);
    if (!S.motion) {
      ctx.moveTo(n.x + n.r + 7.5, n.y);
      ctx.arc(n.x, n.y, n.r + 7.5, 0, TAU);
    }
    ctx.stroke();
    if (S.motion && a === 1) {
      const ph = (S.time / 1700 + n.seed) % 1;
      ctx.strokeStyle = rgba(pal.kevRGB, 0.75 * (1 - ph));
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r + 5 + ph * 16, 0, TAU);
      ctx.stroke();
    }
  }

  // Pins.
  ctx.fillStyle = pal.fg;
  ctx.beginPath();
  for (const n of visible) {
    if (n.fx == null) continue;
    const r = Math.max(1.8, 2.2 * px);
    ctx.moveTo(n.x + n.r * 0.9 + r, n.y - n.r * 0.9);
    ctx.arc(n.x + n.r * 0.9, n.y - n.r * 0.9, r, 0, TAU);
  }
  ctx.fill();

  // Search matches.
  if (S.match && S.match.size <= 600) {
    ctx.strokeStyle = pal.accent;
    ctx.lineWidth = Math.max(1.2, 1.6 * px);
    ctx.beginPath();
    for (const i of S.match) {
      const n = nodes[i];
      if (!vis(n.x, n.y, 30)) continue;
      const r = n.r + (n.kev ? 10 : 6);
      ctx.moveTo(n.x + r, n.y);
      ctx.arc(n.x, n.y, r, 0, TAU);
    }
    ctx.stroke();
  }

  // Selection: blast radius rings, infection pulses, reticle.
  if (S.sel >= 0 && nodes[S.sel]) {
    const sn = nodes[S.sel];
    const scol = pal.riskRGB[sn.b];
    ctx.setLineDash([3 * px, 3 * px]);
    ctx.lineWidth = Math.max(1, 1.3 * px);
    for (const i of focus || []) {
      if (i === S.sel) continue;
      const n = nodes[i];
      ctx.strokeStyle = rgba(pal.riskRGB[n.b] && n.b ? pal.riskRGB[n.b] : pal.fgRGB, 0.85);
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r + 5, 0, TAU);
      ctx.stroke();
    }
    ctx.setLineDash([]);
    const paths = S.paths || [];
    ctx.strokeStyle = rgba(sn.b ? scol : pal.fgRGB, 0.85);
    ctx.lineWidth = Math.max(1.6, 1.8 * px);
    ctx.beginPath();
    const seen = new Set();
    for (const p of paths) {
      for (let q = 1; q < p.length; q++) {
        const a = nodes[p[q - 1]], b = nodes[p[q]];
        const key = Math.min(a.i, b.i) + ":" + Math.max(a.i, b.i);
        if (seen.has(key)) continue;
        seen.add(key);
        if (b.parent === a.i) filament(ctx, a, b);
        else filament(ctx, b, a);
      }
    }
    ctx.stroke();
    const spr = S.sprites[sn.b || 0];
    const white = S.sprites[5];
    if (S.motion) {
      ctx.globalCompositeOperation = pal.dark ? "lighter" : "source-over";
      paths.forEach((p, pi) => {
        for (const m of [0, 0.5]) {
          const t = (S.time / (900 * (p.length - 1)) + m + pi * 0.137) % 1;
          const pt = pathPoint(model, p, t);
          const s = Math.max(7, 9 * px);
          ctx.globalAlpha = 0.95;
          ctx.drawImage(spr, pt.x - s, pt.y - s, s * 2, s * 2);
          const w = Math.max(2.5, 3 * px);
          ctx.drawImage(white, pt.x - w, pt.y - w, w * 2, w * 2);
        }
      });
      ctx.globalAlpha = 1;
      ctx.globalCompositeOperation = "source-over";
    } else {
      // Static chevrons show the direction instead of moving dots.
      ctx.fillStyle = rgba(sn.b ? scol : pal.fgRGB, 0.95);
      ctx.beginPath();
      for (const p of paths) {
        for (let q = 1; q < p.length; q++) {
          const a = pathPoint(model, p, (q - 0.55) / (p.length - 1));
          const b = pathPoint(model, p, (q - 0.45) / (p.length - 1));
          const ang = Math.atan2(b.y - a.y, b.x - a.x), s = Math.max(3.5, 5 * px);
          ctx.moveTo(b.x + Math.cos(ang) * s, b.y + Math.sin(ang) * s);
          ctx.lineTo(b.x + Math.cos(ang + 2.5) * s, b.y + Math.sin(ang + 2.5) * s);
          ctx.lineTo(b.x + Math.cos(ang - 2.5) * s, b.y + Math.sin(ang - 2.5) * s);
          ctx.closePath();
        }
      }
      ctx.fill();
    }
    // Reticle.
    const rr = sn.r + 11;
    const rot = S.motion ? S.time / 2400 : 0;
    ctx.strokeStyle = pal.fg;
    ctx.lineWidth = Math.max(1.2, 1.6 * px);
    ctx.beginPath();
    for (let q = 0; q < 4; q++) {
      const a0 = rot + (q * TAU) / 4 + 0.25, a1 = a0 + TAU / 4 - 0.5;
      ctx.moveTo(sn.x + Math.cos(a0) * rr, sn.y + Math.sin(a0) * rr);
      ctx.arc(sn.x, sn.y, rr, a0, a1);
    }
    for (let q = 0; q < 4; q++) {
      const a = rot + (q * TAU) / 4;
      ctx.moveTo(sn.x + Math.cos(a) * (rr - 3), sn.y + Math.sin(a) * (rr - 3));
      ctx.lineTo(sn.x + Math.cos(a) * (rr + 5), sn.y + Math.sin(a) * (rr + 5));
    }
    ctx.stroke();
  }

  // Hover.
  if (S.hover >= 0 && nodes[S.hover]) {
    const n = nodes[S.hover];
    ctx.strokeStyle = pal.fg;
    ctx.lineWidth = Math.max(1, 1.2 * px);
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.r + 3.5, 0, TAU);
    ctx.stroke();
  }

  // Labels in screen space, highest priority first, no overlaps.
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const placed = [];
  const free = (x0, y0, x1, y1) => {
    for (const b of placed) if (x0 < b[2] && x1 > b[0] && y0 < b[3] && y1 > b[1]) return false;
    placed.push([x0, y0, x1, y1]);
    return true;
  };
  const sx = (x) => x * k + tx, sy = (y) => y * k + ty;
  ctx.lineJoin = "round";
  ctx.textBaseline = "alphabetic";
  const text = (s, x, y, color, font) => {
    ctx.font = font;
    ctx.strokeStyle = pal.halo;
    ctx.lineWidth = 3.5;
    ctx.strokeText(s, x, y);
    ctx.fillStyle = color;
    ctx.fillText(s, x, y);
  };
  // Reserve the selected and hovered devices first.
  const devLabels = [];
  const want = new Set();
  if (S.sel >= 0) want.add(S.sel);
  if (S.hover >= 0) want.add(S.hover);
  for (const i of focus || []) if (focus.size <= 60) want.add(i);
  for (const n of visible) {
    if (dim(n.i) && !want.has(n.i)) continue;
    if (want.has(n.i) || k >= 1.5 || n.risk >= 7) devLabels.push(n);
  }
  const host = S.sel >= 0 && nodes[S.sel] ? nodes[S.sel].parent : -1;
  for (const i of want) {
    const n = nodes[i], r = n.r * k + 2;
    placed.push([sx(n.x) - r, sy(n.y) - r, sx(n.x) + r, sy(n.y) + r]);
  }
  const prio = (n) => (n.i === S.sel ? 1e6 : n.i === S.hover ? 1e5 : n.i === host ? 5e4 : want.has(n.i) ? 1e4 : 0) + n.risk * 10 + n.kev;
  devLabels.sort((a, b) => prio(b) - prio(a));
  const netLabels = [];
  for (const c of model.clusters) {
    const h = hulls[c.i];
    if (!h) continue;
    const x = sx(h.cx), y = sy(h.y0) - 8;
    if (x < -100 || x > W + 100 || y < -20 || y > H + 40) continue;
    netLabels.push({ c, x, y });
  }
  netLabels.sort((a, b) => (b.c.risk - a.c.risk) || (b.c.members.length - a.c.members.length));
  const devFont = `600 12px ${FONT}`, subFont = `11px ${FONT}`;
  // Top labels first: the selected device and its blast radius.
  const drawDev = (n) => {
    ctx.font = devFont;
    const name = n.name.length > 28 ? n.name.slice(0, 27) + "…" : n.name;
    const wName = ctx.measureText(name).width;
    const sub = k >= 2.2 || want.has(n.i) ? `${n.g.ips?.[0] || n.kind}${n.risk ? " · " + n.risk.toFixed(1) : ""}${n.kev ? " · KEV" : ""}` : "";
    ctx.font = subFont;
    const w = Math.max(wName, sub ? ctx.measureText(sub).width : 0);
    const h = sub ? 27 : 16;
    const cx = sx(n.x), cy = sy(n.y), off = n.r * k + 7;
    if (cx + off > W + 40 || cx - off < -40 || cy < -20 || cy > H + 20) return;
    // Right, left, below, above the star: the first free place wins.
    const spots = [[cx + off, cy - 8], [cx - off - w, cy - 8], [cx - w / 2, cy + off - 2], [cx - w / 2, cy - off - h + 4]];
    for (const [x0, y0] of spots) {
      if (!free(x0 - 2, y0 - 2, x0 + w + 2, y0 + h - 2)) continue;
      text(name, x0, y0 + 11, pal.fg, devFont);
      if (sub) text(sub, x0, y0 + 24, n.b ? pal.risk[n.b] : pal.muted, subFont);
      return;
    }
  };
  let budget = 260;
  for (const n of devLabels) {
    if (n.i !== S.sel && n.i !== S.hover && !want.has(n.i)) break;
    drawDev(n);
    budget--;
  }
  ctx.textAlign = "center";
  const netFont = `700 12.5px ${FONT}`;
  for (const { c, x, y } of netLabels) {
    const label = c.noaddr ? "no address" : c.id;
    const sub = `${c.members.length} device${c.members.length === 1 ? "" : "s"}${c.risk ? " · max " + c.risk.toFixed(1) : ""}`;
    ctx.font = subFont;
    const ws = ctx.measureText(sub).width;
    ctx.font = netFont;
    const w = Math.max(ctx.measureText(label).width, ws);
    if (!free(x - w / 2 - 2, y - 26, x + w / 2 + 2, y + 2)) continue;
    const f = netFocus && !netFocus.has(c.i) ? 0.35 : 1;
    ctx.globalAlpha = f;
    text(label, x, y - 13, pal.fg, netFont);
    text(sub, x, y, c.risk ? pal.risk[bucketOf(c.risk)] : pal.muted, subFont);
    ctx.globalAlpha = 1;
  }
  ctx.textAlign = "left";
  for (const n of devLabels) {
    if (budget-- <= 0) break;
    if (n.i === S.sel || n.i === S.hover || want.has(n.i)) continue;
    drawDev(n);
  }
  return { kevVisible };
}

function bucketOf(r) {
  if (!r) return 0;
  if (r >= 9) return 4;
  if (r >= 7) return 3;
  if (r >= 4) return 2;
  return 1;
}

// legendIcon draws a small legend picture (24 x 24 CSS px).
export function legendIcon(ctx, type, pal, dpr = 1) {
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, 24, 24);
  ctx.lineWidth = 1.3;
  const c = 12;
  switch (type) {
    case "kev":
      ctx.fillStyle = pal.risk[4];
      ctx.beginPath(); ctx.arc(c, c, 4, 0, TAU); ctx.fill();
      ctx.strokeStyle = pal.kev;
      ctx.beginPath(); ctx.arc(c, c, 6.5, 0, TAU); ctx.moveTo(c + 9.5, c); ctx.arc(c, c, 9.5, 0, TAU); ctx.stroke();
      break;
    case "rays": {
      ctx.fillStyle = pal.risk[3];
      for (let j = 0; j < 4; j++) {
        const a = (j * TAU) / 4 + 0.4, ca = Math.cos(a), sa = Math.sin(a);
        ctx.beginPath();
        ctx.moveTo(c + ca * 3 - sa * 1.4, c + sa * 3 + ca * 1.4);
        ctx.lineTo(c + ca * 11, c + sa * 11);
        ctx.lineTo(c + ca * 3 + sa * 1.4, c + sa * 3 - ca * 1.4);
        ctx.fill();
      }
      ctx.beginPath(); ctx.arc(c, c, 4, 0, TAU); ctx.fill();
      break;
    }
    case "filament":
      ctx.strokeStyle = pal.risk[3];
      ctx.beginPath(); ctx.moveTo(5, 18); ctx.quadraticCurveTo(8, 6, 19, 6); ctx.stroke();
      ctx.fillStyle = pal.risk[3];
      ctx.beginPath(); glyph(ctx, "host", 5, 18, 3.4); ctx.fill();
      ctx.beginPath(); glyph(ctx, "vm", 19, 6, 3); ctx.fill();
      break;
    case "nebula": {
      const g = ctx.createRadialGradient(c, c, 0, c, c, 11);
      g.addColorStop(0, rgba(pal.neb[3], 0.45));
      g.addColorStop(1, rgba(pal.neb[3], 0.08));
      ctx.fillStyle = g;
      ctx.strokeStyle = rgba(pal.neb[3], 0.7);
      ctx.beginPath(); ctx.ellipse(c, c, 11, 8, 0.3, 0, TAU); ctx.fill(); ctx.stroke();
      break;
    }
    case "bridge":
      ctx.strokeStyle = pal.fg;
      ctx.setLineDash([2.5, 2.5]);
      ctx.beginPath(); ctx.moveTo(2, 20); ctx.lineTo(22, 4); ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = pal.risk[2];
      ctx.beginPath(); ctx.arc(c, c, 3.5, 0, TAU); ctx.fill();
      break;
    case "size":
      ctx.fillStyle = pal.risk[0];
      ctx.strokeStyle = pal.outline;
      ctx.beginPath(); ctx.arc(5, 15, 2.5, 0, TAU); ctx.moveTo(18 + 5.5, 12); ctx.arc(17, 12, 5.5, 0, TAU); ctx.fill(); ctx.stroke();
      break;
    default: {
      // a kind glyph
      ctx.fillStyle = pal.risk[0];
      ctx.strokeStyle = pal.outline;
      ctx.beginPath();
      if (type === "unknown") {
        ctx.arc(c, c, 5, 0, TAU);
        ctx.strokeStyle = pal.plain;
        ctx.lineWidth = 1.6;
        ctx.stroke();
      } else {
        glyph(ctx, type, c, c, 5.5);
        ctx.fill();
        ctx.stroke();
      }
    }
  }
}
