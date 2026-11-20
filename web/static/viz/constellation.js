// Constellation: the inventory as a star map. Networks are nebulae, devices
// are stars (size = components, color = risk, glyph = kind), hosts and
// guests are joined by filaments, KEV devices have a ring, exposed services
// are spikes. Select a star to see its blast radius.
import { fill } from "../map-kit.js";
import * as L from "./constellation-layout.js";
import { draw, palette, sprites, dust, legendIcon } from "./constellation-draw.js";

export const meta = {
  id: "constellation",
  title: "Constellation",
  description: "Networks are nebulae, devices are stars: size = components, color = risk, ring = KEV, spikes = exposed services. Click a star to see its blast radius.",
};

const LEGEND_KEY = "nn.map.cst.legend";
const KIND_NAME = { host: "host", vm: "VM", container: "container", "network-device": "network device", unknown: "unknown" };
const K_MIN = 0.02, K_MAX = 8;
const clampK = (k) => Math.max(K_MIN, Math.min(K_MAX, k));
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;

export function mount(container, graph, kit) {
  kit.loadCSS("viz/constellation.css");
  const { el } = kit;
  const mqDark = matchMedia("(prefers-color-scheme: dark)");
  const mqMotion = matchMedia("(prefers-reduced-motion: reduce)");
  let motion = !mqMotion.matches;
  let destroyed = false, raf = 0, dirty = false, lastDraw = 0, drawFailed = false;
  let W = 1, H = 1, dpr = 1;
  const cam = { x: 0, y: 0, k: 1 };
  let fly = null, userMoved = false;
  let model = null, sim = null, simRunning = false, hulls = [], hullsDirty = true;
  let worst = [], worstPos = -1, matchList = [], matchPos = -1;
  let sel = -1, hover = -1, focus = null, match = null, paths = [];
  let query = "", kevOnly = false, kevOnScreen = 0;
  let pal = null, spr = null, dustCv = null;
  const S = {};

  const mk = (w, h) => {
    const c = document.createElement("canvas");
    c.width = w;
    c.height = h;
    return c;
  };

  // DOM.
  const canvas = el("canvas", { class: "cst-canvas", role: "img", "aria-label": "Star map of devices and networks" });
  const ctx = canvas.getContext("2d");
  const search = el("input", { class: "cst-search", type: "search", placeholder: "Search name, IP, CVE, port", "aria-label": "Search devices" });
  const count = el("span", { class: "cst-count", "aria-live": "polite" });
  const kevBtn = el("button", { class: "cst-btn", type: "button", "aria-pressed": "false", title: "Show only devices with known exploited vulnerabilities" }, "KEV only");
  const worstBtn = el("button", { class: "cst-btn cst-hot", type: "button", title: "Fly to the riskiest device. Press again for the next one." }, "Worst first");
  const fitBtn = el("button", { class: "cst-btn", type: "button", title: "Show all devices" }, "Fit");
  const pinsBtn = el("button", { class: "cst-btn", type: "button", hidden: true, title: "Let all pinned stars move again" }, "Release pins");
  const bar = el("div", { class: "cst-bar cst-glass" }, search, count, kevBtn, worstBtn, fitBtn, pinsBtn);
  const tip = el("div", { class: "cst-tip cst-glass", hidden: true, role: "tooltip" });
  const panel = el("aside", { class: "cst-panel cst-glass", hidden: true, "aria-label": "Device details" });
  const legendBody = el("div", { class: "cst-legend-body" });
  const legendToggle = el("button", { class: "cst-legend-toggle", type: "button", "aria-expanded": "true" }, "Legend");
  const legend = el("div", { class: "cst-legend cst-glass" }, legendToggle, legendBody);
  const root = el("div", { class: "cst" }, canvas, bar, legend, panel, tip);
  container.append(root);

  let legendCollapsed = false;
  try { legendCollapsed = localStorage.getItem(LEGEND_KEY) === "0"; } catch { /* private mode */ }
  const setLegend = (c) => {
    legendCollapsed = c;
    legendBody.hidden = c;
    legendToggle.setAttribute("aria-expanded", String(!c));
  };
  setLegend(legendCollapsed);
  legendToggle.addEventListener("click", () => {
    setLegend(!legendCollapsed);
    try { localStorage.setItem(LEGEND_KEY, legendCollapsed ? "0" : "1"); } catch { /* private mode */ }
  });

  function icon(type) {
    const d = Math.min(2, devicePixelRatio || 1);
    const c = el("canvas", { class: "cst-ico", width: String(24 * d), height: String(24 * d), "aria-hidden": "true" });
    legendIcon(c.getContext("2d"), type, pal, d);
    return c;
  }
  function swatch(b) {
    const s = el("span", { class: "cst-sw", "aria-hidden": "true" });
    s.style.background = pal.risk[b];
    return s;
  }
  function fillLegend() {
    const item = (type, text) => el("div", { class: "cst-li" }, icon(type), el("span", {}, text));
    fill(legendBody,
      el("div", { class: "cst-lg-kinds" }, ["host", "vm", "container", "network-device", "unknown"].map((k) => item(k, KIND_NAME[k]))),
      el("div", { class: "cst-lg-risk" }, el("span", { class: "muted" }, "Risk"),
        [0, 1, 2, 3, 4].map((b) => el("span", { class: "cst-li" }, swatch(b), ["none", "low", "medium", "high", "critical"][b]))),
      item("size", "Size: number of components (log)"),
      item("kev", "Ring: known exploited (KEV)"),
      item("rays", "Spikes: exposed services (long = vulnerable)"),
      item("filament", "Filament: host to guest"),
      item("nebula", "Nebula: network, tint = worst risk"),
      item("bridge", "Dashed: device in several networks"),
      el("div", { class: "cst-hint muted" }, "Wheel: zoom · drag: pan · drag a star: pin · click: blast radius · double-click: open · Esc: clear"),
    );
  }

  function theme() {
    pal = palette(kit);
    spr = sprites(mk, pal);
    dustCv = dust(mk, pal);
    S.dustPattern = null;
    fillLegend();
    if (sel >= 0) renderPanel(false);
    requestDraw();
  }

  // Data.
  function load(g, keep) {
    const selId = keep && sel >= 0 ? model.nodes[sel].id : null;
    const hadIds = keep ? new Set(model.nodes.map((n) => n.id)) : null;
    model = L.buildModel(g, keep ? model : null);
    sim = L.createSim(model);
    if (keep) {
      const fresh = model.nodes.some((n) => !hadIds.has(n.id));
      sim.alpha = fresh ? 0.35 : 0.08;
      if (!motion) sim.run(400);
    } else {
      sim.run(450, motion ? 0.05 : sim.alphaMin);
    }
    simRunning = sim.active();
    hullsDirty = true;
    worst = L.worstOrder(model);
    worstPos = -1;
    updateWorstBtn();
    updatePinsBtn();
    hover = -1;
    sel = selId != null && model.byId.has(selId) ? model.byId.get(selId).i : -1;
    applyFilter();
    select(sel, false);
  }

  function applyFilter() {
    match = L.matchNodes(model, query, kevOnly);
    matchList = match ? [...match].sort((a, b) => model.nodes[b].risk - model.nodes[a].risk) : [];
    matchPos = -1;
    count.textContent = match ? `${match.size} ${match.size === 1 ? "match" : "matches"}` : plural(model.nodes.length, "device");
    focus = sel >= 0 ? L.blastSet(model, sel) : match;
    requestDraw();
  }

  function select(i, flyTo) {
    sel = i >= 0 && model.nodes[i] ? i : -1;
    focus = sel >= 0 ? L.blastSet(model, sel) : match;
    paths = sel >= 0 ? L.blastPaths(model, sel) : [];
    renderPanel(true);
    if (flyTo && sel >= 0) flyToNode(sel);
    requestDraw();
  }

  function updateWorstBtn() {
    worstBtn.disabled = !worst.length;
    worstBtn.textContent = worstPos >= 0 ? `Worst first ${worstPos + 1}/${worst.length}` : "Worst first";
  }
  function updatePinsBtn() {
    const n = model.nodes.reduce((a, m) => a + (m.fx != null ? 1 : 0), 0);
    pinsBtn.hidden = n === 0;
    pinsBtn.textContent = `Release pins (${n})`;
  }
  function heat(a) {
    sim.reheat(a);
    simRunning = true;
    requestDraw();
  }

  // Camera.
  const toWorld = (sx, sy) => ({ x: cam.x + (sx - W / 2) / cam.k, y: cam.y + (sy - H / 2) / cam.k });
  function flyTo(x, y, k) {
    userMoved = true;
    const to = { x, y, k: clampK(k) };
    if (!motion) {
      Object.assign(cam, to);
      fly = null;
      requestDraw();
      return;
    }
    fly = { from: { ...cam }, to, t0: performance.now(), dur: 800 };
    requestDraw();
  }
  function flyToNode(i) {
    const n = model.nodes[i];
    if (!n) return;
    const k = Math.max(cam.k, 1.7);
    const off = panel.hidden ? 0 : Math.min(W * 0.5, panel.offsetWidth + 20) / 2 / k;
    flyTo(n.x + off, n.y, k);
  }
  function fit(animate) {
    const b = L.bounds(model);
    for (const h of hulls) {
      if (!h) continue;
      b.x0 = Math.min(b.x0, h.x0); b.x1 = Math.max(b.x1, h.x1);
      b.y0 = Math.min(b.y0, h.y0 - 30); b.y1 = Math.max(b.y1, h.y1);
    }
    const k = clampK(Math.min(W / (b.x1 - b.x0 + 60), H / (b.y1 - b.y0 + 90), 2.2));
    const x = (b.x0 + b.x1) / 2, y = (b.y0 + b.y1) / 2;
    if (animate) flyTo(x, y, k);
    else Object.assign(cam, { x, y, k });
    requestDraw();
  }
  function zoomAt(p, f) {
    userMoved = true;
    fly = null;
    const w = toWorld(p.x, p.y);
    const k = clampK(cam.k * f);
    cam.k = k;
    cam.x = w.x - (p.x - W / 2) / k;
    cam.y = w.y - (p.y - H / 2) / k;
    requestDraw();
  }
  function stepFly(now) {
    const t = Math.min(1, (now - fly.t0) / fly.dur);
    const e = t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
    const { from, to } = fly;
    const dist = Math.hypot(to.x - from.x, to.y - from.y) * Math.min(from.k, to.k);
    const dip = Math.min(0.6, dist / (Math.max(W, H) * 2));
    cam.x = from.x + (to.x - from.x) * e;
    cam.y = from.y + (to.y - from.y) * e;
    cam.k = Math.exp(Math.log(from.k) + (Math.log(to.k) - Math.log(from.k)) * e) * (1 - dip * Math.sin(Math.PI * e));
    if (t >= 1) {
      Object.assign(cam, to);
      fly = null;
    }
  }

  // Frames: simulation, camera flight, ambient pulses (30 fps).
  function requestDraw() {
    dirty = true;
    schedule();
  }
  function schedule() {
    if (!raf && !destroyed) raf = requestAnimationFrame(frame);
  }
  function frame(now) {
    raf = 0;
    if (destroyed || !model) return;
    let busy = false;
    if (simRunning) {
      const steps = model.nodes.length > 1200 ? 1 : 2;
      for (let s = 0; s < steps && sim.active(); s++) sim.step();
      simRunning = sim.active();
      hullsDirty = true;
      busy = true;
    }
    if (fly) {
      stepFly(now);
      busy = true;
    }
    const ambient = motion && (sel >= 0 || kevOnScreen > 0);
    if (!busy && !dirty && now - lastDraw < 32) {
      if (ambient) schedule();
      return;
    }
    dirty = false;
    lastDraw = now;
    if (hullsDirty) {
      hulls = L.computeHulls(model);
      hullsDirty = false;
    }
    Object.assign(S, { W, H, dpr, cam, model, hulls, pal, sprites: spr, dust: dustCv, time: now, motion, sel, focus, match, hover, paths });
    try {
      kevOnScreen = draw(ctx, S).kevVisible;
    } catch (e) {
      if (!drawFailed) console.error("constellation", e);
      drawFailed = true;
    }
    if (busy || (motion && (sel >= 0 || kevOnScreen > 0))) schedule();
  }

  function resize() {
    W = Math.max(1, container.clientWidth);
    H = Math.max(1, container.clientHeight);
    dpr = Math.min(2, devicePixelRatio || 1);
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    if (!userMoved) {
      if (hullsDirty) {
        hulls = L.computeHulls(model);
        hullsDirty = false;
      }
      fit(false);
    }
    requestDraw();
  }

  // Tooltip and panel.
  const glyphOf = (n) => kit.kindGlyph[n.kind] || kit.kindGlyph.unknown;
  const riskText = (r) => `${kit.riskLabel(r)} ${(+r || 0).toFixed(1)}`;
  const ipText = (ips) => (ips.length > 3 ? `${ips.slice(0, 3).join(", ")} +${ips.length - 3}` : ips.join(", "));
  function relText(n) {
    const parts = [];
    if (n.parent >= 0) parts.push(`on ${model.nodes[n.parent].name}`);
    if (n.children.length) parts.push(plural(n.children.length, "guest"));
    return parts.join(" · ");
  }
  let tipFor = -1;
  function showTip(i, p) {
    const n = model.nodes[i], g = n.g;
    if (tipFor !== i) {
      tipFor = i;
      const top = L.sortVulns(g.top)[0];
      const rel = relText(n);
      fill(tip,
        el("div", { class: "cst-tip-name" }, `${glyphOf(n)} ${n.name}`),
        el("div", { class: "muted" }, KIND_NAME[n.kind], g.ips?.length ? ` · ${ipText(g.ips)}` : " · no IP"),
        el("div", { class: "cst-tip-risk" }, swatch(n.b), `Risk ${riskText(n.risk)}`,
          n.kev ? el("span", { class: "tag kev" }, `KEV ${n.kev}`) : null),
        top ? el("div", {}, el("span", { class: "mono" }, top.id), ` ${(+top.score || 0).toFixed(1)}`,
          top.package ? ` · ${top.package}` : "", top.kev ? " · KEV" : "") :
          el("div", { class: "muted" }, g.agent ? "No open findings" : "No package data"),
        el("div", { class: "muted" }, plural(n.exposed.length, "exposed service"), rel ? ` · ${rel}` : ""),
      );
    }
    tip.hidden = false;
    const tw = tip.offsetWidth, th = tip.offsetHeight;
    let x = p.x + 16, y = p.y + 16;
    if (x + tw > W - 8) x = p.x - tw - 16;
    if (y + th > H - 8) y = p.y - th - 16;
    tip.style.left = `${Math.max(8, x)}px`;
    tip.style.top = `${Math.max(8, y)}px`;
  }
  function hideTip() {
    tip.hidden = true;
    tipFor = -1;
  }

  function section(title, ...body) {
    return el("section", { class: "cst-sec" }, el("h4", {}, title), ...body);
  }
  function devButton(j, role) {
    const m = model.nodes[j];
    const g = el("span", { class: "cst-rel-glyph", "aria-hidden": "true" }, glyphOf(m));
    g.style.color = pal.risk[m.b];
    return el("li", {}, el("button", { class: "cst-rel", type: "button", title: `Go to ${m.name}`, onclick: () => select(j, true) },
      g, el("span", { class: "cst-rel-name" }, m.name),
      el("span", { class: "cst-rel-role muted" }, role),
      el("span", { class: "cst-rel-risk" }, m.risk ? m.risk.toFixed(1) : "–", m.kev ? " KEV" : "")));
  }
  function renderPanel(resetScroll) {
    if (sel < 0) {
      panel.hidden = true;
      panel.replaceChildren();
      return;
    }
    const n = model.nodes[sel], g = n.g;
    const gl = el("span", { class: "cst-p-glyph", "aria-hidden": "true" }, glyphOf(n));
    gl.style.color = pal.risk[n.b];
    const badge = el("span", { class: "cst-badge" }, riskText(n.risk));
    badge.style.background = pal.risk[n.b];
    badge.style.color = n.b === 0 ? pal.fg : pal.dark ? "#111" : "#fff";
    const blastN = L.blastSet(model, sel).size - 1;
    const rr = +g.related_risk || 0;
    const vulns = L.sortVulns(g.top);
    const svcs = n.exposed;
    const host = n.parent >= 0 ? [n.parent] : [];
    const guests = n.children;
    const siblings = n.related.filter((j) => j !== n.parent && !guests.includes(j));
    fill(panel,
      el("div", { class: "cst-p-head" }, gl, el("h3", { class: "cst-p-name" }, n.name),
        el("button", { class: "cst-x", type: "button", "aria-label": "Close", title: "Close (Esc)", onclick: () => select(-1, false) }, "×")),
      el("div", { class: "cst-p-risk" }, badge, n.kev ? el("span", { class: "tag kev" }, `KEV ${n.kev}`) : null,
        el("span", { class: "muted small" }, `${plural(+g.findings || 0, "finding")} · ${plural(+g.components || 0, "component")}`)),
      el("div", { class: "cst-p-facts muted small" }, `${KIND_NAME[n.kind]} · ${(g.ips || []).join(", ") || "no IP"}`,
        g.networks?.length ? ` · ${g.networks.join(", ")}` : ""),
      el("div", { class: "cst-p-actions" },
        el("button", { class: "cst-btn cst-primary", type: "button", onclick: () => kit.openDevice(n.id) }, "Open device"),
        el("button", { class: "cst-btn", type: "button", onclick: () => flyToNode(sel) }, "Center"),
        n.fx != null ? el("button", {
          class: "cst-btn", type: "button",
          onclick: () => { n.fx = null; n.fy = null; updatePinsBtn(); heat(0.2); renderPanel(false); },
        }, "Unpin") : null),
      el("p", { class: "cst-p-blast" }, blastN ?
        `Blast radius: ${plural(blastN, "related device")}, worst ${riskText(rr)}` :
        "Blast radius: no host or guests known"),
      section("Top vulnerabilities", vulns.length ? el("ul", { class: "cst-list" }, vulns.map((v) => el("li", {},
        el("div", { class: "cst-v-head" }, el("span", { class: "mono" }, v.id), el("span", { class: "cst-v-score" }, (+v.score || 0).toFixed(1)),
          v.kev ? el("span", { class: "tag kev" }, "KEV") : null, v.exposed ? el("span", { class: "tag exposed" }, "exposed") : null),
        el("div", { class: "small muted" }, `${v.package || ""} ${v.version || ""}`, v.fixed ? ` → ${v.fixed}` : "",
          v.epss ? ` · EPSS ${Math.round(v.epss * 100)}%` : ""),
        v.summary ? el("div", { class: "small" }, v.summary) : null))) :
        el("p", { class: "muted small" }, g.agent ? "No open findings." : "No package data (no agent)."),
        (+g.findings || 0) > vulns.length ? el("p", { class: "muted small" }, `${(+g.findings) - vulns.length} more on the device page.`) : null),
      section(`Exposed services (${svcs.length})`, svcs.length ? el("ul", { class: "cst-list" }, svcs.map((s) => el("li", { class: "cst-svc" },
        el("span", { class: "mono" }, `${s.port}/${s.proto || "?"}`), ` ${s.process || s.product || ""}`,
        s.vulns ? el("span", { class: "muted small" }, ` · ${plural(s.vulns, "vuln")}`) : null,
        s.kev ? el("span", { class: "tag kev" }, "KEV") : null))) : el("p", { class: "muted small" }, "None known.")),
      section("Related devices", blastN ? el("ul", { class: "cst-rels" },
        host.map((j) => devButton(j, "host")), guests.map((j) => devButton(j, "guest")), siblings.map((j) => devButton(j, "sibling"))) :
        el("p", { class: "muted small" }, "None.")),
    );
    panel.hidden = false;
    if (resetScroll) panel.scrollTop = 0;
  }

  // Input.
  const pointers = new Map();
  let drag = null, pinch = null;
  const local = (e) => {
    const r = canvas.getBoundingClientRect();
    return { x: e.clientX - r.left, y: e.clientY - r.top };
  };
  const hitAt = (p) => {
    const w = toWorld(p.x, p.y);
    return L.pick(model, w.x, w.y, 6 / cam.k);
  };
  canvas.addEventListener("pointerdown", (e) => {
    if (e.pointerType === "mouse" && e.button !== 0) return;
    try { canvas.setPointerCapture(e.pointerId); } catch { /* pointer gone */ }
    const p = local(e);
    pointers.set(e.pointerId, p);
    fly = null;
    hideTip();
    if (pointers.size === 2) {
      const [a, b] = [...pointers.values()];
      const m = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
      pinch = { d: Math.hypot(a.x - b.x, a.y - b.y) || 1, k: cam.k, w: toWorld(m.x, m.y) };
      if (drag?.mode === "node" && drag.moved) sim.alphaTarget = 0;
      drag = null;
      return;
    }
    const i = hitAt(p);
    drag = { mode: i >= 0 ? "node" : "pan", i, sx: p.x, sy: p.y, lx: p.x, ly: p.y, moved: false };
  });
  canvas.addEventListener("pointermove", (e) => {
    const p = local(e);
    if (pointers.has(e.pointerId)) pointers.set(e.pointerId, p);
    if (pinch && pointers.size >= 2) {
      const [a, b] = [...pointers.values()];
      const k = clampK((pinch.k * Math.hypot(a.x - b.x, a.y - b.y)) / pinch.d);
      const m = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
      cam.k = k;
      cam.x = pinch.w.x - (m.x - W / 2) / k;
      cam.y = pinch.w.y - (m.y - H / 2) / k;
      userMoved = true;
      requestDraw();
      return;
    }
    if (drag) {
      if (!drag.moved && Math.hypot(p.x - drag.sx, p.y - drag.sy) < 4) return;
      if (!drag.moved) {
        drag.moved = true;
        canvas.classList.add("cst-dragging");
        if (drag.mode === "node") {
          sim.alphaTarget = 0.25;
          heat(0.25);
        }
      }
      if (drag.mode === "pan") {
        userMoved = true;
        cam.x -= (p.x - drag.lx) / cam.k;
        cam.y -= (p.y - drag.ly) / cam.k;
      } else {
        const w = toWorld(p.x, p.y);
        const n = model.nodes[drag.i];
        n.fx = n.x = w.x;
        n.fy = n.y = w.y;
        hullsDirty = true;
      }
      drag.lx = p.x;
      drag.ly = p.y;
      requestDraw();
      return;
    }
    if (e.pointerType !== "mouse") return;
    const i = hitAt(p);
    if (i !== hover) {
      hover = i;
      canvas.classList.toggle("cst-over", i >= 0);
      requestDraw();
    }
    if (i >= 0) showTip(i, p);
    else hideTip();
  });
  const end = (e) => {
    pointers.delete(e.pointerId);
    if (pinch) {
      if (pointers.size < 2) pinch = null;
      drag = null;
      return;
    }
    if (!drag) return;
    const d = drag;
    drag = null;
    canvas.classList.remove("cst-dragging");
    if (d.mode === "node" && d.moved) {
      sim.alphaTarget = 0;
      updatePinsBtn();
      if (d.i === sel) renderPanel(false);
    } else if (!d.moved && e.type === "pointerup") {
      select(d.i, false);
    }
  };
  canvas.addEventListener("pointerup", end);
  canvas.addEventListener("pointercancel", end);
  canvas.addEventListener("pointerleave", () => {
    if (hover >= 0) {
      hover = -1;
      canvas.classList.remove("cst-over");
      requestDraw();
    }
    hideTip();
  });
  canvas.addEventListener("dblclick", (e) => {
    const p = local(e);
    const i = hitAt(p);
    if (i >= 0) kit.openDevice(model.nodes[i].id);
    else zoomAt(p, 2);
  });
  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const dy = e.deltaMode === 1 ? e.deltaY * 33 : e.deltaMode === 2 ? e.deltaY * H : e.deltaY;
    zoomAt(local(e), Math.exp(-Math.max(-300, Math.min(300, dy)) * 0.0018));
  }, { passive: false });

  search.addEventListener("input", () => {
    query = search.value;
    applyFilter();
  });
  search.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" || !matchList.length) return;
    e.preventDefault();
    matchPos = (matchPos + 1) % matchList.length;
    select(matchList[matchPos], true);
  });
  kevBtn.addEventListener("click", () => {
    kevOnly = !kevOnly;
    kevBtn.setAttribute("aria-pressed", String(kevOnly));
    applyFilter();
  });
  worstBtn.addEventListener("click", () => {
    if (!worst.length) return;
    worstPos = (worstPos + 1) % worst.length;
    updateWorstBtn();
    select(worst[worstPos], true);
  });
  fitBtn.addEventListener("click", () => fit(true));
  pinsBtn.addEventListener("click", () => {
    for (const n of model.nodes) {
      n.fx = null;
      n.fy = null;
    }
    updatePinsBtn();
    heat(0.3);
    if (sel >= 0) renderPanel(false);
  });

  const onKey = (e) => {
    if (e.key !== "Escape") return;
    if (document.activeElement === search && search.value) {
      search.value = "";
      query = "";
      applyFilter();
      return;
    }
    if (sel >= 0) {
      select(-1, false);
      return;
    }
    if (kevOnly || query) {
      kevOnly = false;
      kevBtn.setAttribute("aria-pressed", "false");
      search.value = "";
      query = "";
      applyFilter();
    }
  };
  const onTheme = () => theme();
  const onMotion = () => {
    motion = !mqMotion.matches;
    if (!motion) fly = null;
    requestDraw();
  };
  document.addEventListener("keydown", onKey);
  mqDark.addEventListener("change", onTheme);
  mqMotion.addEventListener("change", onMotion);
  const ro = new ResizeObserver(() => resize());
  ro.observe(container);

  theme();
  load(graph, false);
  resize();

  return {
    update(g) {
      if (destroyed) return;
      load(g, true);
      requestDraw();
    },
    destroy() {
      destroyed = true;
      if (raf) cancelAnimationFrame(raf);
      raf = 0;
      ro.disconnect();
      document.removeEventListener("keydown", onKey);
      mqDark.removeEventListener("change", onTheme);
      mqMotion.removeEventListener("change", onMotion);
      root.remove();
    },
  };
}
