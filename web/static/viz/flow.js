import { fill } from "../map-kit.js";
import { STAGES, buildFlow, layoutFlow, blastIds } from "./flow-layout.js";

export const meta = {
  id: "flow",
  title: "Flow",
  description: "Follow findings through packages and listeners to devices, hypervisors and networks.",
};

const NS = "http://www.w3.org/2000/svg";
const finite = (v) => Number.isFinite(Number(v)) ? Number(v) : 0;
const intersects = (a, b) => {
  if (!a || !b) return false;
  const [small, big] = a.size < b.size ? [a, b] : [b, a];
  for (const value of small) if (big.has(value)) return true;
  return false;
};
const svgEl = (tag, attrs = {}, content) => {
  const node = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  if (content !== undefined) node.textContent = content;
  return node;
};
const clip = (s, count) => String(s).length > count ? String(s).slice(0, count - 1) + "…" : String(s);

export function mount(container, graph, kit) {
  kit.loadCSS("viz/flow.css");
  const el = kit.el;
  const controller = new AbortController();
  const listen = (target, event, handler, options = {}) => target.addEventListener(event, handler, { ...options, signal: controller.signal });
  let data = graph, model, selection = null, hovered = null, frame = 0, destroyed = false;
  let topN = 15, grouping = "host", zoom = 1, autoFit = true, kevOnly = false, pan = null;
  let suppressClick = false, panelLimit = 50;
  let itemLookup = new Map(), visuals = [];
  const root = el("section", { class: "nn-flow", "aria-label": "Vulnerability dependency flow" });
  const search = el("input", { type: "search", placeholder: "Find device, IP, package or CVE", "aria-label": "Filter Flow by device name, IP, package or CVE" });
  const range = el("input", { type: "range", min: 10, max: 200, step: 1, value: topN, "aria-label": "Number of top vulnerabilities" });
  const rangeValue = el("output", {}, String(topN));
  const groupSelect = el("select", { "aria-label": "Device grouping" },
    el("option", { value: "host" }, "Group by host"), el("option", { value: "network" }, "Group by network"));
  const kevInput = el("input", { type: "checkbox" });
  const status = el("div", { class: "flow-status", role: "status", "aria-live": "polite" });
  const viewport = el("div", { class: "flow-viewport", tabindex: 0, "aria-label": "Flow diagram. Scroll to explore. Drag background to pan. Control plus wheel to zoom." });
  const paper = el("div", { class: "flow-paper" });
  const inspector = el("aside", { class: "flow-inspector", "aria-label": "Flow selection and related devices" });
  const tooltip = el("div", { class: "flow-tip", role: "tooltip", hidden: true });
  const zoomLabel = el("span", {}, "100%");
  const button = (label, action, title) => el("button", { type: "button", class: "flow-button", "data-flow-action": action, title: title || label }, label);
  const chart = el("div", { class: "flow-chart" }, status, viewport);
  viewport.append(paper);
  root.append(
    el("div", { class: "flow-tools" },
      el("div", { class: "flow-brand" }, el("span", { class: "flow-eyebrow" }, "Dependency map"), el("strong", {}, "Flow")),
      el("div", { class: "flow-search" }, search),
      el("label", { class: "flow-range" }, el("span", {}, "Top CVEs"), rangeValue, range),
      groupSelect, el("label", { class: "flow-check" }, kevInput, "KEV devices"),
      button("−", "zoom-out", "Zoom out"), zoomLabel, button("+", "zoom-in", "Zoom in"), button("Fit", "fit", "Fit diagram width")),
    el("div", { class: "flow-body" }, chart, inspector),
    el("div", { class: "flow-legend" },
      el("span", { class: "flow-key" }, el("i", { class: "flow-swatch" }), "Width = unique devices per ribbon"),
      el("span", { class: "flow-key" }, el("i", { class: "flow-dash" }), "! KEV · known exploited"),
      el("span", {}, "Risk: ", el("b", {}, "critical ≥9 · high ≥7 · medium ≥4 · low >0")),
      el("span", {}, "Dashed blue = related host / guests"),
      el("span", {}, "Top 5 findings per device · CVEs ranked by risk × reach"),
      el("span", {}, "Exposed = non-loopback listener · ribbons are not additive")),
    tooltip);
  container.append(root);

  function highest(ids) {
    let result = null;
    for (const id of ids || []) {
      const n = model.index.get(id);
      if (n && (!result || finite(n.risk) > finite(result.risk))) result = n;
    }
    return result;
  }

  function describeRisk(r) { return `${kit.riskLabel(r)} ${finite(r).toFixed(1)}`; }

  function deviceRow(n, trace = true) {
    const score = el("span", { class: "flow-device-risk" }, `${n.kev ? "! " : ""}${finite(n.risk).toFixed(1)}`);
    score.style.color = kit.riskColor(n.risk);
    return el("div", { class: "flow-device" },
      el("button", { type: "button", class: "flow-device-open", "data-flow-open": n.id, title: "Open device" }, `${kit.kindGlyph[n.kind] || "?"} ${n.name || n.id}`),
      score,
      el("small", {}, `${n.kind || "unknown"} · ${(n.ips || []).join(", ") || "No IP"} · ${describeRisk(n.risk)}${n.kev ? ` · ${n.kev} KEV` : ""}`),
      trace && el("button", { type: "button", class: "flow-trace", "data-flow-trace": n.id }, "Trace dependencies →"));
  }

  function metric(value, label) {
    return el("div", { class: "flow-metric" }, el("strong", {}, String(value)), el("span", {}, label));
  }

  function updatePanel() {
    inspector.replaceChildren();
    if (!selection) {
      const nodes = [...(data.nodes || [])].sort((a, b) => finite(b.risk) - finite(a.risk) || finite(b.related_risk) - finite(a.related_risk));
      const exposed = nodes.filter((n) => finite(n.exposed) > 0).length;
      inspector.append(el("div", { class: "flow-eyebrow" }, "Start with the highest risk"), el("h2", {}, "Trace the blast radius"),
        el("p", { class: "flow-note" }, "Click a CVE to find affected devices and their related hosts and guests. Click a device to trace its dependencies."),
        el("div", { class: "flow-metrics" }, metric(nodes.filter((n) => n.kev > 0).length, "KEV devices"), metric(exposed, "exposed devices")),
        el("h3", {}, "Priority devices"), ...nodes.slice(0, 6).map((n) => deviceRow(n)),
        el("p", { class: "flow-note" }, "Hover follows complete paths. Double-click a device to open it. Drag empty space to pan; Ctrl + wheel to zoom. Escape clears the trace."),
        el("p", { class: "flow-note" }, "No top findings means no findings supplied here. Related devices share a host relationship; it does not establish exploitability."));
      return;
    }
    const affected = [...selection.ids].map((id) => model.index.get(id)).filter(Boolean).sort((a, b) => finite(b.risk) - finite(a.risk));
    const all = blastIds(data, selection.ids);
    const related = [...all].filter((id) => !selection.ids.has(id)).map((id) => model.index.get(id)).filter(Boolean).sort((a, b) => finite(b.risk) - finite(a.risk));
    const worst = highest(selection.ids);
    inspector.append(el("div", { class: "flow-eyebrow" }, selection.kind), el("h2", {}, selection.label),
      button("Clear trace ×", "clear"),
      el("div", { class: "flow-metrics" }, metric(affected.length, "on this path"), metric(related.length, "related devices")),
      el("p", { class: "flow-note" }, `Worst device risk: ${describeRisk(worst?.risk || 0)}. ${affected.reduce((s, n) => s + finite(n.kev), 0)} KEV findings on these devices.`));
    const device = selection.deviceId !== undefined ? model.index.get(selection.deviceId) : null;
    if (device) {
      inspector.append(el("button", { type: "button", "data-flow-open": device.id }, "Open device →"));
      const host = model.index.get(device.parent);
      inspector.append(el("p", { class: "flow-note" }, `Host: ${host?.name || ((device.children || []).length ? "This device is a hypervisor" : "No hypervisor")}. Networks: ${(device.networks || []).join(", ") || "Unassigned"}.`));
      for (const v of (device.top || []).slice(0, 5)) inspector.append(el("div", { class: "flow-chip", title: v.summary || "" }, `${v.kev ? "! " : ""}${v.id} · ${v.package}`));
    }
    if (selection.vulnId) {
      const finding = model.paths.find((p) => p.vuln?.id === selection.vulnId)?.vuln;
      if (finding) inspector.append(el("p", { class: "flow-note" }, `${finding.summary || finding.id}${finding.epss ? ` · EPSS ${(finding.epss * 100).toFixed(1)}%` : ""}`));
    }
    inspector.append(el("h3", {}, `On this path · ${affected.length}`), ...affected.slice(0, panelLimit).map((n) => deviceRow(n, n.id !== selection.deviceId)));
    if (affected.length > panelLimit) inspector.append(button(`Show next ${Math.min(50, affected.length - panelLimit)}`, "more"));
    inspector.append(el("h3", {}, `Related host / guests / siblings · ${related.length}`),
      el("p", { class: "flow-note" }, "Potential blast radius from inventory relationships."),
      ...related.slice(0, panelLimit).map((n) => deviceRow(n)));
    if (related.length > panelLimit) inspector.append(button(`Show more related (${related.length - panelLimit})`, "more"));
    if (!related.length) inspector.append(el("p", { class: "flow-note" }, "No additional related devices recorded."));
  }

  function highlight() {
    const all = selection ? selection.blast : null;
    for (const { element, item, base } of visuals) {
      let state = "";
      if (hovered) state = intersects(item.paths, hovered.paths) ? " is-active" : " is-dim";
      else if (selection) {
        if (intersects(item.paths, selection.paths)) state = " is-active";
        else if (intersects(item.deviceIds, all)) state = " is-related";
        else state = " is-dim";
      }
      if (element.getAttribute("class") !== base + state) element.setAttribute("class", base + state);
    }
  }

  function select(item) {
    panelLimit = 50;
    selection = { ids: new Set(item.deviceIds), paths: new Set(item.paths), label: item.label || `${item.source.label} → ${item.target.label}`,
      kind: item.stage === undefined ? "Dependency ribbon" : STAGES[item.stage], deviceId: item.deviceId, vulnId: item.vulnId };
    selection.blast = blastIds(data, selection.ids);
    hovered = null;
    tooltip.hidden = true;
    updatePanel();
    highlight();
  }

  function traceDevice(id) {
    const n = model.index.get(id);
    if (!n) return;
    // A device reached through the related list may be outside the filter or
    // inside an aggregate. Pin it so its reverse trace is always visible.
    search.value = "";
    kevInput.checked = false;
    kevOnly = false;
    selection = { ids: new Set([id]), deviceId: id, label: n.name || `Device ${id}`, kind: "Device", paths: new Set(), blast: blastIds(data, [id]) };
    render();
    const card = model.nodes.find((item) => item.deviceId === id);
    if (card) viewport.scrollTop = card.y * zoom;
  }

  function clear() {
    selection = null;
    hovered = null;
    tooltip.hidden = true;
    panelLimit = 50;
    updatePanel();
    highlight();
  }

  function positionTooltip(event) {
    const rect = root.getBoundingClientRect();
    const x = event.clientX - rect.left + 14, y = event.clientY - rect.top + 14;
    tooltip.style.left = `${Math.max(8, Math.min(x, rect.width - tooltip.offsetWidth - 8))}px`;
    tooltip.style.top = `${Math.max(8, Math.min(y, rect.height - tooltip.offsetHeight - 8))}px`;
  }

  function showTooltip(item, event) {
    const n = highest(item.deviceIds);
    const ids = item.deviceIds;
    let kevCount = 0;
    for (const id of ids) kevCount += finite(model.index.get(id)?.kev);
    const finding = n?.top?.[0];
    fill(tooltip, 
      el("strong", {}, item.label || `${item.source.label} → ${item.target.label}`),
      el("div", {}, `${ids.size} device${ids.size === 1 ? "" : "s"} · path risk ${describeRisk(item.risk)} · ${kevCount} KEV findings`),
      n && el("div", {}, `${ids.size > 1 ? "Highest risk: " : ""}${n.name} · ${n.kind || "unknown"}`),
      n && el("div", {}, (n.ips || []).join(", ") || "No IP recorded"),
      n && el("div", {}, `Device risk ${describeRisk(n.risk)} · ${finite(n.kev)} KEV`),
      el("div", {}, finding ? `Top: ${finding.id}${finding.kev ? " · KEV" : ""} · ${finding.summary || finding.package || ""}` : "No top finding supplied"),
      el("div", { class: "flow-note" }, "Click to trace · device double-click opens"));
    tooltip.hidden = false;
    positionTooltip(event);
  }

  function setScale(next, anchor) {
    if (!model) return;
    const old = zoom;
    zoom = Math.max(.3, Math.min(2.5, next));
    const x = anchor?.x ?? viewport.clientWidth / 2;
    const y = anchor?.y ?? viewport.clientHeight / 2;
    const sx = (viewport.scrollLeft + x) / old, sy = (viewport.scrollTop + y) / old;
    const width = model.width * zoom;
    paper.style.width = `${width}px`;
    const header = paper.querySelector(".flow-head"), svg = paper.querySelector(".flow-svg");
    if (header) { header.setAttribute("width", width); header.setAttribute("height", 44 * zoom); }
    if (svg) { svg.setAttribute("width", width); svg.setAttribute("height", model.height * zoom); }
    zoomLabel.textContent = `${Math.round(zoom * 100)}%`;
    viewport.scrollLeft = sx * zoom - x;
    viewport.scrollTop = sy * zoom - y;
  }

  function render() {
    if (destroyed) return;
    hovered = null;
    tooltip.hidden = true;
    const oldSelection = selection;
    model = layoutFlow(buildFlow(data, { topN, group: grouping, query: search.value, kevOnly, pinDeviceId: selection?.deviceId }), { width: Math.max(1040, viewport.clientWidth) });
    if (oldSelection) {
      // Recompute provenance on refresh, filter and aggregation changes.
      const item = oldSelection.deviceId !== undefined ? model.nodes.find((n) => n.deviceId === oldSelection.deviceId) :
        model.nodes.find((n) => n.id === oldSelection.itemId) || model.edges.find((e) => e.id === oldSelection.itemId);
      if (item) {
        selection = { ...oldSelection, ids: new Set(item.deviceIds), paths: new Set(item.paths), label: item.label || oldSelection.label };
        selection.blast = blastIds(data, selection.ids);
      } else selection = null;
    }
    const total = (data.nodes || []).length;
    status.replaceChildren(el("strong", {}, `${model.eligible.length} / ${total} devices`), el("span", {}, `${model.shown} / ${model.totalCVEs} CVEs + remainder`),
      el("span", {}, "Hover paths · click to trace"));
    visuals = [];
    itemLookup = new Map();
    paper.replaceChildren();
    if (!model.nodes.length) {
      paper.append(el("div", { class: "flow-empty" }, "No matching devices. Try another search or clear the KEV filter."));
      updatePanel();
      return;
    }
    const header = svgEl("svg", { class: "flow-head", viewBox: `0 0 ${model.width} 44`, "aria-hidden": "true" });
    STAGES.forEach((title, i) => {
      const x = 20 + i * (model.nodeWidth + 38);
      header.append(svgEl("text", { x, y: 14, class: "flow-step" }, `0${i + 1}`), svgEl("text", { x, y: 31 }, title.toUpperCase()));
    });
    const svg = svgEl("svg", { class: "flow-svg", viewBox: `0 0 ${model.width} ${model.height}`, role: "group", "aria-label": "Finding to device dependency paths" });
    const remember = (element, item, base) => {
      const key = String(itemLookup.size);
      element.setAttribute("data-flow-item", key);
      itemLookup.set(key, item);
      visuals.push({ element, item, base });
      element.setAttribute("class", base);
    };
    const edgeLayer = svgEl("g");
    // Thick paths first, small paths last so thin ribbons remain reachable.
    for (const edge of [...model.edges].sort((a, b) => b.thickness - a.thickness)) {
      const path = svgEl("path", { d: edge.d, fill: kit.riskColor(edge.risk), stroke: edge.kev ? kit.cssVar("--fg") : "none", "aria-label": `${edge.source.label} to ${edge.target.label}: ${edge.deviceIds.size} devices, ${describeRisk(edge.risk)}${edge.kev ? ", KEV" : ""}` });
      remember(path, edge, `flow-ribbon${edge.kev ? " is-kev" : ""}`);
      edgeLayer.append(path);
    }
    svg.append(edgeLayer);
    for (const n of model.nodes) {
      const node = svgEl("g", { tabindex: "0", role: "button", "aria-label": `${n.label}, ${n.deviceIds.size} devices, path risk ${describeRisk(n.risk)}${n.kev ? ", known exploited" : ""}` });
      remember(node, n, `flow-node${n.kev ? " is-kev" : ""}${n.aggregate ? " is-aggregate" : ""}`);
      const own = model.index.get(n.deviceId);
      const name = own ? `${kit.kindGlyph[own.kind] || "?"} ${n.label}` : `${n.kev ? "! " : ""}${n.label}`;
      const maxChars = Math.floor((n.width - 18) / 6.5);
      node.append(svgEl("rect", { class: "flow-card", x: n.x, y: n.y, width: n.width, height: n.height, rx: 4 }),
        svgEl("rect", { x: n.x, y: n.y + 4, width: n.risk >= 9 ? 5 : 3, height: n.height - 8, rx: 1, fill: kit.riskColor(n.risk) }),
        svgEl("text", { class: "flow-label", x: n.x + 10, y: n.y + 16 }, clip(n.aggregate && n.stage === 3 ? `${n.deviceIds.size} more · ${name}` : name, maxChars)),
        svgEl("text", { class: "flow-small", x: n.x + 10, y: n.y + 30 }, `${kit.riskLabel(n.risk)} ${n.risk.toFixed(1)}${n.deviceIds.size > 1 ? ` · ${n.deviceIds.size} dev` : ""}`),
        svgEl("title", {}, `${n.label} · ${n.deviceIds.size} devices · ${describeRisk(n.risk)}${n.kev ? " · KEV" : ""}`));
      svg.append(node);
    }
    paper.append(header, svg);
    if (autoFit) zoom = Math.min(1.15, Math.max(.3, (viewport.clientWidth - 2) / model.width));
    setScale(zoom);
    updatePanel();
    highlight();
  }

  function scheduleRender() {
    if (!frame && !destroyed) frame = requestAnimationFrame(() => { frame = 0; render(); });
  }
  const itemAt = (target) => itemLookup.get(target.closest?.("[data-flow-item]")?.getAttribute("data-flow-item"));
  listen(root, "click", (event) => {
    if (suppressClick) { suppressClick = false; return; }
    const target = event.target.closest?.("button");
    if (target?.hasAttribute("data-flow-open")) return kit.openDevice(Number(target.getAttribute("data-flow-open")));
    if (target?.hasAttribute("data-flow-trace")) return traceDevice(Number(target.getAttribute("data-flow-trace")));
    const action = target?.getAttribute("data-flow-action");
    if (action === "clear") clear();
    else if (action === "more") { panelLimit += 50; updatePanel(); }
    else if (action === "fit") { autoFit = true; setScale(Math.min(1.15, (viewport.clientWidth - 2) / model.width)); }
    else if (action === "zoom-in" || action === "zoom-out") { autoFit = false; setScale(zoom * (action === "zoom-in" ? 1.2 : 1 / 1.2)); }
    else {
      const item = itemAt(event.target);
      if (item) { select(item); selection.itemId = item.id; }
    }
  });
  listen(paper, "dblclick", (event) => {
    const item = itemAt(event.target);
    if (item?.deviceId !== undefined) kit.openDevice(item.deviceId);
  });
  listen(paper, "pointermove", (event) => {
    if (pan?.moved) return;
    const item = itemAt(event.target) || null;
    if (item !== hovered) {
      hovered = item || null;
      if (item) showTooltip(item, event);
      else tooltip.hidden = true;
      highlight();
    } else if (item) positionTooltip(event);
  });
  listen(paper, "pointerleave", () => { hovered = null; tooltip.hidden = true; highlight(); });
  listen(paper, "focusin", (event) => {
    const item = itemAt(event.target);
    if (item) { hovered = item; highlight(); }
  });
  listen(paper, "focusout", () => { hovered = null; highlight(); });
  listen(paper, "keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      const item = itemAt(event.target);
      if (item) { event.preventDefault(); select(item); selection.itemId = item.id; }
    }
  });
  listen(window, "keydown", (event) => { if (event.key === "Escape") clear(); });
  listen(search, "input", scheduleRender);
  listen(range, "input", () => { topN = Number(range.value); rangeValue.textContent = String(topN); scheduleRender(); });
  listen(groupSelect, "change", () => { grouping = groupSelect.value; scheduleRender(); });
  listen(kevInput, "change", () => { kevOnly = kevInput.checked; scheduleRender(); });
  listen(viewport, "wheel", (event) => {
    if (!event.ctrlKey && !event.metaKey) return;
    event.preventDefault();
    autoFit = false;
    const rect = viewport.getBoundingClientRect();
    setScale(zoom * Math.exp(-event.deltaY * .002), { x: event.clientX - rect.left, y: event.clientY - rect.top });
  }, { passive: false });
  listen(viewport, "pointerdown", (event) => {
    if (event.button !== 0 || event.pointerType === "touch" || itemAt(event.target)) return;
    suppressClick = false;
    pan = { id: event.pointerId, x: event.clientX, y: event.clientY, left: viewport.scrollLeft, top: viewport.scrollTop, moved: false };
    viewport.setPointerCapture(event.pointerId);
  });
  listen(viewport, "pointermove", (event) => {
    if (!pan || pan.id !== event.pointerId) return;
    const dx = event.clientX - pan.x, dy = event.clientY - pan.y;
    pan.moved ||= Math.abs(dx) + Math.abs(dy) > 4;
    if (pan.moved) {
      viewport.classList.add("is-panning");
      viewport.scrollLeft = pan.left - dx;
      viewport.scrollTop = pan.top - dy;
      tooltip.hidden = true;
    }
  });
  const endPan = () => {
    if (!pan) return;
    suppressClick = pan.moved;
    if (viewport.hasPointerCapture(pan.id)) viewport.releasePointerCapture(pan.id);
    pan = null;
    viewport.classList.remove("is-panning");
  };
  listen(viewport, "pointerup", endPan);
  listen(viewport, "pointercancel", endPan);
  const observer = new ResizeObserver(scheduleRender);
  observer.observe(viewport);
  const theme = window.matchMedia("(prefers-color-scheme: dark)");
  listen(theme, "change", scheduleRender);
  // Everything is event-driven: no motion loop, including reduced-motion mode.
  render();
  return {
    update(next) { data = next; scheduleRender(); },
    destroy() {
      destroyed = true;
      if (frame) cancelAnimationFrame(frame);
      frame = 0;
      observer.disconnect();
      controller.abort();
      endPan();
      tooltip.remove();
      root.remove();
      visuals = [];
      itemLookup.clear();
    },
  };
}
