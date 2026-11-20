// Shared helpers for the visualizations of the Map page (web/static/viz/*.js).
//
// Contract of a visualization module web/static/viz/<id>.js:
//
//   export const meta = { id: "<id>", title: "Short title", description: "One sentence." };
//   export function mount(container, graph, kit) { ...; return { update(graph) {}, destroy() {} }; }
//
// - container: an empty <div class="viz-stage"> that fills the page width
//   and most of the window height. Size it from container.clientWidth/
//   clientHeight and follow resizes (ResizeObserver).
// - graph: the JSON of GET /api/graph (see internal/server/graph.go).
// - kit: this module (import it yourself or use the argument).
// - update(graph) is called with fresh data (refresh); destroy() must stop
//   all timers, animation frames, observers and listeners.
//
// Content Security Policy: default-src 'self'. No external URLs, no inline
// <script>, no style="" attributes and no <style> elements. Set styles
// through element.style.prop = value (CSSOM) or a CSS file of your own
// (kit.loadCSS("viz/<id>.css")). Text into the DOM only as textContent.

import { el } from "./app.js";

export { el };

// cssVar reads a theme color from style.css (--bg, --fg, --muted, --card,
// --line, --accent, --bad, --warn, --ok).
export function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export const dark = () => true;

// riskColor maps a risk 0-10 to a color: none, low, medium, high, critical.
let riskPalette;
export function riskColor(r) {
  // Read once: canvas render loops call this for every device and edge.
  riskPalette ||= ["--muted", "--ok", "--warn", "--high", "--bad"].map(cssVar);
  return riskPalette[!r ? 0 : r >= 9 ? 4 : r >= 7 ? 3 : r >= 4 ? 2 : 1];
}

// riskLabel is a word for a risk value (for text next to the color).
export function riskLabel(r) {
  if (!r) return "none";
  if (r >= 9) return "critical";
  if (r >= 7) return "high";
  if (r >= 4) return "medium";
  return "low";
}

// kindGlyph is a one-character symbol per device kind (works without color).
export const kindGlyph = { host: "■", vm: "◆", container: "▲", "network-device": "●", unknown: "?" };

// index returns a Map from device ID to node.
export const index = (graph) => new Map(graph.nodes.map((n) => [n.id, n]));

// blast returns the IDs of the devices that a problem on device id can
// affect: the device, its host, its guests and the other guests of the host.
export function blast(graph, id) {
  const byId = index(graph);
  const n = byId.get(id);
  if (!n) return new Set();
  return new Set([id, ...n.related]);
}

// openDevice shows the device detail page.
export function openDevice(id) {
  location.hash = `#/devices/${id}`;
}

// loadCSS adds a stylesheet from web/static once.
export function loadCSS(path) {
  const href = "/" + path.replace(/^\//, "");
  if (!document.querySelector(`link[href="${href}"]`)) {
    document.head.append(el("link", { rel: "stylesheet", href }));
  }
}

// fill replaces the children of node. It skips null, undefined and false,
// which replaceChildren would insert as text, and flattens arrays.
export function fill(node, ...children) {
  node.replaceChildren(...children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false));
  return node;
}
