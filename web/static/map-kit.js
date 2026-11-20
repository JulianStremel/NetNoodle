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

export const dark = () => matchMedia("(prefers-color-scheme: dark)").matches;

// riskColor maps a risk 0-10 to a color: none, low, medium, high, critical.
export function riskColor(r) {
  if (!r) return dark() ? "#3a4150" : "#c3cad6";
  if (r >= 9) return dark() ? "#ff4d6d" : "#d61f45";
  if (r >= 7) return dark() ? "#ff8c42" : "#e2620d";
  if (r >= 4) return dark() ? "#ffd166" : "#c99400";
  return dark() ? "#5cc97b" : "#2f9e5b";
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
