// Map: visualizations of the whole inventory. Each visualization is a
// module in web/static/viz/ (contract in map-kit.js). Add its ID to VIZ.
import { api, el, registerView } from "./app.js";
import * as kit from "./map-kit.js";

const VIZ = ["radar", "city", "flow"];
const STORE = "nn.map.viz";

function remember(id) {
  try { localStorage.setItem(STORE, id); } catch { /* private mode */ }
}
function recall() {
  try { return localStorage.getItem(STORE); } catch { return null; }
}

async function page(root) {
  const mods = (await Promise.all(VIZ.map((id) => import(`./viz/${id}.js`).catch((e) => {
    console.error("viz", id, e);
    return null;
  })))).filter(Boolean);
  let graph = await api("/api/graph");
  if (mods.length === 0) {
    root.append(el("p", { class: "muted" }, "No visualizations installed."));
    return;
  }
  const stage = el("div", { class: "viz-stage" });
  const desc = el("span", { class: "muted" });
  const tabs = el("div", { class: "viz-tabs", role: "tablist" });
  let current = null;
  let active = recall();
  if (!mods.some((m) => m.meta.id === active)) active = mods[0].meta.id;

  const show = (id) => {
    current?.destroy?.();
    stage.replaceChildren();
    const m = mods.find((x) => x.meta.id === id);
    active = id;
    remember(id);
    for (const b of tabs.children) b.setAttribute("aria-selected", String(b.dataset.id === id));
    desc.textContent = m.meta.description || "";
    try {
      current = m.mount(stage, graph, kit);
    } catch (e) {
      stage.append(el("p", { class: "error" }, `${m.meta.title}: ${e.message}`));
      current = null;
    }
  };
  for (const m of mods) {
    tabs.append(el("button", { class: "viz-tab", role: "tab", "data-id": m.meta.id, onclick: () => show(m.meta.id) }, m.meta.title));
  }
  const refresh = el("button", {
    class: "link",
    onclick: async () => {
      graph = await api("/api/graph");
      if (current?.update) current.update(graph);
      else show(active);
    },
  }, "Refresh");
  const s = graph.stats;
  root.append(el("div", { class: "viz-bar" }, tabs, el("span", { class: "spacer" }),
    el("span", { class: "muted" }, `${s.devices || 0} devices · ${s.vulnerable || 0} vulnerable · ${s.kev_devices || 0} with KEV · ${s.networks || 0} networks`),
    refresh), el("p", { class: "viz-desc" }, desc), stage);
  show(active);

  const stop = () => {
    current?.destroy?.();
    current = null;
    window.removeEventListener("hashchange", stop);
  };
  window.addEventListener("hashchange", stop);
}

registerView("map", "Map", page);
