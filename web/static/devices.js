// Devices: list and detail pages.
import { api, el, table, fmtTime, registerView, sevPill } from "./app.js";
import { exploitCell, exposedCell, vulnCell } from "./findings.js";

const idsOf = (d, kind) => d.identifiers.filter((i) => i.kind === kind).map((i) => i.value);

function ago(s) {
  if (!s) return "";
  const sec = Math.round((Date.now() - new Date(s).getTime()) / 1000);
  if (sec < 90) return `${sec}s ago`;
  if (sec < 5400) return `${Math.round(sec / 60)}m ago`;
  if (sec < 129600) return `${Math.round(sec / 3600)}h ago`;
  return `${Math.round(sec / 86400)}d ago`;
}

const kindPill = (k) => el("span", { class: "pill" }, k || "unknown");

async function list(root) {
  const devs = await api("/api/devices");
  const byID = new Map(devs.map((d) => [d.id, d]));
  const label = (d) => d.name || idsOf(d, "hostname")[0] || idsOf(d, "ip")[0] || `#${d.id}`;

  const filter = el("input", { placeholder: "Filter by name, IP, MAC, source, kind …", type: "search" });
  const treeBox = el("input", { type: "checkbox" });
  try { treeBox.checked = localStorage.getItem("nn.devices.tree") === "1"; } catch { /* storage blocked */ }

  // Tree order: each device follows its parent, children indented.
  const treeOrder = (list) => {
    const kids = new Map();
    const inList = new Set(list.map((d) => d.id));
    for (const d of list) {
      const p = d.parent_id && inList.has(d.parent_id) ? d.parent_id : 0;
      if (!kids.has(p)) kids.set(p, []);
      kids.get(p).push(d);
    }
    const out = [];
    const walk = (p, depth) => {
      for (const d of kids.get(p) || []) {
        out.push([d, depth]);
        if (depth < 6) walk(d.id, depth + 1);
      }
    };
    walk(0, 0);
    return out;
  };

  const wrap = el("div");
  const draw = () => {
    const q = filter.value.trim().toLowerCase();
    const rows = devs.filter((d) => !q || JSON.stringify(d).toLowerCase().includes(q));
    const ordered = treeBox.checked ? treeOrder(rows) : rows.map((d) => [d, 0]);
    wrap.replaceChildren(table([
      { title: "Device", render: ([d, depth]) => el("span", { class: depth ? `indent-${Math.min(depth, 3)}` : "" }, depth ? "↳ " : "", el("a", { href: `#/devices/${d.id}` }, label(d))) },
      { title: "Kind", render: ([d]) => kindPill(d.kind) },
      { title: "IP", render: ([d]) => idsOf(d, "ip").join(", ") },
      { title: "MAC", render: ([d]) => el("span", { class: "mono" }, idsOf(d, "mac").join(", ")) },
      { title: "Parent", render: ([d]) => (d.parent_id ? el("a", { href: `#/devices/${d.parent_id}` }, byID.has(d.parent_id) ? label(byID.get(d.parent_id)) : `#${d.parent_id}`) : "") },
      { title: "Sources", render: ([d]) => d.sources.join(", ") },
      { title: "Risk", render: ([d]) => (d.findings ? [sevPill(d.max_score), " ", el("a", { href: `#/findings?device=${d.id}`, class: "small" }, `${d.findings}`), d.kev ? [" ", el("span", { class: "tag kev" }, "KEV")] : ""] : "") },
      { title: "Pkgs", render: ([d]) => d.components },
      { title: "Svcs", render: ([d]) => d.services },
      { title: "Last seen", render: ([d]) => el("span", { title: fmtTime(d.last_seen) }, ago(d.last_seen)) },
    ], ordered));
  };
  treeBox.addEventListener("change", () => {
    try { localStorage.setItem("nn.devices.tree", treeBox.checked ? "1" : "0"); } catch { /* storage blocked */ }
    draw();
  });
  filter.addEventListener("input", draw);
  draw();
  root.append(el("div", { class: "card" },
    el("h2", {}, `Devices (${devs.length})`),
    devs.length === 0
      ? el("p", { class: "muted" }, "No devices yet. Enroll a scanner or an agent on the Peers page, or configure a source.")
      : [el("div", { class: "filters" }, filter, el("label", { class: "check" }, treeBox, "Show as tree (guests under their host)")), wrap]));
}

async function detail(root, id) {
  const d = await api(`/api/devices/${id}`);
  const nameInput = el("input", { value: d.name, placeholder: "Display name" });
  const save = el("button", {
    onclick: async () => {
      await api(`/api/devices/${id}/name`, { method: "POST", body: { name: nameInput.value } });
      save.textContent = "Saved";
      setTimeout(() => (save.textContent = "Rename"), 1200);
    },
  }, "Rename");

  root.append(el("p", {}, el("a", { href: "#/devices" }, "← Devices")));
  root.append(el("div", { class: "card" },
    el("h2", {}, d.name || `Device #${d.id}`, " ", kindPill(d.kind)),
    el("div", { class: "row" }, nameInput, save),
    el("p", { class: "muted" },
      `First seen ${fmtTime(d.first_seen)} · last seen ${fmtTime(d.last_seen)}`,
      d.parent_id ? [" · parent ", el("a", { href: `#/devices/${d.parent_id}` }, `#${d.parent_id}`)] : "")));

  root.append(el("div", { class: "card" }, el("h2", {}, "Identifiers"),
    table([
      { title: "Kind", key: "kind" },
      { title: "Value", render: (i) => el("span", { class: "mono" }, i.value) },
      { title: "Strength", render: (i) => el("span", { class: i.strength === "strong" ? "pill ok" : "pill" }, i.strength) },
      { title: "Source", key: "source" },
      { title: "Last seen", render: (i) => ago(i.last_seen) },
    ], d.identifiers)));

  const attrs = Object.entries(d.attributes || {}).sort();
  if (attrs.length) {
    root.append(el("div", { class: "card" }, el("h2", {}, "Attributes"),
      table([{ title: "Key", render: (a) => a[0] }, { title: "Value", render: (a) => a[1] }], attrs)));
  }

  const rel = await api(`/api/devices/${id}/related`);
  if (rel.related.length) {
    const word = (r) => (!r ? "none" : r >= 9 ? "critical" : r >= 7 ? "high" : r >= 4 ? "medium" : "low");
    const riskPill = (r) => el("span", { class: r >= 7 ? "pill bad" : r >= 4 ? "pill warn" : "pill" }, `${word(r)} ${r ? r.toFixed(1) : ""}`);
    const warn = rel.related_risk >= 7 && rel.related_risk > rel.risk;
    root.append(el("div", { class: "card" },
      el("h2", {}, `Shares a hypervisor with (${rel.related.length})`),
      el("p", { class: warn ? "error" : "muted" }, warn ?
        `A related device has ${word(rel.related_risk)} risk (${rel.related_risk.toFixed(1)}). An attacker who controls it can possibly reach this device through the shared host.` :
        "The host, its guests and the other guests of the host. A compromise of one of them can affect the others."),
      table([
        { title: "Device", render: (c) => el("a", { href: `#/devices/${c.id}` }, c.name || `#${c.id}`) },
        { title: "Relation", key: "relation" },
        { title: "Kind", render: (c) => kindPill(c.kind) },
        { title: "Risk", render: (c) => riskPill(c.risk) },
        { title: "Findings", render: (c) => c.agent || c.findings ? `${c.findings}${c.kev ? ` (${c.kev} KEV)` : ""}` : el("span", { class: "muted" }, "no agent") },
      ], rel.related)));
  }

  root.append(el("div", { class: "card" }, el("h2", {}, `Services (${d.services.length})`),
    d.services.length === 0 ? el("p", { class: "muted" }, "None seen.") :
      table([
        { title: "Port", render: (s) => `${s.port}/${s.proto}` },
        { title: "Product", render: (s) => [s.product, s.version].filter(Boolean).join(" ") },
        { title: "Process", key: "process" },
        { title: "Banner", render: (s) => el("span", { class: "mono" }, s.banner || "") },
        { title: "Confidence", key: "confidence" },
        { title: "Source", key: "source" },
      ], d.services)));

  const findings = await api(`/api/findings?device=${id}&limit=200`);
  root.append(el("div", { class: "card" },
    el("h2", {}, `Vulnerabilities (${findings.length}${findings.length === 200 ? "+" : ""})`),
    findings.length === 0 ? el("p", { class: "muted" }, d.components.length ? "No open findings." : "No package data, so no findings.") : [
      table([
        { title: "Severity", render: (f) => sevPill(f.score) },
        { title: "Vulnerability", render: vulnCell },
        { title: "Exploit", render: exploitCell },
        { title: "Package", render: (f) => [f.package, " ", el("span", { class: "muted small" }, f.version)] },
        { title: "Fixed in", render: (f) => f.fixed || el("span", { class: "muted small" }, "no fix yet") },
        { title: "Exposed", render: exposedCell },
      ], findings.slice(0, 25)),
      el("p", {}, el("a", { href: `#/findings?device=${d.id}` }, `All findings of this device →`)),
    ]));

  const cf = el("input", { type: "search", placeholder: "Filter packages …" });
  const cwrap = el("div");
  const drawC = () => {
    const q = cf.value.trim().toLowerCase();
    const rows = d.components.filter((c) => !q || c.purl.toLowerCase().includes(q));
    cwrap.replaceChildren(table([
      { title: "Name", key: "name" },
      { title: "Version", key: "version" },
      { title: "PURL", render: (c) => el("span", { class: "mono" }, c.purl) },
      { title: "Source", key: "source" },
    ], rows.slice(0, 500)), rows.length > 500 ? el("p", { class: "muted" }, `${rows.length - 500} more – refine the filter.`) : "");
  };
  cf.addEventListener("input", drawC);
  drawC();
  root.append(el("div", { class: "card" }, el("h2", {}, `Packages (${d.components.length})`),
    d.components.length === 0 ? el("p", { class: "muted" }, "No package data. Install the agent on this device.") : [cf, el("div", { class: "gap" }), cwrap]));
}

registerView("devices", "Devices", async (root, hash) => {
  const id = hash.split("/")[2];
  if (id) return detail(root, encodeURIComponent(id));
  return list(root);
});
