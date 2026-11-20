// Pure data/layout code. No DOM, browser globals or dependencies.
export const STAGES = ["Vulnerability", "Package", "Exposed service", "Device", "Host", "Network"];
const num = (n) => Number.isFinite(Number(n)) ? Number(n) : 0;
const risk = (n) => Math.max(0, Math.min(10, num(n)));
const rankDevice = (a, b) => risk(b.risk) - risk(a.risk) || num(b.kev) - num(a.kev) || String(a.name).localeCompare(String(b.name));

export function packageName(value) {
  let s = String(value || "");
  if (s.startsWith("pkg:")) s = s.split("?")[0].split("#")[0].split("/").pop().split("@")[0];
  try { s = decodeURIComponent(s); } catch { /* Keep malformed inventory text readable. */ }
  return s.toLowerCase();
}

export function blastIds(graph, ids) {
  const index = new Map((graph.nodes || []).map((n) => [n.id, n]));
  const result = new Set();
  for (const id of ids) {
    if (!index.has(id)) continue;
    result.add(id);
    for (const related of index.get(id).related || []) if (index.has(related)) result.add(related);
  }
  return result;
}

export function buildFlow(graph, options = {}) {
  const all = graph.nodes || [];
  const index = new Map(all.map((n) => [n.id, n]));
  const query = String(options.query || "").trim().toLowerCase();
  const group = options.group === "network" ? "network" : "host";
  const topN = Math.max(10, Math.min(200, num(options.topN) || 15));
  const eligible = all.filter((n) => {
    const hay = [n.name, ...(n.ips || []), ...(n.networks || []), ...((n.top || []).map((v) => `${v.id} ${v.package}`))].join(" ").toLowerCase();
    return (!query || hay.includes(query)) && (!options.kevOnly || num(n.kev) > 0);
  }).sort(rankDevice);
  const hypervisor = (n) => n.parent && index.has(n.parent) ? n.parent : (n.children || []).length ? n.id : null;
  const grouping = (n) => group === "network" ? (n.networks || [])[0] || "Unassigned network" : index.get(hypervisor(n))?.name || "No hypervisor";
  const groupRisk = new Map();
  for (const n of eligible) groupRisk.set(grouping(n), Math.max(groupRisk.get(grouping(n)) || 0, risk(n.risk)));

  // Keep a small number of individual device cards. Every remaining device
  // retains its complete path membership inside a labeled group.
  const visible = new Set(eligible.slice(0, options.deviceLimit || 42).map((n) => n.id));
  if (index.has(options.pinDeviceId)) visible.add(options.pinDeviceId);
  const groupCounts = new Map();
  for (const n of eligible) if (!visible.has(n.id)) groupCounts.set(grouping(n), (groupCounts.get(grouping(n)) || 0) + 1);
  const keepGroups = new Set([...groupCounts].sort((a, b) => b[1] - a[1]).slice(0, 12).map(([key]) => key));

  const vulns = new Map();
  for (const n of eligible) for (const v of (n.top || []).slice(0, 5)) {
    if (!v.id) continue;
    if (!vulns.has(v.id)) vulns.set(v.id, { id: v.id, ids: new Set(), weight: 0, kev: false, risk: 0 });
    const item = vulns.get(v.id);
    if (!item.ids.has(n.id)) item.weight += risk(n.risk) + (v.kev ? 10 : 0) + (v.exposed ? 2 : 0);
    item.ids.add(n.id);
    item.kev ||= !!v.kev;
    item.risk = Math.max(item.risk, risk(n.risk));
  }
  const ranked = [...vulns.values()].sort((a, b) => b.weight - a.weight || a.id.localeCompare(b.id));
  const shown = new Set(ranked.slice(0, topN).map((v) => v.id));
  const specs = new Map();
  const spec = (stage, key, label, extra = {}) => {
    const id = `${stage}:${key}`;
    if (!specs.has(id)) specs.set(id, { id, stage, label, ...extra });
    return id;
  };
  const rawPaths = [];
  for (const n of eligible) {
    const hostId = hypervisor(n);
    const h = index.get(hostId);
    const hostKey = spec(4, hostId ?? "none", h?.name || "No hypervisor", { hostId });
    let deviceKey;
    if (visible.has(n.id)) deviceKey = spec(3, `device:${n.id}`, n.name || `Device ${n.id}`, { deviceId: n.id, groupLabel: grouping(n) });
    else {
      const g = keepGroups.has(grouping(n)) ? grouping(n) : "Other groups";
      deviceKey = spec(3, `group:${g}`, g, { aggregate: true, groupLabel: g });
    }
    const findings = (n.top || []).slice(0, 5);
    for (const v of findings.length ? findings : [null]) {
      const vulnKey = v ? spec(0, shown.has(v.id) ? v.id : "other", shown.has(v.id) ? v.id : `Other ${Math.max(0, vulns.size - shown.size)} CVEs`, { other: !shown.has(v.id), vulnId: shown.has(v.id) ? v.id : null }) : spec(0, "none", "No top findings", { empty: true });
      const pkg = v ? packageName(v.package) || "Unknown package" : "No finding package";
      const packageKey = spec(1, pkg, pkg);
      // GraphVuln.package is a display name; GraphService.package is a PURL.
      // Never infer a service link just from a vulnerability's exposed flag.
      const matches = v ? (n.services || []).filter((s) => s.exposed && s.package && packageName(s.package) === packageName(v.package)) : [];
      const serviceKeys = new Set(matches.map((s) => spec(2, `${s.port}/${s.proto || "tcp"}`, `${s.port}/${s.proto || "tcp"}`, { exposed: true })));
      if (!serviceKeys.size) serviceKeys.add(spec(2, "unlinked", "No linked listener", { empty: true }));
      for (const serviceKey of serviceKeys) for (const network of (n.networks || []).length ? n.networks : ["Unassigned"]) {
        rawPaths.push({ deviceId: n.id, vuln: v, risk: Math.max(risk(n.risk), risk(h?.risk)), kev: !!v?.kev,
          keys: [vulnKey, packageKey, serviceKey, deviceKey, hostKey, spec(5, network, network)] });
      }
    }
  }
  // Bound high-cardinality columns too (e.g. unique packages on each endpoint).
  for (const [stage, limit] of [[1, 64], [2, 56], [4, 36], [5, 36]]) {
    const counts = new Map();
    for (const p of rawPaths) {
      const key = p.keys[stage];
      if (!counts.has(key)) counts.set(key, new Set());
      counts.get(key).add(p.deviceId);
    }
    if (counts.size <= limit) continue;
    const keep = new Set([...counts].sort((a, b) => b[1].size - a[1].size).slice(0, limit).map(([key]) => key));
    const other = spec(stage, "overflow", `Other ${STAGES[stage].toLowerCase()}s`, { aggregate: true });
    for (const p of rawPaths) if (!keep.has(p.keys[stage])) p.keys[stage] = other;
  }
  const nodes = new Map();
  const links = new Map();
  const paths = [];
  // Collapse duplicate paths before indexing provenance.
  const dedup = new Set();
  for (const p of rawPaths) {
    const key = JSON.stringify([p.deviceId, p.vuln?.id, p.keys]);
    if (dedup.has(key)) continue;
    dedup.add(key);
    const pathId = paths.length;
    paths.push(p);
    const absorb = (item) => {
      item.deviceIds.add(p.deviceId);
      item.paths.add(pathId);
      item.risk = Math.max(item.risk, p.risk);
      item.kev ||= p.kev;
    };
    for (const key of p.keys) {
      if (!nodes.has(key)) nodes.set(key, { ...specs.get(key), deviceIds: new Set(), paths: new Set(), risk: 0, kev: false, incoming: [], outgoing: [] });
      absorb(nodes.get(key));
    }
    for (let i = 0; i < 5; i++) {
      const key = JSON.stringify([p.keys[i], p.keys[i + 1]]);
      if (!links.has(key)) {
        const edge = { id: key, source: nodes.get(p.keys[i]), target: nodes.get(p.keys[i + 1]), deviceIds: new Set(), paths: new Set(), risk: 0, kev: false };
        links.set(key, edge);
        edge.source.outgoing.push(edge);
        edge.target.incoming.push(edge);
      }
      absorb(links.get(key));
    }
  }
  const columns = STAGES.map((_, i) => [...nodes.values()].filter((n) => n.stage === i));
  for (const col of columns) col.sort((a, b) => {
    if (a.empty !== b.empty) return a.empty ? 1 : -1;
    if (a.stage === 3) return (groupRisk.get(b.groupLabel) || 0) - (groupRisk.get(a.groupLabel) || 0) || a.groupLabel.localeCompare(b.groupLabel) || b.risk - a.risk || a.label.localeCompare(b.label);
    if (a.stage === 0) return (a.other ? 1 : 0) - (b.other ? 1 : 0) || (vulns.get(b.vulnId)?.weight || 0) - (vulns.get(a.vulnId)?.weight || 0);
    return b.risk - a.risk || b.deviceIds.size - a.deviceIds.size || a.label.localeCompare(b.label);
  });
  return { nodes: [...nodes.values()], edges: [...links.values()], paths, columns, index, eligible, ranked, shown: shown.size, totalCVEs: vulns.size, group, query };
}

export function layoutFlow(model, options = {}) {
  const width = Math.max(1040, num(options.width) || 1300);
  const gap = 38, padding = 20, nodeWidth = (width - padding * 2 - 5 * gap) / 6;
  const maxMass = Math.max(1, ...model.columns.map((col) => col.reduce((sum, n) => {
    n.mass = Math.max(n.deviceIds.size, n.incoming.reduce((s, e) => s + e.deviceIds.size, 0), n.outgoing.reduce((s, e) => s + e.deviceIds.size, 0));
    return sum + n.mass;
  }, 0)));
  const unit = Math.max(0.12, Math.min(9, 560 / maxMass));
  const heights = model.columns.map((col) => col.reduce((s, n) => s + Math.max(38, n.mass * unit + 12) + 9, 0));
  const height = Math.max(640, ...heights.map((h) => h + 30));
  model.columns.forEach((col, i) => {
    let y = 18;
    col.forEach((n, order) => {
      n.x = padding + i * (nodeWidth + gap);
      n.y = y;
      n.width = nodeWidth;
      n.height = Math.max(38, n.mass * unit + 12);
      n.order = order;
      y += n.height + 9;
    });
  });
  for (const n of model.nodes) {
    for (const [list, key, peer] of [[n.outgoing, "sy", "target"], [n.incoming, "ty", "source"]]) {
      list.sort((a, b) => a[peer].order - b[peer].order);
      const total = list.reduce((s, e) => s + e.deviceIds.size * unit, 0);
      let offset = n.y + (n.height - total) / 2;
      for (const edge of list) {
        edge.thickness = edge.deviceIds.size * unit;
        edge[key] = offset;
        offset += edge.thickness;
      }
    }
  }
  for (const e of model.edges) {
    const x1 = e.source.x + nodeWidth, x2 = e.target.x, middle = (x1 + x2) / 2;
    const a = e.sy, b = e.ty, h = e.thickness;
    e.d = `M${x1},${a}C${middle},${a} ${middle},${b} ${x2},${b}L${x2},${b + h}C${middle},${b + h} ${middle},${a + h} ${x1},${a + h}Z`;
  }
  return { ...model, width, height, unit, nodeWidth };
}
