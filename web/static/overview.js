// Operations dashboard. All metrics come from the existing operator APIs.
import { api, el, table, registerView, ago, fmtTime, sevLabel, updateReportStatus } from "./app.js";

const deviceName = (n) => n.name || n.ips?.[0] || `#${n.id}`;
const heading = (title, href, link) => el("div", { class: "panel-heading" }, el("h2", {}, title), href ? el("a", { href }, link || "View all →") : null);
const panel = (title, href, link, ...content) => el("section", { class: "card", "aria-label": title }, heading(title, href, link), ...content);
const empty = (text) => el("p", { class: "muted empty-state" }, text);
const reachBadge = (reach) => el("span", { class: `reach ${["internet", "tunnel"].includes(reach) ? reach : "local"}` }, reach || "local");
const kpi = (label, value, detail, href, tone = "") => el("a", { class: `card kpi ${tone}`, href },
  el("div", { class: "eyebrow" }, label), el("div", { class: "kpi-value" }, value), el("div", { class: "kpi-detail" }, detail));

function riskCell(n) {
  const risk = Number(n.risk) || 0;
  const fill = el("span", { class: `risk-fill risk-${sevLabel(risk)}` });
  fill.style.width = `${Math.min(100, Math.max(0, risk * 10))}%`;
  return el("div", { class: "risk-cell", "aria-label": `Risk ${risk.toFixed(1)} out of 10` },
    el("span", { class: "risk-track", "aria-hidden": "true" }, fill), el("span", { class: "mono" }, risk.toFixed(1)));
}

function networksCard(graph, byID) {
  const legend = ["critical", "high", "medium", "low", "unknown"];
  const rows = graph.networks.map((network) => {
    const nodes = network.devices.map((id) => byID.get(id)).filter(Boolean);
    const counts = Object.fromEntries(legend.map((severity) => [severity, nodes.filter((n) => sevLabel(n.risk) === severity).length]));
    const description = legend.map((s) => `${counts[s]} ${s === "unknown" ? "unscored" : s}`).join(", ");
    const bar = el("div", { class: "network-bar", role: "img", "aria-label": `${network.id}: ${description}`, title: description });
    for (const severity of legend) {
      if (!counts[severity]) continue;
      const segment = el("span", { class: `network-segment risk-${severity}` });
      segment.style.flexGrow = String(counts[severity]);
      bar.append(segment);
    }
    const reach = nodes.some((n) => n.reach === "internet") ? "internet" : nodes.some((n) => n.reach === "tunnel") ? "tunnel" : "local";
    return el("div", { class: "network-row" },
      el("span", { class: "mono" }, network.id),
      bar, el("span", { class: "muted network-count" }, nodes.length), reachBadge(reach));
  });
  return panel("Networks", "#/map", "Explore map →", rows.length ? rows : empty("No networks discovered yet."),
    el("div", { class: "risk-legend muted small" }, legend.map((s) => el("span", {}, el("i", { class: `legend-swatch risk-${s}`, "aria-hidden": "true" }), s === "unknown" ? "Unscored" : s[0].toUpperCase() + s.slice(1)))));
}

function proposalCard(p, reload, error) {
  const agentOnly = (p.target_snapshot || []).some((id) => id.kind === "mac" && !p.target_reported_elsewhere?.[`${id.kind}=${id.value}`]);
  const controls = el("div", { class: "proposal-buttons" });
  let busy = false;
  const decide = async (decision, override = false) => {
    if (busy) return;
    busy = true;
    for (const b of controls.children) b.disabled = true;
    error.textContent = "";
    try {
      await api(`/api/proposals/${p.id}/${decision}`, { method: "POST", body: decision === "approve" ? { override_agent_only: override } : {} });
      await reload();
    } catch (e) {
      error.textContent = e.message;
      busy = false;
      for (const b of controls.children) b.disabled = false;
    }
  };
  controls.append(el("button", { type: "button", onclick: () => decide("approve") }, "Approve"),
    el("button", { type: "button", class: "secondary", onclick: () => decide("reject") }, "Reject"));
  if (agentOnly) controls.append(el("button", { type: "button", class: "secondary small", onclick: () => decide("approve", true) }, "Approve with agent-only MAC override"));
  return el("article", { class: "approval-item" },
    el("div", {}, el("strong", {}, p.action || "Notification"), " ", el("a", { href: `#/devices/${p.device_id}` }, p.device_name || `#${p.device_id}`),
      el("span", { class: "muted small" }, ` · ${p.ttl_s ? `${p.ttl_s / 3600} h` : "no TTL"} · ${ago(p.created_at)}`)),
    el("div", { class: "mono muted" }, [p.vuln_id, p.reason].filter(Boolean).join(" · ")),
    el("div", { class: "mono muted" }, (p.target_snapshot || []).map((id) => `${id.kind} ${id.value}`).join(" · ") || "No target identifiers"),
    p.action === "block-port" ? el("div", { class: "mono muted" }, `Ports: ${(p.params?.ports || []).join(", ") || "None"}`) : null,
    (p.recent_claims || []).map((c) => el("p", { class: "small warning" }, `Identity claimed by agent ${c.agent} on ${fmtTime(c.at)}`)),
    agentOnly ? el("p", { class: "small warning" }, "MAC only reported by the device’s own agent") : null, controls);
}

function eventRow(e) {
  const tone = /fail|error|kev|critical/.test(e.type) ? "danger" : /done|success/.test(e.type) ? "success" : /claim|proposal|reject/.test(e.type) ? "warning" : "info";
  return el("div", { class: "event-row" },
    el("time", { class: "muted", datetime: e.at, title: fmtTime(e.at) }, new Date(e.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })),
    el("span", { class: `event-type ${tone}` }, e.type), el("span", { title: e.actor ? `By ${e.actor}` : "" }, e.summary));
}

async function page(root) {
  const reload = async () => {
    const [o, graph, pending, settings, events, info, actors] = await Promise.all([
      api("/api/overview"), api("/api/graph"), api("/api/proposals?state=pending&limit=20000"),
      api("/api/decide/settings"), api("/api/events"), api("/api/info"), api("/api/actors"),
    ]);
    if (!root.isConnected) return;
    updateReportStatus(o, graph);
    const nodes = graph.nodes;
    const byID = new Map(nodes.map((n) => [n.id, n]));
    const stats = graph.stats;
    const count = settings.stats?.pending ?? pending.length;
    const oldest = pending.length ? pending.reduce((a, p) => Date.parse(p.created_at) < Date.parse(a.created_at) ? p : a) : null;
    const activeActors = actors.filter((a) => !a.peer.disabled);
    const kpis = el("div", { class: "kpi-grid" },
      kpi("Devices", o.devices, `${graph.networks.length} networks`, "#/devices"),
      kpi("Vulnerable", stats.vulnerable ?? nodes.filter((n) => n.findings > 0).length, `${o.findings.open} open findings`, "#/findings"),
      kpi("Known exploited", stats.kev_devices ?? nodes.filter((n) => n.kev > 0).length, "devices with KEV", "#/findings?kev=1", "kev-panel"),
      kpi("Reachable from outside", [stats["reach.internet"] ?? nodes.filter((n) => n.reach === "internet").length,
        el("span", { class: "kpi-secondary" }, ` + ${stats["reach.tunnel"] ?? nodes.filter((n) => n.reach === "tunnel").length} tunnel`)], "internet · tunnel", "#/map"),
      kpi("Needs approval", count, oldest ? `${count > pending.length ? "oldest shown" : "oldest"} ${ago(oldest.created_at)}` : "queue clear", "#/actions", "approval-panel"),
      kpi("Actors", activeActors.length, "View peers →", "#/peers"));

    const risky = [...nodes].sort((a, b) => b.risk - a.risk || b.kev - a.kev || a.id - b.id).slice(0, 8);
    const riskTable = panel("Riskiest devices", "#/devices", `All ${o.devices} →`, risky.length ? table([
      { title: "Device", render: (n) => [el("a", { class: "device-name", href: `#/devices/${n.id}` }, deviceName(n)), " ", el("span", { class: "muted small" }, n.kind)] },
      { title: "Reach", render: (n) => reachBadge(n.reach) },
      { title: "Risk", render: riskCell },
      { title: "Top finding", render: (n) => n.top?.length ? el("span", { class: "mono nowrap" }, n.top[0].kev ? [el("span", { class: "tag kev" }, "KEV"), " "] : null,
        el("a", { href: `#/findings?${new URLSearchParams({ device: n.id, q: n.top[0].id })}`, title: n.top[0].summary || n.top[0].id }, n.top[0].id)) : el("span", { class: "muted" }, n.agent ? "No open findings" : "No package data") },
      { title: "Host", render: (n) => byID.has(n.parent) ? el("a", { href: `#/devices/${n.parent}` }, deviceName(byID.get(n.parent))) : el("span", { class: "muted" }, "—") },
    ], risky) : empty("No devices yet. Enroll a scanner or agent on the Peers page."));
    const error = el("p", { class: "error small", role: "status" });
    const approvals = panel("Needs approval", "#/actions", `${count} →`,
      pending.slice(0, 3).map((p) => proposalCard(p, reload, error)),
      !pending.length ? empty("No proposals waiting for approval.") : null, error,
      el("p", { class: "muted small" }, `${count > 3 ? `+ ${count - 3} more · ` : ""}kill switch ${settings.killswitch ? "on" : "off"} · ${settings.stats?.auto || 0} automatic`));
    approvals.classList.add("approval-list");

    const intel = o.intel;
    const feedError = el("p", { class: "error small", role: "status" });
    const refreshFeeds = el("button", { class: "secondary", type: "button", onclick: async () => {
      refreshFeeds.disabled = true;
      try { await api("/api/intel/refresh", { method: "POST", body: {} }); refreshFeeds.textContent = "Refresh started"; }
      catch (e) { feedError.textContent = e.message; refreshFeeds.disabled = false; }
    } }, "Refresh feeds now");
    const feeds = panel("Threat feeds", null, null,
      el("p", { class: "muted" }, `Matchers: ${intel.matchers.join(", ") || "none"} · Last match ${ago(intel.last_match)}${intel.queued ? ` · ${intel.queued} queued` : ""}`),
      intel.feeds.map((f) => el("p", {}, f.name, ": ", el("span", { class: f.last_error ? "error" : "muted", title: f.last_error || fmtTime(f.last_ok) }, f.last_error || `updated ${ago(f.last_ok)}`))),
      !intel.feeds.length ? empty("No threat feeds configured.") : null,
      intel.last_error ? el("p", { class: "error small" }, intel.last_error) : null, refreshFeeds, feedError);
    const server = panel("Server", null, null,
      el("dl", { class: "server-details" },
        el("dt", {}, "TLS certificate fingerprint"), el("dd", { class: "mono" }, o.tls_fingerprint),
        el("dt", {}, "Order signing public key · Ed25519"), el("dd", { class: "mono" }, info.order_key),
        el("dt", {}, "Order key SHA-256 fingerprint"), el("dd", { class: "mono" }, info.order_key_fingerprint)));
    root.replaceChildren(kpis, el("div", { class: "dashboard-primary" }, riskTable, approvals),
      el("div", { class: "dashboard-secondary" }, networksCard(graph, byID),
        panel("Events", "#/events", "All events →", el("div", { class: "event-feed mono" }, events.length ? events.slice(0, 8).map(eventRow) : empty("No events yet.")))),
      el("div", { class: "dashboard-secondary" }, feeds, server));
  };
  await reload();
}

registerView("overview", "Overview", page);
