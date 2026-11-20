// Proposals, signed orders and actor capabilities.
import { api, el, table, fmtTime, registerView, ago } from "./app.js";
import { vulnCell } from "./findings.js";

async function page(root) {
  const error = el("p", { class: "error", role: "status" });
  const header = el("div", { class: "card" });
  const pending = el("div", { class: "card" });
  const automatic = el("div", { class: "card" });
  const history = el("div", { class: "card" });
  const actorsCard = el("div", { class: "card" });
  let orderRows = [];
  const state = el("select", { "aria-label": "History state" },
    ["all", "approved", "ordered", "done", "failed", "no-actor", "reverted", "rejected", "expired", "resolved", "notify"].map((s) => el("option", { value: s }, s === "all" ? "All history" : s)));
  const filter = el("input", { type: "search", placeholder: "Filter history by device, vulnerability or action", "aria-label": "Filter history" });
  const historyContent = el("div");
  history.append(el("div", { class: "filters" }, state, filter), historyContent);
  let rows = [];
  const historyState = () => state.value === "all" ? "approved,ordered,done,failed,no-actor,reverted,rejected,expired,resolved,notify" : state.value;
  const act = async (p, decision, button) => {
    button.disabled = true;
    try {
      await api(`/api/proposals/${p.id}/${decision}`, { method: "POST", body: {} });
      await refresh();
    } catch (e) { error.textContent = e.message; button.disabled = false; }
  };
  const columns = [
    { title: "Device", render: (p) => el("a", { href: `#/devices/${p.device_id}` }, p.device_name || `#${p.device_id}`) },
    { title: "Vulnerability", render: (p) => vulnCell({ vuln_id: p.vuln_id, aliases: [] }) },
    { title: "Action", render: (p) => p.action || "Notification" },
    { title: "Tier", render: (p) => el("span", { class: "pill" }, p.tier) },
    { title: "Reason", render: (p) => el("span", { title: p.decided_by.join(", ") }, p.reason) },
    { title: "TTL", render: (p) => p.ttl_s ? `${p.ttl_s / 3600}h` : "None" },
    { title: "Order", render: (p) => {
      const orders = orderRows.filter((o) => o.proposal_id === p.id);
      const original = orders.find((o) => !o.revert);
      const latest = orders[0];
      const cell = el("div", {}, latest ? `${latest.revert ? "revert: " : ""}${latest.state}` : p.state,
        latest?.message ? el("p", { class: "small muted" }, latest.message) : "");
      if (original?.state === "done" && original.revert_action && !original.reverted && original.revert_attempts < 6 && !orders.some((o) => o.revert && ["queued", "sent"].includes(o.state))) {
        const revert = el("button", { class: "secondary", onclick: async () => {
          revert.disabled = true;
          try { await api(`/api/orders/${original.id}/revert`, { method: "POST", body: {} }); await refresh(); }
          catch (e) { error.textContent = e.message; revert.disabled = false; }
        } }, "Revert");
        cell.append(revert);
      }
      return cell;
    } },
    { title: "Age", render: (p) => el("span", { title: fmtTime(p.created_at) }, ago(p.created_at)) },
  ];
  const queue = (card, title, list, approval = false) => {
    const cols = [...columns];
    if (approval) cols.push({ title: "Decision", render: (p) => {
      const approve = el("button", { onclick: () => act(p, "approve", approve) }, "Approve");
      const reject = el("button", { class: "secondary", onclick: () => act(p, "reject", reject) }, "Reject");
      return el("div", { class: "proposal-buttons" }, approve, reject);
    } });
    else cols.push({ title: "State", render: (p) => [el("span", { class: "pill" }, p.state), p.decided_user ? el("p", { class: "small muted", title: fmtTime(p.decided_at) }, p.decided_user) : ""] });
    card.replaceChildren(el("h2", {}, `${title} (${list.length})`), list.length ? table(cols, list) : el("p", { class: "muted" }, "None."));
  };
  const drawHistory = () => {
    const text = filter.value.trim().toLowerCase();
    const list = rows.filter((p) => !text || [p.device_name, p.vuln_id, p.action, p.reason].join(" ").toLowerCase().includes(text));
    queue(historyContent, "History", list);
  };
  let historyRequest = 0;
  const loadHistory = async () => {
    const request = ++historyRequest;
    const proposals = await api(`/api/proposals?state=${historyState()}&limit=500`);
    if (request !== historyRequest) return;
    rows = proposals;
    drawHistory();
  };
  state.addEventListener("change", () => loadHistory().catch((e) => { error.textContent = e.message; }));
  filter.addEventListener("input", drawHistory);
  const refresh = async () => {
    const [knownOrders, actors] = await Promise.all([api("/api/orders?limit=20000"), api("/api/actors")]);
    orderRows = knownOrders;
    actorsCard.replaceChildren(el("h2", {}, "Known actors"), actors.length ? table([
      { title: "Actor", render: (a) => `${a.peer.name}${a.peer.disabled ? " (disabled)" : ""}` },
      { title: "Capabilities", render: (a) => a.capabilities.map((c) => el("p", {}, `${c.action}: ${c.target_id_kinds.join(", ")}${c.reversible ? `; revert ${c.revert_action}` : ""}`)) },
    ], actors) : el("p", { class: "muted" }, "No actors enrolled."));
    const [settings, pendingRows, autoRows] = await Promise.all([
      api("/api/decide/settings"), api("/api/proposals?state=pending&limit=500"),
      api("/api/proposals?state=auto&limit=500"), loadHistory(),
    ]);
    const kill = el("input", { type: "checkbox" });
    kill.checked = settings.killswitch;
    kill.addEventListener("change", async () => {
      kill.disabled = true;
      try { await api("/api/decide/settings", { method: "PUT", body: { killswitch: kill.checked } }); error.textContent = ""; await refresh(); }
      catch (e) { error.textContent = e.message; kill.checked = !kill.checked; }
      finally { kill.disabled = false; }
    });
    const reevaluate = el("button", { onclick: async () => {
      reevaluate.disabled = true;
      try { await api("/api/proposals/reevaluate", { method: "POST", body: {} }); error.textContent = "Re-evaluation started. Refresh to see new proposals."; }
      catch (e) { error.textContent = e.message; }
      finally { reevaluate.disabled = false; }
    } }, "Re-evaluate findings");
    const counts = ["pending", "auto", "approved", "ordered", "done", "failed", "no-actor", "reverted", "rejected", "expired", "resolved", "notify"].map((s) => el("span", { class: "chip" }, `${s}: ${settings.stats[s] || 0}`));
    header.replaceChildren(el("h2", {}, "Actions"),
      el("p", { class: "muted" }, "Approved and automatic proposals are sent as signed orders to matching actors."),
      el("div", { class: "filters" }, el("label", { class: "check" }, kill, "Kill switch: no new orders (reverts continue)"), reevaluate,
        el("button", { class: "secondary", onclick: () => refresh().catch((e) => { error.textContent = e.message; }) }, "Refresh")),
      el("div", { class: "proposal-counts" }, counts),
      el("p", { class: "muted" }, "Showing up to 500 proposals per section. Counts include all records."),
      el("p", { class: "small muted" }, `Rules: ${settings.rules.join(", ") || "none"}. Guards: ${settings.guards.join(", ") || "none"}.`));
    queue(pending, "Needs approval", pendingRows, true);
    queue(automatic, "Automatic proposals", autoRows);
  };
  root.append(header, error, pending, automatic, history, actorsCard);
  await refresh();
}
registerView("actions", "Actions", page);
