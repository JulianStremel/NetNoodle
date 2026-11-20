// Recorded proposals and operator approvals. No actors execute actions yet.
import { api, el, table, fmtTime, registerView, ago } from "./app.js";
import { vulnCell } from "./findings.js";

async function page(root) {
  const error = el("p", { class: "error", role: "status" });
  const header = el("div", { class: "card" });
  const pending = el("div", { class: "card" });
  const automatic = el("div", { class: "card" });
  const history = el("div", { class: "card" });
  const state = el("select", { "aria-label": "History state" },
    ["all", "approved", "rejected", "expired", "resolved", "notify"].map((s) => el("option", { value: s }, s === "all" ? "All history" : s)));
  const filter = el("input", { type: "search", placeholder: "Filter history by device, vulnerability or action", "aria-label": "Filter history" });
  const historyContent = el("div");
  history.append(el("div", { class: "filters" }, state, filter), historyContent);
  let rows = [];
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
    const list = rows.filter((p) => !["pending", "auto"].includes(p.state) && (state.value === "all" || p.state === state.value) &&
      (!text || [p.device_name, p.vuln_id, p.action, p.reason].join(" ").toLowerCase().includes(text)));
    queue(historyContent, "History", list);
  };
  state.addEventListener("change", drawHistory);
  filter.addEventListener("input", drawHistory);
  const refresh = async () => {
    const [settings, proposals] = await Promise.all([api("/api/decide/settings"), api("/api/proposals?limit=20000")]);
    rows = proposals;
    const kill = el("input", { type: "checkbox" });
    kill.checked = settings.killswitch;
    kill.addEventListener("change", async () => {
      kill.disabled = true;
      try { await api("/api/decide/settings", { method: "PUT", body: { killswitch: kill.checked } }); error.textContent = ""; }
      catch (e) { error.textContent = e.message; kill.checked = !kill.checked; }
      finally { kill.disabled = false; }
    });
    const reevaluate = el("button", { onclick: async () => {
      reevaluate.disabled = true;
      try { await api("/api/proposals/reevaluate", { method: "POST", body: {} }); error.textContent = "Re-evaluation started. Refresh to see new proposals."; }
      catch (e) { error.textContent = e.message; }
      finally { reevaluate.disabled = false; }
    } }, "Re-evaluate findings");
    const counts = ["pending", "auto", "approved", "rejected", "expired", "resolved", "notify"].map((s) => el("span", { class: "chip" }, `${s}: ${rows.filter((p) => p.state === s).length}`));
    header.replaceChildren(el("h2", {}, "Actions"),
      el("p", { class: "muted" }, "Actions are recorded only. Actors that execute them come in a later version."),
      el("div", { class: "filters" }, el("label", { class: "check" }, kill, "Kill switch: no automatic actions"), reevaluate,
        el("button", { class: "secondary", onclick: () => refresh().catch((e) => { error.textContent = e.message; }) }, "Refresh")),
      el("div", { class: "proposal-counts" }, counts),
      rows.length === 20000 ? el("p", { class: "muted" }, "Showing the latest 20,000 proposals. Counts cover these records.") : "",
      el("p", { class: "small muted" }, `Rules: ${settings.rules.join(", ") || "none"}. Guards: ${settings.guards.join(", ") || "none"}.`));
    queue(pending, "Needs approval", rows.filter((p) => p.state === "pending"), true);
    queue(automatic, "Would run automatically", rows.filter((p) => p.state === "auto"));
    drawHistory();
  };
  root.append(header, error, pending, automatic, history);
  await refresh();
}
registerView("actions", "Actions", page);
