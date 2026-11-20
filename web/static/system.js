import { api, el, fmtTime, registerView, refreshNav } from "./app.js";

registerView("system", "System", async (root) => {
  root.append(el("h1", {}, "System"));
  const data = await api("/api/update");
  const available = data.available;
  const error = el("p", { class: "error", role: "alert" });
  const progress = el("p", { role: "status" });
  const password = el("input", { type: "password", autocomplete: "current-password", required: true });
  const form = el("form", { class: "card narrow", hidden: true },
    el("h2", {}, "Confirm server change"), el("label", {}, "Administrator password", password),
    el("button", { type: "submit" }, "Confirm"),
    el("button", { type: "button", class: "secondary", onclick: () => { form.hidden = true; password.value = ""; } }, "Cancel"), error);
  let action;
  const begin = (next) => { action = next; form.hidden = false; password.value = ""; error.textContent = ""; password.focus(); };
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const buttons = [...form.querySelectorAll("button")];
    buttons.forEach((b) => { b.disabled = true; });
    try {
      const result = await api(action.id ? "/api/update/rollback" : "/api/update", {
        method: "POST", body: { ...action, password: password.value },
      });
      form.hidden = true;
      progress.textContent = `Request ${result.id} accepted. The host updater will report progress below.`;
      root.querySelectorAll("[data-update-action]").forEach((b) => { b.disabled = true; });
      await refreshNav();
    } catch (e) { error.textContent = e.message; }
    finally { password.value = ""; buttons.forEach((b) => { b.disabled = false; }); }
  });
  const disabled = !data.enabled || data.channel === "pinned" || !data.newer || data.pending;
  const summary = el("div", { class: "card" },
    el("p", {}, `Server version: ${data.current_version}`),
    el("p", {}, `Channel: ${data.channel}`),
    el("p", {}, `Automatic updates: ${data.auto ? "on" : "off"}`),
    el("p", {}, `Update window: ${data.window} (server local time)`),
    el("p", {}, data.enabled ? "Host updates enabled" : "Host updates disabled"),
    el("p", {}, available ? `Available: ${available.version} (${available.channel}), checked ${fmtTime(available.checked_at)}` : "No update check available"));
  if (available?.notes_url) {
    const url = new URL(available.notes_url);
    if (url.protocol === "https:") summary.append(el("a", { href: url.href, target: "_blank", rel: "noopener noreferrer" }, "Release notes"));
  }
  summary.append(el("p", {},
    el("button", { disabled, "data-update-action": true, onclick: () => begin({ when: "now" }) }, "Update now"), " ",
    el("button", { disabled, class: "secondary", "data-update-action": true, onclick: () => begin({ when: "window" }) }, "Schedule for window")));
  if (data.pending) summary.append(el("p", { role: "status" }, data.scheduled ? `Scheduled by ${data.scheduled.requested_by} for ${data.window}` : "An update request is pending"));
  if (data.downgrade_warning) summary.append(el("p", { role: "status", class: "error" }, "This channel points to an older release. Downgrades are refused."));
  root.append(summary, form, progress);
  const history = el("div", {}, el("h2", {}, "Update history"));
  let lastSuccess = true;
  for (const st of data.statuses) {
    const entry = el("article", { class: "card" }, el("h3", {}, `${st.state}: ${st.from_version || "unknown"} → ${st.to_version || "unknown"}`),
      el("p", { class: "muted small" }, `${st.id} · ${st.requested_by || "host"}`));
    if (st.error) entry.append(el("p", { class: "error" }, st.error));
    entry.append(el("ol", {}, (st.steps || []).map((step) => el("li", {}, `${step.ok ? "✓" : "✗"} ${step.name} · ${fmtTime(step.at)}${step.message ? `: ${step.message}` : ""}`))));
    if (st.state === "done") {
      if (lastSuccess && st.kind !== "rollback" && st.to_version === data.current_version && Date.parse(st.keep_until) > Date.now()) {
        entry.append(el("button", { class: "secondary", "data-update-action": true, disabled: !data.enabled || data.channel === "pinned" || data.pending,
          onclick: () => begin({ id: st.id }) }, "Roll back"));
      }
      lastSuccess = false;
    }
    history.append(entry);
  }
  if (!data.statuses.length) history.append(el("p", { class: "muted" }, "No updates yet."));
  root.append(history);
  // Refresh progress in place while preserving a password being entered.
  const timer = setInterval(async () => {
    if (!root.isConnected) { clearInterval(timer); return; }
    if (!form.hidden) return;
    try {
      const next = await api("/api/update");
      if (JSON.stringify(next.statuses) !== JSON.stringify(data.statuses) || next.pending !== data.pending) {
        clearInterval(timer);
        window.dispatchEvent(new Event("hashchange"));
      }
    } catch { /* A container replacement can briefly interrupt the connection. */ }
  }, 5000);
  window.addEventListener("nn:before-render", () => clearInterval(timer), { once: true });
});
