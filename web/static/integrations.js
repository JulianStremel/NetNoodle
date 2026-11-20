import { api, el, ago, registerView } from "./app.js";

registerView("integrations", "Integrations", async (root) => {
  const types = await api("/api/integrations/types");
  const list = el("div", { class: "integration-list" });
  const editor = el("div");
  const error = el("p", { class: "error", role: "alert" });
  const close = () => editor.replaceChildren();
  const button = (label, run, secondary = false) => el("button", {
    type: "button", class: secondary ? "secondary" : undefined, onclick: run,
  }, label);

  function change(row, action) {
    const password = el("input", { type: "password", autocomplete: "current-password", required: true });
    const message = el("p", { class: "error", role: "alert" });
    const confirm = el("button", { type: "submit" }, `Confirm ${action}`);
    const form = el("form", { class: "card narrow" }, el("h2", {}, `${action[0].toUpperCase() + action.slice(1)} ${row.name}`),
      action === "delete" ? el("p", {}, "This stops the integration and removes its saved settings and credentials.") : null,
      el("label", {}, "Administrator password", password), confirm, " ", button("Cancel", close, true), message);
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      confirm.disabled = true;
      try {
        await api(`/api/integrations/${row.id}${action === "delete" ? "" : `/${action}`}`, {
          method: action === "delete" ? "DELETE" : "POST", body: { password: password.value },
        });
        close(); await refresh();
      } catch (e) { message.textContent = e.message; }
      finally { password.value = ""; confirm.disabled = false; }
    });
    editor.replaceChildren(form);
    password.focus();
  }

  function settingsForm(schema, row) {
    const controls = new Map();
    const name = el("input", { required: true, maxlength: 63, pattern: "[A-Za-z0-9][A-Za-z0-9._-]{0,62}", value: row?.name || schema.type });
    const fields = el("div", { class: "integration-fields" }, el("label", {}, "Name", name));
    let tested = "";
    let pendingPin = null;
    let busy = false;
    const status = el("p", { role: "status" });
    const message = el("p", { class: "error", role: "alert" });
    const certificate = el("div", { class: "integration-certificate", hidden: true });
    const password = el("input", { type: "password", autocomplete: "current-password", required: true });
    const save = el("button", { type: "submit", disabled: true }, "Save");
    const invalidate = () => { tested = ""; save.disabled = true; status.textContent = "Test the connection before saving."; };
    for (const field of schema.fields) {
      const secretSet = row?.secrets?.[field.key]?.set;
      const attrs = { required: field.required && !secretSet, "aria-label": field.label };
      const input = field.type === "list" ? el("textarea", attrs) : el("input", {
        ...attrs, type: field.type === "bool" ? "checkbox" : field.type === "secret" ? "password" : field.type === "url" ? "url" : "text",
        autocomplete: field.type === "secret" ? "new-password" : undefined,
        placeholder: secretSet ? "Already set; leave empty to keep" : undefined,
      });
      const value = row?.settings?.[field.key] ?? field.default;
      if (field.type === "bool") input.checked = Boolean(value);
      else if (field.type === "list") input.value = (value || []).join("\n");
      else input.value = field.type === "secret" ? "" : value ?? "";
      input.addEventListener("input", () => {
        invalidate();
        if (field.type === "url" || field.type === "fingerprint") { pendingPin = null; certificate.hidden = true; }
      });
      controls.set(field.key, { field, input });
      fields.append(el("label", {}, field.label, input, el("span", { class: "muted small" },
        `${field.help || ""}${secretSet ? " Credential is set. Leave empty to keep it." : ""}`)));
    }
    name.addEventListener("input", invalidate);
    const payload = () => {
      const settings = {}, secrets = {};
      for (const [key, { field, input }] of controls) {
        if (field.type === "secret") secrets[key] = input.value;
        else if (field.type === "bool") settings[key] = input.checked;
        else if (field.type === "list") settings[key] = input.value.split("\n").map(v => v.trim()).filter(Boolean);
        else settings[key] = input.value;
      }
      return { type: schema.type, name: name.value, settings, secrets, ...(row ? { id: row.id } : {}) };
    };
    const test = button("Test connection", async () => {
      if (busy || !fieldsValid()) return;
      if (pendingPin) { message.textContent = "Compare and confirm the fetched fingerprint first."; return; }
      busy = true; test.disabled = true; save.disabled = true; message.textContent = "";
      status.textContent = "Testing connection (up to 30 seconds)…";
      const request = payload();
      try {
        const result = await api("/api/integrations/test", { method: "POST", body: request });
        if (JSON.stringify(request) !== JSON.stringify(payload())) { invalidate(); return; }
        if (result.ok) {
          tested = JSON.stringify(request); save.disabled = false;
          status.textContent = `Connection OK: ${result.entities} entities. No data was imported.`;
        } else { invalidate(); message.textContent = result.error || "Connection test failed."; }
      } catch (e) { invalidate(); message.textContent = e.message; }
      finally { busy = false; test.disabled = false; }
    });
    const fieldsValid = () => {
      for (const input of [name, ...[...controls.values()].map(c => c.input)]) {
        if (!input.reportValidity()) return false;
      }
      return true;
    };
    const pinField = [...controls.values()].find(c => c.field.type === "fingerprint");
    const urlField = [...controls.values()].find(c => c.field.type === "url");
    const fetchPin = pinField && urlField ? button("Fetch fingerprint", async () => {
      if (busy || !urlField.input.reportValidity()) return;
      busy = true; fetchPin.disabled = true; invalidate(); message.textContent = "";
      const url = urlField.input.value;
      try {
        const result = await api("/api/integrations/probe", { method: "POST", body: { url } });
        if (url !== urlField.input.value) return;
        pendingPin = result.fingerprint;
        certificate.replaceChildren(el("p", {}, `Subject: ${result.subject || "(empty)"}`), el("code", {}, result.fingerprint),
          el("p", {}, "Compare this SHA-256 fingerprint with the certificate shown on the source server using a trusted connection."),
          button("I compared it — use this fingerprint", () => {
            pinField.input.value = pendingPin;
            pendingPin = null; certificate.hidden = true; invalidate();
          }));
        certificate.hidden = false;
      } catch (e) { message.textContent = e.message; }
      finally { busy = false; fetchPin.disabled = false; }
    }, true) : null;
    const form = el("form", { class: "card integration-editor" },
      el("h2", {}, `${row ? "Edit" : "Add"} integration: ${schema.type}`),
      el("p", { class: "muted" }, "Settings → confirm certificate if needed → test connection → save"), fields,
      fetchPin, certificate, test, status,
      el("label", {}, "Administrator password (to save)", password), save, " ", button("Cancel", close, true), message);
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      if (busy || pendingPin || !tested || tested !== JSON.stringify(payload())) { invalidate(); return; }
      busy = true; save.disabled = true; message.textContent = "";
      try {
        const request = { ...payload(), password: password.value };
        delete request.id;
        await api(row ? `/api/integrations/${row.id}` : "/api/integrations", { method: row ? "PUT" : "POST", body: request });
        close(); await refresh();
      } catch (e) { message.textContent = e.message; save.disabled = false; }
      finally { busy = false; password.value = ""; }
    });
    editor.replaceChildren(form);
    invalidate(); name.focus();
  }

  function add() {
    const select = el("select", { required: true }, types.map(t => el("option", { value: t.type }, t.type)));
    const form = el("form", { class: "card narrow" }, el("h2", {}, "Add integration: choose type"),
      el("label", {}, "Integration type", select), el("button", { type: "submit", disabled: !types.length }, "Next"), " ", button("Cancel", close, true));
    form.addEventListener("submit", ev => { ev.preventDefault(); settingsForm(types.find(t => t.type === select.value)); });
    editor.replaceChildren(form); select.focus();
  }

  async function refresh() {
    const rows = await api("/api/integrations");
    list.replaceChildren(...rows.map(row => {
      const card = el("article", { class: "card" }, el("h2", {}, row.name),
        el("p", { class: "muted" }, `${row.type}${row.from_config ? " · from config file (read only)" : ""}`),
        el("p", {}, `${row.running ? "Running" : row.enabled ? "Stopped" : "Disabled"} · Last poll: ${ago(row.last_poll)} · Last success: ${ago(row.last_ok_at)}`),
        row.last_error ? el("p", { class: "error" }, row.last_error) : null);
      if (!row.from_config) {
        const schema = types.find(t => t.type === row.type);
        card.append(el("div", { class: "integration-actions" },
          schema ? button("Edit", () => settingsForm(schema, row), true) : null,
          button(row.enabled ? "Disable" : "Enable", () => change(row, row.enabled ? "disable" : "enable"), true),
          button("Delete", () => change(row, "delete"), true)));
      }
      return card;
    }));
    if (!rows.length) list.append(el("p", { class: "muted" }, "No integrations yet. Add one to import devices from a service."));
    error.textContent = "";
  }
  root.append(el("h1", {}, "Integrations"), button("Add integration", add), error, editor, list);
  await refresh();
  const timer = setInterval(async () => {
    if (!root.isConnected) { clearInterval(timer); return; }
    try { await refresh(); } catch (e) { error.textContent = e.message; }
  }, 5000);
  window.addEventListener("nn:before-render", () => clearInterval(timer), { once: true });
});
