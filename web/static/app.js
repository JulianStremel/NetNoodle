// netnoodle web UI. Plain ES modules, no build step.
// Each view is a function that renders into #view; views register in VIEWS.

export const $ = (sel, root = document) => root.querySelector(sel);

export async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: {}, credentials: "same-origin" };
  if (opts.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  const res = await fetch(path, init);
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && path !== "/api/login") {
    showLogin();
    throw new Error("login required");
  }
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

// el builds DOM nodes safely: text is always set as textContent.
export function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === undefined || c === null || c === false) continue;
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}

export function table(cols, rows) {
  return el("div", { class: "table-wrap" },
    el("table", {},
      el("thead", {}, el("tr", {}, cols.map((c) => el("th", {}, c.title)))),
      el("tbody", {}, rows.map((r) => el("tr", {}, cols.map((c) => el("td", {}, c.render ? c.render(r) : r[c.key])))))));
}

export const fmtTime = (s) => (s ? new Date(s).toLocaleString() : "");

const VIEWS = {};

// Severity helpers, shared by the pages.
export function sevLabel(score) {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "unknown";
}
export const sevPill = (score) =>
  el("span", { class: `sev ${sevLabel(score)}`, title: score ? `CVSS ${score.toFixed(1)}` : "no score" },
    score ? `${sevLabel(score)} ${score.toFixed(1)}` : "unknown");

// Query parameters of the hash route, e.g. #/findings?device=3.
export function hashParams() {
  const q = location.hash.split("?")[1] || "";
  return new URLSearchParams(q);
}

const ago = (s) => {
  if (!s) return "never";
  const sec = Math.round((Date.now() - new Date(s).getTime()) / 1000);
  if (sec < 90) return `${sec}s ago`;
  if (sec < 5400) return `${Math.round(sec / 60)}m ago`;
  if (sec < 129600) return `${Math.round(sec / 3600)}h ago`;
  return `${Math.round(sec / 86400)}d ago`;
};
export { ago };

async function overview(root) {
  const o = await api("/api/overview");
  const info = await api("/api/info");
  const f = o.findings;
  const stat = (n, label, cls, href) =>
    el("a", { class: `card stat ${cls || ""}`, href: href || "#/findings" }, el("div", { class: "n" }, String(n)), el("div", { class: "l" }, label));

  root.append(el("div", { class: "grid" },
    stat(f.critical, "Critical", "critical", "#/findings?min=9"),
    stat(f.high, "High", "high", "#/findings?min=7"),
    stat(f.medium, "Medium", "medium", "#/findings?min=4"),
    stat(f.kev, "Known exploited", "critical", "#/findings?kev=1"),
    stat(f.exposed, "On listening ports", "high", "#/findings?exposed=1"),
    stat(`${f.devices}/${o.devices}`, "Devices affected", "", "#/devices")));

  const kinds = Object.entries(o.device_kinds).sort((a, b) => b[1] - a[1]).map(([k, n]) => `${n} ${k}`).join(", ");
  const roles = Object.entries(o.peers).map(([k, n]) => `${n} ${k}`).join(", ") || "none";
  const intel = o.intel;
  const refresh = el("button", {
    onclick: async () => {
      refresh.disabled = true;
      await api("/api/intel/refresh", { method: "POST", body: {} });
      refresh.textContent = "Refresh started";
    },
  }, "Refresh feeds now");

  root.append(el("div", { class: "grid" },
    el("div", { class: "card" }, el("h2", {}, "Inventory"),
      el("p", {}, `${o.devices} devices`, kinds ? ` (${kinds})` : ""),
      el("p", {}, `${o.agent_devices} with an agent`),
      el("p", {}, `Enrolled peers: ${roles}`),
      el("p", { class: "muted small" }, `${f.open} open findings in ${f.vulns} vulnerabilities`)),
    el("div", { class: "card" }, el("h2", {}, "Threat feeds"),
      intel.matchers.length === 0 && intel.feeds.length === 0
        ? el("p", { class: "muted" }, "Disabled in the configuration.")
        : [
          el("p", {}, "Matchers: ", intel.matchers.join(", ") || "none"),
          intel.feeds.map((fd) => el("p", {}, `${fd.name}: `,
            fd.last_error ? el("span", { class: "error", title: fd.last_error }, "error") : `updated ${ago(fd.last_ok)}`)),
          el("p", {}, `Last match ${ago(intel.last_match)}`, intel.queued ? ` · ${intel.queued} queued` : ""),
          intel.last_error ? el("p", { class: "error small" }, intel.last_error) : "",
          refresh,
        ]),
    el("div", { class: "card" }, el("h2", {}, "Server"),
      el("p", { class: "muted small" }, "TLS fingerprint. Pin it in agents, scanners and actors:"),
      el("p", { class: "mono" }, o.tls_fingerprint),
      el("p", { class: "muted small" }, "Order signing public key (Ed25519):"),
      el("p", { class: "mono" }, info.order_key),
      el("p", { class: "muted small" }, "Order key SHA-256 fingerprint:"),
      el("p", { class: "mono" }, info.order_key_fingerprint))));

  root.append(el("div", { class: "card" }, el("h2", {}, "Recent events"),
    o.events.length === 0 ? el("p", { class: "muted" }, "No events.") :
      table([
        { title: "Time", render: (e) => el("span", { class: "nowrap" }, fmtTime(e.at)) },
        { title: "Type", key: "type" },
        { title: "By", key: "actor" },
        { title: "Summary", key: "summary" },
      ], o.events), el("p", {}, el("a", { href: "#/events" }, "All events →"))));
}

async function events(root) {
    const ev = await api("/api/events");
    root.append(el("div", { class: "card" }, el("h2", {}, "Events"),
      table([
        { title: "Time", render: (e) => fmtTime(e.at) },
        { title: "Type", key: "type" },
        { title: "By", key: "actor" },
        { title: "Summary", key: "summary" },
      ], ev)));
}

// registerView lets later modules add pages without changing this file.
export function registerView(name, title, fn) {
  VIEWS[name] = fn;
  if (!$(`#nav a[data-view="${name}"]`)) {
    $("#nav").append(el("a", { href: `#/${name}`, "data-view": name }, title));
  }
}

function currentView() {
  const v = location.hash.replace(/^#\/?/, "").split(/[/?]/)[0];
  return v || "overview";
}

async function render() {
  const name = currentView();
  for (const a of document.querySelectorAll("#nav a")) a.classList.toggle("active", a.dataset.view === name);
  const root = $("#view");
  root.replaceChildren();
  const fn = VIEWS[name];
  if (!fn) {
    root.append(el("p", { class: "muted" }, "Unknown page."));
    return;
  }
  try {
    await fn(root, location.hash);
  } catch (e) {
    if (e.message !== "login required") root.append(el("p", { class: "error" }, e.message));
  }
}

function showLogin() {
  $("#top").hidden = true;
  $("#view").replaceChildren();
  $("#login").hidden = false;
}

async function showApp(user) {
  $("#login").hidden = true;
  $("#top").hidden = false;
  $("#who").textContent = user;
  await render();
}

$("#login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  $("#login-error").textContent = "";
  try {
    const r = await api("/api/login", { method: "POST", body: { user: f.get("user"), password: f.get("password") } });
    ev.target.password.value = "";
    await showApp(r.user);
  } catch (e) {
    $("#login-error").textContent = e.message;
  }
});

$("#logout").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST", body: {} }).catch(() => {});
  showLogin();
});

registerView("overview", "Overview", overview);

// start is called by main.js after all page modules have registered.
export function start() {
  registerView("events", "Events", events);
  window.addEventListener("hashchange", render);
  api("/api/me").then((r) => showApp(r.user)).catch(() => showLogin());
}
