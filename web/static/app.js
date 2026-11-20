import { icon } from "./icons.js";

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
  if (init.method !== "GET" && (/^\/api\/proposals\/[^/]+\/(approve|reject)$/.test(path) || path === "/api/decide/settings")) {
    await refreshNav().catch(() => {});
  }
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
  const time = Date.parse(s);
  if (!Number.isFinite(time) || time <= 0) return "never";
  const sec = Math.max(0, Math.round((Date.now() - time) / 1000));
  if (sec < 90) return `${sec}s ago`;
  if (sec < 5400) return `${Math.round(sec / 60)}m ago`;
  if (sec < 129600) return `${Math.round(sec / 3600)}h ago`;
  return `${Math.round(sec / 86400)}d ago`;
};
export { ago };

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
    $("#nav").append(el("a", { href: `#/${name}`, "data-view": name, "aria-label": title, title },
      icon(name), el("span", { class: "nav-label" }, title),
      ["findings", "devices", "actions"].includes(name) ? el("span", { class: `nav-count ${name === "actions" ? "pending-count" : ""}`, hidden: true }) : null,
      name === "findings" ? el("span", { class: "kev-dot", hidden: true }) : null));
  }
}

function currentView() {
  const v = location.hash.replace(/^#\/?/, "").split(/[/?]/)[0];
  return v || "overview";
}

let authenticated = false;
let navRequest = 0;
let killSaving = false;
let navTimer;

// Fetch complete counts, independently of bounded proposal lists on pages.
export async function refreshNav() {
  if (!authenticated) return;
  const request = ++navRequest;
  const results = await Promise.allSettled([api("/api/overview"), api("/api/decide/settings"), api("/api/graph"), api("/api/update")]);
  if (!authenticated || request !== navRequest) return;
  const [overviewResult, settingsResult, graphResult] = results;
  const o = overviewResult.status === "fulfilled" ? overviewResult.value : null;
  const settings = settingsResult.status === "fulfilled" ? settingsResult.value : null;
  const counts = { findings: o?.findings.open, devices: o?.devices, actions: settings?.stats?.pending };
  for (const [name, count] of Object.entries(counts)) {
    if (count == null) continue;
    const a = $(`#nav a[data-view="${name}"]`);
    const badge = $(".nav-count", a);
    badge.textContent = count;
    badge.hidden = false;
    const title = `${name[0].toUpperCase() + name.slice(1)}, ${count}${name === "findings" ? " open" : name === "actions" ? " waiting" : ""}`;
    a.setAttribute("aria-label", title);
    a.title = title;
  }
  if (o) {
    $(".kev-dot").hidden = !o.findings.kev;
    updateReportStatus(o, graphResult.status === "fulfilled" ? graphResult.value : null);
  }
  if (settings && !killSaving) updateKillSwitch(settings.killswitch);
  const update = results[3];
  let pill = $("#update-available");
  if (!pill) { pill = el("a", { id: "update-available", href: "#/system", class: "update-pill", hidden: true }, "Update available"); $(".sidebar-bottom").append(pill); }
  pill.hidden = update.status !== "fulfilled" || !update.value.newer;
  const failure = results.find((r) => r.status === "rejected");
  $("#shell-error").textContent = failure ? `Status update failed: ${failure.reason.message}` : "";
}

export function updateReportStatus(o, graph) {
  const status = $("#report-status");
  if (graph) {
    const times = graph.nodes.map((n) => Date.parse(n.last_seen)).filter((t) => Number.isFinite(t) && t > 0);
    const last = times.length ? new Date(times.reduce((a, b) => Math.max(a, b), 0)).toISOString() : "";
    status.dataset.report = last;
  }
  const last = status.dataset.report;
  const intel = o.intel;
  const feeds = intel.feeds || [];
  const errors = feeds.some((f) => f.last_error) || intel.last_error;
  const feedState = errors ? "feeds error" : !feeds.length ? "feeds disabled" : feeds.some((f) => ago(f.last_ok) === "never") ? "feeds waiting" : "feeds OK";
  status.textContent = `Last report ${last ? ago(last) : "unknown"} · ${feedState}`;
  status.title = [last ? `Last report: ${fmtTime(last)}` : "Report time is available on Overview", ...feeds.map((f) => `${f.name}: ${f.last_error || `updated ${ago(f.last_ok)}`}`)].join("\n");
  status.classList.toggle("error", Boolean(errors));
}

function updateKillSwitch(on) {
  const input = $("#kill-switch");
  input.checked = on;
  input.disabled = false;
  $("#kill-state").textContent = on ? "New orders paused" : "Kill switch off";
  const title = `Kill switch ${on ? "on: no new orders; reverts continue" : "off: actions enabled"}`;
  input.setAttribute("aria-label", title);
  input.parentElement.title = title;
}

async function render() {
  if (!authenticated) return;
  window.dispatchEvent(new Event("nn:before-render"));
  const name = currentView();
  for (const a of document.querySelectorAll("#nav a")) {
    const active = a.dataset.view === name;
    a.classList.toggle("active", active);
    if (active) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  // Each render owns its root, so an older request cannot append to a newer page.
  const root = el("div", { class: "page-content" });
  $("#view").replaceChildren(root);
  const fn = VIEWS[name];
  if (!fn) {
    root.append(el("p", { class: "muted" }, "Unknown page."));
    return;
  }
  root.setAttribute("aria-busy", "true");
  try { await fn(root, location.hash); }
  catch (e) {
    if (e.message !== "login required") root.append(el("p", { class: "error", role: "alert" }, e.message));
  } finally { root.removeAttribute("aria-busy"); }
}

function showLogin() {
  window.dispatchEvent(new Event("nn:before-render"));
  authenticated = false;
  ++navRequest;
  clearInterval(navTimer);
  $("#app").hidden = true;
  $("#view").replaceChildren();
  $("#login").hidden = false;
}

async function showApp(user) {
  authenticated = true;
  $("#login").hidden = true;
  $("#app").hidden = false;
  $("#who").textContent = user;
  $("#user-initial").textContent = (user || "A").slice(0, 1).toUpperCase();
  $("#user-initial").title = user;
  $("#logout").title = `${user} · Log out`;
  clearInterval(navTimer);
  navTimer = setInterval(() => { refreshNav().catch(() => {}); }, 60000);
  await Promise.all([render(), refreshNav(), api("/api/info").then((info) => {
    let footer = $("#server-version");
    if (!footer) { footer = el("div", { id: "server-version", class: "muted small user-name" }); $(".sidebar-bottom").append(footer); }
    footer.textContent = `netnoodle ${info.version}`;
    footer.title = `Protocol ${info.protocol}`;
  }).catch(() => {})]);
}

$("#login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  $("#login-error").textContent = "";
  try {
    const r = await api("/api/login", { method: "POST", body: { user: f.get("user"), password: f.get("password") } });
    ev.target.password.value = "";
    await showApp(r.user);
  } catch (e) { $("#login-error").textContent = e.message; }
});

$("#logout").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST", body: {} }).catch(() => {});
  showLogin();
});

// start is called by main.js after all page modules have registered.
export function start() {
  registerView("events", "Events", events);
  // Keep the reference navigation order, independent of module load order.
  for (const name of ["overview", "map", "findings", "devices", "actions", "peers", "events", "system"]) {
    const link = $(`#nav a[data-view="${name}"]`);
    if (link) $("#nav").append(link);
  }
  const media = matchMedia("(max-width: 759px)");
  let preference = null;
  try { preference = localStorage.getItem("nn.sidebar"); } catch { /* storage blocked */ }
  let collapsed = preference === "collapsed" || (preference !== "expanded" && media.matches);
  const applySidebar = () => {
    $("#app").classList.toggle("sidebar-collapsed", collapsed);
    const toggle = $("#sidebar-toggle");
    toggle.setAttribute("aria-expanded", String(!collapsed));
    toggle.setAttribute("aria-label", collapsed ? "Expand sidebar" : "Collapse sidebar");
    toggle.title = `${collapsed ? "Expand" : "Collapse"} sidebar ([)`;
  };
  const toggleSidebar = () => {
    collapsed = !collapsed;
    preference = collapsed ? "collapsed" : "expanded";
    try { localStorage.setItem("nn.sidebar", preference); } catch { /* storage blocked */ }
    applySidebar();
  };
  $("#sidebar-toggle").append(icon("chevron"));
  $("#sidebar-toggle").addEventListener("click", toggleSidebar);
  media.addEventListener("change", () => { if (!preference) { collapsed = media.matches; applySidebar(); } });
  applySidebar();
  if (/Mac|iPhone|iPad/.test(navigator.platform)) $("#search-shortcut").textContent = "Cmd K";
  document.addEventListener("keydown", (ev) => {
    if (!authenticated) return;
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "k") {
      ev.preventDefault(); $("#global-search").focus();
    } else if (ev.key === "[" && !ev.target.closest("input, textarea, select, [contenteditable]")) {
      ev.preventDefault(); toggleSidebar();
    }
  });
  $("#global-search-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const q = $("#global-search").value.trim();
    if (!q) return;
    const page = /CVE-\d{4}-\d+/i.test(q) ? "findings" : "devices";
    const hash = `#/${page}?${new URLSearchParams({ q })}`;
    if (location.hash === hash) render();
    else location.hash = hash;
  });
  $("#refresh").addEventListener("click", async () => {
    const button = $("#refresh");
    button.disabled = true;
    try { await Promise.all([render(), refreshNav()]); }
    finally { button.disabled = false; }
  });
  $("#kill-switch").addEventListener("change", async () => {
    const input = $("#kill-switch");
    const next = input.checked;
    killSaving = true;
    input.disabled = true;
    ++navRequest;
    try {
      await api("/api/decide/settings", { method: "PUT", body: { killswitch: next } });
      updateKillSwitch(next);
      $("#shell-error").textContent = "";
      if (currentView() === "actions" || currentView() === "overview") await render();
    } catch (e) {
      updateKillSwitch(!next);
      $("#shell-error").textContent = e.message;
    } finally { killSaving = false; input.disabled = false; }
  });
  window.addEventListener("hashchange", render);
  api("/api/me").then((r) => showApp(r.user)).catch(() => showLogin());
}
