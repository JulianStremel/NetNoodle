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
  for (const c of children.flat()) {
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

async function overview(root) {
    const info = await api("/api/info");
    root.append(
      el("div", { class: "card" },
        el("h2", {}, "Server"),
        el("p", {}, "Protocol ", info.protocol),
        el("p", {}, "TLS fingerprint (pin this in agents, scanners and actors):"),
        el("p", { class: "mono" }, info.tls_fingerprint)));
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
  const v = location.hash.replace(/^#\/?/, "").split("/")[0];
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
