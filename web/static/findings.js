// Findings: vulnerabilities in the installed packages of all devices.
import { api, el, table, fmtTime, registerView, sevPill, hashParams, ago } from "./app.js";

const osvLink = (id) =>
  el("a", { href: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`, target: "_blank", rel: "noopener noreferrer" }, id);

export function exploitCell(f) {
  return [
    f.kev ? el("span", { class: "tag kev", title: f.facts && f.facts["kev.name"] ? `CISA KEV: ${f.facts["kev.name"]}` : "CISA known exploited" }, "KEV") : "",
    f.kev ? " " : "",
    f.epss ? el("span", { class: "small", title: `EPSS percentile ${(f.epss_pct * 100).toFixed(0)}` }, `EPSS ${(f.epss * 100).toFixed(1)}%`) : "",
  ];
}

export const exposedCell = (f) =>
  f.exposed.length ? el("span", { class: "tag exposed", title: "The package has a listening service on this device" }, f.exposed.join(" ")) : "";

export function vulnCell(f) {
  const cves = f.aliases.filter((a) => a.startsWith("CVE-") && a !== f.vuln_id);
  return [
    osvLink(f.vuln_id),
    cves.length ? el("span", { class: "muted small" }, " ", cves.slice(0, 3).join(", ")) : "",
    f.summary ? el("p", { class: "summary" }, f.summary) : "",
  ];
}

const pkgCell = (f) => [el("span", {}, f.package || f.purl), " ", el("span", { class: "muted small" }, f.version)];
const fixedCell = (f) => (f.fixed ? el("span", { class: "small nowrap" }, f.fixed) : el("span", { class: "muted small" }, "no fix yet"));

async function page(root) {
  const params = hashParams();
  const device = params.get("device");
  const state = params.get("state") || "open";
  const q = new URLSearchParams({ state, limit: "20000" });
  if (device) q.set("device", device);
  const rows = await api(`/api/findings?${q}`);

  const minSel = el("select", {}, [["0", "All severities"], ["4", "Medium and higher"], ["7", "High and higher"], ["9", "Critical"]]
    .map(([v, t]) => el("option", { value: v }, t)));
  minSel.value = params.get("min") || "0";
  const kev = el("input", { type: "checkbox" });
  kev.checked = params.get("kev") === "1";
  const exposed = el("input", { type: "checkbox" });
  exposed.checked = params.get("exposed") === "1";
  const fixable = el("input", { type: "checkbox" });
  const text = el("input", { type: "search", placeholder: "Filter by CVE, package, device …" });
  const stateSel = el("select", {}, [["open", "Open"], ["resolved", "Resolved"]].map(([v, t]) => el("option", { value: v }, t)));
  stateSel.value = state;
  stateSel.addEventListener("change", () => {
    const p = hashParams();
    p.set("state", stateSel.value);
    location.hash = `#/findings?${p}`;
  });

  const wrap = el("div");
  const counter = el("span", { class: "muted" });
  const draw = () => {
    const min = Number(minSel.value);
    const t = text.value.trim().toLowerCase();
    const list = rows.filter((f) =>
      f.score >= min &&
      (!kev.checked || f.kev) &&
      (!exposed.checked || f.exposed.length) &&
      (!fixable.checked || f.fixed) &&
      (!t || [f.vuln_id, f.package, f.purl, f.device_name, f.summary, ...f.aliases].join(" ").toLowerCase().includes(t)));
    counter.textContent = `${list.length} of ${rows.length}`;
    const shown = list.slice(0, 500);
    wrap.replaceChildren(
      list.length === 0 ? el("p", { class: "muted" }, rows.length ? "No finding matches the filter." : "No findings.") :
        table([
          { title: "Severity", render: (f) => sevPill(f.score) },
          { title: "Vulnerability", render: vulnCell },
          { title: "Exploit", render: exploitCell },
          { title: "Package", render: pkgCell },
          { title: "Fixed in", render: fixedCell },
          { title: "Device", render: (f) => el("a", { class: "nowrap", href: `#/devices/${f.device_id}` }, f.device_name || `#${f.device_id}`) },
          { title: "Exposed", render: exposedCell },
          { title: state === "open" ? "Since" : "Resolved", render: (f) => el("span", { class: "nowrap small", title: fmtTime(state === "open" ? f.first_seen : f.resolved_at) }, ago(state === "open" ? f.first_seen : f.resolved_at)) },
        ], shown),
      list.length > shown.length ? el("p", { class: "muted" }, `${list.length - shown.length} more. Refine the filter.`) : "");
  };
  for (const c of [minSel, kev, exposed, fixable]) c.addEventListener("change", draw);
  text.addEventListener("input", draw);

  const devName = device && rows[0] ? rows[0].device_name || `#${device}` : device ? `#${device}` : "";
  root.append(el("div", { class: "card" },
    el("h2", {}, "Findings ", counter),
    device ? el("p", {}, el("span", { class: "chip" }, `Device ${devName}`, el("a", { href: "#/findings", title: "Show all devices" }, "×"))) : "",
    el("div", { class: "filters" },
      el("label", {}, "State", stateSel),
      el("label", {}, "Severity", minSel),
      el("label", { class: "check" }, kev, "Known exploited"),
      el("label", { class: "check" }, exposed, "On a listening port"),
      el("label", { class: "check" }, fixable, "Fix available"),
      text),
    wrap));
  draw();
}

registerView("findings", "Findings", page);
