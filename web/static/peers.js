// Peers: enrolled scanners, agents and actors, and join tokens.
import { api, el, table, fmtTime, registerView } from "./app.js";

function enrollHelp(role, token, fingerprint) {
  const server = location.origin;
  const cmd = {
    source: `NN_JOIN_TOKEN=${token} nn-scan enroll -server ${server} -fingerprint ${fingerprint} -name <name>`,
    agent: `NN_JOIN_TOKEN=${token} nn-agent enroll --server ${server} --fingerprint ${fingerprint}`,
    actor: `NN_JOIN_TOKEN=${token} nn-actor enroll -server ${server} -fingerprint ${fingerprint} -name <name>`,
  }[role];
  return el("div", { class: "card" },
    el("h2", {}, "Join token created"),
    el("p", {}, "Copy the token now. The server does not show it again."),
    el("p", { class: "mono" }, token),
    el("p", { class: "muted" }, "Example command on the peer:"),
    el("p", { class: "mono" }, cmd));
}

async function page(root) {
  const [peers, tokens] = await Promise.all([api("/api/peers"), api("/api/join-tokens")]);
  const out = el("div");
  const tokensCard = el("div", { class: "card" });
  const drawTokens = (list) => tokensCard.replaceChildren(el("h2", {}, `Active join tokens (${list.length})`),
    list.length === 0 ? el("p", { class: "muted" }, "None.") :
      table([
        { title: "ID", key: "id" },
        { title: "Role", key: "role" },
        { title: "Name", key: "name" },
        { title: "Uses left", key: "uses_left" },
        { title: "Expires", render: (t) => fmtTime(t.expires) },
        {
          title: "",
          render: (t) => el("button", {
            class: "link",
            onclick: async () => {
              await api(`/api/join-tokens/${t.id}`, { method: "DELETE", body: {} });
              drawTokens(await api("/api/join-tokens"));
            },
          }, "Revoke"),
        },
      ], list));

  const role = el("select", {}, ["source", "agent", "actor"].map((r) => el("option", { value: r }, r)));
  const name = el("input", { placeholder: "Fixed name (optional)" });
  const uses = el("input", { type: "number", min: "1", max: "1000", value: "1" });
  const hours = el("input", { type: "number", min: "1", max: "720", value: "24" });
  const msg = el("p", { class: "error" });
  const form = el("form", {
    onsubmit: async (ev) => {
      ev.preventDefault();
      msg.textContent = "";
      try {
        const r = await api("/api/join-tokens", {
          method: "POST",
          body: { role: role.value, name: name.value.trim(), uses: Number(uses.value), hours: Number(hours.value) },
        });
        out.replaceChildren(enrollHelp(role.value, r.token, r.fingerprint));
        drawTokens(await api("/api/join-tokens"));
      } catch (e) {
        msg.textContent = e.message;
      }
    },
  },
  el("div", { class: "grid" },
    el("label", {}, "Role", role),
    el("label", {}, "Name", name),
    el("label", {}, "Uses", uses),
    el("label", {}, "Valid (hours)", hours)),
  el("button", { type: "submit" }, "Create join token"), msg);

  root.append(el("div", { class: "card" }, el("h2", {}, "Enroll a peer"),
    el("p", { class: "muted" }, "A scanner or importer uses role source. An agent on a host uses role agent. A program that executes actions uses role actor."),
    form), out);

  root.append(el("div", { class: "card" }, el("h2", {}, `Peers (${peers.length})`),
    peers.length === 0 ? el("p", { class: "muted" }, "No peers enrolled.") :
      table([
        { title: "Name", key: "name" },
        { title: "Role", render: (p) => el("span", { class: "pill" }, p.role) },
        { title: "Last seen", render: (p) => fmtTime(p.last_seen) },
        { title: "Status", render: (p) => el("span", { class: p.disabled ? "pill bad" : "pill ok" }, p.disabled ? "disabled" : "active") },
        {
          title: "",
          render: (p) => el("button", {
            class: "link",
            onclick: async () => {
              await api(`/api/peers/${p.id}/${p.disabled ? "enable" : "disable"}`, { method: "POST", body: {} });
              location.reload();
            },
          }, p.disabled ? "Enable" : "Disable"),
        },
      ], peers)));

  root.append(tokensCard);
  drawTokens(tokens);
}

registerView("peers", "Peers", page);
