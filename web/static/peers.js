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

function pairHelp(r) {
  return el("div", { class: "card" },
    el("h2", {}, `Pair the pull agent ${r.peer.name}`),
    el("p", {}, "On the host of the agent, run this command. Then start the service (nn-agent serve). The server connects each minute until the pairing is complete."),
    el("p", { class: "mono" }, r.command),
    el("p", { class: "muted" }, `The code is valid until ${fmtTime(r.expires)}. Use it one time only.`));
}

function pullCard(data, out) {
  const card = el("div", { class: "card" });
  const draw = (d) => {
    const name = el("input", { placeholder: "Name, e.g. rproxy" });
    const addr = el("input", { placeholder: "Address, e.g. 10.1.2.3:7444" });
    const interval = el("input", { value: "1h" });
    const msg = el("p", { class: "error" });
    const refresh = async () => draw(await api("/api/pull-peers"));
    const form = el("form", {
      onsubmit: async (ev) => {
        ev.preventDefault();
        msg.textContent = "";
        try {
          const r = await api("/api/pull-peers", {
            method: "POST",
            body: { name: name.value.trim(), address: addr.value.trim(), interval: interval.value.trim() },
          });
          out.replaceChildren(pairHelp(r));
          await refresh();
        } catch (e) {
          msg.textContent = e.message;
        }
      },
    },
    el("div", { class: "grid" },
      el("label", {}, "Name", name),
      el("label", {}, "Address (host:port)", addr),
      el("label", {}, "Interval", interval)),
    el("button", { type: "submit" }, "Add pull agent"), msg);

    const state = (p) => {
      if (p.disabled) return el("span", { class: "pill bad" }, "disabled");
      if (!p.paired) return el("span", { class: "pill" }, "waiting for pairing");
      if (p.last_error) return el("span", { class: "pill bad" }, "error");
      return el("span", { class: "pill ok" }, "paired");
    };
    card.replaceChildren(el("h2", {}, `Pull agents (${d.peers.length})`),
      el("p", { class: "muted" }, "The server connects to these agents and pulls their reports. Use pull mode when the agent's host must not connect to the server, for example in a DMZ."),
      d.peers.length === 0 ? el("p", { class: "muted" }, "None.") :
        table([
          { title: "Name", key: "name" },
          { title: "Version", render: (p) => el("span", {}, p.version || "unknown", p.outdated ? el("span", { class: "pill bad" }, "outdated") : null) },
          { title: "Address", render: (p) => el("span", { class: "mono" }, p.address) },
          { title: "State", render: state },
          { title: "Interval", key: "interval" },
          { title: "Last pull", render: (p) => fmtTime(p.last_pull) },
          { title: "Next", render: (p) => fmtTime(p.next_pull) },
          { title: "Last error", render: (p) => el("span", { class: "muted" }, p.last_error || "") },
          {
            title: "",
            render: (p) => el("span", {},
              el("button", {
                class: "link",
                onclick: async () => {
                  await api(`/api/pull-peers/${p.id}/pull`, { method: "POST", body: {} });
                  setTimeout(refresh, 2000);
                },
              }, "Pull now"), " ",
              el("button", {
                class: "link",
                title: "Removes the pinned agent certificate and makes a new pairing code",
                onclick: async () => {
                  out.replaceChildren(pairHelp(await api(`/api/pull-peers/${p.id}/pair`, { method: "POST", body: {} })));
                  await refresh();
                },
              }, "New pairing code")),
          },
        ], d.peers),
      el("p", { class: "muted" }, "Server pull certificate fingerprint: ", el("span", { class: "mono" }, d.client_fingerprint || "")),
      form);
  };
  draw(data);
  return card;
}

function onboardWizard() {
  const kind = el("select", {}, ["agent", "agent-pull", "scan", "actor-host", "actor-unifi", "actor-proxmox"].map((value) => el("option", { value }, value)));
  const name = el("input", { required: true, maxlength: "63", pattern: "[A-Za-z0-9][A-Za-z0-9._-]{0,62}", placeholder: "web01" });
  const platform = el("select", {}, el("option", { value: "linux" }, "Linux"), el("option", { value: "windows" }, "Windows"));
  const password = el("input", { type: "password", required: true, maxlength: "1024", autocomplete: "current-password" });
  const message = el("p", { class: "error", role: "alert" });
  const output = el("div");
  const submit = el("button", { type: "submit" }, "Add peer");
  let timer;
  let active = true;
  let generation = 0;
  window.addEventListener("nn:before-render", () => { active = false; clearTimeout(timer); }, { once: true });
  const supported = () => {
    const windows = kind.value === "agent" || kind.value === "scan";
    platform.options[1].disabled = !windows;
    if (!windows) platform.value = "linux";
  };
  kind.addEventListener("change", supported);
  const copyField = (title, value) => el("div", {}, el("h3", {}, title),
    el("pre", { class: "mono" }, value),
    el("button", { type: "button", class: "link", onclick: async (event) => {
      try { await navigator.clipboard.writeText(value); event.target.textContent = "Copied"; }
      catch { message.textContent = "Copy failed. Select and copy the text above."; }
    } }, `Copy ${title.toLowerCase()}`));
  const form = el("form", { onsubmit: async (event) => {
    event.preventDefault();
    message.textContent = "";
    submit.disabled = true;
    try {
      const result = await api("/api/onboard", { method: "POST", body: { kind: kind.value, name: name.value.trim(), platform: platform.value, password: password.value } });
      password.value = "";
      if (!active) return;
      clearTimeout(timer);
      const current = ++generation;
      const status = el("p", { role: "status", "aria-live": "polite" }, "Waiting for installation");
      const steps = el("div");
      const cancel = el("button", { type: "button", class: "link", onclick: async () => {
        cancel.disabled = true;
        try { await api(`/api/onboard/${result.session}/cancel`, { method: "POST", body: {} }); await poll(); }
        catch (error) { message.textContent = error.message; cancel.disabled = false; }
      } }, "Cancel installation");
      const poll = async () => {
        clearTimeout(timer);
        if (!active || current !== generation) return;
        try {
          const session = await api(`/api/onboard/${result.session}`);
          if (!active || current !== generation) return;
          const labels = { created: "Waiting for installation", enrolled: "Enrolled", connected: "Connected", done: "Done", aborted: "Rolled back", expired: "Rolled back: setup code expired" };
          status.textContent = `${labels[session.state] || session.state}${session.error ? `: ${session.error}` : ""}`;
          steps.replaceChildren(...session.steps.map((step) => el("p", { class: step.ok ? "muted" : "error" }, `${step.ok ? "✓" : "✗"} ${step.name}${step.message ? `: ${step.message}` : ""}`)));
          if (["done", "aborted", "expired"].includes(session.state)) { cancel.disabled = true; submit.disabled = false; return; }
        } catch (error) { status.textContent = `Status unavailable: ${error.message}`; }
        if (active && current === generation) timer = setTimeout(poll, 2000);
      };
      output.replaceChildren(el("p", { class: "muted" }, `On the device, run the command. Then paste the setup code. It expires at ${fmtTime(result.expires)}. Keep the code private.`),
        copyField("Command", result.one_liner), copyField("Setup code", result.setup_code), status, steps, cancel);
      await poll();
    } catch (error) { message.textContent = error.message; submit.disabled = false; }
    finally { password.value = ""; }
  } }, el("div", { class: "grid" }, el("label", {}, "Kind", kind), el("label", {}, "Name", name),
    el("label", {}, "Platform", platform), el("label", {}, "Confirm your password", password)), submit, message);
  return el("div", { class: "card" }, el("h2", {}, "Add peer"), form, output);
}

async function page(root) {
  root.append(onboardWizard());
  const [peers, tokens, pulls] = await Promise.all([api("/api/peers"), api("/api/join-tokens"), api("/api/pull-peers")]);
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
        { title: "Version", render: (p) => el("span", {}, p.version || "unknown", p.outdated ? el("span", { class: "pill bad" }, "outdated") : null) },
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
  const pullOut = el("div");
  root.append(pullCard(pulls, pullOut), pullOut);
}

registerView("peers", "Peers", page);
