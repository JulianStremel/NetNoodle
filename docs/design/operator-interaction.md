# Operator interaction: how netnoodle asks a person

Status: design (2026-11-20); decisions of the user in section 9.

netnoodle works alone most of the time. Some events need a person: a decision, a confirmation, or an action on a device. This document sets one strategy for all of them, so that the operator gets the right message at the right time on the right device, and so that silence never becomes consent.

## 1. Principles

1. **Silence is never consent.** If nobody answers, the safe default happens (usually: nothing changes, the request expires). No decision is approved by a timeout.
2. **One inbox.** Every open request is in one list in the web interface ("Needs you"), with a count in the sidebar. A notification is only a pointer to that list.
3. **Decide where you are authenticated.** A notification opens the request in the web interface (deep link). The decision needs a login; dangerous decisions need the password again (step-up). A broker, a chat service or a webhook receiver can never approve.
4. **Urgency decides the channel, not the event type.**
5. **Every decision is recorded:** who, when, from which request, with what reason.

## 2. What needs a person (request types)

| Request | Today | Default when nobody answers | Urgency |
|---|---|---|---|
| Approve or reject an action (proposal `pending`) | Actions page | expires after 7 days, no action | P2; P1 if KEV and reachable from the internet or tunnel |
| Order result uncertain / revert blocked / action failed | event | stays visible until acknowledged | P1 |
| Agent took over a device (`device.claimed`) | event, approval hold 30 days | no automatic action on the device for 30 days | P2 |
| Devices not merged (`device.merge_refused`) | event | stay separate | P3 |
| Kill switch on (manual or automatic) | Actions page | stays on | P1 |
| Update available / scheduled / failed / rolled back | System page | no update without a click (or scheduled window) | P3 / P1 on failure |
| Onboarding session waiting for the device | Peers wizard | session expires after 30 min, rollback | live (wizard) |
| Actor capabilities changed (planned, actor pinning) | — | actor not used until confirmed | P2 |
| New device, new finding | event | none (information) | P3 |
| Notification channel broken | — | banner in the web interface | P2 |

## 3. Urgency levels

- **P1 now:** sent at once on all configured urgent channels, also in quiet hours. Reminder every hour if not acknowledged, at most 3. Examples: action failed or uncertain, kill switch, KEV exposed to the internet, update failed.
- **P2 today:** sent at once on the normal channel, not in quiet hours (held until they end). One reminder after 24 hours, one before expiry.
- **P3 digest:** collected and sent once a day (time configurable) as a summary; always visible in the web interface.

## 4. Channels

| Channel | Use | Status |
|---|---|---|
| Web interface (inbox, badge, banner) | always | partly (Actions page) |
| Home Assistant via MQTT (**first**) | phone notification through the HA companion app, with action buttons; HA automations | events exist (generic titles); actionable notifications and the response relay: planned |
| ntfy (self-hosted or ntfy.sh) | simple phone push with a "View" button (deep link) | planned |
| Webhook / Slack format | chat channels, other tools | exists |
| Telegram bot (**second**, user request) | phone push from an externally hosted service; inline buttons for decisions | planned |
| E-mail (SMTP) | digest, P1 fallback | planned |

**No inbound path (user decision).** netnoodle must not need a reverse proxy or an open port to get answers from outside the network. A channel that carries answers back is a **response relay**: netnoodle keeps an outbound connection to it and reads the answers. Home Assistant: the companion app button goes through HA's own remote connection (for example Nabu Casa) to HA; an HA automation (generated blueprint) publishes the answer to the MQTT topic `<prefix>/decision`; netnoodle reads it on its existing outbound MQTT connection. Telegram (second channel, user request): netnoodle sends with the Bot API (`sendMessage`, inline keyboard) and reads button presses with `getUpdates` long polling, outbound only; no webhook, so no inbound port. Settings: `bot_token_file` (secret), `chat_ids` (allow list; answers from other chats are ignored and logged), `event_details` (default off: generic titles without device names, because messages pass through Telegram). A button carries only the request ID and the decision token (callback data, at most 64 bytes); the server checks the token as for every relay. Later relays with the same interface: ntfy.sh (subscribe). The deep link to the web interface works only where the web interface is reachable (home network, VPN, Tailscale).

Each channel is a notifier plug-in (registry `notify`), with `urgency_min` (lowest urgency it gets), `quiet_hours`, and `digest: true|false`. A **Send test** button checks a channel. A channel that fails 3 times in a row creates a P2 request "notification channel broken" (shown as a banner, because the channel cannot report itself).

## 5. Messages

- Title without secrets; device names only where the channel is private (MQTT keeps generic titles unless `event_details`).
- Body: what, why (rule, CVSS, KEV, reachability), what happens if nobody answers and when, deep link `https://<server>/#/inbox/<id>`.
- Deduplication: one message per request; updates of the same request edit/replace when the channel supports it (ntfy, HA tag), else a short "update" message. Bursts are grouped (already done for proposals: at most 20 details per state).

## 6. Deciding

- From the inbox or the deep link: **Approve**, **Reject**, **Snooze** (P2/P3: 1 h, 1 day), **Acknowledge** (P1 results).
- Approve of an action, kill switch off, join token / onboarding, update and rollback: password again (step-up). The approval shows the exact target snapshot; if the targets change before the click, the server refuses and shows the new snapshot (planned fix from the review).
- Mobile: the inbox and decision pages work on a phone (no wide tables).
- **Approve from the notification (user decision: optional per action).** Off by default. The operator allows it per action type (for example `block-port` with TTL); never for devices tagged `protected`, never for infrastructure devices (UniFi devices, `never_block`/`never_isolate` targets), never for actions without a revert or TTL, never for kill switch off, updates or tokens. The notification carries a decision token: single-use, valid 10 minutes, bound to the request ID, the action and the hash of the target snapshot (HMAC with a server key). The relay returns `{request, decision, token}`; the server accepts it only if the token is valid and unused, the request is still open and the snapshot hash still matches. The relay itself (HA, broker, ntfy) can never decide without a token, and a token cannot be used for another request. "Reject" and "Snooze" from the notification need the same token. Every use is in the history with the channel name.

## 7. Nobody answers

- Requests expire with the safe default of section 2. The expiry is an event (P3) and in the history.
- P1 reminders stop after 3; the request stays open in the inbox.
- If all channels fail, the web interface banner is the last resort; the dashboard shows "N requests waiting".

## 8. Later: more than one person

Roles `viewer`, `approver`, `admin`; requests can be assigned; "four eyes" (a second approver) as an option for `isolate` of protected or infrastructure devices. Not in the first version (one admin today).

## 9. Decisions of the user (2026-11-20)

1. First channel: **Home Assistant** (companion app), then **Telegram**; pluggable for others later. No reverse proxy: answers come back over an outbound relay (section 4).
2. Approve from the notification: **optional per action** (section 6).
3. Quiet hours **22:00-07:00**, digest **08:00** (defaults, configurable).
4. P1 reminders: **every hour, at most 3**.

## 10. Order of work

1. Inbox model (one table of requests with type, urgency, state, expiry, link; built from the existing events and proposals) and the "Needs you" page with badge.
2. Notifier options `urgency_min`, `quiet_hours`, `digest`; digest job; reminders; channel health banner; Send test.
3. Home Assistant actionable notifications (generated HA automation blueprint) with deep links; then the Telegram notifier (send first, inline-button answers with the relay of step 4).
4. Response relay on MQTT and decision tokens (approve from notification, per action).
