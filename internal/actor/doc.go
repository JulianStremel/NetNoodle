// Package actor runs signed, locally permitted orders through configured backends.
//
// Safety and recovery contract (D-055 through D-059)
//
// Only an order marked Revert whose action is a configured capability's
// RevertAction bypasses the hourly limit. Merely setting Revert on a forward
// action is invalid. Backend selection matches action, identifier kind and every
// target's TargetScope. Scopes are kind=glob patterns; empty means unrestricted.
// A literal source/* includes nested guest identifiers such as source/cluster/id.
// Host capabilities are scoped to agent=<agent>; PVE to proxmox.guest=<source>/*.
// UniFi has unrestricted MAC scope; the local allowlist still applies to all.
//
// A failure after sending a mutation wraps ErrPossiblyApplied, yielding the wire
// status uncertain and a "possibly applied: ..." message. This includes failed
// verification and transport errors: receipt of an error does not prove that the
// system was unchanged. Until the server accepts explicit uncertain results, its
// existing sent-order expiry -> uncertain -> precautionary revert path (D-058)
// covers these orders. Result messages are valid UTF-8 and at most 4000 bytes.
// Upstream bodies, HTTP reason phrases, stderr and arbitrary API rc strings are
// never included. Only fixed diagnostics and numeric HTTP/command codes escape.
// PVE task IDs are returned only if they match the strict UPID grammar in
// pveactor; otherwise a successful snapshot reports "task started".
//
// The runner injects a shared Journal through JournalAware.SetJournal before
// executing orders. The file is <nonce_file>.journal, next to the nonce/outbox
// files. Intent and prior state are saved before mutation by atomic private-file
// replacement, file fsync and directory fsync on Unix, using the nonce store's
// durable writer. Failed persistence prevents the mutation. Entries are keyed by
// order ID and bound to backend, target and action; they are pruned on open/write
// 48 hours after expiry. One actor process must exclusively own these files.
// Keep backend names stable across restarts so journal bindings continue to match.
//
// PVE records already-down NICs and the NICs it changes; RevertOf enables only
// the latter. Missing history uses the documented recovery fallback: remove
// link_down from all netN and report "no journal entry; all links enabled".
// Isolation refuses PCI/USB passthrough and netdev args on QEMU, lxc.net.* and
// devN on LXC, and pending netN edits. Both reads use current=1; verification
// compares NIC options independently of ordering and treats absent link_down
// like link_down=0. Snapshot creation first counts nn-* snapshots against
// max_snapshots (default 3). never_isolate must contain the management, router
// and VPN guests. An empty list refuses startup unless
// allow_empty_never_isolate is explicitly true.
//
// UniFi adds and logs all local interface MACs to never_block at startup. Also
// configure the controller host and nn-server host MACs in never_block or in
// protect_macs_file (an optional whitespace-separated list of 48-bit MACs).
// Already-blocked clients are journaled as pre-existing and left blocked by both
// isolate and its RevertOf; a prior-state read failure prevents isolation.
//
// Host defaults never_block_ports to [22, 7444] when omitted; an explicit empty
// list overrides this protection. Both input (priority -10) and prerouting
// (priority -150, before DNAT) accept loopback and established/related traffic
// before dropping TCP/UDP ports in the timeout sets. This preserves replies to
// outbound actor connections and covers Docker/k8s published ports. Existing
// established connections remain accepted. Port holders are journaled until
// min(order TTL, max_ttl), with TTL 0 using max_ttl. The element is refreshed to
// the latest unexpired holder's expiry; a revert releases its holder and removes
// the element only when no other active holder remains. An unbound/manual
// unblock also respects active holders. stop-service records whether the unit
// was active, and its RevertOf starts it only if it was active before the stop.
// Service operations still require explicit unit permissions and root/polkit;
// the supplied service unit authorizes nftables port actions only.
package actor
