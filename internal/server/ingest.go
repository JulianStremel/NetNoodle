package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/JulianStremel/netnoodle/internal/inventory"
	"github.com/JulianStremel/netnoodle/internal/notify"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

// maxObservation is the largest observation body. An agent report of a
// host with many packages is a few MiB.
const maxObservation = 64 << 20

// maxStoredRaw is the largest raw observation kept for audit. Larger
// payloads are recorded as a size note only.
const maxStoredRaw = 2 << 20

// maxNewDeviceEvents is the number of single "device.new" events per
// observation. Above it, one summary event is sent.
const maxNewDeviceEvents = 20

// Ingest applies one observation of a source and emits events for new
// devices. It is used by in-process sources.
func (s *Server) Ingest(ctx context.Context, obs proto.Observation, raw []byte) (inventory.Result, error) {
	inventory.StripAgentIDs(obs.Entities)
	return s.ingestAs(ctx, obs, raw, "")
}

// ingestAs applies an observation; agent is the agent peer name or "".
func (s *Server) ingestAs(ctx context.Context, obs proto.Observation, raw []byte, agent string) (inventory.Result, error) {
	if len(raw) > maxStoredRaw {
		raw = []byte(fmt.Sprintf(`{"note":"payload not stored","bytes":%d}`, len(raw)))
	}
	res, err := inventory.IngestAs(ctx, s.st, obs, raw, s.now(), agent)
	if err != nil {
		return res, err
	}
	if len(res.New) > maxNewDeviceEvents {
		s.emit(ctx, notify.Event{
			Type:     "device.new",
			Severity: "info",
			Title:    fmt.Sprintf("%d new devices from %s", len(res.New), obs.Source),
			Link:     "#/devices",
			Fields:   map[string]string{"source": obs.Source},
		}, obs.Source, "")
	} else {
		for _, nd := range res.New {
			var ids []string
			for _, id := range nd.Identifiers {
				ids = append(ids, id.Kind+"="+id.Value)
			}
			name := nd.Name
			if name == "" {
				name = "device #" + strconv.FormatInt(nd.ID, 10)
			}
			data, _ := json.Marshal(nd)
			s.emit(ctx, notify.Event{
				Type:     "device.new",
				Severity: "info",
				Title:    "New device: " + name,
				Detail:   strings.Join(ids, ", "),
				Link:     "#/devices/" + strconv.FormatInt(nd.ID, 10),
				Fields:   map[string]string{"source": nd.Source, "kind": string(nd.Kind)},
			}, nd.Source, string(data))
		}
	}
	for _, id := range res.Claimed {
		data, _ := json.Marshal(map[string]any{"device_id": id})
		// An agent took over a device that other sources had found. This
		// is normal for a new agent, but it is also what a rogue agent
		// would do; make it visible (security review 2026-11-20).
		s.emit(ctx, notify.Event{
			Type:     "device.claimed",
			Severity: "warning",
			Title:    fmt.Sprintf("Agent %s took over device #%d", obs.Source, id),
			Detail:   "An agent report now describes a device that other sources found first. Check that this agent runs on that device.",
			Link:     "#/devices/" + strconv.FormatInt(id, 10),
			Fields:   map[string]string{"source": obs.Source},
		}, obs.Source, string(data))
	}
	for _, m := range res.Merged {
		s.event(ctx, "device.merged", obs.Source, fmt.Sprintf("device #%d merged into #%d", m[1], m[0]))
	}
	for _, m := range res.MergeRefused {
		data, _ := json.Marshal(map[string]any{"kept": m[0], "other": m[1], "source": obs.Source})
		s.emit(ctx, notify.Event{
			Type:     "device.merge_refused",
			Severity: "warning",
			Title:    fmt.Sprintf("%s reports devices #%d and #%d as one device", obs.Source, m[0], m[1]),
			Detail:   "They were not merged because one of them is described by an agent or has tags. If the source data is wrong, a device may report identifiers that are not its own.",
			Link:     "#/devices/" + strconv.FormatInt(m[0], 10),
			Fields:   map[string]string{"source": obs.Source},
		}, obs.Source, string(data))
	}
	if hasComponents(obs.Entities) || len(res.Merged) > 0 {
		s.enqueueMatch(res.Devices...)
	}
	return res, nil
}

// handleObservations is POST /v1/observations for sources and agents.
func (s *Server) handleObservations(w http.ResponseWriter, r *http.Request) {
	p, _ := peerFrom(r.Context())
	if !s.peerRate.allow(strconv.FormatInt(p.ID, 10), s.now()) {
		writeErr(w, http.StatusTooManyRequests, "too many observations from this peer")
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "body too large or too slow")
		return
	}
	res, code, err := s.acceptObservation(r.Context(), p, raw)
	if err != nil {
		writeErr(w, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"devices": len(res.Devices), "new": len(res.New), "merged": len(res.Merged), "skipped": res.Skipped,
	})
}

// errIngest hides internal ingest errors from peers.
var errIngest = errors.New("ingest failed")

// acceptObservation checks and ingests one raw observation of peer p
// (pushed or pulled). On error it returns an HTTP status for the peer.
func (s *Server) acceptObservation(ctx context.Context, p store.Peer, raw []byte) (inventory.Result, int, error) {
	var obs proto.Observation
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&obs); err != nil {
		return inventory.Result{}, http.StatusBadRequest, fmt.Errorf("invalid observation: %w", err)
	}
	if dec.More() {
		return inventory.Result{}, http.StatusBadRequest, errors.New("invalid observation: data after the JSON object")
	}
	if obs.Version != proto.Version {
		return inventory.Result{}, http.StatusBadRequest, errors.New("unsupported version " + strconv.Quote(obs.Version))
	}
	if n := inventory.CountEntities(obs.Entities); n > inventory.MaxEntities {
		return inventory.Result{}, http.StatusRequestEntityTooLarge, fmt.Errorf("too many entities (%d, maximum %d)", n, inventory.MaxEntities)
	}
	// The source name is the authenticated peer, not what the body says.
	obs.Source = p.Name
	agent := ""
	if p.Role == store.RoleAgent {
		// An agent reports about its own host only. The server sets the
		// agent identifier; the agent cannot claim or merge other devices.
		if err := inventory.PrepareAgent(&obs, p.Name); err != nil {
			return inventory.Result{}, http.StatusBadRequest, err
		}
		agent = p.Name
	} else {
		inventory.StripAgentIDs(obs.Entities)
	}
	if p.Role == store.RoleAgent && len(obs.Entities) > 0 {
		if v := obs.Entities[0].Attributes["agent.version"]; v != "" {
			if len(v) > 128 {
				return inventory.Result{}, http.StatusBadRequest, errors.New("version too long")
			}
			if err := s.st.SetPeerVersion(ctx, p.ID, v); err != nil {
				return inventory.Result{}, http.StatusInternalServerError, errIngest
			}
		}
	}
	res, err := s.ingestAs(ctx, obs, raw, agent)
	if err != nil {
		s.log.Error("ingest", "peer", p.Name, "err", err)
		return res, http.StatusInternalServerError, errIngest
	}
	return res, http.StatusOK, nil
}

// --- operator API for devices ---

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	ds, err := s.st.ListDevices(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if ds == nil {
		ds = []store.DeviceRow{}
	}
	writeJSON(w, http.StatusOK, ds)
}

func (s *Server) handleGetDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	d, err := s.st.GetDevice(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such device")
		return
	}
	devs, err := s.st.ListDevices(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	row := store.DeviceRow{ID: d.ID, Name: d.Name, Attributes: d.Attributes, Interfaces: d.Interfaces}
	for _, id := range d.IDs {
		row.Identifiers = append(row.Identifiers, id.Identifier)
	}
	reach := classifyDevice(row, routedNetworks(devs))
	writeJSON(w, http.StatusOK, struct {
		store.DeviceDetail
		Reach         string   `json:"reach"`
		ReachEvidence []string `json:"reach_evidence"`
	}{d, reach.level, reach.evidence})
}

func (s *Server) handleRenameDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil || len(req.Name) > 255 {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := s.st.RenameDevice(r.Context(), id, inventory.CleanText(req.Name, 255)); err != nil {
		writeErr(w, http.StatusNotFound, "no such device")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{})
}
