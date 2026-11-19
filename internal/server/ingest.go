package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"netnoodle/internal/inventory"
	"netnoodle/internal/notify"
	"netnoodle/internal/proto"
	"netnoodle/internal/store"
)

// maxObservation is the largest observation body. An agent report of a
// host with many packages is a few MiB.
const maxObservation = 64 << 20

// Ingest applies one observation and emits events for new devices. It is
// used by the HTTP endpoint and by in-process sources.
func (s *Server) Ingest(ctx context.Context, obs proto.Observation, raw []byte) (inventory.Result, error) {
	res, err := inventory.Ingest(ctx, s.st, obs, raw, s.now())
	if err != nil {
		return res, err
	}
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
	for _, m := range res.Merged {
		s.event(ctx, "device.merged", obs.Source, fmt.Sprintf("device #%d merged into #%d", m[1], m[0]))
	}
	return res, nil
}

// handleObservations is POST /v1/observations for sources and agents.
func (s *Server) handleObservations(w http.ResponseWriter, r *http.Request) {
	p, _ := peerFrom(r.Context())
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxObservation))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
		return
	}
	var obs proto.Observation
	if err := json.Unmarshal(raw, &obs); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid observation: "+err.Error())
		return
	}
	if obs.Version != proto.Version {
		writeErr(w, http.StatusBadRequest, "unsupported version "+strconv.Quote(obs.Version))
		return
	}
	// The source name is the authenticated peer, not what the body says.
	obs.Source = p.Name
	if p.Role == store.RoleAgent {
		// An agent reports about its own host only. The server adds the
		// agent identifier, so an agent cannot claim other devices by it.
		if len(obs.Entities) != 1 {
			writeErr(w, http.StatusBadRequest, "an agent must send exactly one top-level entity")
			return
		}
		e := &obs.Entities[0]
		var ids []proto.Identifier
		for _, id := range e.Identifiers {
			if id.Kind != "agent" {
				ids = append(ids, id)
			}
		}
		e.Identifiers = append(ids, proto.Identifier{Kind: "agent", Value: p.Name, Strength: proto.Strong})
	}
	res, err := s.Ingest(r.Context(), obs, raw)
	if err != nil {
		s.log.Error("ingest", "peer", p.Name, "err", err)
		writeErr(w, http.StatusInternalServerError, "ingest failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"devices": len(res.Devices), "new": len(res.New), "merged": len(res.Merged), "skipped": res.Skipped,
	})
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
	writeJSON(w, http.StatusOK, d)
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
