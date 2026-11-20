package server

import (
	"bytes"
	"context"
	"encoding/json"
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
	for _, m := range res.Merged {
		s.event(ctx, "device.merged", obs.Source, fmt.Sprintf("device #%d merged into #%d", m[1], m[0]))
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
	var obs proto.Observation
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&obs); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid observation: "+err.Error())
		return
	}
	if obs.Version != proto.Version {
		writeErr(w, http.StatusBadRequest, "unsupported version "+strconv.Quote(obs.Version))
		return
	}
	if n := inventory.CountEntities(obs.Entities); n > inventory.MaxEntities {
		writeErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("too many entities (%d, maximum %d)", n, inventory.MaxEntities))
		return
	}
	// The source name is the authenticated peer, not what the body says.
	obs.Source = p.Name
	agent := ""
	if p.Role == store.RoleAgent {
		// An agent reports about its own host only. The server sets the
		// agent identifier; the agent cannot claim or merge other devices.
		if err := inventory.PrepareAgent(&obs, p.Name); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		agent = p.Name
	} else {
		inventory.StripAgentIDs(obs.Entities)
	}
	res, err := s.ingestAs(r.Context(), obs, raw, agent)
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
