package server

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JulianStremel/netnoodle/internal/pull"
	"github.com/JulianStremel/netnoodle/internal/store"
)

// Pull mode settings (docs/design/pull-mode.md).
const (
	pullTick        = 30 * time.Second
	pullParallel    = 4
	pullMinInterval = time.Minute
	pullDefault     = time.Hour
	pairCodeTTL     = 24 * time.Hour
	pairRetry       = time.Minute
	pullRetryMax    = 15 * time.Minute
)

type pullState struct {
	mu         sync.Mutex
	transports map[string]pull.Transport
	clientFP   string // fingerprint of the pull client certificate
	inflight   map[int64]bool
	kick       chan struct{}
}

func newPullState() *pullState {
	return &pullState{transports: map[string]pull.Transport{}, inflight: map[int64]bool{}, kick: make(chan struct{}, 1)}
}

// SetPull installs the pull transports and the fingerprint of the client
// certificate that pull agents pin.
func (s *Server) SetPull(transports map[string]pull.Transport, clientFP string) {
	s.pull.mu.Lock()
	defer s.pull.mu.Unlock()
	s.pull.transports, s.pull.clientFP = transports, clientFP
}

func (s *Server) kickPull() {
	select {
	case s.pull.kick <- struct{}{}:
	default:
	}
}

// RunPull polls due pull peers until ctx ends.
func (s *Server) RunPull(ctx context.Context) {
	t := time.NewTicker(pullTick)
	defer t.Stop()
	sem := make(chan struct{}, pullParallel)
	for {
		s.pullDue(ctx, sem)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.pull.kick:
		}
	}
}

func (s *Server) pullDue(ctx context.Context, sem chan struct{}) {
	due, err := s.st.DuePullPeers(ctx, s.now())
	if err != nil {
		s.log.Error("pull: list peers", "err", err)
		return
	}
	for _, p := range due {
		s.pull.mu.Lock()
		busy := s.pull.inflight[p.ID]
		if !busy {
			s.pull.inflight[p.ID] = true
		}
		s.pull.mu.Unlock()
		if busy {
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			// All slots are busy (slow agents). Try again at the next
			// tick instead of blocking the scheduler.
			s.pull.mu.Lock()
			delete(s.pull.inflight, p.ID)
			s.pull.mu.Unlock()
			return
		}
		go func() {
			defer func() {
				<-sem
				s.pull.mu.Lock()
				delete(s.pull.inflight, p.ID)
				s.pull.mu.Unlock()
			}()
			s.pullOne(ctx, p)
		}()
	}
}

// jitter returns d ±10 %.
func jitter(d time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d/5)+1))
	if err != nil {
		return d
	}
	return d - d/10 + time.Duration(n.Int64())
}

// shortErr keeps stored error texts small.
func shortErr(err error) string {
	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return msg
}

// pullOne pairs (if needed) and pulls one peer, and records the result.
func (s *Server) pullOne(ctx context.Context, p store.PullPeer) {
	s.pull.mu.Lock()
	tr := s.pull.transports[p.Transport]
	s.pull.mu.Unlock()
	now := s.now()
	fail := func(next time.Duration, err error) {
		_ = s.st.SetPullResult(ctx, p.ID, false, now, now.Add(next), shortErr(err))
	}
	if tr == nil {
		fail(pullRetryMax, fmt.Errorf("unknown transport %q", p.Transport))
		return
	}
	target := pull.Target{Name: p.Name, Address: p.Address, Pin: p.Pin}
	if p.Pin == "" {
		if p.PairCode == "" || now.After(p.PairExpires) {
			// Nothing to do until the operator makes a new code.
			fail(pullRetryMax, errors.New("not paired and the pairing code expired: make a new pairing code"))
			return
		}
		pin, err := tr.Pair(ctx, target, p.PairCode)
		if err != nil {
			fail(pairRetry, fmt.Errorf("pairing: %w", err))
			return
		}
		if err := s.st.SetPin(ctx, p.ID, p.PairCode, pin); err != nil {
			fail(pairRetry, errors.New("pairing: the code changed during pairing"))
			return
		}
		s.event(ctx, "peer.paired", p.Name, "pull agent "+p.Name+" paired, certificate "+pin)
		target.Pin = pin
	}
	raw, err := tr.Pull(ctx, target)
	if err != nil {
		fail(min(max(p.Interval/4, pullMinInterval), pullRetryMax), err)
		return
	}
	if _, _, err := s.acceptObservation(ctx, p.Peer, raw); err != nil {
		fail(p.Interval, err)
		return
	}
	_ = s.st.TouchPeer(ctx, p.ID, now)
	_ = s.st.SetPullResult(ctx, p.ID, true, now, now.Add(jitter(p.Interval)), "")
}

// newPairCode returns 20 random bytes in base32 without padding.
func newPairCode() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// --- operator API ---

type pullView struct {
	store.PullPeer
	Paired   bool   `json:"paired"`
	Interval string `json:"interval"`
}

func viewPull(p store.PullPeer) pullView {
	return pullView{PullPeer: p, Paired: p.Pin != "", Interval: p.Interval.String()}
}

type pairInfo struct {
	Peer    pullView  `json:"peer"`
	Code    string    `json:"code"`
	Expires time.Time `json:"expires"`
	Command string    `json:"command"`
}

func (s *Server) pairInfo(p store.PullPeer) pairInfo {
	s.pull.mu.Lock()
	fp := s.pull.clientFP
	s.pull.mu.Unlock()
	return pairInfo{
		Peer: viewPull(p), Code: p.PairCode, Expires: p.PairExpires,
		// The code goes in the environment, not on the command line, where
		// other local users could read it from the process list.
		Command: "NN_PAIR_CODE=" + p.PairCode + " nn-agent pair --server-fingerprint " + fp + " --listen " + p.Address,
	}
}

func (s *Server) handleListPullPeers(w http.ResponseWriter, r *http.Request) {
	ps, err := s.st.ListPullPeers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]pullView, 0, len(ps))
	for _, p := range ps {
		out = append(out, viewPull(p))
	}
	s.pull.mu.Lock()
	fp := s.pull.clientFP
	s.pull.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"peers": out, "client_fingerprint": fp})
}

func (s *Server) handleCreatePullPeer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Address  string `json:"address"`
		Interval string `json:"interval"`
	}
	if err := readJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	req.Name, req.Address = strings.TrimSpace(req.Name), strings.TrimSpace(req.Address)
	if !peerNameRE.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+peerNameRE.String())
		return
	}
	if s.reserved[strings.ToLower(req.Name)] {
		writeErr(w, http.StatusConflict, "this name is reserved")
		return
	}
	if err := pull.ValidAddress(req.Address); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	interval := pullDefault
	if req.Interval != "" {
		d, err := time.ParseDuration(req.Interval)
		if err != nil || d < pullMinInterval || d > 7*24*time.Hour {
			writeErr(w, http.StatusBadRequest, "interval must be a duration from 1m to 168h")
			return
		}
		interval = d
	}
	now := s.now()
	p, err := s.st.CreatePullPeer(r.Context(), store.PullPeer{
		Peer:      store.Peer{Name: req.Name},
		Transport: "https", Address: req.Address, Interval: interval,
		PairCode: newPairCode(), PairExpires: now.Add(pairCodeTTL), NextPull: now.Add(pairRetry),
	}, HashToken(RandomToken(32)), now)
	if errors.Is(err, store.ErrConflict) {
		writeErr(w, http.StatusConflict, "a peer with this name exists already")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	u, _ := userFrom(r.Context())
	s.event(r.Context(), "peer.pull.created", u.Name, "pull agent "+p.Name+" at "+p.Address+" created")
	writeJSON(w, http.StatusOK, s.pairInfo(p))
}

func (s *Server) handleNewPairCode(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	now := s.now()
	if err := s.st.SetPairCode(r.Context(), id, newPairCode(), now.Add(pairCodeTTL), now.Add(pairRetry)); err != nil {
		writeErr(w, http.StatusNotFound, "no such pull agent")
		return
	}
	p, err := s.st.GetPullPeer(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such pull agent")
		return
	}
	u, _ := userFrom(r.Context())
	s.event(r.Context(), "peer.pull.unpaired", u.Name, "pull agent "+p.Name+": new pairing code, pinned certificate removed")
	writeJSON(w, http.StatusOK, s.pairInfo(p))
}

func (s *Server) handlePullNow(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := s.st.SetNextPull(r.Context(), id, s.now()); err != nil {
		writeErr(w, http.StatusNotFound, "no such pull agent")
		return
	}
	s.kickPull()
	writeJSON(w, http.StatusOK, map[string]string{"id": strconv.FormatInt(id, 10)})
}
