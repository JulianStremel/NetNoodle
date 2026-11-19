// Package epss enriches vulnerabilities with FIRST's exploit prediction scores.
package epss

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"netnoodle/internal/intel"
	"netnoodle/internal/registry"
	"netnoodle/internal/tlspin"
)

const defaultURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

// Limits against a broken or hostile feed: the real file is about 15 MB
// uncompressed with about 300k rows.
const (
	maxDownload     = 64 << 20
	maxDecompressed = 256 << 20
	maxRows         = 2000000
)

func init() { intel.Enrichers.Register("epss", New) }

// Settings configures the scores endpoint.
type Settings struct {
	URL string `json:"url"`
}

type prediction struct {
	score, pct float32
}

type enricher struct {
	name string
	url  string
	c    *http.Client
	mu   sync.RWMutex
	data map[string]prediction
	date string
}

// New builds an EPSS enricher. An empty URL selects FIRST's daily feed.
func New(name string, raw json.RawMessage) (intel.Enricher, error) {
	var s Settings
	if err := registry.Decode(raw, &s); err != nil {
		return nil, err
	}
	if s.URL == "" {
		s.URL = defaultURL
	}
	return &enricher{name: name, url: s.URL, c: &http.Client{Timeout: 120 * time.Second, CheckRedirect: tlspin.HTTPSRedirects}}, nil
}

func (e *enricher) Name() string { return e.name }

func (e *enricher) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.url, nil)
	if err != nil {
		return fmt.Errorf("epss request: %w", err)
	}
	req.Header.Set("User-Agent", "netnoodle")
	res, err := e.c.Do(req)
	if err != nil {
		return fmt.Errorf("epss download: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("epss download returned %s", res.Status)
	}
	reader := bufio.NewReader(io.LimitReader(res.Body, maxDownload))
	if magic, _ := reader.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return fmt.Errorf("epss gzip: %w", err)
		}
		defer gz.Close()
		reader = bufio.NewReader(io.LimitReader(gz, maxDecompressed))
	}
	var date string
	if first, _ := reader.Peek(1); len(first) == 1 && first[0] == '#' {
		comment, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("epss comment: %w", err)
		}
		for _, field := range strings.Split(strings.TrimPrefix(comment, "#"), ",") {
			key, value, _ := strings.Cut(strings.TrimSpace(field), ":")
			if key == "score_date" {
				date = strings.TrimSpace(value)
			}
		}
	}
	csvReader := csv.NewReader(reader)
	csvReader.FieldsPerRecord = 3
	header, err := csvReader.Read()
	if err != nil {
		return fmt.Errorf("epss header: %w", err)
	}
	if header[0] != "cve" || header[1] != "epss" || header[2] != "percentile" {
		return fmt.Errorf("epss unexpected header %q", header)
	}
	data := make(map[string]prediction)
	for {
		row, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("epss CSV: %w", err)
		}
		if len(data) >= maxRows {
			return fmt.Errorf("epss feed has more than %d rows", maxRows)
		}
		if len(row[0]) > 32 {
			return fmt.Errorf("epss invalid CVE %.40q", row[0])
		}
		if !strings.HasPrefix(row[0], "CVE-") || len(row[0]) <= 4 {
			return fmt.Errorf("epss invalid CVE %q", row[0])
		}
		score, err := probability(row[1])
		if err != nil {
			return fmt.Errorf("epss score for %s: %w", row[0], err)
		}
		pct, err := probability(row[2])
		if err != nil {
			return fmt.Errorf("epss percentile for %s: %w", row[0], err)
		}
		data[row[0]] = prediction{score: score, pct: pct}
	}
	if len(data) == 0 || (e.url == defaultURL && len(data) < 1000) {
		return fmt.Errorf("epss feed has too few entries: %d", len(data))
	}
	e.mu.Lock()
	e.data, e.date = data, date
	e.mu.Unlock()
	return nil
}

func probability(value string) (float32, error) {
	n, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, err
	}
	if math.IsNaN(n) || n < 0 || n > 1 {
		return 0, fmt.Errorf("invalid probability %q", value)
	}
	return float32(n), nil
}

func (e *enricher) Enrich(v *intel.Vuln) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var selected prediction
	found := false
	for _, cve := range v.CVEs() {
		if item, ok := e.data[cve]; ok && (!found || item.score > selected.score) {
			selected, found = item, true
		}
	}
	if found {
		v.EPSS, v.EPSSPct = float64(selected.score), float64(selected.pct)
		if e.date != "" {
			v.SetFact("epss.date", e.date)
		}
	}
}
