package storetest

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/JulianStremel/netnoodle/internal/intel"
	"github.com/JulianStremel/netnoodle/internal/proto"
	"github.com/JulianStremel/netnoodle/internal/store"
)

func testFindingsSyncFiltersExposureAndStats(t *testing.T, open func(*testing.T) store.Store) {
	st, ctx, now := open(t), context.Background(), time.Now().UTC()
	entity := proto.Entity{Kind: proto.KindHost, Name: "web", Identifiers: []proto.Identifier{strong("serial", "web")}}
	var vulns []intel.Vuln
	var findings []store.Finding
	for i, score := range []float64{9.5, 8, 5, 2, 0} {
		purl, vuln := fmt.Sprintf("pkg:generic/p%d@1", i), fmt.Sprintf("CVE-%d", i)
		entity.Components = append(entity.Components, proto.Component{PURL: purl, Name: fmt.Sprint("p", i), Version: "1"})
		vulns = append(vulns, intel.Vuln{ID: vuln, Score: score, KEV: i == 0, Summary: vuln})
		findings = append(findings, store.Finding{PURL: purl, VulnID: vuln, Fixed: "2", Confidence: "high"})
		address := "127.0.0.1"
		if i == 0 {
			address = "0.0.0.0"
		}
		if i == 1 {
			address = "::1"
		}
		entity.Services = append(entity.Services, proto.Service{Port: 80 + i, Proto: "tcp", Address: address, Component: purl})
	}
	id := ingest(t, st, "scan", now, true, entity).Devices[0]
	other := ingest(t, st, "scan", now, true, proto.Entity{Identifiers: []proto.Identifier{strong("serial", "other")}}).Devices[0]
	must(t, st.PutVulns(ctx, vulns, now))
	opened, err := st.SyncFindings(ctx, id, "matcher", append(findings, findings[0]), now)
	must(t, err)
	if len(opened) != 5 {
		t.Fatalf("new findings: %+v", opened)
	}
	opened, err = st.SyncFindings(ctx, id, "matcher", findings, now.Add(time.Minute))
	must(t, err)
	if len(opened) != 0 {
		t.Fatal("unchanged findings reopened", opened)
	}
	_, err = st.SyncFindings(ctx, other, "other-matcher", findings[:1], now)
	must(t, err)
	rows, err := st.ListFindings(ctx, store.FindingFilter{DeviceID: id})
	must(t, err)
	if len(rows) != 5 || rows[0].VulnID != "CVE-0" || !reflect.DeepEqual(rows[0].Exposed, []string{"80/tcp"}) || rows[0].Package != "p0" || rows[0].Fixed != "2" {
		t.Fatal(rows)
	}
	for _, row := range rows[1:] {
		if len(row.Exposed) != 0 {
			t.Fatalf("loopback service exposed: %+v", row)
		}
	}
	for _, tc := range []struct {
		filter store.FindingFilter
		want   int
	}{
		{store.FindingFilter{DeviceID: id, MinScore: 7}, 2},
		{store.FindingFilter{DeviceID: id, KEV: true}, 1},
		{store.FindingFilter{DeviceID: other}, 1},
		{store.FindingFilter{Limit: 2}, 2},
		{store.FindingFilter{State: "resolved"}, 0},
	} {
		rows, err := st.ListFindings(ctx, tc.filter)
		must(t, err)
		if len(rows) != tc.want {
			t.Fatalf("filter %+v: got %d want %d", tc.filter, len(rows), tc.want)
		}
	}
	stats, err := st.FindingStats(ctx)
	must(t, err)
	want := store.FindingStats{Open: 6, Critical: 2, High: 1, Medium: 1, Low: 1, Unknown: 1, KEV: 2, Exposed: 1, Devices: 2, Vulns: 5}
	if stats != want {
		t.Fatalf("stats %+v, want %+v", stats, want)
	}
	ids, err := st.OpenVulnIDs(ctx, id)
	must(t, err)
	if len(ids) != 5 {
		t.Fatal(ids)
	}
	// Sync is scoped to the device and matcher, including resolution.
	_, err = st.SyncFindings(ctx, id, "independent", findings[:1], now)
	must(t, err)
	resolvedAt := now.Add(2 * time.Minute)
	_, err = st.SyncFindings(ctx, id, "matcher", nil, resolvedAt)
	must(t, err)
	rows, err = st.ListFindings(ctx, store.FindingFilter{DeviceID: id, State: "resolved"})
	must(t, err)
	if len(rows) != 5 {
		t.Fatal(rows)
	}
	for _, row := range rows {
		if !row.FirstSeen.Equal(now) || !row.ResolvedAt.Equal(resolvedAt) {
			t.Fatal(row)
		}
	}
	rows, err = st.ListFindings(ctx, store.FindingFilter{})
	must(t, err)
	if len(rows) != 2 {
		t.Fatalf("sync affected another source/device: %+v", rows)
	}
	opened, err = st.SyncFindings(ctx, id, "matcher", findings[:1], now.Add(3*time.Minute))
	must(t, err)
	if len(opened) != 1 {
		t.Fatal(opened)
	}
	rows, err = st.ListFindings(ctx, store.FindingFilter{DeviceID: id, State: "all"})
	must(t, err)
	if len(rows) != 6 {
		t.Fatal(rows)
	}
	for _, row := range rows {
		if row.Source == "matcher" && row.VulnID == "CVE-0" && (row.State != "open" || !row.ResolvedAt.IsZero() || !row.FirstSeen.Equal(now) || !row.LastSeen.Equal(now.Add(3*time.Minute))) {
			t.Fatal(row)
		}
	}
	stats, err = st.FindingStats(ctx)
	must(t, err)
	if stats.Open != 3 || stats.Critical != 3 || stats.Exposed != 2 || stats.Devices != 2 || stats.Vulns != 1 {
		t.Fatal(stats)
	}
}
