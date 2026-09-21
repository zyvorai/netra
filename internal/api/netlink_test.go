// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/store"
)

func nlEvent(seq uint64, kind, action string, at time.Time) models.NetlinkEvent {
	return models.NetlinkEvent{Epoch: 1, Sequence: seq, Kind: kind, Action: action, ObservedAt: at}
}

func nlServer(now time.Time) *Server {
	st := store.New()
	snap := &models.NetlinkSnapshot{Links: []models.NetlinkLink{{Index: 1, Name: "lo"}}}
	st.Report(models.AgentReport{Node: "worker-1", ObservedAt: now, Netlink: &models.NetlinkReport{
		Available: true, Epoch: 1, Sequence: 3, Cursor: 3, Snapshot: snap,
		Counts: models.NetlinkCounts{Links: 1}, Overruns: 1, Totals: map[string]uint64{"route": 2, "link": 1},
		Events: []models.NetlinkEvent{
			nlEvent(1, "route", "delete", now.Add(-2*time.Hour)),
			nlEvent(2, "route", "new", now.Add(-10*time.Minute)),
			nlEvent(3, "link", "new", now.Add(-5*time.Minute)),
		},
	}})
	st.Report(models.AgentReport{Node: "worker-2", ObservedAt: now, Netlink: &models.NetlinkReport{
		Available: true, Epoch: 9, Sequence: 1, Cursor: 1,
		Events: []models.NetlinkEvent{nlEvent(1, "neighbor", "new", now.Add(-time.Minute))},
	}})
	st.Report(models.AgentReport{Node: "off-node", ObservedAt: now})
	return &Server{store: st, agentStaleAfter: time.Minute}
}

func nlGet(t *testing.T, s *Server, query string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.netlinkChanges(rec, httptest.NewRequest("GET", "/api/v1/netlink"+query, nil))
	var body map[string]any
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("bad json: %v: %s", err, rec.Body.String())
		}
	}
	return rec.Code, body
}

func TestNetlinkEventsAreTimeOrderedFilteredAndCrossNode(t *testing.T) {
	now := time.Now().UTC()
	s := nlServer(now)
	code, body := nlGet(t, s, "?since=30m")
	if code != 200 {
		t.Fatalf("status=%d", code)
	}
	ev := body["events"].([]any)
	// The two-hour-old route delete is outside since=30m; the rest interleave by time.
	if len(ev) != 3 {
		t.Fatalf("events=%v", ev)
	}
	first := ev[0].(map[string]any)
	last := ev[2].(map[string]any)
	if first["kind"] != "route" || first["node"] != "worker-1" || last["kind"] != "neighbor" || last["node"] != "worker-2" {
		t.Fatalf("not time-ordered with node attribution: %v", ev)
	}
	_, body = nlGet(t, s, "?since=3h&kind=route")
	if got := len(body["events"].([]any)); got != 2 {
		t.Fatalf("kind filter: %d events", got)
	}
	_, body = nlGet(t, s, "?since=3h&limit=1")
	if got := body["events"].([]any); len(got) != 1 || got[0].(map[string]any)["kind"] != "neighbor" {
		t.Fatalf("limit must keep the newest: %v", got)
	}
	_, body = nlGet(t, s, "?since=3h&node=worker-2")
	if got := len(body["events"].([]any)); got != 1 {
		t.Fatalf("node filter: %d", got)
	}
}

func TestNetlinkViewsAndNodeStates(t *testing.T) {
	s := nlServer(time.Now().UTC())
	_, body := nlGet(t, s, "")
	nodes := body["nodes"].([]any)
	if len(nodes) != 3 {
		t.Fatalf("nodes=%v", nodes)
	}
	byName := map[string]map[string]any{}
	for _, n := range nodes {
		m := n.(map[string]any)
		byName[m["node"].(string)] = m
	}
	if byName["worker-1"]["reporting"] != true || byName["worker-1"]["overruns"].(float64) != 1 {
		t.Fatalf("worker-1=%v", byName["worker-1"])
	}
	if _, has := byName["worker-1"]["snapshot"]; has {
		t.Fatal("the default view must not ship every node's full snapshot")
	}
	if byName["off-node"]["reporting"] != false || byName["off-node"]["unavailable"] == "" {
		t.Fatalf("a node without the recorder must say so: %v", byName["off-node"])
	}
	if byName["worker-1"]["historySince"] == nil {
		t.Fatal("historySince (the blind-spot edge) missing")
	}

	_, state := nlGet(t, s, "?view=state")
	if _, has := state["events"]; has {
		t.Fatal("view=state must not include events")
	}
	for _, n := range state["nodes"].([]any) {
		m := n.(map[string]any)
		if m["node"] == "worker-1" && m["snapshot"] == nil {
			t.Fatal("view=state must include the snapshot")
		}
	}
	_, all := nlGet(t, s, "?view=all")
	if all["events"] == nil {
		t.Fatal("view=all must include events")
	}
}

func TestNetlinkRejectsBadInput(t *testing.T) {
	s := nlServer(time.Now().UTC())
	for _, q := range []string{"?kind=bogus", "?view=bogus", "?limit=0", "?limit=99999", "?limit=x", "?since=yesterday"} {
		if code, _ := nlGet(t, s, q); code != http.StatusBadRequest {
			t.Errorf("%s: status=%d, want 400", q, code)
		}
	}
	if code, _ := nlGet(t, s, "?since=2026-09-21T10:00:00Z&kind=ROUTE"); code != 200 {
		t.Errorf("RFC3339 since and an upper-case kind must be accepted: %d", code)
	}
}

func TestNetlinkAggregateAndMetricsUseFreshReportingNodesOnly(t *testing.T) {
	agents := []models.AgentStatus{
		{AgentReport: models.AgentReport{Node: "a", Netlink: &models.NetlinkReport{
			Available: true, Overruns: 2, Dropped: 5, Suppressed: 7, Resubscribes: 2,
			Totals: map[string]uint64{"route": 10, "overrun": 2}, Counts: models.NetlinkCounts{Links: 3, Routes: 40},
		}}},
		{AgentReport: models.AgentReport{Node: "b", Netlink: &models.NetlinkReport{
			Available: true, Totals: map[string]uint64{"route": 1}, Counts: models.NetlinkCounts{Links: 2},
		}}},
		{AgentReport: models.AgentReport{Node: "old"}},
		{AgentReport: models.AgentReport{Node: "blind", Netlink: &models.NetlinkReport{Unavailable: "no rtnl"}}},
		{AgentReport: models.AgentReport{Node: "gone", Netlink: &models.NetlinkReport{Available: true, Overruns: 999}}, Stale: true},
	}
	v := aggregateNetlink(agents)
	if v.Reporting != 2 || v.NotReporting != 2 || v.Overruns != 2 || v.Events["route"] != 11 || v.Counts.Links != 5 {
		t.Fatalf("aggregate=%+v", v)
	}
	rec := httptest.NewRecorder()
	writeNetlinkMetrics(rec, agents)
	out := rec.Body.String()
	for _, want := range []string{
		"netra_netlink_nodes_reporting 2", "netra_netlink_nodes_not_reporting 2",
		`netra_netlink_events{kind="route"} 11`, `netra_netlink_events{kind="link"} 0`,
		"netra_netlink_overruns 2", "netra_netlink_routes 40",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "999") {
		t.Error("a stale node leaked into the metrics")
	}
	// Cardinality guard: no label other than the fixed kind set.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "netra_netlink") && strings.Contains(line, "{") && !strings.Contains(line, "{kind=") {
			t.Errorf("unexpected label on %q", line)
		}
	}
}

func TestNetlinkMetricsAreAbsentNotZeroWhenNothingReports(t *testing.T) {
	rec := httptest.NewRecorder()
	writeNetlinkMetrics(rec, []models.AgentStatus{{AgentReport: models.AgentReport{Node: "old"}}})
	out := rec.Body.String()
	if !strings.Contains(out, "netra_netlink_nodes_not_reporting 1") || strings.Contains(out, "netra_netlink_overruns") {
		t.Fatalf("metrics=%s", out)
	}
}
