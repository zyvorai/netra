// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package rtnlactor

import (
	"testing"
	"time"

	"github.com/zyvorai/netra/internal/models"
)

var t0 = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

func at(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }

// joiner starts long before the changes under test, so "the sensor just started"
// never masks what a test is about.
func joiner() *Joiner { return newJoiner(nil, t0.Add(-time.Hour)) }

func rec(tgid uint32, comm string, typ uint16, ifindex uint32, ms int) Record {
	return Record{TGID: tgid, PID: tgid, Comm: comm, Type: typ, IfIndex: ifindex, CgroupID: 100 + uint64(tgid), Wall: at(ms)}
}

func route(action string, ms int) models.NetlinkEvent {
	return models.NetlinkEvent{Kind: models.NetlinkKindRoute, Action: action, ObservedAt: at(ms), Destination: "10.9.0.0/24"}
}

func onLink(kind, action string, idx, ms int) models.NetlinkEvent {
	return models.NetlinkEvent{Kind: kind, Action: action, InterfaceIndex: idx, ObservedAt: at(ms)}
}

func TestOneRequesterIsAProbableActorWithItsPod(t *testing.T) {
	j := newJoiner(func(cg uint64) (string, string, string, bool) {
		if cg == 100+42 {
			return "kube-system", "calico-node-x", "calico-node", true
		}
		return "", "", "", false
	}, t0.Add(-time.Hour))
	j.Add(rec(42, "calico-node", RTMDelRoute, 0, 1000))
	a, origin := j.Attribute(route("delete", 1030))
	if origin != models.NetlinkOriginProcess || a == nil || a.Confidence != models.NetlinkActorProbable {
		t.Fatalf("actor=%+v origin=%q", a, origin)
	}
	if a.Comm != "calico-node" || a.PID != 42 || a.Namespace != "kube-system" || a.Pod != "calico-node-x" || a.Workload != "calico-node" {
		t.Fatalf("actor=%+v", a)
	}
	// A host process has no pod.
	j.Add(rec(7, "ip", RTMNewRoute, 0, 5000))
	a, _ = j.Attribute(route("new", 5020))
	if a.Comm != "ip" || a.Pod != "" || a.Namespace != "" {
		t.Fatalf("host process: %+v", a)
	}
}

func TestTheRequestTypeMustMatchTheChange(t *testing.T) {
	j := joiner()
	j.Add(rec(1, "ip", RTMNewRoute, 0, 1000))
	// A route was DELETED; an add request does not explain it.
	if a, origin := j.Attribute(route("delete", 1020)); a != nil || origin != models.NetlinkOriginKernel {
		t.Fatalf("a mismatched type was attributed: %+v %q", a, origin)
	}
	// A link "new" is explained by NEWLINK or SETLINK.
	j.Add(rec(2, "ip", RTMSetLink, 5, 2000))
	if a, _ := j.Attribute(onLink(models.NetlinkKindLink, "new", 5, 2020)); a == nil || a.Comm != "ip" {
		t.Fatalf("SETLINK must explain a link change: %+v", a)
	}
	j.Add(rec(3, "ip", RTMDelLink, 6, 3000))
	if a, _ := j.Attribute(onLink(models.NetlinkKindLink, "delete", 6, 3020)); a == nil {
		t.Fatal("DELLINK must explain a link deletion")
	}
	if a, origin := j.Attribute(onLink(models.NetlinkKindLink, "new", 6, 3020)); a != nil || origin != models.NetlinkOriginKernel {
		t.Fatalf("a deletion request must not explain a link that appeared: %+v %q", a, origin)
	}
}

func TestTheTimeWindowHasEdges(t *testing.T) {
	cases := []struct {
		name    string
		reqAt   int
		matches bool
	}{
		{"request 700 ms before the notification", 300, true},
		{"request 800 ms before: too old", 200, false},
		{"request 50 ms after (read before the record)", 1050, true},
		{"request 200 ms after: too late", 1200, false},
	}
	for _, c := range cases {
		j := joiner()
		j.Add(rec(1, "ip", RTMNewRoute, 0, c.reqAt))
		a, origin := j.Attribute(route("new", 1000))
		if (a != nil) != c.matches {
			t.Errorf("%s: matched=%v origin=%q", c.name, a != nil, origin)
		}
	}
}

func TestARequestForAnotherInterfaceDoesNotExplainThisOne(t *testing.T) {
	j := joiner()
	// ip link set <peer> down: the kernel then takes the far end's carrier away.
	j.Add(rec(1, "ip", RTMSetLink, 7, 1000))
	if a, origin := j.Attribute(onLink(models.NetlinkKindLink, "new", 5, 1020)); a != nil || origin != models.NetlinkOriginKernel {
		t.Fatalf("the carrier loss on ifindex 5 was credited to a request for ifindex 7: %+v %q", a, origin)
	}
	if a, _ := j.Attribute(onLink(models.NetlinkKindLink, "new", 7, 1020)); a == nil {
		t.Fatal("the request for ifindex 7 must explain the change on ifindex 7")
	}
	// A link create names no interface (ifindex 0), so it explains any.
	j2 := joiner()
	j2.Add(rec(2, "ip", RTMNewLink, 0, 1000))
	if a, _ := j2.Attribute(onLink(models.NetlinkKindLink, "new", 9, 1020)); a == nil {
		t.Fatal("a create request (no ifindex) must match")
	}
	// An event with no interface index cannot be ruled out either.
	j3 := joiner()
	j3.Add(rec(3, "ip", RTMSetLink, 7, 1000))
	if a, _ := j3.Attribute(onLink(models.NetlinkKindLink, "new", 0, 1020)); a == nil {
		t.Fatal("an event without an ifindex must not be ruled out by the interface check")
	}
}

func TestABatchFromOneProcessIsOneActor(t *testing.T) {
	j := joiner()
	for i := 0; i < 500; i++ {
		j.Add(rec(9, "ip", RTMNewRoute, 0, 1000+i%50))
	}
	a, _ := j.Attribute(route("new", 1040))
	if a == nil || a.Confidence != models.NetlinkActorProbable || a.Candidates != 1 {
		t.Fatalf("a batch from one process must be one probable actor: %+v", a)
	}
}

func TestSeveralRequestersAreAmbiguousAndNoneIsNamed(t *testing.T) {
	j := joiner()
	j.Add(rec(1, "kubelet", RTMNewRoute, 0, 1000))
	j.Add(rec(2, "calico-node", RTMNewRoute, 0, 1010))
	j.Add(rec(3, "calico-node", RTMNewRoute, 0, 1020)) // a second process with the same name
	a, origin := j.Attribute(route("new", 1030))
	if origin != models.NetlinkOriginProcess || a == nil || a.Confidence != models.NetlinkActorAmbiguous || a.Candidates != 3 {
		t.Fatalf("actor=%+v origin=%q", a, origin)
	}
	if a.Comm != "" || a.PID != 0 || a.Pod != "" {
		t.Fatalf("an ambiguous match must not name a process: %+v", a)
	}
	if len(a.Alternatives) != 2 || a.Alternatives[0] != "calico-node" || a.Alternatives[1] != "kubelet" {
		t.Fatalf("alternatives=%v", a.Alternatives)
	}
	// The list is bounded.
	j2 := joiner()
	for i, c := range []string{"a", "b", "c", "d", "e"} {
		j2.Add(rec(uint32(i+1), c, RTMNewRoute, 0, 1000))
	}
	a, _ = j2.Attribute(route("new", 1010))
	if a.Candidates != 5 || len(a.Alternatives) != 3 {
		t.Fatalf("candidates=%d alternatives=%v", a.Candidates, a.Alternatives)
	}
}

func TestKernelOriginIsOnlyClaimedWhenTheSensorCouldHaveSeenARequest(t *testing.T) {
	// The sensor started 200 ms before the change: a request from before that would not be in the ring.
	fresh := newJoiner(nil, at(800))
	if a, origin := fresh.Attribute(route("new", 1000)); a != nil || origin != "" {
		t.Fatalf("claimed kernel origin 200 ms after start: %q", origin)
	}
	// A drop near the change: the missing request may be the dropped one.
	dropped := joiner()
	dropped.NoteDropped(3, at(500))
	if _, origin := dropped.Attribute(route("new", 1000)); origin != "" {
		t.Fatalf("claimed kernel origin next to a ring-buffer drop: %q", origin)
	}
	// The same drop long ago no longer matters.
	if _, origin := dropped.Attribute(route("new", 60_000)); origin != models.NetlinkOriginKernel {
		t.Fatalf("a drop a minute ago must not block the claim: %q", origin)
	}
	// Drop counter unchanged is not a new drop.
	dropped.NoteDropped(3, at(59_000))
	if _, origin := dropped.Attribute(route("new", 60_000)); origin != models.NetlinkOriginKernel {
		t.Fatalf("an unchanged drop counter was treated as a fresh drop: %q", origin)
	}
	// The ring wrapped: its oldest request is newer than the window, so a match could have been evicted.
	wrapped := joiner()
	for i := 0; i < maxRecords+10; i++ {
		wrapped.Add(rec(uint32(i+1), "x", RTMNewNeigh, 0, 2000)) // all at 2 s
	}
	if _, origin := wrapped.Attribute(route("new", 2100)); origin != "" {
		t.Fatalf("claimed kernel origin with a ring that no longer reaches back: %q", origin)
	}
}

func TestChangesNoRequestCanExplainAreLeftAlone(t *testing.T) {
	j := joiner()
	if a, origin := j.Attribute(models.NetlinkEvent{Kind: models.NetlinkKindOverrun, Action: "lost", ObservedAt: at(1000)}); a != nil || origin != "" {
		t.Fatalf("the recorder's own overrun is not a network change: %+v %q", a, origin)
	}
	if a, origin := j.Attribute(models.NetlinkEvent{Kind: models.NetlinkKindRoute, Action: "new"}); a != nil || origin != "" {
		t.Fatalf("an event with no time cannot be joined: %+v %q", a, origin)
	}
}

func TestStatusCountsRecordsAndDrops(t *testing.T) {
	j := joiner()
	j.Add(rec(1, "ip", RTMNewRoute, 0, 1))
	j.Add(rec(1, "ip", RTMNewRoute, 0, 2))
	j.NoteDropped(4, at(3))
	s := j.Status()
	if !s.Available || s.Records != 2 || s.Dropped != 4 {
		t.Fatalf("status=%+v", s)
	}
}
