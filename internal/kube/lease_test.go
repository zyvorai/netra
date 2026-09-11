package kube

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeLeaseAPI struct {
	mu    sync.Mutex
	lease *leaseDocument
	rv    int
}

func (f *fakeLeaseAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !strings.Contains(r.URL.Path, "/leases") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		if f.lease == nil {
			http.Error(w, `{"reason":"NotFound"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(f.lease)
	case http.MethodPost:
		if f.lease != nil {
			http.Error(w, `{"reason":"Conflict"}`, http.StatusConflict)
			return
		}
		var x leaseDocument
		if err := json.NewDecoder(r.Body).Decode(&x); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		f.rv++
		x.Metadata.ResourceVersion = strconv.Itoa(f.rv)
		f.lease = &x
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(x)
	case http.MethodPut:
		if f.lease == nil {
			http.Error(w, `{"reason":"NotFound"}`, http.StatusNotFound)
			return
		}
		var x leaseDocument
		if err := json.NewDecoder(r.Body).Decode(&x); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if x.Metadata.ResourceVersion != f.lease.Metadata.ResourceVersion {
			http.Error(w, `{"reason":"Conflict"}`, http.StatusConflict)
			return
		}
		f.rv++
		x.Metadata.ResourceVersion = strconv.Itoa(f.rv)
		f.lease = &x
		_ = json.NewEncoder(w).Encode(x)
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func TestLeaseAcquireRenewReleaseAndTakeover(t *testing.T) {
	api := &fakeLeaseAPI{}
	ts := httptest.NewServer(api)
	defer ts.Close()
	c := &Client{base: ts.URL, http: ts.Client()}
	ctx := context.Background()

	ok, err := c.TryAcquireOrRenewLease(ctx, "netra", "controller", "pod-a", 15*time.Second)
	if err != nil || !ok {
		t.Fatalf("acquire: ok=%v err=%v", ok, err)
	}
	ok, err = c.TryAcquireOrRenewLease(ctx, "netra", "controller", "pod-b", 15*time.Second)
	if err != nil || ok {
		t.Fatalf("second holder must not acquire live lease: ok=%v err=%v", ok, err)
	}
	ok, err = c.TryAcquireOrRenewLease(ctx, "netra", "controller", "pod-a", 15*time.Second)
	if err != nil || !ok {
		t.Fatalf("renew: ok=%v err=%v", ok, err)
	}
	if err := c.ReleaseLease(ctx, "netra", "controller", "pod-a"); err != nil {
		t.Fatal(err)
	}
	ok, err = c.TryAcquireOrRenewLease(ctx, "netra", "controller", "pod-b", 15*time.Second)
	if err != nil || !ok {
		t.Fatalf("takeover after release: ok=%v err=%v", ok, err)
	}
}

func TestLeaseExpiredHolderCanBeTakenOver(t *testing.T) {
	api := &fakeLeaseAPI{}
	ts := httptest.NewServer(api)
	defer ts.Close()
	c := &Client{base: ts.URL, http: ts.Client()}

	now := time.Now().UTC().Add(-time.Minute)
	var old leaseDocument
	old.APIVersion = "coordination.k8s.io/v1"
	old.Kind = "Lease"
	old.Metadata.Name = "controller"
	old.Metadata.Namespace = "netra"
	old.Metadata.ResourceVersion = "1"
	old.Spec.HolderIdentity = "dead-pod"
	old.Spec.LeaseDurationSeconds = 10
	old.Spec.AcquireTime = now.Format(time.RFC3339Nano)
	old.Spec.RenewTime = now.Format(time.RFC3339Nano)
	api.lease = &old
	api.rv = 1

	ok, err := c.TryAcquireOrRenewLease(context.Background(), "netra", "controller", "pod-b", 15*time.Second)
	if err != nil || !ok {
		t.Fatalf("expired takeover: ok=%v err=%v", ok, err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if api.lease.Spec.HolderIdentity != "pod-b" || api.lease.Spec.LeaseTransitions != 1 {
		t.Fatalf("lease after takeover: %#v", api.lease.Spec)
	}
}
