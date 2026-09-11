// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zyvorai/netra/internal/api"
	"github.com/zyvorai/netra/internal/ha"
	"github.com/zyvorai/netra/internal/hubble"
	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/store"
)

const version = "0.13.0"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	allowUnauthenticated := strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_ALLOW_UNAUTHENTICATED")), "true")
	if !allowUnauthenticated {
		if strings.TrimSpace(os.Getenv("NETRA_API_KEY")) == "" || strings.TrimSpace(os.Getenv("NETRA_AGENT_KEY")) == "" {
			log.Error("secure startup refused", "reason", "NETRA_API_KEY and NETRA_AGENT_KEY are required unless NETRA_ALLOW_UNAUTHENTICATED=true")
			os.Exit(1)
		}
	} else {
		log.Warn("unauthenticated development mode enabled")
	}

	k, err := kube.NewFromEnvironment()
	if err != nil {
		log.Error("kubernetes client", "error", err)
		os.Exit(1)
	}
	h, err := hubble.NewFromEnvironment()
	if err != nil {
		log.Error("hubble client", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	stateFile := strings.TrimSpace(os.Getenv("NETRA_STATE_FILE"))
	haEnabled := strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_HA_ENABLED")), "true")
	if haEnabled {
		if stateFile == "" {
			log.Error("HA startup refused", "reason", "NETRA_STATE_FILE is required in HA mode")
			os.Exit(1)
		}
		runHA(ctx, log, k, h, stateFile)
		return
	}

	st, err := store.Open(stateFile)
	if err != nil {
		log.Error("state store", "error", err)
		os.Exit(1)
	}
	defer st.Close()
	handler := api.New(log, k, h, st).Handler()
	runHTTP(ctx, log, handler, st.Persistent(), false)
}

func runHA(ctx context.Context, log *slog.Logger, k *kube.Client, h *hubble.Client, stateFile string) {
	identity := strings.TrimSpace(os.Getenv("NETRA_POD_NAME"))
	if identity == "" {
		identity, _ = os.Hostname()
	}
	if identity == "" {
		identity = "netra-unknown"
	}
	namespace := env("NETRA_NAMESPACE", "netra")
	leaseName := env("NETRA_HA_LEASE_NAME", "netra-controller")
	leaseDuration := envDuration("NETRA_HA_LEASE_DURATION", 15*time.Second)
	renewDeadline := envDuration("NETRA_HA_RENEW_DEADLINE", 10*time.Second)
	retryPeriod := envDuration("NETRA_HA_RETRY_PERIOD", 2*time.Second)
	if retryPeriod <= 0 || renewDeadline <= retryPeriod || leaseDuration <= renewDeadline {
		log.Error("invalid HA timing", "leaseDuration", leaseDuration, "renewDeadline", renewDeadline, "retryPeriod", retryPeriod)
		os.Exit(1)
	}

	gate := ha.NewGate(identity, version)
	go electionLoop(ctx, log, k, h, gate, stateFile, namespace, leaseName, identity, leaseDuration, renewDeadline, retryPeriod)
	runHTTP(ctx, log, gate, true, true)
}

func electionLoop(
	ctx context.Context,
	log *slog.Logger,
	k *kube.Client,
	h *hubble.Client,
	gate *ha.Gate,
	stateFile, namespace, leaseName, identity string,
	leaseDuration, renewDeadline, retryPeriod time.Duration,
) {
	var st *store.Store
	var lastRenew time.Time

	demote := func(reason string) {
		if !gate.IsLeader() {
			return
		}
		gate.Demote()
		if st != nil {
			if err := st.Close(); err != nil {
				log.Error("close leader state", "error", err)
			}
			st = nil
		}
		log.Warn("controller demoted", "identity", identity, "reason", reason)
	}
	defer func() {
		demote("shutdown")
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := k.ReleaseLease(c, namespace, leaseName, identity); err != nil {
			log.Warn("release leader lease", "error", err)
		}
	}()

	attempt := func() {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		acquired, err := k.TryAcquireOrRenewLease(c, namespace, leaseName, identity, leaseDuration)
		cancel()
		if err != nil {
			log.Warn("leader lease renewal failed", "error", err)
			if gate.IsLeader() && !lastRenew.IsZero() && time.Since(lastRenew) >= renewDeadline {
				demote("renew deadline exceeded")
			}
			return
		}
		if !acquired {
			demote("lease held by another replica")
			return
		}
		lastRenew = time.Now()
		if gate.IsLeader() {
			return
		}

		opened, err := store.Open(stateFile)
		if err != nil {
			log.Warn("lease acquired but shared state lock unavailable", "error", err)
			c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = k.ReleaseLease(c, namespace, leaseName, identity)
			cancel()
			return
		}
		st = opened
		gate.Promote(api.New(log, k, h, st).Handler())
		log.Info("controller promoted", "identity", identity, "lease", namespace+"/"+leaseName, "stateFile", stateFile)
	}

	attempt()
	ticker := time.NewTicker(retryPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			attempt()
		}
	}
}

func runHTTP(ctx context.Context, log *slog.Logger, handler http.Handler, persistent, haMode bool) {
	s := &http.Server{
		Addr:              env("NETRA_LISTEN", ":30870"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = s.Shutdown(c)
	}()
	certFile := strings.TrimSpace(os.Getenv("NETRA_TLS_CERT"))
	keyFile := strings.TrimSpace(os.Getenv("NETRA_TLS_KEY"))
	tlsOn := certFile != "" && keyFile != ""
	log.Info("netrad starting", "addr", s.Addr, "version", version, "persistentState", persistent, "ha", haMode, "tls", tlsOn)
	var err error
	if tlsOn {
		err = s.ListenAndServeTLS(certFile, keyFile)
	} else {
		err = s.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server", "error", err)
	}
}

func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}

func envDuration(k string, d time.Duration) time.Duration {
	if raw := strings.TrimSpace(os.Getenv(k)); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			return parsed
		}
	}
	return d
}
