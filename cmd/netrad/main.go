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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zyvorai/netra/internal/alert"
	"github.com/zyvorai/netra/internal/api"
	"github.com/zyvorai/netra/internal/gitops"
	"github.com/zyvorai/netra/internal/ha"
	"github.com/zyvorai/netra/internal/hubble"
	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/siem"
	"github.com/zyvorai/netra/internal/store"
	"github.com/zyvorai/netra/internal/webhook"
)

const version = "0.27.68"

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

	dispatcher, alertCfg := buildAlerting(log)
	if dispatcher != nil {
		dispatcher.Start(envInt("NETRA_ALERT_WORKERS", 2))
		defer dispatcher.Stop()
	}
	gitopsCfg, gitopsEnabled := buildGitOps()

	stateFile := strings.TrimSpace(os.Getenv("NETRA_STATE_FILE"))
	haEnabled := strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_HA_ENABLED")), "true")
	if haEnabled {
		if stateFile == "" {
			log.Error("HA startup refused", "reason", "NETRA_STATE_FILE is required in HA mode")
			os.Exit(1)
		}
		runHA(ctx, log, k, h, stateFile, dispatcher, alertCfg, gitopsCfg, gitopsEnabled)
		return
	}

	st, err := store.Open(stateFile)
	if err != nil {
		log.Error("state store", "error", err)
		os.Exit(1)
	}
	defer st.Close()

	var gr *gitops.Reconciler
	if gitopsEnabled {
		gr = gitops.New(log, k, st, gitopsCfg)
	}
	handler := api.New(log, k, h, st).WithGitOps(gr).Handler()

	if dispatcher != nil {
		var pollerWG sync.WaitGroup
		pctx, cancel := context.WithCancel(ctx)
		defer cancel()
		pollerWG.Add(1)
		go func() {
			defer pollerWG.Done()
			alert.New(log, st, dispatcher.Publish, alertCfg, k.ListPods).Run(pctx)
		}()
		defer pollerWG.Wait()
	}
	if gr != nil {
		var gitopsWG sync.WaitGroup
		gctx, cancel := context.WithCancel(ctx)
		defer cancel()
		gitopsWG.Add(1)
		go func() {
			defer gitopsWG.Done()
			gr.Run(gctx)
		}()
		defer gitopsWG.Wait()
	}
	var syslogWG sync.WaitGroup
	if stop := startSyslog(ctx, log, st, &syslogWG); stop != nil {
		defer stop()
		defer syslogWG.Wait()
	}

	runHTTP(ctx, log, handler, st.Persistent(), false)
}

// startSyslog starts the optional RFC5424/CEF/JSONL push sink when
// NETRA_SYSLOG_ADDR is set. Off by default. Best-effort; pull export
// still works if the collector is down. Leader-only callers must cancel
// on demote so two replicas never double-ship.
func startSyslog(ctx context.Context, log *slog.Logger, st *store.Store, wg *sync.WaitGroup) func() {
	addr := strings.TrimSpace(os.Getenv("NETRA_SYSLOG_ADDR"))
	if addr == "" || st == nil || wg == nil {
		return nil
	}
	fwd, err := siem.NewForwarder(siem.ForwardConfig{
		Network: env("NETRA_SYSLOG_NETWORK", "udp"),
		Addr:    addr,
		Format:  env("NETRA_SYSLOG_FORMAT", "syslog"),
		Timeout: envDuration("NETRA_SYSLOG_TIMEOUT", 3*time.Second),
	}, log)
	if err != nil {
		log.Error("syslog forwarder config", "error", err)
		os.Exit(1)
	}
	interval := envDuration("NETRA_SYSLOG_INTERVAL", 15*time.Second)
	sctx, cancel := context.WithCancel(ctx)
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("syslog forwarder started", "addr", addr, "interval", interval)
		fwd.Run(sctx, interval, func() []models.AuditEvent {
			return st.Audit(200)
		})
	}()
	return cancel
}

// buildGitOps reads NETRA_GITOPS_DIR/NETRA_GITOPS_AUTO_APPLY/NETRA_GITOPS_INTERVAL.
// An empty NETRA_GITOPS_DIR means GitOps is off — the supported default,
// matching every other optional feature in this codebase.
func buildGitOps() (gitops.Config, bool) {
	dir := strings.TrimSpace(os.Getenv("NETRA_GITOPS_DIR"))
	if dir == "" {
		return gitops.Config{}, false
	}
	return gitops.Config{
		Dir:       dir,
		AutoApply: strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_GITOPS_AUTO_APPLY")), "true"),
		Interval:  envDuration("NETRA_GITOPS_INTERVAL", 60*time.Second),
	}, true
}

// buildAlerting constructs the webhook dispatcher and alert-poller config
// from env vars. It returns a nil dispatcher (alerting fully disabled) when
// NETRA_ALERT_WEBHOOKS is unset, matching the off-by-default convention
// used for every other optional feature in this codebase.
func buildAlerting(log *slog.Logger) (*webhook.Dispatcher, alert.Config) {
	cfg := alert.Config{
		Interval:   envDuration("NETRA_ALERT_POLL_INTERVAL", 30*time.Second),
		Cooldown:   envDuration("NETRA_ALERT_COOLDOWN", 5*time.Minute),
		StaleAfter: envDuration("NETRA_AGENT_STALE_AFTER", 45*time.Second),
		TopN:       envInt("NETRA_ALERT_TOPN", 0),
	}
	raw := strings.TrimSpace(os.Getenv("NETRA_ALERT_WEBHOOKS"))
	if raw == "" {
		return nil, cfg
	}
	sinkCfgs, err := webhook.ParseConfigs(raw)
	if err != nil {
		log.Error("alert webhook config", "error", err)
		os.Exit(1)
	}
	d := webhook.NewDispatcher(envInt("NETRA_ALERT_QUEUE_SIZE", 256))
	for _, sc := range sinkCfgs {
		sink, err := webhook.New(sc)
		if err != nil {
			log.Error("alert webhook sink", "name", sc.Name, "error", err)
			os.Exit(1)
		}
		d.Add(sink)
	}
	return d, cfg
}

func runHA(ctx context.Context, log *slog.Logger, k *kube.Client, h *hubble.Client, stateFile string, dispatcher *webhook.Dispatcher, alertCfg alert.Config, gitopsCfg gitops.Config, gitopsEnabled bool) {
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
	// Tracked (not fire-and-forget) so runHA can wait for electionLoop —
	// and therefore any alert poller it started on this replica's last
	// leadership stint — to fully stop before the caller stops the shared
	// dispatcher, so in-flight alert deliveries aren't cut off mid-shutdown.
	var electionWG sync.WaitGroup
	electionWG.Add(1)
	go func() {
		defer electionWG.Done()
		electionLoop(ctx, log, k, h, gate, stateFile, namespace, leaseName, identity, leaseDuration, renewDeadline, retryPeriod, dispatcher, alertCfg, gitopsCfg, gitopsEnabled)
	}()
	runHTTP(ctx, log, gate, true, true)
	electionWG.Wait()
}

func electionLoop(
	ctx context.Context,
	log *slog.Logger,
	k *kube.Client,
	h *hubble.Client,
	gate *ha.Gate,
	stateFile, namespace, leaseName, identity string,
	leaseDuration, renewDeadline, retryPeriod time.Duration,
	dispatcher *webhook.Dispatcher,
	alertCfg alert.Config,
	gitopsCfg gitops.Config,
	gitopsEnabled bool,
) {
	var st *store.Store
	var lastRenew time.Time
	// pollerCancel/pollerWG (and gitopsCancel/gitopsWG, identically) track
	// the alert poller (and GitOps reconciler) started on this replica's
	// current leadership stint, if any. Tied 1:1 to the store's own
	// open/close lifecycle rather than to ha.Gate, which exposes no "give
	// me the current store" query.
	var pollerCancel func()
	var pollerWG sync.WaitGroup
	var gitopsCancel func()
	var gitopsWG sync.WaitGroup
	var syslogCancel func()
	var syslogWG sync.WaitGroup

	demote := func(reason string) {
		if !gate.IsLeader() {
			return
		}
		gate.Demote()
		if pollerCancel != nil {
			pollerCancel()
			pollerWG.Wait()
			pollerCancel = nil
		}
		if gitopsCancel != nil {
			gitopsCancel()
			gitopsWG.Wait()
			gitopsCancel = nil
		}
		if syslogCancel != nil {
			syslogCancel()
			syslogWG.Wait()
			syslogCancel = nil
		}
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
		var gr *gitops.Reconciler
		if gitopsEnabled {
			gr = gitops.New(log, k, st, gitopsCfg)
		}
		gate.Promote(api.New(log, k, h, st).WithGitOps(gr).Handler())
		if dispatcher != nil {
			pctx, cancel := context.WithCancel(ctx)
			pollerCancel = cancel
			pollerWG.Add(1)
			go func() {
				defer pollerWG.Done()
				alert.New(log, st, dispatcher.Publish, alertCfg, k.ListPods).Run(pctx)
			}()
		}
		if gr != nil {
			gctx, gcancel := context.WithCancel(ctx)
			gitopsCancel = gcancel
			gitopsWG.Add(1)
			go func() {
				defer gitopsWG.Done()
				gr.Run(gctx)
			}()
		}
		if stop := startSyslog(ctx, log, st, &syslogWG); stop != nil {
			syslogCancel = stop
		}
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

func envInt(k string, d int) int {
	if raw := strings.TrimSpace(os.Getenv(k)); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			return parsed
		}
	}
	return d
}
