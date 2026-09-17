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
	"github.com/zyvorai/netra/internal/capture"
	"github.com/zyvorai/netra/internal/dnsdetect"
	"github.com/zyvorai/netra/internal/gitops"
	"github.com/zyvorai/netra/internal/ha"
	"github.com/zyvorai/netra/internal/hubble"
	"github.com/zyvorai/netra/internal/kube"
	"github.com/zyvorai/netra/internal/models"
	"github.com/zyvorai/netra/internal/notify"
	"github.com/zyvorai/netra/internal/scandetect"
	"github.com/zyvorai/netra/internal/siem"
	"github.com/zyvorai/netra/internal/snowflakesink"
	"github.com/zyvorai/netra/internal/store"
	"github.com/zyvorai/netra/internal/sysctlaudit"
)

const version = "0.27.96"

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
	artifacts := buildArtifactStore(log)
	gitopsCfg, gitopsEnabled := buildGitOps()

	stateFile := strings.TrimSpace(os.Getenv("NETRA_STATE_FILE"))
	haEnabled := strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_HA_ENABLED")), "true")
	if haEnabled {
		if stateFile == "" {
			log.Error("HA startup refused", "reason", "NETRA_STATE_FILE is required in HA mode")
			os.Exit(1)
		}
		runHA(ctx, log, k, h, stateFile, dispatcher, alertCfg, artifacts, gitopsCfg, gitopsEnabled)
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
	dnsDet, dnsInterval, dnsEnabled := buildDNSDetect()
	scanDet, scanInterval, scanEnabled := buildScanDetect()
	handler := api.New(log, k, h, st).WithGitOps(gr).WithDNSDetect(dnsDet).WithScanDetect(scanDet).WithArtifacts(artifacts).Handler()

	if shouldRunAlertPoller(dispatcher) {
		var pollerWG sync.WaitGroup
		pctx, cancel := context.WithCancel(ctx)
		defer cancel()
		pollerWG.Add(1)
		go func() {
			defer pollerWG.Done()
			newAlertPoller(log, st, dispatcher, alertCfg, k.ListPods).Run(pctx)
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
	var snowflakeWG sync.WaitGroup
	if stop := startSnowflake(ctx, log, st, &snowflakeWG); stop != nil {
		defer stop()
		defer snowflakeWG.Wait()
	}
	staleAfter := envDuration("NETRA_AGENT_STALE_AFTER", 45*time.Second)
	if dnsEnabled {
		var dnsWG sync.WaitGroup
		dctx, cancel := context.WithCancel(ctx)
		defer cancel()
		dnsWG.Add(1)
		go func() {
			defer dnsWG.Done()
			log.Info("dns-detect started", "interval", dnsInterval)
			dnsDet.Run(dctx, dnsInterval, func() []models.AgentStatus { return st.AgentStatuses(time.Now(), staleAfter) })
		}()
		defer dnsWG.Wait()
	}
	if scanEnabled {
		var scanWG sync.WaitGroup
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()
		scanWG.Add(1)
		go func() {
			defer scanWG.Done()
			log.Info("scan-detect started", "interval", scanInterval)
			scanDet.Run(sctx, scanInterval, func() []models.AgentStatus { return st.AgentStatuses(time.Now(), staleAfter) })
		}()
		defer scanWG.Wait()
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

// sysctlExportDefaultTopN is the default row cap for the sysctl-audit
// Snowflake export. It is deliberately much larger than
// sysctlaudit.Build's own HTTP-handler default of 50 (see
// internal/api/server.go's ebpfSysctlAudit) — that default sizes an
// operator-facing HTTP page, and reusing it here would silently
// truncate findings per node, contradicting this export's contract of
// pushing the full current snapshot every tick.
const sysctlExportDefaultTopN = 100000

// startSnowflake starts the optional audit-event export sink when
// NETRA_SNOWFLAKE_ACCOUNT is set. Off by default. Same optional-feature
// shape as startSyslog: env-var gated, best-effort per flush, and
// leader-only in HA mode so two replicas never double-ship. Unlike
// startSyslog, this dials Snowflake and creates the target table once
// at startup, so a bad account/credential/warehouse config fails fast
// here — matching NETRA_API_KEY's fail-closed startup check — rather
// than being discovered later as a stream of failed-flush warnings.
//
// When NETRA_SNOWFLAKE_SYSCTL_ENABLED is also set, a second export loop
// runs alongside the audit loop, reusing the same Snowflake connection
// to push sysctl-audit findings into their own table. See
// docs/snowflake-export.md for why that table carries no watermark.
func startSnowflake(ctx context.Context, log *slog.Logger, st *store.Store, wg *sync.WaitGroup) func() {
	account := strings.TrimSpace(os.Getenv("NETRA_SNOWFLAKE_ACCOUNT"))
	if account == "" || st == nil || wg == nil {
		return nil
	}
	extraCols, err := snowflakesink.ParseExtraColumns(env("NETRA_SNOWFLAKE_EXTRA_COLUMNS", ""))
	if err != nil {
		log.Error("snowflake extra columns config", "error", err)
		os.Exit(1)
	}
	cfg := snowflakesink.Config{
		Account:        account,
		User:           env("NETRA_SNOWFLAKE_USER", ""),
		PrivateKeyPath: env("NETRA_SNOWFLAKE_PRIVATE_KEY_PATH", ""),
		Warehouse:      env("NETRA_SNOWFLAKE_WAREHOUSE", ""),
		Database:       env("NETRA_SNOWFLAKE_DATABASE", ""),
		Schema:         env("NETRA_SNOWFLAKE_SCHEMA", ""),
		Table:          env("NETRA_SNOWFLAKE_TABLE", "NETRA_AUDIT"),
		BatchSize:      envInt("NETRA_SNOWFLAKE_BATCH_SIZE", 50),
		ExtraColumns:   extraCols,
	}
	sink, err := snowflakesink.New(ctx, cfg, log)
	if err != nil {
		log.Error("snowflake sink config", "error", err)
		os.Exit(1)
	}
	interval := envDuration("NETRA_SNOWFLAKE_INTERVAL", 15*time.Second)
	sctx, cancel := context.WithCancel(ctx)

	// inner tracks only the export loops below, so sink.Close() (which
	// closes the *sql.DB both loops share) runs strictly after both have
	// fully returned regardless of goroutine scheduling order — without
	// this, one loop returning and closing the shared DB while the other
	// is still mid-flush would be a use-after-close race.
	var inner sync.WaitGroup

	inner.Add(1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer inner.Done()
		log.Info("snowflake sink started", "account", account, "table", cfg.Table, "interval", interval, "extraColumns", len(cfg.ExtraColumns))
		sink.Run(sctx, interval, func() []models.AuditEvent {
			return st.Audit(200)
		})
	}()

	if strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_SNOWFLAKE_SYSCTL_ENABLED")), "true") {
		sysctlCfg := snowflakesink.SysctlConfig{
			Table:     env("NETRA_SNOWFLAKE_SYSCTL_TABLE", "NETRA_SYSCTL_AUDIT"),
			BatchSize: envInt("NETRA_SNOWFLAKE_SYSCTL_BATCH_SIZE", 50),
		}
		sysctlSink, err := sink.NewSysctlSink(ctx, sysctlCfg)
		if err != nil {
			log.Error("snowflake sysctl sink config", "error", err)
			os.Exit(1)
		}
		sysctlInterval := envDuration("NETRA_SNOWFLAKE_SYSCTL_INTERVAL", 30*time.Second)
		staleAfter := envDuration("NETRA_AGENT_STALE_AFTER", 45*time.Second)
		topN := envInt("NETRA_SNOWFLAKE_SYSCTL_TOPN", sysctlExportDefaultTopN)

		inner.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer inner.Done()
			log.Info("snowflake sysctl sink started", "table", sysctlCfg.Table, "interval", sysctlInterval)
			sysctlSink.Run(sctx, sysctlInterval, func() models.SysctlAuditResponse {
				return sysctlaudit.Build(st.AgentStatuses(time.Now(), staleAfter), topN)
			})
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		inner.Wait()
		sink.Close()
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

// buildAlerting constructs the notify dispatcher and alert-poller config
// from env vars. Prefer NETRA_ALERT_CHANNELS; fall back to legacy
// NETRA_ALERT_WEBHOOKS. Returns a nil dispatcher (alerting fully disabled)
// when both are unset, matching the off-by-default convention used for
// every other optional feature in this codebase.
func buildAlerting(log *slog.Logger) (*notify.Dispatcher, alert.Config) {
	cfg := alert.Config{
		Interval:             envDuration("NETRA_ALERT_POLL_INTERVAL", 30*time.Second),
		Cooldown:             envDuration("NETRA_ALERT_COOLDOWN", 5*time.Minute),
		StaleAfter:           envDuration("NETRA_AGENT_STALE_AFTER", 45*time.Second),
		TopN:                 envInt("NETRA_ALERT_TOPN", 0),
		DropSpikeWindow:      envInt("NETRA_DROP_SPIKE_WINDOW", 0),
		DropSpikeMultiplier:  envFloat("NETRA_DROP_SPIKE_MULTIPLIER", 0),
		DropSpikeMinAbsolute: envUint64("NETRA_DROP_SPIKE_MIN_ABSOLUTE", 0),
	}
	channelsRaw := strings.TrimSpace(os.Getenv("NETRA_ALERT_CHANNELS"))
	webhooksRaw := strings.TrimSpace(os.Getenv("NETRA_ALERT_WEBHOOKS"))
	if channelsRaw == "" && webhooksRaw == "" {
		return nil, cfg
	}
	var (
		chs []notify.Channel
		err error
	)
	if channelsRaw != "" {
		chs, err = notify.ParseChannels(channelsRaw)
		if err != nil {
			log.Error("alert channels config", "error", err)
			os.Exit(1)
		}
	} else {
		chs, err = notify.ParseLegacyWebhooks(webhooksRaw)
		if err != nil {
			log.Error("alert webhook config", "error", err)
			os.Exit(1)
		}
	}
	d := notify.NewDispatcher(envInt("NETRA_ALERT_QUEUE_SIZE", 256))
	for _, ch := range chs {
		d.Add(ch)
	}
	return d, cfg
}

func autoCaptureEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_AUTO_CAPTURE")), "true")
}

func shouldRunAlertPoller(dispatcher *notify.Dispatcher) bool {
	return dispatcher != nil || autoCaptureEnabled()
}

func buildArtifactStore(log *slog.Logger) *capture.ArtifactStore {
	if !autoCaptureEnabled() {
		return nil
	}
	dir := strings.TrimSpace(os.Getenv("NETRA_AUTO_CAPTURE_DIR"))
	if dir == "" {
		dir = capture.DefaultArtifactDir
	}
	maxArt := envInt("NETRA_AUTO_CAPTURE_MAX_ARTIFACTS", capture.DefaultMaxArtifacts)
	maxTotal := int64(envInt("NETRA_AUTO_CAPTURE_MAX_TOTAL_MB", int(capture.DefaultMaxTotalBytes/(1<<20)))) << 20
	maxSession := int64(envInt("NETRA_AUTO_CAPTURE_MAX_SESSION_MB", int(capture.DefaultMaxSessionBytes/(1<<20)))) << 20
	store, err := capture.NewArtifactStore(dir, maxArt, maxTotal, maxSession)
	if err != nil {
		log.Error("auto-capture artifact store", "error", err)
		os.Exit(1)
	}
	log.Info("auto-capture artifact store ready", "dir", dir)
	return store
}

func newAlertPoller(log *slog.Logger, st *store.Store, dispatcher *notify.Dispatcher, alertCfg alert.Config, listPods func(ctx context.Context, ns string) ([]models.PodInfo, error)) *alert.Poller {
	publish := func(ev notify.Event) bool {
		if dispatcher == nil {
			return true
		}
		return dispatcher.Publish(ev)
	}
	p := alert.New(log, st, publish, alertCfg, listPods)
	if !autoCaptureEnabled() {
		return p
	}
	cfg := alert.AutoConfig{
		Enabled:       true,
		Duration:      envDuration("NETRA_AUTO_CAPTURE_DURATION", 60*time.Second),
		Cooldown:      envDuration("NETRA_AUTO_CAPTURE_COOLDOWN", 10*time.Minute),
		Protocol:      env("NETRA_AUTO_CAPTURE_PROTOCOL", "tcp"),
		Backend:       env("NETRA_AUTO_CAPTURE_BACKEND", models.CaptureBackendEBPF),
		MaxPPS:        uint32(envInt("NETRA_AUTO_CAPTURE_MAX_PPS", 1000)),
		MaxConcurrent: envInt("NETRA_AUTO_CAPTURE_MAX_CONCURRENT", 5),
	}
	auto := alert.NewAutoCapture(log, cfg,
		func(spec models.CaptureSpec) models.CaptureSpec {
			return st.SetCapture(spec, spec.Requestor)
		},
		func(node string) *models.CaptureSpec { return st.Capture(node) },
		func() int { return len(st.Captures()) },
		publish,
	)
	return p.WithAutoCapture(auto)
}

// buildDNSDetect reads NETRA_DNSDETECT_* env vars and constructs a
// dnsdetect.Detector when enabled. Off by default via a plain feature
// flag — matching gitops/chatops's "enabled: false" shape rather than a
// "presence of one required value" gate, since there's no single natural
// required config value here (every dnsdetect.Config field already has a
// sane default).
func buildDNSDetect() (*dnsdetect.Detector, time.Duration, bool) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_DNSDETECT_ENABLED")), "true") {
		return nil, 0, false
	}
	cfg := dnsdetect.DefaultConfig()
	if v := envInt("NETRA_DNSDETECT_MAX_UNIQUE_SUBDOMAINS", 0); v > 0 {
		cfg.MaxUniqueSubdomains = v
	}
	if v := envFloat("NETRA_DNSDETECT_NXDOMAIN_RATIO", 0); v > 0 {
		cfg.NXDomainRatio = v
	}
	if v := envFloat("NETRA_DNSDETECT_SERVFAIL_RATIO", 0); v > 0 {
		cfg.ServfailRatio = v
	}
	if v := envInt("NETRA_DNSDETECT_MAX_DOMAINS", 0); v > 0 {
		cfg.MaxDomains = v
	}
	if v := envDuration("NETRA_DNSDETECT_FINDINGS_TTL", 0); v > 0 {
		cfg.FindingsTTL = v
	}
	interval := envDuration("NETRA_DNSDETECT_INTERVAL", 30*time.Second)
	return dnsdetect.New(cfg), interval, true
}

// buildScanDetect is scandetect's analog of buildDNSDetect above.
func buildScanDetect() (*scandetect.Detector, time.Duration, bool) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("NETRA_SCANDETECT_ENABLED")), "true") {
		return nil, 0, false
	}
	cfg := scandetect.DefaultConfig()
	if v := envDuration("NETRA_SCANDETECT_WINDOW", 0); v > 0 {
		cfg.Window = v
	}
	if v := envInt("NETRA_SCANDETECT_MAX_DEST_IPS", 0); v > 0 {
		cfg.MaxDestIPs = v
	}
	if v := envInt("NETRA_SCANDETECT_MAX_DEST_PORTS", 0); v > 0 {
		cfg.MaxDestPorts = v
	}
	if v := envUint64("NETRA_SCANDETECT_MIN_ATTEMPTS", 0); v > 0 {
		cfg.MinAttempts = v
	}
	interval := envDuration("NETRA_SCANDETECT_INTERVAL", 30*time.Second)
	return scandetect.New(cfg), interval, true
}

func runHA(ctx context.Context, log *slog.Logger, k *kube.Client, h *hubble.Client, stateFile string, dispatcher *notify.Dispatcher, alertCfg alert.Config, artifacts *capture.ArtifactStore, gitopsCfg gitops.Config, gitopsEnabled bool) {
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
		electionLoop(ctx, log, k, h, gate, stateFile, namespace, leaseName, identity, leaseDuration, renewDeadline, retryPeriod, dispatcher, alertCfg, artifacts, gitopsCfg, gitopsEnabled)
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
	dispatcher *notify.Dispatcher,
	alertCfg alert.Config,
	artifacts *capture.ArtifactStore,
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
	var snowflakeCancel func()
	var snowflakeWG sync.WaitGroup
	var dnsDetectCancel func()
	var dnsDetectWG sync.WaitGroup
	var scanDetectCancel func()
	var scanDetectWG sync.WaitGroup

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
		if snowflakeCancel != nil {
			snowflakeCancel()
			snowflakeWG.Wait()
			snowflakeCancel = nil
		}
		if dnsDetectCancel != nil {
			dnsDetectCancel()
			dnsDetectWG.Wait()
			dnsDetectCancel = nil
		}
		if scanDetectCancel != nil {
			scanDetectCancel()
			scanDetectWG.Wait()
			scanDetectCancel = nil
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
		dnsDet, dnsInterval, dnsEnabled := buildDNSDetect()
		scanDet, scanInterval, scanEnabled := buildScanDetect()
		gate.Promote(api.New(log, k, h, st).WithGitOps(gr).WithDNSDetect(dnsDet).WithScanDetect(scanDet).WithArtifacts(artifacts).Handler())
		if shouldRunAlertPoller(dispatcher) {
			pctx, cancel := context.WithCancel(ctx)
			pollerCancel = cancel
			pollerWG.Add(1)
			go func() {
				defer pollerWG.Done()
				newAlertPoller(log, st, dispatcher, alertCfg, k.ListPods).Run(pctx)
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
		if stop := startSnowflake(ctx, log, st, &snowflakeWG); stop != nil {
			snowflakeCancel = stop
		}
		staleAfter := envDuration("NETRA_AGENT_STALE_AFTER", 45*time.Second)
		// leaderSt pins this stint's specific *store.Store: st is an outer
		// variable electionLoop reassigns (to nil on demote, to a new store
		// on the next promotion), so a closure capturing st directly would
		// read whatever the *next* stint left there instead of this one's —
		// exactly the failure alert.New(log, st, ...) avoids by taking st as
		// a plain argument, copied once, at call time.
		leaderSt := st
		if dnsEnabled {
			dctx, dcancel := context.WithCancel(ctx)
			dnsDetectCancel = dcancel
			dnsDetectWG.Add(1)
			go func() {
				defer dnsDetectWG.Done()
				dnsDet.Run(dctx, dnsInterval, func() []models.AgentStatus { return leaderSt.AgentStatuses(time.Now(), staleAfter) })
			}()
		}
		if scanEnabled {
			sctx, scancel := context.WithCancel(ctx)
			scanDetectCancel = scancel
			scanDetectWG.Add(1)
			go func() {
				defer scanDetectWG.Done()
				scanDet.Run(sctx, scanInterval, func() []models.AgentStatus { return leaderSt.AgentStatuses(time.Now(), staleAfter) })
			}()
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

func envFloat(k string, d float64) float64 {
	if raw := strings.TrimSpace(os.Getenv(k)); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
			return parsed
		}
	}
	return d
}

func envUint64(k string, d uint64) uint64 {
	if raw := strings.TrimSpace(os.Getenv(k)); raw != "" {
		if parsed, err := strconv.ParseUint(raw, 10, 64); err == nil {
			return parsed
		}
	}
	return d
}
