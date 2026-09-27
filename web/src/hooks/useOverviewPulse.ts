// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useRef, useState } from 'react';
import { api } from '../api';

export const PULSE_INTERVAL_MS = 5000;
export const PULSE_SAMPLES = 30;

export type PulseRates = { packets: number; bytes: number; dns: number; blocked: number };

export type OverviewPulse = {
  status?: any;
  obs?: any;
  health?: any;
  l7?: any;
  insights?: any;
  path?: any;
  drops?: any;
  features?: { on?: number; off?: number } | null;
  err: string;
  /** Per-second rates from the last two summaries; undefined until two samples exist. */
  rates?: PulseRates;
  /** Oldest first, at most PULSE_SAMPLES entries. */
  history: PulseRates[];
  updatedAt?: number;
};

type Counters = { at: number; packets: number; bytes: number; dns: number; blocked: number };

function counters(obs: any, at: number): Counters | undefined {
  if (!obs) return undefined;
  return {
    at,
    packets: Number(obs.packets) || 0,
    bytes: Number(obs.bytes) || 0,
    dns: Number(obs.dnsQueries) || 0,
    blocked: Number(obs.blocked) || 0,
  };
}

// Counters reset when an agent restarts; a negative delta is a reset, not negative traffic.
export function ratesBetween(prev: Counters, next: Counters): PulseRates | undefined {
  const secs = (next.at - prev.at) / 1000;
  if (secs <= 0) return undefined;
  const r = (a: number, b: number) => Math.max(0, b - a) / secs;
  return {
    packets: r(prev.packets, next.packets),
    bytes: r(prev.bytes, next.bytes),
    dns: r(prev.dns, next.dns),
    blocked: r(prev.blocked, next.blocked),
  };
}

export function useOverviewPulse(): OverviewPulse {
  const [state, setState] = useState<OverviewPulse>({ err: '', history: [] });
  const last = useRef<Counters | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      if (typeof document !== 'undefined' && document.hidden) return;
      // allSettled, not all: /api/v1/insights/summary answers 502 when the controller cannot reach the
      // Kubernetes API, and with Promise.all that one failure zeroed every board on the landing page
      // (0 agents, no health score) although the agent feeds were healthy. Each feed applies on its
      // own; the first failure is still shown.
      Promise.allSettled([
        api('/api/v1/status'),
        api('/api/v1/ebpf/summary'),
        api('/api/v1/ebpf/health?limit=1'),
        api('/api/v1/ebpf/l7?limit=1'),
        api('/api/v1/insights/summary'),
        api('/api/v1/ebpf/path?limit=1'),
        api('/api/v1/ebpf/drops?limit=1'),
        api<{ summary?: { on?: number; off?: number } }>('/api/v1/features'),
      ]).then((rs) => {
        if (cancelled) return;
        const val = (n: number): any => (rs[n].status === 'fulfilled' ? (rs[n] as PromiseFulfilledResult<any>).value : undefined);
        const failed = rs.filter((r): r is PromiseRejectedResult => r.status === 'rejected');
        const now = Date.now();
        const next = counters(val(1), now);
        const rates = next && last.current ? ratesBetween(last.current, next) : undefined;
        if (next) last.current = next;
        setState((s) => ({
          status: val(0) ?? s.status,
          obs: val(1) ?? s.obs,
          health: val(2) ?? s.health,
          l7: val(3) ?? s.l7,
          insights: val(4) ?? s.insights,
          path: val(5) ?? s.path,
          drops: val(6) ?? s.drops,
          features: val(7) !== undefined ? val(7)?.summary || null : s.features,
          err: failed.length ? String(failed[0].reason) : '',
          rates: rates ?? s.rates,
          history: rates ? [...s.history, rates].slice(-PULSE_SAMPLES) : s.history,
          updatedAt: now,
        }));
      });
    };
    load();
    const t = setInterval(load, PULSE_INTERVAL_MS);
    const onVisible = () => {
      if (!document.hidden) load();
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      cancelled = true;
      clearInterval(t);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, []);

  return state;
}
