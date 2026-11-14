// App-wide state, refreshed from the service.

import { history, isDemo, live } from './api';
import type { AppTotals, FlowView, Live, Problem } from './types';

const LIVE_EVERY_MS = 2000;
const HISTORY_EVERY_MS = 30_000;
/** Throughput samples kept for the activity graph (two minutes). */
const ACTIVITY_SAMPLES = 60;

class Store {
  live = $state<Live | null>(null);
  history = $state<AppTotals[]>([]);
  problem = $state<Problem | null>(null);
  updated = $state<Date | null>(null);
  /** Bytes per second between refreshes, oldest first. */
  activity = $state<number[]>([]);
  #lastTotal: { bytes: number; at: number } | null = null;
  readonly demo = isDemo;

  /** Current flows grouped by app, largest first. */
  apps = $derived.by(() => groupByApp(this.live?.flows ?? []));

  async refreshLive(): Promise<void> {
    const result = await live();
    if (result.ok) {
      this.#sample(result.value);
      this.live = result.value;
      this.problem = null;
      this.updated = new Date();
    } else {
      this.problem = result.problem;
    }
  }

  #sample(next: Live): void {
    const bytes = next.flows.reduce((t, f) => t + f.bytes_sent + f.bytes_received, 0);
    const at = Date.now();
    if (this.#lastTotal) {
      const seconds = Math.max(0.5, (at - this.#lastTotal.at) / 1000);
      // Closed flows leave the list, so the total can fall; count that as quiet.
      const rate = Math.max(0, (bytes - this.#lastTotal.bytes) / seconds);
      this.activity = [...this.activity, rate].slice(-ACTIVITY_SAMPLES);
    }
    this.#lastTotal = { bytes, at };
  }

  async refreshHistory(): Promise<void> {
    const result = await history();
    if (result.ok) this.history = result.value;
  }

  start(): () => void {
    void this.refreshLive();
    void this.refreshHistory();
    const a = setInterval(() => void this.refreshLive(), LIVE_EVERY_MS);
    const b = setInterval(() => void this.refreshHistory(), HISTORY_EVERY_MS);
    return () => {
      clearInterval(a);
      clearInterval(b);
    };
  }
}

export interface AppGroup {
  app: string;
  publisher: string;
  publisherConfirmed: boolean;
  flows: FlowView[];
  sent: number;
  received: number;
  destinations: number;
  countries: string[];
  trackers: number;
}

const TRACKING_KINDS = ['analytics', 'advertising', 'tracking', 'attribution'];

export function isTracking(owner: string | null): boolean {
  const kind = owner?.split(' · ')[1];
  return !!kind && (TRACKING_KINDS.includes(kind) || owner?.startsWith('tracker') === true);
}

function groupByApp(flows: FlowView[]): AppGroup[] {
  const groups = new Map<string, AppGroup>();
  for (const flow of flows) {
    let group = groups.get(flow.app);
    if (!group) {
      group = {
        app: flow.app,
        publisher: flow.publisher,
        publisherConfirmed: flow.publisher_confirmed,
        flows: [],
        sent: 0,
        received: 0,
        destinations: 0,
        countries: [],
        trackers: 0,
      };
      groups.set(flow.app, group);
    }
    group.flows.push(flow);
    group.sent += flow.bytes_sent;
    group.received += flow.bytes_received;
    if (flow.country && !group.countries.includes(flow.country)) group.countries.push(flow.country);
    if (isTracking(flow.owner)) group.trackers += 1;
  }
  for (const group of groups.values()) {
    group.destinations = new Set(group.flows.map((f) => f.domain ?? f.remote)).size;
  }
  return [...groups.values()].sort((a, b) => b.sent + b.received - (a.sent + a.received));
}

export const store = new Store();
