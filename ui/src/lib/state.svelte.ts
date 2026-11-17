// App-wide state, refreshed from the service.

import { addRule, history, isDemo, live, removeRule, rules, setBlockingPaused } from './api';
import type { AppTotals, FlowView, Live, Problem, Rules, RuleSpec } from './types';

const LIVE_EVERY_MS = 2000;
const HISTORY_EVERY_MS = 30_000;
const RULES_EVERY_MS = 10_000;
/** How long the "Blocked · Undo" note stays. */
const NOTE_MS = 8000;

/** A short note at the bottom of the window, with an optional Undo. */
export interface Note {
  text: string;
  tone: 'good' | 'bad';
  undo?: number;
}
/** Throughput samples kept for the activity graph (two minutes). */
const ACTIVITY_SAMPLES = 60;

class Store {
  live = $state<Live | null>(null);
  history = $state<AppTotals[]>([]);
  problem = $state<Problem | null>(null);
  updated = $state<Date | null>(null);
  rules = $state<Rules | null>(null);
  note = $state<Note | null>(null);
  #noteTimer: ReturnType<typeof setTimeout> | undefined;
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

  async refreshRules(): Promise<void> {
    const result = await rules();
    if (result.ok) this.rules = result.value;
  }

  showNote(note: Note | null): void {
    clearTimeout(this.#noteTimer);
    this.note = note;
    if (note) this.#noteTimer = setTimeout(() => (this.note = null), NOTE_MS);
  }

  /**
   * Asks to block `rule` (Windows shows exactly what in its own dialog).
   * `true` if it was blocked; problems are shown in the note.
   */
  async block(rule: RuleSpec, what: string): Promise<boolean> {
    const result = await addRule(rule);
    if (!result.ok) {
      this.showNote({ text: result.problem.message, tone: 'bad' });
      return false;
    }
    if (result.value === null) return false;
    this.showNote({ text: `Blocked ${what}.`, tone: 'good', undo: result.value });
    await this.refreshRules();
    return true;
  }

  /** Deletes a rule and lifts its block. */
  async unblock(id: number): Promise<void> {
    const result = await removeRule(id);
    if (result.ok) {
      this.rules = result.value;
      this.showNote({ text: 'Unblocked.', tone: 'good' });
    } else {
      this.showNote({ text: result.problem.message, tone: 'bad' });
    }
  }

  async setPaused(paused: boolean): Promise<void> {
    const result = await setBlockingPaused(paused);
    if (result.ok) {
      this.rules = result.value;
      void this.refreshLive();
    } else {
      this.showNote({ text: result.problem.message, tone: 'bad' });
    }
  }

  async refreshHistory(): Promise<void> {
    const result = await history();
    if (result.ok) this.history = result.value;
  }

  start(): () => void {
    void this.refreshLive();
    void this.refreshHistory();
    void this.refreshRules();
    const a = setInterval(() => void this.refreshLive(), LIVE_EVERY_MS);
    const b = setInterval(() => void this.refreshHistory(), HISTORY_EVERY_MS);
    const c = setInterval(() => void this.refreshRules(), RULES_EVERY_MS);
    return () => {
      clearInterval(a);
      clearInterval(b);
      clearInterval(c);
    };
  }
}

export interface AppGroup {
  app: string;
  /** The program's full path, if the service knows it. */
  path: string | null;
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
        path: null,
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
    group.path ??= flow.path;
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

/** The address part of "1.2.3.4:443" or "[2001:db8::1]:443". */
export function remoteAddress(remote: string): string | null {
  const v6 = /^\[([0-9a-f:.]+)\]:\d+$/i.exec(remote)?.[1];
  if (v6) return v6;
  return /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(remote)?.[1] ?? null;
}

/** The file name of a full path. */
export function fileName(path: string): string {
  return path.split('\\').pop() || path;
}

/** The rule that blocks this whole program, if any. */
export function appRule(rules: Rules | null, path: string | null) {
  if (!rules || !path) return undefined;
  const lower = path.toLowerCase();
  return rules.rules.find((r) => r.rule.kind === 'app' && r.rule.path.toLowerCase() === lower);
}

export const store = new Store();
