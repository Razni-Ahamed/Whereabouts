// App-wide state, refreshed from the service.

import { groupByApp } from './apps';
import {
  addRule,
  alerts,
  checkListsNow,
  setListUpdates,
  dismissAlert,
  getSettings,
  history,
  isDemo,
  live,
  removeRule,
  rules,
  setBlockingPaused,
  setSettings,
} from './api';
import type {
  AlertView,
  AppSettings,
  AppTotals,
  Live,
  Problem,
  Rules,
  RuleSpec,
} from './types';

const LIVE_EVERY_MS = 2000;
const HISTORY_EVERY_MS = 30_000;
const RULES_EVERY_MS = 10_000;
const ALERTS_EVERY_MS = 15_000;
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
  settings = $state<AppSettings | null>(null);
  alerts = $state<AlertView[] | null>(null);
  /** Alerts that need a look: medium or higher, not marked fine. */
  needsLook = $derived((this.alerts ?? []).filter((a) => a.severity !== 'info' && !a.dismissed).length);
  note = $state<Note | null>(null);
  #noteTimer: ReturnType<typeof setTimeout> | undefined;
  /** Bytes per second between refreshes, oldest first. */
  activity = $state<number[]>([]);
  #lastTotal: { bytes: number; at: number } | null = null;
  readonly demo = isDemo;

  /** Current flows grouped by program (full path), largest first. */
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

  async refreshAlerts(): Promise<void> {
    const result = await alerts();
    if (result.ok) this.alerts = result.value;
  }

  /** Marks an alert as fine (with `allow`, alerts like it stop too). */
  async dismiss(id: number, allow: boolean): Promise<void> {
    const result = await dismissAlert(id, allow);
    if (!result.ok) {
      this.showNote({ text: result.problem.message, tone: 'bad' });
    } else if (result.value) {
      this.showNote({ text: allow ? "Marked as fine. You won't be told about this again." : 'Marked as seen.', tone: 'good' });
      await this.refreshAlerts();
    }
  }

  /** Turns list updates on or off; `false` (with a note) if that failed. */
  async setLists(data: boolean, drop: boolean): Promise<boolean> {
    const result = await setListUpdates(data, drop);
    if (!result.ok) {
      this.showNote({ text: result.problem.message, tone: 'bad' });
      return false;
    }
    if (this.live) this.live = { ...this.live, status: { ...this.live.status, lists: result.value } };
    return true;
  }

  async checkLists(): Promise<void> {
    const result = await checkListsNow();
    if (!result.ok) {
      this.showNote({ text: result.problem.message, tone: 'bad' });
    } else if (this.live) {
      this.live = { ...this.live, status: { ...this.live.status, lists: result.value } };
    }
  }

  async loadSettings(): Promise<void> {
    const result = await getSettings();
    if (result.ok) this.settings = result.value;
  }

  /** Saves the app's settings; `false` (with a note) if that failed. */
  async saveSettings(
    choice: Pick<AppSettings, 'start_at_sign_in' | 'notifications' | 'show_names'>,
  ): Promise<boolean> {
    const result = await setSettings(choice);
    if (result.ok) {
      this.settings = result.value;
      return true;
    }
    this.showNote({ text: result.problem.message, tone: 'bad' });
    return false;
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
    if (result.value.already) {
      // Nothing new was blocked: no Undo, which would lift the existing rule.
      this.showNote({ text: `${what} was already blocked.`, tone: 'good' });
    } else {
      this.showNote({ text: `Blocked ${what}.`, tone: 'good', undo: result.value.id });
    }
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
    void this.loadSettings();
    void this.refreshAlerts();
    const d = setInterval(() => void this.refreshAlerts(), ALERTS_EVERY_MS);
    const a = setInterval(() => void this.refreshLive(), LIVE_EVERY_MS);
    const b = setInterval(() => void this.refreshHistory(), HISTORY_EVERY_MS);
    const c = setInterval(() => void this.refreshRules(), RULES_EVERY_MS);
    return () => {
      clearInterval(a);
      clearInterval(b);
      clearInterval(c);
      clearInterval(d);
    };
  }
}

export { isTracking, type AppGroup } from './apps';

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
