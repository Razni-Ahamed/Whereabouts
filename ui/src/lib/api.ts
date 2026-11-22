// Talks to the app's Rust side, which asks the Whereabouts service over its
// local pipe. In an ordinary browser (design work only) it returns demo
// data instead, and says so.

import { invoke } from '@tauri-apps/api/core';
import {
  demoAddRule,
  demoAlerts,
  demoDismissAlert,
  demoHistory,
  demoLive,
  demoRemoveRule,
  demoRules,
  demoLists,
  demoSetPaused,
} from './demo';
import type { Added, AlertView, AppSettings, AppTotals, ListsView, Live, Problem, Rules, RuleSpec } from './types';

export const isDemo = !('__TAURI_INTERNALS__' in window);

export type Result<T> = { ok: true; value: T } | { ok: false; problem: Problem };

function asProblem(error: unknown): Problem {
  if (error && typeof error === 'object' && 'kind' in error && 'message' in error) {
    return error as Problem;
  }
  return { kind: 'other', message: String(error) };
}

async function call<T>(command: string, args: Record<string, unknown> = {}): Promise<Result<T>> {
  try {
    return { ok: true, value: await invoke<T>(command, args) };
  } catch (error) {
    return { ok: false, problem: asProblem(error) };
  }
}

/** Status and current flows (largest first). */
export async function live(limit = 500): Promise<Result<Live>> {
  if (isDemo) return { ok: true, value: demoLive() };
  return call<Live>('live', { limit });
}

export interface Exported {
  path: string;
  rows: number;
}

/**
 * Asks where to save (a native Windows dialog) and exports all saved flows
 * there as CSV. `null` if the user cancelled.
 */
export async function exportHistory(): Promise<Result<Exported | null>> {
  if (isDemo) {
    await new Promise((r) => setTimeout(r, 600));
    return { ok: true, value: { path: 'C:\\Users\\you\\Documents\\whereabouts-history.csv', rows: 4812 } };
  }
  return call<Exported | null>('export_history');
}

/**
 * Asks for confirmation (a native Windows dialog) and deletes everything
 * saved. `false` if the user said no.
 */
export async function deleteHistory(): Promise<Result<boolean>> {
  if (isDemo) {
    await new Promise((r) => setTimeout(r, 600));
    return { ok: true, value: window.confirm('Demo: delete everything Whereabouts saved?') };
  }
  return call<boolean>('delete_history');
}

/** The blocking rules, and whether blocking is paused. */
export async function rules(): Promise<Result<Rules>> {
  if (isDemo) return { ok: true, value: demoRules() };
  return call<Rules>('rules');
}

/**
 * Shows what will be blocked in a native Windows dialog and blocks it if
 * the user agrees. The rule's ID, or `null` if the user said no.
 */
export async function addRule(rule: RuleSpec): Promise<Result<Added | null>> {
  if (isDemo) return demoAddRule(rule);
  return call<Added | null>('add_rule', { rule });
}

/** Deletes a rule and lifts its block. */
export async function removeRule(id: number): Promise<Result<Rules>> {
  if (isDemo) return { ok: true, value: demoRemoveRule(id) };
  return call<Rules>('remove_rule', { id });
}

/** Pauses (lifts every block, keeps the rules) or resumes blocking. */
export async function setBlockingPaused(paused: boolean): Promise<Result<Rules>> {
  if (isDemo) return { ok: true, value: demoSetPaused(paused) };
  return call<Rules>('set_blocking_paused', { paused });
}

/** Turns list updates on or off. */
export async function setListUpdates(data: boolean, drop: boolean): Promise<Result<ListsView>> {
  if (isDemo) {
    const now = Math.floor(Date.now() / 1000);
    Object.assign(demoLists, {
      data_updates: data,
      drop_updates: drop,
      data_version: data ? '2026-11-17T04:17:00Z' : null,
      data_checked_secs: data ? now : null,
      drop_fetched_secs: drop ? now : null,
    });
    return { ok: true, value: { ...demoLists } };
  }
  return call<ListsView>('set_list_updates', { data, drop });
}

/** Checks for list updates now. */
export async function checkListsNow(): Promise<Result<ListsView>> {
  if (isDemo) {
    demoLists.data_checked_secs = Math.floor(Date.now() / 1000);
    return { ok: true, value: { ...demoLists } };
  }
  return call<ListsView>('check_lists_now');
}

/** Saved alerts of the last `hours`, newest first. */
export async function alerts(hours = 30 * 24, limit = 500): Promise<Result<AlertView[]>> {
  if (isDemo) return { ok: true, value: demoAlerts() };
  return call<AlertView[]>('alerts', { hours, limit });
}

/**
 * Marks an alert as seen and fine; with `allow`, alerts like it stop
 * (Windows asks first for risky networks). `false` if the user said no.
 */
export async function dismissAlert(id: number, allow: boolean): Promise<Result<boolean>> {
  if (isDemo) return { ok: true, value: demoDismissAlert(id, allow) };
  return call<boolean>('dismiss_alert', { id, allow });
}

// Demo settings, kept while the page is open.
let demoSettings: AppSettings = {
  start_at_sign_in: false,
  can_start_at_sign_in: true,
  notifications: true,
  show_names: false,
  first_run_done: false,
};

/** The app's own settings. */
export async function getSettings(): Promise<Result<AppSettings>> {
  if (isDemo) return { ok: true, value: { ...demoSettings } };
  return call<AppSettings>('get_settings');
}

/** Saves the app's settings (and marks the first-run question answered). */
export async function setSettings(
  choice: Pick<AppSettings, 'start_at_sign_in' | 'notifications' | 'show_names'>,
): Promise<Result<AppSettings>> {
  if (isDemo) {
    demoSettings = { ...demoSettings, ...choice, first_run_done: true };
    return { ok: true, value: { ...demoSettings } };
  }
  return call<AppSettings>('set_settings', {
    startAtSignIn: choice.start_at_sign_in,
    notifications: choice.notifications,
    showNames: choice.show_names,
  });
}

/** Saved per-app totals of the last `hours`. */
export async function history(hours = 24, limit = 50): Promise<Result<AppTotals[]>> {
  if (isDemo) return { ok: true, value: demoHistory() };
  return call<AppTotals[]>('history', { hours, limit });
}
