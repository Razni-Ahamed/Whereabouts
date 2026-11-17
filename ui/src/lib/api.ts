// Talks to the app's Rust side, which asks the Whereabouts service over its
// local pipe. In an ordinary browser (design work only) it returns demo
// data instead, and says so.

import { invoke } from '@tauri-apps/api/core';
import { demoAddRule, demoHistory, demoLive, demoRemoveRule, demoRules, demoSetPaused } from './demo';
import type { AppTotals, Live, Problem, Rules, RuleSpec } from './types';

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
export async function addRule(rule: RuleSpec): Promise<Result<number | null>> {
  if (isDemo) return demoAddRule(rule);
  return call<number | null>('add_rule', { rule });
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

/** Saved per-app totals of the last `hours`. */
export async function history(hours = 24, limit = 50): Promise<Result<AppTotals[]>> {
  if (isDemo) return { ok: true, value: demoHistory() };
  return call<AppTotals[]>('history', { hours, limit });
}
