// Talks to the app's Rust side, which asks the Whereabouts service over its
// local pipe. In an ordinary browser (design work only) it returns demo
// data instead, and says so.

import { invoke } from '@tauri-apps/api/core';
import { demoHistory, demoLive } from './demo';
import type { AppTotals, Live, Problem } from './types';

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

/** Saved per-app totals of the last `hours`. */
export async function history(hours = 24, limit = 50): Promise<Result<AppTotals[]>> {
  if (isDemo) return { ok: true, value: demoHistory() };
  return call<AppTotals[]>('history', { hours, limit });
}
