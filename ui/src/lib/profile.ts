// Small helpers for showing an app's behaviour profile.

const DAY_SECS = 86_400;

/**
 * Bar heights (0 to 8) for the 24 hourly shares of activity: the busiest
 * hour is 8. An hour with any activity shows at least 1; a program that was
 * never active gets all zeros.
 */
export function activeHoursBars(shares: number[]): number[] {
  const clean = shares.map((s) => (Number.isFinite(s) && s > 0 ? s : 0));
  const max = Math.max(0, ...clean);
  if (max === 0) return clean.map(() => 0);
  return clean.map((s) => (s === 0 ? 0 : Math.min(8, Math.max(1, Math.round((s / max) * 8)))));
}

/** Whole days until `endsSecs` (rounded up), never below zero. Both in seconds since 1970. */
export function daysLeft(endsSecs: number, nowSecs: number): number {
  return Math.max(0, Math.ceil((endsSecs - nowSecs) / DAY_SECS));
}
