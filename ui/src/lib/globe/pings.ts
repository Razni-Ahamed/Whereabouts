// Which connections are new, so the globe can flash their country. Only what
// the live view already shows is used; nothing is made up.

import { countryCentre } from './geo.ts';

export interface FlowLike {
  app: string;
  remote: string;
  country: string | null;
  owner: string | null;
  /** Still open (the live list also keeps recently closed connections). */
  active: boolean;
}

export interface Ping {
  /** ISO 3166-1 alpha-2, upper case. */
  country: string;
  /** A tracker: shown in amber. */
  warn: boolean;
}

/** At most this many pings per update, so a browser opening 50 connections is not a storm. */
export const MAX_PINGS = 4;
/**
 * How long a connection counts as already seen after it was last listed. The
 * live list is cut to the largest rows, so a connection near the cut can drop
 * out and come back; it is not new when it does.
 */
export const SEEN_FOR_S = 600;
/**
 * After the service starts, its table fills up again bit by bit with
 * connections that were open all along; nothing pings until it has settled.
 */
export const WARM_UP_S = 90;

const key = (f: FlowLike) => `${f.app}|${f.remote}`;

export class PingTracker {
  /** Connection → when it was last listed (seconds). Empty = no baseline yet. */
  readonly #seen = new Map<string, number>();
  #lastUptime: number | null = null;
  readonly #isWarn: (owner: string | null) => boolean;

  constructor(isWarn: (owner: string | null) => boolean) {
    this.#isWarn = isWarn;
  }

  /**
   * Pings for open connections not listed in the last `SEEN_FOR_S` seconds.
   * The first update, any update after an empty one (no data, or the service
   * unreachable), and every update while the service warms up after starting
   * only build the baseline.
   *
   * @param uptimeSecs the service's uptime, from its status
   * @param nowSecs the current time, in seconds
   */
  update(flows: FlowLike[], uptimeSecs: number, nowSecs: number): Ping[] {
    const restarted = this.#lastUptime !== null && uptimeSecs < this.#lastUptime;
    this.#lastUptime = uptimeSecs;
    if (flows.length === 0 || restarted) this.#seen.clear();
    const quiet = this.#seen.size === 0 || uptimeSecs < WARM_UP_S;

    const pings: Ping[] = [];
    for (const f of flows) {
      const k = key(f);
      const isNew = !this.#seen.has(k);
      this.#seen.set(k, nowSecs);
      if (quiet || !isNew || !f.active || pings.length >= MAX_PINGS) continue;
      if (!f.country || !countryCentre(f.country)) continue;
      pings.push({ country: f.country.toUpperCase(), warn: this.#isWarn(f.owner) });
    }
    for (const [k, at] of this.#seen) {
      if (nowSecs - at > SEEN_FOR_S) this.#seen.delete(k);
    }
    return pings;
  }
}

/** Countries with an open connection now; true when any of them is a tracker. Unknown countries are left out. */
export function activeCountries(flows: FlowLike[], isWarn: (owner: string | null) => boolean): Map<string, boolean> {
  const countries = new Map<string, boolean>();
  for (const f of flows) {
    if (!f.active || !f.country || !countryCentre(f.country)) continue;
    const code = f.country.toUpperCase();
    countries.set(code, (countries.get(code) ?? false) || isWarn(f.owner));
  }
  return countries;
}
