// Which connections are new, so the globe can flash their country. Only what
// the live view already shows is used; nothing is made up.

import { countryCentre } from './geo.ts';

export interface FlowLike {
  app: string;
  remote: string;
  country: string | null;
  owner: string | null;
}

export interface Ping {
  /** ISO 3166-1 alpha-2, upper case. */
  country: string;
  /** A tracker: shown in amber. */
  warn: boolean;
}

/** At most this many pings per update, so a browser opening 50 connections is not a storm. */
export const MAX_PINGS = 4;

const key = (f: FlowLike) => `${f.app}|${f.remote}`;

export class PingTracker {
  #previous: Set<string> | null = null;
  readonly #isWarn: (owner: string | null) => boolean;

  constructor(isWarn: (owner: string | null) => boolean) {
    this.#isWarn = isWarn;
  }

  /**
   * Pings for flows not in the previous update. The first update, and any
   * update after an empty one (the service restarting), only sets the baseline.
   */
  update(flows: FlowLike[]): Ping[] {
    const previous = this.#previous;
    const current = new Set(flows.map(key));
    this.#previous = current;
    if (!previous || previous.size === 0) return [];

    const pings: Ping[] = [];
    const seen = new Set<string>();
    for (const f of flows) {
      if (pings.length >= MAX_PINGS) break;
      const k = key(f);
      if (previous.has(k) || seen.has(k)) continue;
      seen.add(k);
      if (!f.country || !countryCentre(f.country)) continue;
      pings.push({ country: f.country.toUpperCase(), warn: this.#isWarn(f.owner) });
    }
    return pings;
  }
}

/** Countries with a connection now; true when any of them is a tracker. Unknown countries are left out. */
export function activeCountries(flows: FlowLike[], isWarn: (owner: string | null) => boolean): Map<string, boolean> {
  const countries = new Map<string, boolean>();
  for (const f of flows) {
    if (!f.country || !countryCentre(f.country)) continue;
    const code = f.country.toUpperCase();
    countries.set(code, (countries.get(code) ?? false) || isWarn(f.owner));
  }
  return countries;
}
