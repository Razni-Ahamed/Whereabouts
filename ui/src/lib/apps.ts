// Grouping the live connections into apps.
//
// An app is one program file, so connections are grouped by the program's
// full path, never by its file name alone: anything can be called
// "chrome.exe", and a copy in a temporary folder must not borrow the real
// program's publisher, its "signed" badge or its Block button.

import type { FlowView } from './types';

export interface AppGroup {
  /** Identifies the group: its program's path, or its name when the path is unknown. */
  key: string;
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
  /** Whether another group has the same file name (then the folder tells them apart). */
  sameName: boolean;
}

const TRACKING_KINDS = ['analytics', 'advertising', 'tracking', 'attribution'];

export function isTracking(owner: string | null): boolean {
  const kind = owner?.split(' · ')[1];
  return !!kind && (TRACKING_KINDS.includes(kind) || owner?.startsWith('tracker') === true);
}

/** The key of the app that runs `path` (or is called `app` when the path is unknown). */
export function appKey(app: string, path: string | null | undefined): string {
  // Windows paths compare without regard to case.
  return path ? `path:${path.toLowerCase()}` : `name:${app.toLowerCase()}`;
}

/** Current connections grouped by program, largest first. */
export function groupByApp(flows: FlowView[]): AppGroup[] {
  const groups = new Map<string, AppGroup>();
  for (const flow of flows) {
    const key = appKey(flow.app, flow.path);
    let group = groups.get(key);
    if (!group) {
      group = {
        key,
        app: flow.app,
        path: flow.path,
        publisher: flow.publisher,
        publisherConfirmed: flow.publisher_confirmed,
        flows: [],
        sent: 0,
        received: 0,
        destinations: 0,
        countries: [],
        trackers: 0,
        sameName: false,
      };
      groups.set(key, group);
    }
    group.flows.push(flow);
    group.sent += flow.bytes_sent;
    group.received += flow.bytes_received;
    if (flow.country && !group.countries.includes(flow.country)) group.countries.push(flow.country);
    if (isTracking(flow.owner)) group.trackers += 1;
  }
  const names = new Map<string, number>();
  for (const group of groups.values()) {
    group.destinations = new Set(group.flows.map((f) => f.domain ?? f.remote)).size;
    const name = group.app.toLowerCase();
    names.set(name, (names.get(name) ?? 0) + 1);
  }
  for (const group of groups.values()) group.sameName = (names.get(group.app.toLowerCase()) ?? 0) > 1;
  return [...groups.values()].sort((a, b) => b.sent + b.received - (a.sent + a.received));
}

/**
 * The app `pick` names: a group key, or else a plain file name (from places
 * that only know the name, such as the saved history), which picks the
 * largest app of that name.
 */
export function findApp(groups: AppGroup[], pick: string | null): AppGroup | undefined {
  if (!pick) return undefined;
  return groups.find((g) => g.key === pick) ?? groups.find((g) => g.app === pick);
}

/** The folder of a full path, for telling apart programs with the same name. */
export function folderOf(path: string): string {
  const cut = path.lastIndexOf('\\');
  return cut > 0 ? path.slice(0, cut) : path;
}
