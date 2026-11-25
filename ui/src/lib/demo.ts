// Made-up data, shown only when the UI runs in an ordinary browser (for
// design work). The desktop app always shows real data from the service.

import type {
  Added,
  AlertView,
  AppTotals,
  FlowView,
  GoesAnywhereChoice,
  ListsView,
  Live,
  Problem,
  ProfileItemView,
  ProfileView,
  Rules,
  RuleSpec,
} from './types';
import { appKey } from './apps';

// Demo list updates, kept while the page is open.
export const demoLists: ListsView = {
  data_updates: null,
  drop_updates: null,
  data_version: null,
  data_checked_secs: null,
  drop_fetched_secs: null,
  problem: null,
  checking: false,
};

/** Demo choice to save history (null until chosen), kept while the page is open. */
export const demoHistorySetting: { save: boolean | null } = { save: null };

/** Where the demo apps live. */
const PATHS: Record<string, string> = {
  'chrome.exe': 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'ms-teams.exe': 'C:\\Program Files\\WindowsApps\\MSTeams_8wekyb3d8bbwe\\ms-teams.exe',
  'Spotify.exe': 'C:\\Users\\you\\AppData\\Roaming\\Spotify\\Spotify.exe',
  'OneDrive.exe': 'C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe',
  'Discord.exe': 'C:\\Users\\you\\AppData\\Local\\Discord\\app-1.0.9200\\Discord.exe',
  'steam.exe': 'C:\\Program Files (x86)\\Steam\\steam.exe',
  'svchost.exe': 'C:\\Windows\\System32\\svchost.exe',
  'updater.exe': 'C:\\Users\\you\\AppData\\Local\\Temp\\freeware\\updater.exe',
  'Code.exe': 'C:\\Users\\you\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe',
  'zoom.exe': 'C:\\Users\\you\\AppData\\Roaming\\Zoom\\bin\\zoom.exe',
};

interface Seed {
  pid: number;
  app: string;
  publisher: string;
  confirmed?: boolean;
  protocol?: string;
  domain: string | null;
  trust?: FlowView['domain_trust'];
  via?: string;
  owner: string | null;
  country: string | null;
  remote: string;
  sent: number;
  received: number;
  rate: number;
  /** Comes and goes (about half the time), so the preview shows new connections. */
  comes?: boolean;
}

const SEEDS: Seed[] = [
  { pid: 8124, app: 'chrome.exe', publisher: 'Google LLC', domain: 'www.youtube.com', owner: 'Google LLC', country: 'US', remote: '142.250.183.14:443', sent: 1_820_000, received: 312_000_000, rate: 1.8 },
  { pid: 8124, app: 'chrome.exe', publisher: 'Google LLC', domain: 'www.google-analytics.com', owner: 'Google · analytics', country: 'US', remote: '142.250.182.78:443', sent: 48_200, received: 9_300, rate: 0.2 },
  { pid: 8124, app: 'chrome.exe', publisher: 'Google LLC', domain: 'connect.facebook.net', owner: 'Meta · advertising', country: 'IE', remote: '157.240.16.20:443', sent: 21_400, received: 61_000, rate: 0.1 },
  { pid: 5512, app: 'ms-teams.exe', publisher: 'Microsoft Corporation', domain: 'teams.microsoft.com', owner: 'Microsoft Corporation', country: 'IE', remote: '52.113.194.132:443', sent: 24_600_000, received: 88_400_000, rate: 1.2 },
  { pid: 5512, app: 'ms-teams.exe', publisher: 'Microsoft Corporation', protocol: 'UDP', domain: 'worldaz.relay.teams.microsoft.com', owner: 'Microsoft Corporation', country: 'NL', remote: '52.114.252.8:3478', sent: 9_100_000, received: 11_900_000, rate: 0.9 },
  { pid: 9340, app: 'Spotify.exe', publisher: 'Spotify AB', domain: 'audio-ak.spotifycdn.com', owner: 'Akamai International B.V.', country: 'SE', remote: '23.48.201.33:443', sent: 412_000, received: 64_500_000, rate: 0.7 },
  { pid: 9340, app: 'Spotify.exe', publisher: 'Spotify AB', domain: 'api-partner.spotify.com', owner: 'Spotify AB', country: 'SE', remote: '35.186.224.25:443', sent: 92_000, received: 380_000, rate: 0.1 },
  { pid: 7720, app: 'OneDrive.exe', publisher: 'Microsoft Corporation', domain: 'my.microsoftpersonalcontent.com', owner: 'Microsoft Corporation', country: 'US', remote: '13.107.42.12:443', sent: 152_000_000, received: 2_100_000, rate: 1.5 },
  { pid: 6104, app: 'Discord.exe', publisher: 'Discord Inc.', domain: 'gateway.discord.gg', owner: 'Cloudflare, Inc.', country: 'US', remote: '162.159.135.234:443', sent: 1_200_000, received: 7_800_000, rate: 0.3 },
  { pid: 6104, app: 'Discord.exe', publisher: 'Discord Inc.', domain: 'sentry.io', trust: 'guessed', owner: 'Sentry · diagnostics', country: 'US', remote: '34.120.195.249:443', sent: 31_000, received: 4_100, rate: 0.05 },
  { pid: 3388, app: 'steam.exe', publisher: 'Valve Corp.', domain: 'cache8-sin1.steamcontent.com', owner: 'Valve Corporation', country: 'SG', remote: '103.10.124.98:443', sent: 640_000, received: 210_000_000, rate: 1.1 },
  { pid: 4410, app: 'svchost.exe', publisher: 'Microsoft Windows Publisher', protocol: 'UDP', domain: null, owner: 'local network', country: null, remote: '192.168.1.1:53', sent: 38_000, received: 91_000, rate: 0.1 },
  { pid: 4410, app: 'svchost.exe', publisher: 'Microsoft Windows Publisher', domain: 'settings-win.data.microsoft.com', owner: 'Microsoft · diagnostics', country: 'US', remote: '20.42.65.85:443', sent: 210_000, received: 52_000, rate: 0.1 },
  { pid: 9921, app: 'updater.exe', publisher: 'UNSIGNED', domain: 'cdn.freeware-updates.net', trust: 'app_reported', owner: 'DigitalOcean, LLC', country: 'DE', remote: '164.92.137.55:443', sent: 2_400, received: 1_900_000, rate: 0.05, comes: true },
  { pid: 2216, app: 'Code.exe', publisher: 'Microsoft Corporation', domain: 'marketplace.visualstudio.com', owner: 'Microsoft Corporation', country: 'US', remote: '13.107.6.175:443', sent: 120_000, received: 3_400_000, rate: 0.2 },
  { pid: 2216, app: 'Code.exe', publisher: 'Microsoft Corporation', domain: 'dc.services.visualstudio.com', owner: 'Microsoft · diagnostics', country: 'US', remote: '20.189.173.5:443', sent: 66_000, received: 8_000, rate: 0.05 },
  { pid: 1404, app: 'zoom.exe', publisher: 'Zoom Video Communications, Inc.', protocol: 'UDP', domain: 'zoomsg.zoom.us', owner: 'Zoom Video Communications', country: 'SG', remote: '149.137.9.12:8801', sent: 3_100_000, received: 3_600_000, rate: 0.6, comes: true },
  // The same destination twice (an earlier, closed flow), as the service can report.
  { pid: 2216, app: 'Code.exe', publisher: 'Microsoft Corporation', domain: 'marketplace.visualstudio.com', owner: 'Microsoft Corporation', country: 'US', remote: '13.107.6.175:443', sent: 40_000, received: 900_000, rate: 0.01 },
  // A tracker hidden behind a site's own name (CNAME cloaking).
  { pid: 8124, app: 'chrome.exe', publisher: 'Google LLC', domain: 'metrics.shop.example', via: 'shop.example.sc.omtrdc.net', owner: 'Adobe · analytics', country: 'US', remote: '63.140.38.12:443', sent: 12_400, received: 3_100, rate: 0.05, comes: true },
  { pid: 8124, app: 'chrome.exe', publisher: 'Google LLC', domain: 'news.lk', owner: 'Sri Lanka Telecom PLC', country: 'LK', remote: '222.165.164.34:443', sent: 34_000, received: 2_100_000, rate: 0.2, comes: true },
];

const started = Date.now() - 3 * 3600 * 1000 - 17 * 60 * 1000;

/** A connection that comes back reaches another server (as CDNs do), so it is new each time. */
function nextAddress(remote: string, cycle: number): string {
  return remote.replace(/\.(\d+):/, (_, octet: string) => `.${((Number(octet) + cycle) % 254) + 1}:`);
}

export function demoLive(): Live {
  const elapsed = (Date.now() - started) / 1000;
  // Traffic that always grows, in bursts: the integral of
  // 1 + 0.6 sin(t / 7) + 0.35 sin(t / 2.3 + i), which is never negative.
  const grown = (i: number) =>
    elapsed - 4.2 * Math.cos(elapsed / 7) - 0.805 * Math.cos(elapsed / 2.3 + i);
  const flows: FlowView[] = SEEDS.map((s, i) => ({
    pid: s.pid,
    app: s.app,
    path: PATHS[s.app] ?? null,
    publisher: s.publisher,
    publisher_confirmed: s.confirmed ?? true,
    protocol: s.protocol ?? 'TCP',
    domain: s.domain,
    domain_trust: s.domain ? (s.trust ?? 'verified') : null,
    via: s.via ?? null,
    owner: s.owner,
    country: s.country,
    remote: s.comes ? nextAddress(s.remote, Math.floor((elapsed / 9 + i) / (2 * Math.PI))) : s.remote,
    bytes_sent: Math.round(s.sent + grown(i) * s.rate * 9_000),
    bytes_received: Math.round(s.received + grown(i + 3) * s.rate * 42_000),
    active: i % 7 !== 6,
  }))
    .filter((_, i) => !SEEDS[i]!.comes || Math.sin(elapsed / 9 + i) > 0)
    .sort((a, b) => b.bytes_sent + b.bytes_received - (a.bytes_sent + a.bytes_received));
  return {
    version: '0.1.0',
    status: {
      uptime_secs: Math.round(elapsed),
      events: Math.round(184_000 + elapsed * 41),
      dropped: 0,
      unreadable: 0,
      rejected: 0,
      over_limit: 0,
      unattributed: 0,
      active_flows: flows.filter((f) => f.active).length + 23,
      kernel_events_protected: true,
      saving: demoHistorySetting.save !== false,
      save_history: demoHistorySetting.save,
      tracker_domains: 47_359,
      block_rules: demo.rules.length,
      blocking_paused: demo.paused,
      drop_list: demoLists.drop_updates === true,
      lists: { ...demoLists },
    },
    flows,
    own_pids: [],
  };
}

// Demo blocking rules, kept in memory while the page is open.
const day = 86_400;
const now = () => Math.floor(Date.now() / 1000);
let nextId = 3;
const demo: Rules = {
  rules: [
    { id: 1, rule: { kind: 'domain', name: 'connect.facebook.net', app: null }, created_secs: now() - 3 * day, blocked_addresses: 2 },
    { id: 2, rule: { kind: 'app', path: PATHS['updater.exe'] ?? 'updater.exe' }, created_secs: now() - 2 * 3600, blocked_addresses: 0 },
  ],
  paused: false,
};

const copy = (): Rules => ({ rules: demo.rules.map((r) => ({ ...r })), paused: demo.paused });

export function demoRules(): Rules {
  return copy();
}

export async function demoAddRule(
  rule: RuleSpec,
): Promise<{ ok: true; value: Added | null } | { ok: false; problem: Problem }> {
  await new Promise((r) => setTimeout(r, 300));
  if (rule.kind === 'app' && /\\windows\\system32\\svchost\.exe$/i.test(rule.path)) {
    return {
      ok: false,
      problem: {
        kind: 'other',
        message: 'Whereabouts answered: not blocked: svchost.exe is part of Windows; blocking it could cut the computer off',
      },
    };
  }
  if (!window.confirm(`Demo: block ${JSON.stringify(rule)}?`)) return { ok: true, value: null };
  // Like the service: the same rule again is the existing one.
  const existing = demo.rules.find((r) => JSON.stringify(r.rule) === JSON.stringify(rule));
  if (existing) return { ok: true, value: { id: existing.id, already: true } };
  const id = nextId++;
  demo.rules.push({ id, rule, created_secs: now(), blocked_addresses: rule.kind === 'domain' ? 1 : 0 });
  return { ok: true, value: { id, already: false } };
}

export function demoRemoveRule(id: number): Rules {
  demo.rules = demo.rules.filter((r) => r.id !== id);
  return copy();
}

export function demoSetPaused(paused: boolean): Rules {
  demo.paused = paused;
  return copy();
}

// Demo alerts, kept in memory while the page is open.
const minute = 60;
let demoAlertList: AlertView[] = [
  { id: 8, created_secs: now() - 9 * minute, kind: 'behaviour', severity: 'high', app: 'Discord.exe', path: PATHS['Discord.exe'] ?? null, target: null, detail: null, dismissed: false, can_allow: true, seen_again: 2, reasons: [{ signal: 'upload_spike', value: null, observed: 356_515_840, usual: 5_242_880, count: null }] },
  { id: 7, created_secs: now() - 21 * minute, kind: 'behaviour', severity: 'medium', app: 'Code.exe', path: PATHS['Code.exe'] ?? null, target: 'RU', detail: null, dismissed: false, can_allow: true, seen_again: 0, reasons: [{ signal: 'new_country', value: 'RU', observed: null, usual: null, count: null }, { signal: 'new_company', value: 'Selectel', observed: null, usual: null, count: null }] },
  { id: 6, created_secs: now() - 4 * minute, kind: 'bad_network', severity: 'high', app: 'updater.exe', path: PATHS['updater.exe'] ?? null, target: '185.215.113.66', detail: '185.215.113.0/24 (SBL549867)', dismissed: false, can_allow: true },
  { id: 5, created_secs: now() - 38 * minute, kind: 'faked_dns', severity: 'medium', app: null, path: null, target: null, detail: '3 events', dismissed: false, can_allow: false },
  { id: 4, created_secs: now() - 52 * minute, kind: 'tracker', severity: 'info', app: 'chrome.exe', path: PATHS['chrome.exe'] ?? null, target: 'google-analytics.com', detail: 'Google', dismissed: false, can_allow: true },
  { id: 3, created_secs: now() - 70 * minute, kind: 'tracker', severity: 'info', app: 'chrome.exe', path: PATHS['chrome.exe'] ?? null, target: 'facebook.net', detail: 'Meta', dismissed: false, can_allow: true },
  { id: 2, created_secs: now() - 3 * 3600, kind: 'tracker', severity: 'info', app: 'Discord.exe', path: PATHS['Discord.exe'] ?? null, target: 'sentry.io', detail: 'Sentry', dismissed: false, can_allow: true },
  { id: 1, created_secs: now() - day, kind: 'tracker', severity: 'info', app: 'Code.exe', path: PATHS['Code.exe'] ?? null, target: 'visualstudio.com', detail: null, dismissed: true, can_allow: true },
];

export function demoAlerts(): AlertView[] {
  return demoAlertList.map((a) => ({ ...a }));
}

export function demoDismissAlert(id: number, allow: boolean): boolean {
  const alert = demoAlertList.find((a) => a.id === id);
  if (!alert) return false;
  if (allow && alert.severity === 'high' && !window.confirm('Demo: stop warnings about this network for this app?')) {
    return false;
  }
  demoAlertList = demoAlertList.map((a) =>
    a.id === id || (allow && a.kind === alert.kind && a.path === alert.path && a.target === alert.target)
      ? { ...a, dismissed: true }
      : a,
  );
  return true;
}

export function demoHistory(): AppTotals[] {
  const byApp = new Map<string, AppTotals>();
  for (const flow of demoLive().flows) {
    const key = appKey(flow.app, flow.path);
    const entry = byApp.get(key) ?? {
      app: flow.app,
      path: flow.path,
      publisher: flow.publisher,
      flows: 0,
      destinations: 0,
      bytes_sent: 0,
      bytes_received: 0,
    };
    entry.flows += 37;
    entry.destinations += 4;
    entry.bytes_sent += flow.bytes_sent * 6;
    entry.bytes_received += flow.bytes_received * 6;
    byApp.set(key, entry);
  }
  return [...byApp.values()].sort(
    (a, b) => b.bytes_sent + b.bytes_received - (a.bytes_sent + a.bytes_received),
  );
}

// Demo behaviour profiles, kept while the page is open.
const DAY = 86_400;
const items = (values: string[], state = 'learned'): ProfileItemView[] =>
  values.map((value, i) => ({ value, last_seen_secs: now() - (i + 1) * 3600, state }));
const hours = (active: Record<number, number>): number[] =>
  Array.from({ length: 24 }, (_, h) => active[h] ?? 0);

let demoProfiles: ProfileView[] = [
  {
    path: PATHS['chrome.exe'] ?? '',
    app: 'chrome.exe',
    learning: false,
    learning_ends_secs: now() - 20 * DAY,
    learned_since_secs: now() - 27 * DAY,
    goes_anywhere: true,
    goes_anywhere_choice: 'auto',
    recognised_browser: true,
    sites: items([
      'youtube.com', 'google.com', 'github.com', 'wikipedia.org', 'microsoft.com', 'reddit.com',
      'cloudflare.com', 'stackoverflow.com', 'nytimes.com', 'bbc.co.uk', 'amazon.com',
    ]),
    companies: items(['Google LLC', 'Cloudflare', 'Microsoft Corporation', 'Akamai International B.V.']),
    countries: items(['US', 'IE', 'NL', 'DE', 'GB']),
    usual_sent_per_hour: 6_400_000,
    busiest_sent_per_hour: 182_000_000,
    active_hours: hours({ 8: 0.06, 9: 0.1, 10: 0.11, 11: 0.1, 12: 0.07, 13: 0.09, 14: 0.11, 15: 0.1, 16: 0.08, 20: 0.1, 21: 0.08 }),
  },
  {
    path: PATHS['Spotify.exe'] ?? '',
    app: 'Spotify.exe',
    learning: true,
    learning_ends_secs: now() + 4 * DAY + 3600,
    learned_since_secs: now() - 3 * DAY + 3600,
    goes_anywhere: false,
    goes_anywhere_choice: 'auto',
    recognised_browser: false,
    sites: items(['spotifycdn.com', 'spotify.com', 'scdn.co']),
    companies: items(['Spotify AB', 'Akamai International B.V.']),
    countries: items(['SE', 'NL']),
    usual_sent_per_hour: 410_000,
    busiest_sent_per_hour: 1_900_000,
    active_hours: hours({ 9: 0.2, 10: 0.2, 17: 0.3, 18: 0.3 }),
  },
  {
    path: PATHS['Discord.exe'] ?? '',
    app: 'Discord.exe',
    learning: false,
    learning_ends_secs: now() - 2 * DAY,
    learned_since_secs: now() - 9 * DAY,
    goes_anywhere: false,
    goes_anywhere_choice: 'off',
    recognised_browser: false,
    sites: items(['discord.com', 'discordapp.com', 'sentry.io']),
    companies: items(['Discord Inc.', 'Cloudflare']),
    countries: items(['US', 'DE']),
    usual_sent_per_hour: 2_100_000,
    busiest_sent_per_hour: 9_800_000,
    active_hours: hours({ 19: 0.3, 20: 0.4, 21: 0.3 }),
  },
];

export function demoProfile(path: string): ProfileView | null {
  const found = demoProfiles.find((p) => p.path.toLowerCase() === path.toLowerCase());
  return found ? structuredClone(found) : null;
}

/** Asks like the native dialog does; if agreed, the profile starts learning again. */
export function demoResetProfile(path: string, app: string): boolean {
  if (!window.confirm(`Demo: reset what Whereabouts learned about ${app}? It will start a new 7-day learning period.`)) {
    return false;
  }
  demoProfiles = demoProfiles.map((p) =>
    p.path.toLowerCase() === path.toLowerCase()
      ? {
          ...p,
          learning: true,
          learning_ends_secs: now() + 7 * DAY,
          learned_since_secs: now(),
          sites: [],
          companies: [],
          countries: [],
          usual_sent_per_hour: null,
          busiest_sent_per_hour: null,
          active_hours: hours({}),
        }
      : p,
  );
  return true;
}

export function demoGoesAnywhere(path: string, choice: GoesAnywhereChoice): ProfileView | null {
  demoProfiles = demoProfiles.map((p) =>
    p.path.toLowerCase() === path.toLowerCase()
      ? {
          ...p,
          goes_anywhere_choice: choice,
          goes_anywhere: choice === 'auto' ? p.recognised_browser : choice === 'on',
        }
      : p,
  );
  return demoProfile(path);
}
