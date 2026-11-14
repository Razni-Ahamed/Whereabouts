// Made-up data, shown only when the UI runs in an ordinary browser (for
// design work). The desktop app always shows real data from the service.

import type { AppTotals, FlowView, Live } from './types';

interface Seed {
  pid: number;
  app: string;
  publisher: string;
  confirmed?: boolean;
  protocol?: string;
  domain: string | null;
  trust?: FlowView['domain_trust'];
  owner: string | null;
  country: string | null;
  remote: string;
  sent: number;
  received: number;
  rate: number;
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
  { pid: 9921, app: 'updater.exe', publisher: 'UNSIGNED', domain: 'cdn.freeware-updates.net', trust: 'app_reported', owner: 'DigitalOcean, LLC', country: 'DE', remote: '164.92.137.55:443', sent: 2_400, received: 1_900_000, rate: 0.05 },
  { pid: 2216, app: 'Code.exe', publisher: 'Microsoft Corporation', domain: 'marketplace.visualstudio.com', owner: 'Microsoft Corporation', country: 'US', remote: '13.107.6.175:443', sent: 120_000, received: 3_400_000, rate: 0.2 },
  { pid: 2216, app: 'Code.exe', publisher: 'Microsoft Corporation', domain: 'dc.services.visualstudio.com', owner: 'Microsoft · diagnostics', country: 'US', remote: '20.189.173.5:443', sent: 66_000, received: 8_000, rate: 0.05 },
  { pid: 1404, app: 'zoom.exe', publisher: 'Zoom Video Communications, Inc.', protocol: 'UDP', domain: 'zoomsg.zoom.us', owner: 'Zoom Video Communications', country: 'SG', remote: '149.137.9.12:8801', sent: 3_100_000, received: 3_600_000, rate: 0.6 },
  // The same destination twice (an earlier, closed flow), as the service can report.
  { pid: 2216, app: 'Code.exe', publisher: 'Microsoft Corporation', domain: 'marketplace.visualstudio.com', owner: 'Microsoft Corporation', country: 'US', remote: '13.107.6.175:443', sent: 40_000, received: 900_000, rate: 0.01 },
  { pid: 8124, app: 'chrome.exe', publisher: 'Google LLC', domain: 'news.lk', owner: 'Sri Lanka Telecom PLC', country: 'LK', remote: '222.165.164.34:443', sent: 34_000, received: 2_100_000, rate: 0.2 },
];

const started = Date.now() - 3 * 3600 * 1000 - 17 * 60 * 1000;

export function demoLive(): Live {
  const elapsed = (Date.now() - started) / 1000;
  // Traffic that always grows, in bursts: the integral of
  // 1 + 0.6 sin(t / 7) + 0.35 sin(t / 2.3 + i), which is never negative.
  const grown = (i: number) =>
    elapsed - 4.2 * Math.cos(elapsed / 7) - 0.805 * Math.cos(elapsed / 2.3 + i);
  const flows: FlowView[] = SEEDS.map((s, i) => ({
    pid: s.pid,
    app: s.app,
    publisher: s.publisher,
    publisher_confirmed: s.confirmed ?? true,
    protocol: s.protocol ?? 'TCP',
    domain: s.domain,
    domain_trust: s.domain ? (s.trust ?? 'verified') : null,
    owner: s.owner,
    country: s.country,
    remote: s.remote,
    bytes_sent: Math.round(s.sent + grown(i) * s.rate * 9_000),
    bytes_received: Math.round(s.received + grown(i + 3) * s.rate * 42_000),
    active: i % 7 !== 6,
  })).sort((a, b) => b.bytes_sent + b.bytes_received - (a.bytes_sent + a.bytes_received));
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
      saving: true,
      tracker_domains: 47_359,
    },
    flows,
  };
}

export function demoHistory(): AppTotals[] {
  const byApp = new Map<string, AppTotals>();
  for (const flow of demoLive().flows) {
    const entry = byApp.get(flow.app) ?? {
      app: flow.app,
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
    byApp.set(flow.app, entry);
  }
  return [...byApp.values()].sort(
    (a, b) => b.bytes_sent + b.bytes_received - (a.bytes_sent + a.bytes_received),
  );
}
