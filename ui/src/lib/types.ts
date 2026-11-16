// Mirrors the message types of the `whereabouts-ipc` crate.

export interface Status {
  uptime_secs: number;
  events: number;
  dropped: number;
  unreadable: number;
  rejected: number;
  over_limit: number;
  unattributed: number;
  active_flows: number;
  kernel_events_protected: boolean;
  saving: boolean;
  tracker_domains: number;
}

export type DomainTrust = 'verified' | 'app_reported' | 'guessed';

export interface FlowView {
  pid: number;
  app: string;
  publisher: string;
  publisher_confirmed: boolean;
  protocol: string;
  domain: string | null;
  domain_trust: DomainTrust | null;
  owner: string | null;
  country: string | null;
  remote: string;
  bytes_sent: number;
  bytes_received: number;
  active: boolean;
}

export interface AppTotals {
  app: string;
  publisher: string | null;
  flows: number;
  destinations: number;
  bytes_sent: number;
  bytes_received: number;
}

/** Why the service could not be reached. */
export type ProblemKind = 'not_running' | 'access_denied' | 'untrusted' | 'refused' | 'other';

export interface Problem {
  kind: ProblemKind;
  message: string;
}

export interface Live {
  version: string;
  status: Status;
  flows: FlowView[];
  /** Process IDs that are Whereabouts: the app, its WebView2 helpers, the service. */
  own_pids: number[];
}
