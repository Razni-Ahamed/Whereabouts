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
  /** Saved blocking rules (0 from a 0.1 service). */
  block_rules: number;
  blocking_paused: boolean;
  /** Whether connections are checked against Spamhaus DROP (once downloaded). */
  drop_list: boolean;
}

export type DomainTrust = 'verified' | 'app_reported' | 'guessed';

export interface FlowView {
  pid: number;
  app: string;
  /** The program's full path, when the service knows it. */
  path: string | null;
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

/** What a blocking rule blocks. */
export type RuleSpec =
  | { kind: 'app'; path: string }
  | { kind: 'domain'; name: string; app: string | null }
  | { kind: 'address'; ip: string; app: string | null };

export interface RuleView {
  id: number;
  rule: RuleSpec;
  /** Seconds since 1970. */
  created_secs: number;
  /** For a domain rule: how many of its addresses are blocked now. */
  blocked_addresses: number;
}

export interface Rules {
  rules: RuleView[];
  paused: boolean;
}

export type Severity = 'info' | 'medium' | 'high' | 'critical';
export type AlertKind = 'tracker' | 'bad_network' | 'faked_dns' | 'unattributed';

export interface AlertView {
  id: number;
  /** Seconds since 1970. */
  created_secs: number;
  kind: AlertKind;
  severity: Severity;
  app: string | null;
  path: string | null;
  /** The domain or address concerned. */
  target: string | null;
  /** A company, a listing, a count. */
  detail: string | null;
  dismissed: boolean;
  /** Whether "this is fine" also stops alerts like it. */
  can_allow: boolean;
}

/** The app's own settings (per Windows user). */
export interface AppSettings {
  /** Whether Windows starts the app in the tray at sign-in. */
  start_at_sign_in: boolean;
  /** False for a developer build: only the installed app can start at sign-in. */
  can_start_at_sign_in: boolean;
  notifications: boolean;
  /** Whether notifications may name apps and sites. */
  show_names: boolean;
  first_run_done: boolean;
}

export interface Live {
  version: string;
  status: Status;
  flows: FlowView[];
  /** Process IDs that are Whereabouts: the app, its WebView2 helpers, the service. */
  own_pids: number[];
}
