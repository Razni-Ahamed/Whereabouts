<script lang="ts">
  import { Ban, Check, EyeOff, Ghost, Radar, ShieldCheck, Siren, Sparkles } from '@lucide/svelte';
  import AppAvatar from '../lib/components/AppAvatar.svelte';
  import BlockMenu from '../lib/components/BlockMenu.svelte';
  import { appKey } from '../lib/apps';
  import { appLabel } from '../lib/format';
  import { alertTitle, reasonText } from '../lib/reasons';
  import { store } from '../lib/state.svelte';
  import type { AlertView, FlowView } from '../lib/types';

  let { onpickapp }: { onpickapp: (app: string) => void } = $props();

  type Filter = 'look' | 'trackers' | 'all';
  let filter = $state<Filter>('look');
  let blocking = $state<FlowView | null>(null);
  let busy = $state<number | null>(null);

  const all = $derived(store.alerts ?? []);
  const FILTERS: { id: Filter; label: string; test: (a: AlertView) => boolean }[] = [
    { id: 'look', label: 'Needs a look', test: (a) => a.severity !== 'info' && !a.dismissed },
    { id: 'trackers', label: 'Trackers', test: (a) => a.kind === 'tracker' },
    { id: 'all', label: 'All', test: () => true },
  ];
  const shown = $derived(all.filter(FILTERS.find((f) => f.id === filter)?.test ?? (() => true)));
  const counts = $derived(Object.fromEntries(FILTERS.map((f) => [f.id, all.filter(f.test).length])));

  function name(alert: AlertView): string {
    return alert.app ? appLabel(alert.app) : 'An app';
  }

  /** What happened, and why it matters, in plain words. */
  function explain(alert: AlertView): { title: string; why: string } {
    switch (alert.kind) {
      case 'bad_network':
        return {
          title: `${name(alert)} connected to a risky network`,
          why: `${alert.target ?? 'The address'} is in ${alert.detail ?? 'a range'} that Spamhaus lists as run by criminals (its DROP list). Connections there are often malware calling home.`,
        };
      case 'tracker':
        return {
          title: `${name(alert)} contacted ${alert.detail ?? alert.target ?? 'a tracker'}`,
          why: `${alert.target ?? 'This domain'} is on EasyPrivacy, a list of tracking and analytics services.`,
        };
      case 'faked_dns':
        return {
          title: 'Fake name lookups',
          why: `${alert.detail ?? 'Some events'} claimed to come from the Windows DNS service but didn't. A program may be trying to make its connections look like other sites.`,
        };
      case 'unattributed':
        return {
          title: "Traffic that couldn't be tied to an app",
          why: `${alert.detail ?? 'Some events'} went into a shared count because many connections flooded Whereabouts' table at once, which can be used to hide.`,
        };
      case 'behaviour':
        return {
          title: alertTitle(alert),
          why: 'This is not what Whereabouts has learned is usual for it.',
        };
    }
  }

  const ICONS = { bad_network: Siren, tracker: Radar, faked_dns: Ghost, unattributed: EyeOff, behaviour: Sparkles };

  function ago(secs: number): string {
    const minutes = Math.max(0, Math.round((Date.now() / 1000 - secs) / 60));
    if (minutes < 1) return 'just now';
    if (minutes < 60) return `${minutes} min ago`;
    const hours = Math.round(minutes / 60);
    if (hours < 24) return `${hours} h ago`;
    return new Date(secs * 1000).toLocaleDateString('en', { day: 'numeric', month: 'short' });
  }

  /** The first site (not a company or country) a behaviour alert's reasons name. */
  function siteOf(alert: AlertView): string | null {
    const site = alert.reasons?.find(
      (r) =>
        ['new_site', 'random_name', 'beaconing'].includes(r.signal) &&
        r.value?.includes('.') &&
        !isIpLiteral(r.value),
    );
    return site?.value ?? null;
  }

  /** Whether `host` is an IPv4 or IPv6 address, not a host name (an address cannot be blocked as a site). */
  function isIpLiteral(host: string): boolean {
    const bare = host.replace(/^\[|\]$/g, '');
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(bare) || (bare.includes(':') && /^[0-9a-f:.]+$/i.test(bare));
  }

  /** A stand-in connection, so the Block… picker can offer its choices. `site` makes it about one domain. */
  function asFlow(alert: AlertView, site: string | null = null): FlowView {
    const isDomain = alert.kind === 'tracker';
    return {
      pid: 0,
      app: alert.app ?? '',
      path: alert.path,
      publisher: '',
      publisher_confirmed: false,
      protocol: 'TCP',
      domain: isDomain ? alert.target : site,
      domain_trust: isDomain || site ? 'verified' : null,
      owner: null,
      country: null,
      remote: alert.kind !== 'behaviour' && alert.target && !isDomain ? `${alert.target.includes(':') ? `[${alert.target}]` : alert.target}:0` : '',
      bytes_sent: 0,
      bytes_received: 0,
      active: false,
    };
  }

  /** Clears an alert; with `trust`, alerts like it stop too ("This is fine"). */
  async function dismiss(alert: AlertView, trust: boolean) {
    busy = alert.id;
    await store.dismiss(alert.id, trust && alert.can_allow);
    busy = null;
  }
</script>

{#if blocking}
  <BlockMenu flow={blocking} onclose={() => (blocking = null)} />
{/if}

<section class="glass panel">
  <header>
    <div>
      <p class="eyebrow">Last 30 days</p>
      <h1 class="display">Alerts</h1>
    </div>
    <div class="filters">
      {#each FILTERS as f (f.id)}
        <button type="button" class:active={filter === f.id} onclick={() => (filter = f.id)}>
          {f.label} <span class="num">{counts[f.id]}</span>
        </button>
      {/each}
    </div>
  </header>

  {#if store.live && !store.live.status.drop_list}
    <p class="note muted">
      Risky-network checks start once this computer has downloaded Spamhaus' DROP list, which comes with list
      updates. Tracker and hiding checks already run.
    </p>
  {/if}

  {#if !store.alerts}
    <p class="muted empty">Reading alerts…</p>
  {:else if shown.length === 0}
    <div class="empty">
      <ShieldCheck size={36} strokeWidth={1.3} />
      <p><strong>{filter === 'look' ? 'Nothing needs a look.' : 'No alerts.'}</strong></p>
      <p class="muted">
        Whereabouts checks every connection against known lists and watches for signs that something is hiding.
      </p>
    </div>
  {:else}
    <ul>
      {#each shown as alert (alert.id)}
        {@const text = explain(alert)}
        {@const Icon = ICONS[alert.kind]}
        <li class="alert {alert.severity}" class:dismissed={alert.dismissed}>
          <span class="icon"><Icon size={18} /></span>
          <div class="body">
            <div class="top">
              <span class="title">{text.title}</span>
              <span class="chip sev">{alert.severity}</span>
              <span class="muted when">{ago(alert.created_secs)}</span>
            </div>
            {#if alert.kind === 'behaviour'}
              <ul class="reasons">
                {#each alert.reasons ?? [] as reason, i (i)}
                  <li>{reasonText(reason)}</li>
                {/each}
              </ul>
              <p class="why">
                {text.why}
                {#if alert.seen_again}Seen again {alert.seen_again} {alert.seen_again === 1 ? 'time' : 'times'}.{/if}
              </p>
            {:else}
              <p class="why">{text.why}</p>
            {/if}
            {#if alert.app}
              <button class="who" type="button" title={alert.path ?? undefined} onclick={() => onpickapp(alert.app ? appKey(alert.app, alert.path) : '')}>
                <AppAvatar app={alert.app} size={20} />
                {alert.path ?? alert.app}
              </button>
            {/if}
          </div>
          <div class="actions">
            {#if alert.dismissed}
              <span class="muted fine"><Check size={14} /> Cleared</span>
            {:else}
              {#if alert.app && alert.path && (alert.kind === 'tracker' || alert.kind === 'bad_network')}
                <button class="btn btn-ghost small" type="button" onclick={() => (blocking = asFlow(alert))}>
                  <Ban size={14} /> Block…
                </button>
              {:else if alert.app && alert.path && alert.kind === 'behaviour'}
                <button class="btn btn-ghost small" type="button" onclick={() => (blocking = asFlow(alert))}>
                  <Ban size={14} /> Block app
                </button>
                {#if siteOf(alert)}
                  <button class="btn btn-ghost small" type="button" onclick={() => (blocking = asFlow(alert, siteOf(alert)))}>
                    <Ban size={14} /> Block site
                  </button>
                {/if}
              {/if}
              <button
                class="btn btn-ghost small"
                type="button"
                disabled={busy === alert.id}
                title="Clear this alert. You'll be told again if it happens again."
                onclick={() => dismiss(alert, false)}
              >
                {alert.can_allow ? 'Dismiss' : 'Got it'}
              </button>
              {#if alert.can_allow}
                <button
                  class="btn btn-ghost small"
                  type="button"
                  disabled={busy === alert.id}
                  title={alert.kind === 'behaviour'
                    ? 'Treat this as normal: no more alerts about these destinations for this app.'
                    : `Trust this: no more alerts about this app and ${alert.kind === 'tracker' ? 'tracker' : 'network'}.`}
                  onclick={() => dismiss(alert, true)}
                >
                  This is fine
                </button>
              {/if}
            {/if}
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</section>

<style>
  .panel {
    padding: 24px 22px 12px;
    border-radius: var(--radius-xl);
  }
  header {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
    margin-bottom: 12px;
  }
  .eyebrow {
    margin: 0;
  }
  h1 {
    margin: 2px 0 0;
    font-size: 32px;
  }
  .filters {
    display: flex;
    gap: 8px;
  }
  .filters button {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    height: 34px;
    padding: 0 14px;
    border-radius: var(--radius-pill);
    border: 1px solid var(--glass-border);
    background: var(--glass);
    color: var(--text-soft);
    cursor: pointer;
  }
  .filters button.active {
    background: rgb(95 224 195 / 0.14);
    border-color: rgb(95 224 195 / 0.35);
    color: var(--accent);
  }
  .filters span {
    font-size: 12px;
    color: var(--text-muted);
  }
  .note {
    margin: 0 0 12px;
    font-size: 12.5px;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .alert {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr) auto;
    gap: 14px;
    align-items: start;
    padding: 14px 4px;
    border-bottom: 1px solid rgb(205 230 255 / 0.06);
  }
  .alert:last-child {
    border-bottom: 0;
  }
  .dismissed {
    opacity: 0.55;
  }
  .icon {
    display: grid;
    place-items: center;
    width: 36px;
    height: 36px;
    border-radius: 12px;
    background: var(--glass-strong);
    color: var(--text-soft);
  }
  .high .icon,
  .critical .icon {
    background: var(--danger-bg);
    color: var(--danger);
  }
  .medium .icon {
    background: var(--warn-bg);
    color: var(--warn);
  }
  .info .icon {
    color: var(--info);
  }
  .top {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }
  .title {
    font-weight: 600;
  }
  .sev {
    height: 20px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .high .sev,
  .critical .sev {
    color: var(--danger);
    background: var(--danger-bg);
    border-color: rgb(255 138 122 / 0.3);
  }
  .medium .sev {
    color: var(--warn);
    background: var(--warn-bg);
    border-color: rgb(242 196 109 / 0.3);
  }
  .when {
    font-size: 12px;
  }
  .reasons {
    margin: 6px 0 0;
    padding-left: 18px;
    list-style: disc;
    font-size: 13px;
    color: var(--text);
  }
  .reasons li {
    margin: 2px 0;
    overflow-wrap: anywhere;
  }
  .why {
    margin: 4px 0 6px;
    font-size: 13px;
    color: var(--text-soft);
  }
  .who {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    max-width: 100%;
    padding: 0;
    border: 0;
    background: none;
    font-size: 12px;
    color: var(--text-muted);
    cursor: pointer;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .who:hover {
    color: var(--text);
  }
  .actions {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
    justify-content: flex-end;
  }
  @media (max-width: 560px) {
    .alert {
      grid-template-columns: auto minmax(0, 1fr);
    }
    .actions {
      grid-column: 1 / -1;
      justify-content: flex-start;
    }
  }
  .small {
    height: 32px;
    padding: 0 12px;
    font-size: 12.5px;
  }
  .btn:disabled {
    opacity: 0.55;
    cursor: default;
    transform: none;
  }
  .fine {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 12px;
  }
  .empty {
    display: grid;
    justify-items: center;
    gap: 2px;
    padding: 36px 20px 30px;
    text-align: center;
    color: var(--accent);
  }
  .empty p {
    margin: 4px 0 0;
    color: var(--text);
  }
  .empty .muted {
    color: var(--text-muted);
    max-width: 440px;
  }
</style>
