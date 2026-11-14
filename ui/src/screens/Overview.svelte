<script lang="ts">
  import {
    AppWindow,
    ArrowRight,
    Building2,
    CircleCheck,
    EyeOff,
    Globe,
    HardDrive,
    Lock,
    MapPin,
    Radar,
    TriangleAlert,
    Upload,
    Download,
  } from '@lucide/svelte';
  import BarList, { type BarItem } from '../lib/components/BarList.svelte';
  import FlowTable from '../lib/components/FlowTable.svelte';
  import Sparkline from '../lib/components/Sparkline.svelte';
  import { appLabel, bytes, count, countryName, ownerParts, uptime } from '../lib/format';
  import { isTracking, store } from '../lib/state.svelte';

  let {
    onpickapp,
    ongo,
  }: { onpickapp: (app: string) => void; ongo: (screen: 'apps' | 'connections' | 'privacy') => void } =
    $props();

  const status = $derived(store.live?.status);
  const flows = $derived(store.live?.flows ?? []);

  const topApps = $derived<BarItem[]>(
    store.apps.slice(0, 6).map((a) => ({
      key: a.app,
      label: appLabel(a.app),
      sub: a.publisher !== '-' && a.publisher !== '…' ? a.publisher : null,
      value: a.sent + a.received,
      display: bytes(a.sent + a.received),
      tone: a.publisher === 'UNSIGNED' ? 'warn' : 'accent',
    })),
  );

  const companies = $derived.by<BarItem[]>(() => {
    const totals = new Map<string, { value: number; kind: string | null; tracking: boolean }>();
    for (const f of flows) {
      if (!f.owner || f.owner === 'local network' || f.owner === 'multicast') continue;
      const { name, kind } = ownerParts(f.owner);
      const entry = totals.get(name) ?? { value: 0, kind, tracking: false };
      entry.value += f.bytes_sent + f.bytes_received;
      entry.tracking ||= isTracking(f.owner);
      totals.set(name, entry);
    }
    return [...totals.entries()]
      .sort((a, b) => b[1].value - a[1].value)
      .slice(0, 6)
      .map(([name, e]) => ({
        key: name,
        label: name,
        sub: e.tracking ? 'tracking' : null,
        value: e.value,
        display: bytes(e.value),
        tone: e.tracking ? 'warn' : 'accent',
      }));
  });

  const countries = $derived.by<BarItem[]>(() => {
    const totals = new Map<string, number>();
    for (const f of flows) {
      if (!f.country) continue;
      totals.set(f.country, (totals.get(f.country) ?? 0) + f.bytes_sent + f.bytes_received);
    }
    return [...totals.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([cc, value]) => ({ key: cc, label: countryName(cc), sub: cc, value, display: bytes(value) }));
  });

  const day = $derived.by(() => {
    if (store.history.length > 0) {
      return {
        sent: store.history.reduce((t, a) => t + a.bytes_sent, 0),
        received: store.history.reduce((t, a) => t + a.bytes_received, 0),
        label: 'last 24 h',
      };
    }
    return {
      sent: flows.reduce((t, f) => t + f.bytes_sent, 0),
      received: flows.reduce((t, f) => t + f.bytes_received, 0),
      label: 'right now',
    };
  });

  const destinations = $derived(new Set(flows.map((f) => f.domain ?? f.remote)).size);
  const countryCount = $derived(new Set(flows.map((f) => f.country).filter(Boolean)).size);
  const trackers = $derived(flows.filter((f) => isTracking(f.owner)).length);

  const checks = $derived(
    status
      ? [
          { ok: true, text: `Watching network events · up ${uptime(status.uptime_secs)}` },
          {
            ok: status.kernel_events_protected,
            text: status.kernel_events_protected
              ? 'Kernel events cannot be faked by apps'
              : 'This Windows version lets apps fake kernel events',
          },
          {
            ok: status.saving,
            text: status.saving ? 'Saving history, encrypted on this PC' : 'History is not being saved',
          },
          {
            ok: status.rejected === 0,
            text:
              status.rejected === 0
                ? 'No faked domain names detected'
                : `${count(status.rejected)} faked domain-name events rejected`,
          },
          {
            ok: status.tracker_domains > 0,
            text: `${count(status.tracker_domains)} tracker domains known offline`,
          },
        ]
      : [],
  );
</script>

<div class="grid">
  <section class="glass hero">
    <p class="eyebrow">Private by design</p>
    <h1 class="display">
      Every app.<br />Every destination.<br /><span class="accent">Nothing read.</span>
    </h1>
    <p class="lead">
      Whereabouts shows which app on this PC talks to which company and country, and how much it
      sends. It never looks inside what is sent.
    </p>
    <div class="promises">
      <div><EyeOff size={20} strokeWidth={1.5} /><span>Never reads<br />content</span></div>
      <div><HardDrive size={20} strokeWidth={1.5} /><span>Stays on<br />this PC</span></div>
      <div><Lock size={20} strokeWidth={1.5} /><span>Encrypted<br />history</span></div>
    </div>
    <div class="actions">
      <button class="btn btn-primary" type="button" onclick={() => ongo('apps')}>
        Explore apps <ArrowRight size={17} />
      </button>
      <button class="btn btn-ghost" type="button" onclick={() => ongo('privacy')}>How it stays private</button>
    </div>
  </section>

  <section class="glass now">
    <p class="eyebrow">Right now</p>
    <div class="big">
      <span class="display num">{status ? count(status.active_flows) : '—'}</span>
      <span class="unit">open connections<br />from {store.apps.length} apps</span>
    </div>
    <div class="activity">
      <div class="activity-head">
        <span class="eyebrow">Activity · last 2 minutes</span>
        <span class="num rate">{bytes(store.activity.at(-1) ?? 0)}/s</span>
      </div>
      <Sparkline values={store.activity} />
    </div>
    <ul class="checks">
      {#each checks as check (check.text)}
        <li class:bad={!check.ok}>
          {#if check.ok}<CircleCheck size={17} strokeWidth={1.7} />{:else}<TriangleAlert size={17} strokeWidth={1.7} />{/if}
          {check.text}
        </li>
      {/each}
    </ul>
  </section>

  <section class="glass band">
    <div><AppWindow size={22} strokeWidth={1.4} /><span><b class="num">{store.apps.length}</b>apps online</span></div>
    <div><MapPin size={22} strokeWidth={1.4} /><span><b class="num">{destinations}</b>destinations</span></div>
    <div><Globe size={22} strokeWidth={1.4} /><span><b class="num">{countryCount}</b>countries</span></div>
    <div><Upload size={22} strokeWidth={1.4} /><span><b class="num">{bytes(day.sent)}</b>sent · {day.label}</span></div>
    <div><Download size={22} strokeWidth={1.4} /><span><b class="num">{bytes(day.received)}</b>received · {day.label}</span></div>
    <div class:warnstat={trackers > 0}>
      <Radar size={22} strokeWidth={1.4} /><span><b class="num">{trackers}</b>tracker connections</span>
    </div>
  </section>

  <div class="three">
    <BarList title="Top apps" icon={AppWindow} items={topApps} onpick={onpickapp} />
    <BarList title="Companies" icon={Building2} items={companies} />
    <BarList title="Countries" icon={Globe} items={countries} />
  </div>

  <section class="glass live">
    <header>
      <div>
        <p class="eyebrow">Live</p>
        <h2 class="display">Biggest connections</h2>
      </div>
      <button class="btn btn-ghost" type="button" onclick={() => ongo('connections')}>
        All connections <ArrowRight size={16} />
      </button>
    </header>
    <FlowTable flows={flows.slice(0, 7)} {onpickapp} />
  </section>
</div>

<style>
  .grid {
    display: grid;
    grid-template-columns: 1.45fr 1fr;
    gap: 18px;
  }
  .hero {
    padding: 34px 36px 32px;
    border-radius: var(--radius-xl);
  }
  h1 {
    margin: 10px 0 14px;
    font-size: 46px;
    line-height: 1.04;
  }
  .accent {
    color: var(--accent);
  }
  .lead {
    max-width: 520px;
    margin: 0 0 22px;
    font-size: 15px;
    color: var(--text-soft);
  }
  .promises {
    display: inline-grid;
    grid-template-columns: repeat(3, auto);
    margin-bottom: 24px;
    border-radius: var(--radius-md);
    border: 1px solid var(--glass-border);
    background: rgb(3 10 18 / 0.25);
  }
  .promises div {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 18px;
    font-size: 11.5px;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    line-height: 1.3;
    color: var(--text-soft);
  }
  .promises div + div {
    border-left: 1px solid var(--glass-border);
  }
  .promises :global(svg) {
    color: var(--accent);
    flex: none;
  }
  .actions {
    display: flex;
    gap: 12px;
  }
  .now {
    padding: 30px 30px 26px;
    border-radius: var(--radius-xl);
    display: flex;
    flex-direction: column;
  }
  .big {
    display: flex;
    align-items: flex-end;
    gap: 14px;
    margin: 6px 0 18px;
  }
  .big .display {
    font-size: 76px;
    line-height: 0.95;
    color: var(--mint);
  }
  .unit {
    padding-bottom: 8px;
    color: var(--text-soft);
    font-size: 13px;
    line-height: 1.35;
  }
  .activity {
    margin: 0 0 16px;
  }
  .activity-head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 6px;
  }
  .rate {
    font-size: 13px;
    color: var(--accent);
  }
  .checks {
    list-style: none;
    margin: auto 0 0;
    padding: 16px 0 0;
    display: grid;
    gap: 10px;
    border-top: 1px solid var(--glass-border);
  }
  .checks li {
    display: flex;
    align-items: center;
    gap: 10px;
    color: var(--text-soft);
    font-size: 13.5px;
  }
  .checks :global(svg) {
    color: var(--accent);
    flex: none;
  }
  .checks li.bad,
  .checks li.bad :global(svg) {
    color: var(--warn);
  }
  .band {
    grid-column: 1 / -1;
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    padding: 18px 8px;
  }
  .band div {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 2px 18px;
    color: var(--accent);
  }
  .band div + div {
    border-left: 1px solid var(--glass-border);
  }
  .band span {
    display: grid;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--text-muted);
  }
  .band b {
    font-family: var(--font-display);
    font-size: 24px;
    font-weight: 500;
    letter-spacing: 0;
    text-transform: none;
    color: var(--text);
    line-height: 1.15;
  }
  .band .warnstat {
    color: var(--warn);
  }
  .three {
    grid-column: 1 / -1;
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 18px;
  }
  .live {
    grid-column: 1 / -1;
    padding: 22px 18px 10px;
  }
  .live header {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    padding: 0 8px 12px;
  }
  h2 {
    margin: 2px 0 0;
    font-size: 24px;
  }
</style>
