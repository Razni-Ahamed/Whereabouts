<script lang="ts">
  import { AppWindow, CirclePause, Globe, MapPin, Play, ShieldCheck } from '@lucide/svelte';
  import { appLabel } from '../lib/format';
  import { fileName, store } from '../lib/state.svelte';
  import type { RuleView } from '../lib/types';

  const rules = $derived(store.rules?.rules ?? []);
  const paused = $derived(store.rules?.paused ?? false);
  let busy = $state<number | 'pause' | null>(null);

  function describe(view: RuleView): { icon: typeof Globe; title: string; scope: string; full?: string } {
    const rule = view.rule;
    switch (rule.kind) {
      case 'app':
        return { icon: AppWindow, title: appLabel(fileName(rule.path)), scope: 'All connections', full: rule.path };
      case 'domain':
        return {
          icon: Globe,
          title: rule.name,
          scope: rule.app ? `For ${appLabel(fileName(rule.app))}, with subdomains` : 'For every app, with subdomains',
          full: rule.app ?? undefined,
        };
      case 'address':
        return {
          icon: MapPin,
          title: rule.ip,
          scope: rule.app ? `For ${appLabel(fileName(rule.app))}` : 'For every app',
          full: rule.app ?? undefined,
        };
    }
  }

  const since = new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' });

  async function unblock(id: number) {
    busy = id;
    await store.unblock(id);
    busy = null;
  }

  async function togglePause() {
    busy = 'pause';
    await store.setPaused(!paused);
    busy = null;
  }
</script>

<div class="layout">
  <section class="glass panel">
    <header>
      <div>
        <p class="eyebrow">Blocking</p>
        <h1 class="display">Rules</h1>
      </div>
      {#if rules.length}
        <button
          class="btn {paused ? 'btn-primary' : 'btn-ghost'}"
          type="button"
          disabled={busy !== null || !store.rules}
          onclick={togglePause}
        >
          {#if paused}<Play size={16} /> Resume blocking{:else}<CirclePause size={16} /> Pause all blocks{/if}
        </button>
      {/if}
    </header>

    {#if !store.rules}
      <p class="muted empty">Reading the rules…</p>
    {:else if rules.length === 0}
      <div class="empty">
        <ShieldCheck size={36} strokeWidth={1.3} />
        <p><strong>Nothing is blocked.</strong></p>
        <p class="muted">
          To block an app or a site, choose <b>Block</b> next to a connection on the Connections or Apps
          screen.
        </p>
      </div>
    {:else}
      <ul class:dim={paused}>
        {#each rules as view (view.id)}
          {@const d = describe(view)}
          {@const Icon = d.icon}
          <li class="row">
            <span class="icon"><Icon size={18} /></span>
            <span class="what">
              <span class="title" title={d.full}>{d.title}</span>
              <span class="scope">{d.scope}</span>
            </span>
            <span class="meta">
              {#if view.rule.kind === 'domain'}
                <span class="chip" title="Addresses Windows' DNS service confirmed for it in the last day">
                  {view.blocked_addresses}
                  {view.blocked_addresses === 1 ? 'address' : 'addresses'} blocked now
                </span>
              {/if}
              <span class="muted since">Since {since.format(new Date(view.created_secs * 1000))}</span>
            </span>
            <button class="btn btn-ghost unblock" type="button" disabled={busy !== null} onclick={() => unblock(view.id)}>
              Unblock
            </button>
          </li>
        {/each}
      </ul>
    {/if}
  </section>

  <aside class="glass how">
    <h2 class="display">How blocking works</h2>
    <ul>
      <li>Blocks are rules in the Windows firewall. They stay when Whereabouts is closed or restarted.</li>
      <li>
        A site is blocked by its addresses, as Windows' DNS service confirms them. A connection that is
        already starting may get through once.
      </li>
      <li>
        Whereabouts never blocks core Windows programs, DNS servers or your local network, and a block for
        every app skips addresses that unblocked sites share.
      </li>
      <li><b>Pause</b> lifts every block at once and keeps your rules. Uninstalling removes every block.</li>
      <li>
        If something goes wrong, an administrator can lift every block with
        <code>whereabouts-service --unblock-all</code>.
      </li>
    </ul>
  </aside>
</div>

<style>
  .layout {
    display: grid;
    grid-template-columns: 1fr 320px;
    gap: 18px;
    align-items: start;
  }
  .panel {
    padding: 24px 22px 14px;
    border-radius: var(--radius-xl);
    min-width: 0;
  }
  header {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 14px;
  }
  .eyebrow {
    margin: 0;
  }
  h1 {
    margin: 2px 0 0;
    font-size: 32px;
  }
  header .btn {
    height: 38px;
    padding: 0 16px;
    font-size: 13px;
  }
  .btn:disabled {
    opacity: 0.55;
    cursor: default;
    transform: none;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .dim {
    opacity: 0.6;
  }
  .row {
    display: grid;
    grid-template-columns: auto 1fr auto auto;
    align-items: center;
    gap: 14px;
    padding: 12px 4px;
    border-bottom: 1px solid rgb(205 230 255 / 0.06);
  }
  .row:last-child {
    border-bottom: 0;
  }
  .icon {
    display: grid;
    place-items: center;
    width: 36px;
    height: 36px;
    border-radius: 12px;
    background: var(--danger-bg);
    color: var(--danger);
  }
  .what {
    display: grid;
    min-width: 0;
  }
  .title {
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .scope {
    font-size: 12.5px;
    color: var(--text-muted);
  }
  .meta {
    display: grid;
    justify-items: end;
    gap: 4px;
  }
  .since {
    font-size: 12px;
  }
  .unblock {
    height: 34px;
    padding: 0 14px;
    font-size: 13px;
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
    max-width: 420px;
  }
  .how {
    padding: 20px 22px;
  }
  .how h2 {
    margin: 0 0 8px;
    font-size: 18px;
  }
  .how ul {
    display: grid;
    gap: 10px;
    padding-left: 18px;
    list-style: disc;
    color: var(--text-soft);
    font-size: 13px;
  }
  code {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--mint);
    overflow-wrap: anywhere;
  }
  @media (max-width: 1000px) {
    .layout {
      grid-template-columns: 1fr;
    }
  }
</style>
