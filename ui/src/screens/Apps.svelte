<script lang="ts">
  import { Download, Globe, MapPin, Radar, Search, Upload } from '@lucide/svelte';
  import AppAvatar from '../lib/components/AppAvatar.svelte';
  import FlowTable from '../lib/components/FlowTable.svelte';
  import Trust from '../lib/components/Trust.svelte';
  import { appLabel, bytes, countryName } from '../lib/format';
  import { store } from '../lib/state.svelte';

  let { selected = $bindable() }: { selected: string | null } = $props();
  let query = $state('');

  const apps = $derived(
    store.apps.filter((a) => a.app.toLowerCase().includes(query.trim().toLowerCase())),
  );
  const current = $derived(
    store.apps.find((a) => a.app === selected) ?? store.apps[0] ?? null,
  );
  const saved = $derived(current ? store.history.find((h) => h.app === current.app) : undefined);
</script>

<div class="layout">
  <aside class="glass list">
    <label class="search">
      <Search size={16} />
      <input placeholder="Search apps" bind:value={query} />
    </label>
    <ul>
      {#each apps as app (app.app)}
        <li>
          <button
            type="button"
            class:active={current?.app === app.app}
            onclick={() => (selected = app.app)}
          >
            <AppAvatar app={app.app} size={36} />
            <span class="who">
              <span class="name">{appLabel(app.app)}</span>
              <span class="pub">{app.publisher === '-' ? 'no program file' : app.publisher}</span>
            </span>
            <span class="total num">{bytes(app.sent + app.received)}</span>
          </button>
        </li>
      {:else}
        <li class="muted none">No apps found.</li>
      {/each}
    </ul>
  </aside>

  {#if current}
    <section class="detail">
      <div class="glass head">
        <AppAvatar app={current.app} size={64} />
        <div class="title">
          <h1 class="display">{appLabel(current.app)}</h1>
          <p class="pub">
            {current.publisher === '-' ? 'No program file' : current.publisher}
            <Trust kind="publisher" publisher={current.publisher} confirmed={current.publisherConfirmed} />
          </p>
          <p class="file muted">{current.app} · process {[...new Set(current.flows.map((f) => f.pid))].join(', ')}</p>
        </div>
      </div>

      <div class="glass care">
        <div><Upload size={22} strokeWidth={1.4} /><b class="num">{bytes(current.sent)}</b><span>Sent now</span></div>
        <div><Download size={22} strokeWidth={1.4} /><b class="num">{bytes(current.received)}</b><span>Received now</span></div>
        <div><MapPin size={22} strokeWidth={1.4} /><b class="num">{current.destinations}</b><span>Destinations</span></div>
        <div>
          <Globe size={22} strokeWidth={1.4} /><b class="num">{current.countries.length}</b>
          <span title={current.countries.map(countryName).join(', ')}>Countries</span>
        </div>
        <div class:warn={current.trackers > 0}>
          <Radar size={22} strokeWidth={1.4} /><b class="num">{current.trackers}</b><span>Trackers</span>
        </div>
      </div>

      {#if saved}
        <p class="saved muted">
          Last 24 hours: {saved.flows} connections to {saved.destinations} destinations ·
          {bytes(saved.bytes_sent)} sent · {bytes(saved.bytes_received)} received
        </p>
      {/if}

      <div class="glass where">
        <h2 class="display">Where it connects</h2>
        <FlowTable flows={current.flows} showApp={false} />
      </div>
    </section>
  {:else}
    <section class="glass detail empty">
      <p class="muted">No app has used the network yet.</p>
    </section>
  {/if}
</div>

<style>
  .layout {
    display: grid;
    grid-template-columns: 320px 1fr;
    gap: 18px;
    align-items: start;
  }
  .list {
    padding: 14px;
    position: sticky;
    top: 20px;
    max-height: calc(100vh - 140px);
    display: flex;
    flex-direction: column;
  }
  .search {
    display: flex;
    align-items: center;
    gap: 10px;
    height: 42px;
    padding: 0 16px;
    margin-bottom: 10px;
    border-radius: var(--radius-pill);
    background: rgb(3 10 18 / 0.35);
    border: 1px solid var(--glass-border);
    color: var(--text-muted);
  }
  .search input {
    flex: 1;
    border: 0;
    outline: 0;
    background: transparent;
    color: var(--text);
    font: inherit;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    overflow-y: auto;
    display: grid;
    gap: 2px;
  }
  li button {
    width: 100%;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 9px 10px;
    border: 1px solid transparent;
    border-radius: var(--radius-md);
    background: transparent;
    text-align: left;
    cursor: pointer;
    transition: background 0.2s var(--ease);
  }
  li button:hover {
    background: var(--glass-strong);
  }
  li button.active {
    background: var(--glass-hover);
    border-color: var(--glass-border-strong);
  }
  .who {
    flex: 1;
    display: grid;
    min-width: 0;
  }
  .name {
    font-weight: 600;
  }
  .who .pub {
    font-size: 12px;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .total {
    font-size: 12.5px;
    color: var(--text-soft);
  }
  .none {
    padding: 12px;
  }
  .detail {
    display: grid;
    gap: 18px;
    min-width: 0;
  }
  .head {
    display: flex;
    align-items: center;
    gap: 22px;
    padding: 26px 28px;
    border-radius: var(--radius-xl);
  }
  h1 {
    margin: 0;
    font-size: 36px;
    line-height: 1.1;
  }
  .title .pub {
    margin: 4px 0 2px;
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--accent);
    font-size: 15px;
  }
  .file {
    margin: 0;
    font-size: 12.5px;
  }
  .care {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    padding: 18px 6px;
  }
  .care div {
    display: grid;
    justify-items: center;
    gap: 4px;
    color: var(--accent);
    text-align: center;
  }
  .care div + div {
    border-left: 1px solid var(--glass-border);
  }
  .care b {
    font-family: var(--font-display);
    font-weight: 500;
    font-size: 22px;
    color: var(--text);
  }
  .care span {
    font-size: 11.5px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    font-weight: 600;
    color: var(--text-muted);
  }
  .care .warn {
    color: var(--warn);
  }
  .saved {
    margin: -6px 6px 0;
    font-size: 13px;
  }
  .where {
    padding: 22px 16px 8px;
  }
  .where h2 {
    margin: 0 10px 10px;
    font-size: 22px;
  }
  .empty {
    padding: 40px;
    text-align: center;
  }
</style>
