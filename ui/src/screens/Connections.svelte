<script lang="ts">
  import { Search } from '@lucide/svelte';
  import FlowTable from '../lib/components/FlowTable.svelte';
  import { countryName } from '../lib/format';
  import { isTracking, store } from '../lib/state.svelte';
  import type { FlowView } from '../lib/types';

  let { onpickapp }: { onpickapp: (app: string) => void } = $props();

  type Filter = 'all' | 'trackers' | 'unverified' | 'unsigned';
  const FILTERS: { id: Filter; label: string; test: (f: FlowView) => boolean }[] = [
    { id: 'all', label: 'All', test: () => true },
    { id: 'trackers', label: 'Trackers', test: (f) => isTracking(f.owner) },
    { id: 'unverified', label: 'Unverified names', test: (f) => f.domain_trust === 'app_reported' },
    { id: 'unsigned', label: 'Unsigned apps', test: (f) => f.publisher === 'UNSIGNED' || f.publisher === 'INVALID SIGNATURE' },
  ];

  let query = $state('');
  let filter = $state<Filter>('all');

  const flows = $derived.by(() => {
    const q = query.trim().toLowerCase();
    const test = FILTERS.find((f) => f.id === filter)?.test ?? (() => true);
    return (store.live?.flows ?? []).filter(
      (f) =>
        test(f) &&
        (!q ||
          [f.app, f.domain, f.owner, f.remote, f.country, countryName(f.country), f.publisher]
            .filter(Boolean)
            .some((v) => String(v).toLowerCase().includes(q))),
    );
  });
  const counts = $derived(
    Object.fromEntries(FILTERS.map((f) => [f.id, (store.live?.flows ?? []).filter(f.test).length])),
  );
</script>

<section class="glass panel">
  <header>
    <div>
      <p class="eyebrow">Live · largest first</p>
      <h1 class="display">Connections</h1>
    </div>
    <label class="search">
      <Search size={16} />
      <input placeholder="Search app, domain, company, country…" bind:value={query} />
    </label>
  </header>
  <div class="filters">
    {#each FILTERS as f (f.id)}
      <button type="button" class:active={filter === f.id} onclick={() => (filter = f.id)}>
        {f.label} <span class="num">{counts[f.id]}</span>
      </button>
    {/each}
  </div>
  <FlowTable {flows} {onpickapp} />
</section>

<style>
  .panel {
    padding: 24px 16px 10px;
    border-radius: var(--radius-xl);
  }
  header {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 20px;
    padding: 0 10px 16px;
  }
  h1 {
    margin: 2px 0 0;
    font-size: 32px;
  }
  .search {
    display: flex;
    align-items: center;
    gap: 10px;
    width: min(420px, 50%);
    height: 44px;
    padding: 0 18px;
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
  .filters {
    display: flex;
    gap: 8px;
    padding: 0 10px 14px;
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
    transition: background 0.2s var(--ease);
  }
  .filters button:hover {
    background: var(--glass-hover);
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
</style>
