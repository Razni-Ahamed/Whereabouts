<script lang="ts">
  import { ArrowDown, ArrowUp, Ban } from '@lucide/svelte';
  import AppAvatar from './AppAvatar.svelte';
  import BlockMenu from './BlockMenu.svelte';
  import Trust from './Trust.svelte';
  import { appLabel, bytes, countryName, ownerParts } from '../format';
  import { isTracking } from '../state.svelte';
  import type { FlowView } from '../types';

  let {
    flows,
    showApp = true,
    onpickapp,
  }: { flows: FlowView[]; showApp?: boolean; onpickapp?: (app: string) => void } = $props();

  let blocking = $state<FlowView | null>(null);
</script>

{#if blocking}
  <BlockMenu flow={blocking} onclose={() => (blocking = null)} />
{/if}

<div class="table" role="table" aria-label="Connections">
  <div class="head" role="row" class:noapp={!showApp}>
    {#if showApp}<span role="columnheader">App</span>{/if}
    <span role="columnheader">Destination</span>
    <span role="columnheader">Company</span>
    <span role="columnheader">Country</span>
    <span role="columnheader" class="right">Sent</span>
    <span role="columnheader" class="right">Received</span>
    <span role="columnheader"><span class="sr">Block</span></span>
  </div>
  <!-- Keyed by position: the same app, protocol and address can appear twice
       (a closed flow and a newer one to the same place). -->
  {#each flows as flow, i (i)}
    {@const owner = ownerParts(flow.owner)}
    <div class="row" role="row" class:noapp={!showApp} class:closed={!flow.active}>
      {#if showApp}
        <button class="app" type="button" onclick={() => onpickapp?.(flow.app)} title="PID {flow.pid}">
          <AppAvatar app={flow.app} size={30} />
          <span class="stack">
            <span class="name">{appLabel(flow.app)}</span>
            <span class="minor">
              {flow.publisher === '-' ? 'no program file' : flow.publisher}
            </span>
          </span>
        </button>
      {/if}
      <span class="stack" role="cell">
        <span class="name mono">
          {flow.domain ?? flow.remote}
          <Trust kind="domain" trust={flow.domain_trust} />
        </span>
        {#if flow.via}
          <span class="minor mono via" title="{flow.domain} points to {flow.via}, which is what shows who is behind it">
            via {flow.via}
          </span>
        {:else}
          <span class="minor mono">{flow.domain ? flow.remote : flow.protocol}</span>
        {/if}
      </span>
      <span class="stack" role="cell">
        <span class="name">{owner.name}</span>
        {#if owner.kind}
          <span class="minor" class:tracking={isTracking(flow.owner)}>{owner.kind}</span>
        {/if}
      </span>
      <span class="country" role="cell">
        {#if flow.country}<span class="cc">{flow.country}</span>{/if}
        <span class="minor">{flow.country ? countryName(flow.country) : '—'}</span>
      </span>
      <span class="right num" role="cell"><ArrowUp size={12} /> {bytes(flow.bytes_sent)}</span>
      <span class="right num" role="cell"><ArrowDown size={12} /> {bytes(flow.bytes_received)}</span>
      <span role="cell">
        <button
          class="block"
          type="button"
          title="Block…"
          aria-label="Block {appLabel(flow.app)} → {flow.domain ?? flow.remote}"
          onclick={() => (blocking = flow)}
        >
          <Ban size={15} />
        </button>
      </span>
    </div>
  {:else}
    <p class="muted empty">No connections yet.</p>
  {/each}
</div>

<style>
  .table {
    display: grid;
    overflow-x: auto;
  }
  .head,
  .row {
    display: grid;
    grid-template-columns: minmax(170px, 1.2fr) minmax(200px, 1.6fr) minmax(140px, 1fr) minmax(110px, 0.8fr) 96px 104px 32px;
    align-items: center;
    gap: 14px;
    padding: 10px 14px;
  }
  .noapp {
    grid-template-columns: minmax(160px, 1.6fr) minmax(110px, 1fr) minmax(80px, 0.8fr) 88px 96px 32px;
  }
  .head {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--text-faint);
    border-bottom: 1px solid var(--glass-border);
  }
  .row {
    border-bottom: 1px solid rgb(205 230 255 / 0.06);
    transition: background 0.2s var(--ease);
  }
  .row:hover {
    background: rgb(196 222 245 / 0.045);
  }
  .row:last-child {
    border-bottom: 0;
  }
  .closed {
    opacity: 0.62;
  }
  .app {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
    padding: 0;
    border: 0;
    background: none;
    text-align: left;
    cursor: pointer;
  }
  .stack {
    display: grid;
    min-width: 0;
  }
  .name {
    font-weight: 500;
    font-size: 13px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .minor {
    font-size: 11.5px;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .mono {
    font-feature-settings: 'tnum', 'zero';
  }
  .tracking {
    color: var(--warn);
  }
  .via {
    color: var(--warn);
  }
  .country {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }
  .cc {
    flex: none;
    font-size: 10.5px;
    font-weight: 700;
    letter-spacing: 0.06em;
    padding: 2px 6px;
    border-radius: 6px;
    background: var(--glass-strong);
    border: 1px solid var(--glass-border);
    color: var(--text-soft);
  }
  .right {
    justify-self: end;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 13px;
    color: var(--text-soft);
  }
  .right :global(svg) {
    color: var(--text-faint);
  }
  .empty {
    padding: 18px 14px;
    margin: 0;
  }
  .block {
    display: grid;
    place-items: center;
    width: 30px;
    height: 30px;
    padding: 0;
    border-radius: 50%;
    border: 1px solid transparent;
    background: transparent;
    color: var(--text-faint);
    cursor: pointer;
    opacity: 0;
    transition:
      opacity 0.2s var(--ease),
      background 0.2s var(--ease),
      color 0.2s var(--ease);
  }
  .row:hover .block,
  .block:focus-visible {
    opacity: 1;
  }
  .block:hover {
    color: var(--danger);
    background: var(--danger-bg);
    border-color: rgb(255 138 122 / 0.3);
  }
  .sr {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip-path: inset(50%);
  }
  @media (hover: none) {
    .block {
      opacity: 1;
    }
  }
</style>
