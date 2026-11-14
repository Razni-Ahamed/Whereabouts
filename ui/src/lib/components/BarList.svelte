<script lang="ts">
  import type { Component } from 'svelte';

  export interface BarItem {
    key: string;
    label: string;
    sub?: string | null;
    value: number;
    display: string;
    tone?: 'accent' | 'warn';
  }

  let {
    title,
    icon: Icon,
    items,
    empty = 'Nothing yet.',
    onpick,
  }: {
    title: string;
    icon: Component<{ size?: number; strokeWidth?: number }>;
    items: BarItem[];
    empty?: string;
    onpick?: (key: string) => void;
  } = $props();

  const max = $derived(Math.max(1, ...items.map((i) => i.value)));
</script>

<section class="glass card">
  <header>
    <span class="icon"><Icon size={17} strokeWidth={1.6} /></span>
    <h3>{title}</h3>
  </header>
  {#if items.length === 0}
    <p class="muted empty">{empty}</p>
  {:else}
    <ol>
      {#each items as item (item.key)}
        <li>
          <button type="button" disabled={!onpick} onclick={() => onpick?.(item.key)}>
            <span class="row">
              <span class="label">
                {item.label}
                {#if item.sub}<span class="sub">{item.sub}</span>{/if}
              </span>
              <span class="value num">{item.display}</span>
            </span>
            <span class="track">
              <span
                class="bar"
                class:warn={item.tone === 'warn'}
                style:width="{Math.max(3, (item.value / max) * 100)}%"
              ></span>
            </span>
          </button>
        </li>
      {/each}
    </ol>
  {/if}
</section>

<style>
  .card {
    padding: 20px 22px 18px;
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 14px;
  }
  .icon {
    display: grid;
    place-items: center;
    width: 32px;
    height: 32px;
    border-radius: 50%;
    color: var(--accent);
    background: rgb(95 224 195 / 0.1);
    border: 1px solid rgb(95 224 195 / 0.2);
  }
  h3 {
    margin: 0;
    font-size: 15px;
    font-weight: 600;
    letter-spacing: 0.01em;
  }
  ol {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 4px;
  }
  button {
    width: 100%;
    display: grid;
    gap: 6px;
    padding: 7px 8px;
    margin: 0 -8px;
    width: calc(100% + 16px);
    border: 0;
    background: transparent;
    border-radius: var(--radius-sm);
    text-align: left;
    cursor: pointer;
    transition: background 0.2s var(--ease);
  }
  button:disabled {
    cursor: default;
  }
  button:not(:disabled):hover {
    background: var(--glass-strong);
  }
  .row {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    font-size: 13px;
  }
  .label {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    color: var(--text);
  }
  .sub {
    margin-left: 6px;
    color: var(--text-muted);
    font-size: 12px;
  }
  .value {
    color: var(--text-soft);
    flex: none;
  }
  .track {
    display: block;
    height: 5px;
    border-radius: 5px;
    background: rgb(205 230 255 / 0.07);
    overflow: hidden;
  }
  .bar {
    display: block;
    height: 100%;
    border-radius: 5px;
    background: linear-gradient(90deg, var(--ink-600), var(--accent));
    transition: width 0.6s var(--ease);
  }
  .bar.warn {
    background: linear-gradient(90deg, #7a6233, var(--warn));
  }
  .empty {
    margin: 8px 0;
  }
</style>
