<script lang="ts">
  // Picks what to block for one connection. Windows then shows exactly what
  // will be blocked in its own dialog; nothing is blocked from here alone.
  import { AppWindow, Globe, MapPin, Users, X } from '@lucide/svelte';
  import { appLabel } from '../format';
  import { portal } from '../portal';
  import { remoteAddress, store } from '../state.svelte';
  import type { FlowView, RuleSpec } from '../types';

  let { flow, onclose }: { flow: FlowView; onclose: () => void } = $props();

  interface Choice {
    icon: typeof Globe;
    title: string;
    detail: string;
    rule: RuleSpec;
    what: string;
    warn?: boolean;
  }

  const name = $derived(appLabel(flow.app));
  const ip = $derived(remoteAddress(flow.remote));

  const choices = $derived.by(() => {
    const list: Choice[] = [];
    const path = flow.path;
    if (flow.domain && path) {
      list.push({
        icon: Globe,
        title: `${flow.domain} for ${name}`,
        detail: `${name} can't reach this site or its subdomains. Other apps still can.`,
        rule: { kind: 'domain', name: flow.domain, app: path },
        what: `${flow.domain} for ${name}`,
      });
    }
    if (flow.domain) {
      list.push({
        icon: Users,
        title: `${flow.domain} for every app`,
        detail:
          'No app can reach this site. Addresses that other, unblocked sites share are never blocked.',
        rule: { kind: 'domain', name: flow.domain, app: null },
        what: `${flow.domain} for every app`,
        warn: true,
      });
    }
    if (!flow.domain && ip && path) {
      list.push({
        icon: MapPin,
        title: `${ip} for ${name}`,
        detail: `${name} can't reach this address. Other sites may share it.`,
        rule: { kind: 'address', ip, app: path },
        what: `${ip} for ${name}`,
      });
    }
    if (path) {
      list.push({
        icon: AppWindow,
        title: `Everything ${name} connects to`,
        detail: `${name} can't use the network at all.`,
        rule: { kind: 'app', path },
        what: name,
      });
    }
    return list;
  });

  let busy = $state(false);

  async function pick(choice: Choice) {
    busy = true;
    const blocked = await store.block(choice.rule, choice.what);
    busy = false;
    if (blocked || store.note?.tone === 'bad') onclose();
  }

  function onkeydown(event: KeyboardEvent) {
    if (event.key === 'Escape') onclose();
  }
</script>

<svelte:window {onkeydown} />

<!-- Moved to <body> so it covers the window wherever it is opened from (see portal.ts). -->
<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<div class="scrim" onclick={onclose} use:portal>
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div
    class="glass sheet fade-in"
    role="dialog"
    aria-modal="true"
    aria-labelledby="block-title"
    tabindex="-1"
    onclick={(e) => e.stopPropagation()}
  >
    <header>
      <div>
        <p class="eyebrow">Block</p>
        <h2 id="block-title" class="display">What should be blocked?</h2>
      </div>
      <button class="close" type="button" aria-label="Close" onclick={onclose}><X size={18} /></button>
    </header>

    {#if choices.length}
      <ul>
        {#each choices as choice (choice.title)}
          {@const Icon = choice.icon}
          <li>
            <button type="button" class:warn={choice.warn} disabled={busy} onclick={() => pick(choice)}>
              <span class="icon"><Icon size={18} /></span>
              <span class="text">
                <span class="title">{choice.title}</span>
                <span class="detail">{choice.detail}</span>
              </span>
            </button>
          </li>
        {/each}
      </ul>
      <p class="foot muted">
        Windows asks you to confirm. Blocks stay when Whereabouts is closed, and you can lift them on the
        Rules screen. Core Windows programs, DNS servers and your local network are never blocked.
      </p>
    {:else}
      <p class="muted">
        Whereabouts doesn't know which program file made this connection (it may be part of Windows, or it
        ended before it was checked), so it can't be blocked from here.
      </p>
    {/if}
  </div>
</div>

<style>
  .scrim {
    position: fixed;
    inset: 0;
    z-index: 20;
    display: grid;
    place-items: center;
    padding: 24px;
    background: rgb(3 8 14 / 0.6);
    backdrop-filter: blur(4px);
  }
  .sheet {
    width: min(520px, 100%);
    padding: 22px 22px 18px;
    border-radius: var(--radius-xl);
    background-color: rgb(11 26 39 / 0.92);
    outline: none;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 12px;
    margin-bottom: 14px;
  }
  .eyebrow {
    margin: 0;
  }
  h2 {
    margin: 2px 0 0;
    font-size: 22px;
  }
  .close {
    display: grid;
    place-items: center;
    width: 34px;
    height: 34px;
    border-radius: 50%;
    border: 1px solid var(--glass-border);
    background: var(--glass);
    color: var(--text-soft);
    cursor: pointer;
  }
  .close:hover {
    background: var(--glass-hover);
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 8px;
  }
  li button {
    width: 100%;
    display: flex;
    gap: 14px;
    align-items: flex-start;
    padding: 12px 14px;
    border-radius: var(--radius-md);
    border: 1px solid var(--glass-border);
    background: var(--glass);
    text-align: left;
    cursor: pointer;
    transition:
      background 0.2s var(--ease),
      border-color 0.2s var(--ease);
  }
  li button:hover:not(:disabled) {
    background: var(--glass-hover);
    border-color: rgb(255 138 122 / 0.35);
  }
  li button:disabled {
    opacity: 0.6;
    cursor: default;
  }
  .icon {
    display: grid;
    place-items: center;
    flex: none;
    width: 34px;
    height: 34px;
    border-radius: 11px;
    background: var(--danger-bg);
    color: var(--danger);
  }
  .warn .icon {
    background: var(--warn-bg);
    color: var(--warn);
  }
  .text {
    display: grid;
    gap: 2px;
    min-width: 0;
  }
  .title {
    font-weight: 600;
    overflow-wrap: anywhere;
  }
  .detail {
    font-size: 12.5px;
    color: var(--text-muted);
  }
  .foot {
    margin: 14px 2px 0;
    font-size: 12px;
  }
</style>
