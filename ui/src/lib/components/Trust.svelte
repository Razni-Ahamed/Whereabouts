<script lang="ts">
  // Small, honest labels for how far a publisher or domain can be trusted.
  import { BadgeCheck, CircleHelp, ShieldAlert, Sparkles, Hourglass } from '@lucide/svelte';
  import type { DomainTrust } from '../types';
  import { publisherState } from '../format';

  type Props =
    | { kind: 'publisher'; publisher: string; confirmed: boolean }
    | { kind: 'domain'; trust: DomainTrust | null };
  let props: Props = $props();

  const view = $derived.by(() => {
    if (props.kind === 'domain') {
      if (props.trust === 'app_reported')
        return { tone: 'warn', text: 'app-reported', title: 'Only the app itself said this name; it could be false.' };
      if (props.trust === 'guessed')
        return { tone: 'soft', text: 'guessed', title: "Guessed from another app's lookup of the same address." };
      return null;
    }
    const state = publisherState(props.publisher, props.confirmed);
    switch (state) {
      case 'signed':
        return { tone: 'good', text: 'signed', title: 'Code signature checked on the running file.' };
      case 'unconfirmed':
        return { tone: 'soft', text: 'signed?', title: 'Signature checked by file path only; not confirmed as the running file.' };
      case 'unsigned':
        return { tone: 'warn', text: 'unsigned', title: 'This program has no code signature.' };
      case 'invalid':
        return { tone: 'danger', text: 'bad signature', title: 'The code signature is invalid: the file may have been changed.' };
      case 'pending':
        return { tone: 'soft', text: 'checking', title: 'The signature is being checked.' };
      default:
        return null;
    }
  });
</script>

{#if view}
  <span class="trust {view.tone}" title={view.title}>
    {#if view.tone === 'good'}<BadgeCheck size={12} />
    {:else if view.tone === 'danger' || view.tone === 'warn'}<ShieldAlert size={12} />
    {:else if view.text === 'checking'}<Hourglass size={12} />
    {:else if view.text === 'guessed'}<Sparkles size={12} />
    {:else}<CircleHelp size={12} />{/if}
    {view.text}
  </span>
{/if}

<style>
  .trust {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 1px 7px 1px 5px;
    border-radius: var(--radius-pill);
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: 0.02em;
    border: 1px solid transparent;
    white-space: nowrap;
    vertical-align: 1px;
  }
  .good {
    color: var(--accent);
    background: rgb(95 224 195 / 0.1);
    border-color: rgb(95 224 195 / 0.22);
  }
  .soft {
    color: var(--text-soft);
    background: var(--glass-strong);
    border-color: var(--glass-border);
  }
  .warn {
    color: var(--warn);
    background: var(--warn-bg);
    border-color: rgb(242 196 109 / 0.28);
  }
  .danger {
    color: var(--danger);
    background: var(--danger-bg);
    border-color: rgb(255 138 122 / 0.3);
  }
</style>
