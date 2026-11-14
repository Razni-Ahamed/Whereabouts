<script lang="ts">
  import { onMount } from 'svelte';
  import { CircleAlert, FlaskConical } from '@lucide/svelte';
  import Backdrop from './lib/components/Backdrop.svelte';
  import Logo from './lib/components/Logo.svelte';
  import { store } from './lib/state.svelte';
  import Overview from './screens/Overview.svelte';
  import Apps from './screens/Apps.svelte';
  import Connections from './screens/Connections.svelte';
  import Privacy from './screens/Privacy.svelte';

  type Screen = 'overview' | 'apps' | 'connections' | 'privacy';
  const TABS: { id: Screen; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'apps', label: 'Apps' },
    { id: 'connections', label: 'Connections' },
    { id: 'privacy', label: 'Privacy' },
  ];

  let screen = $state<Screen>('overview');
  let selectedApp = $state<string | null>(null);

  function openApp(app: string) {
    selectedApp = app;
    screen = 'apps';
  }

  onMount(() => store.start());

  const health = $derived.by(() => {
    if (store.problem) return { tone: 'bad', text: 'Not connected' };
    if (!store.live) return { tone: 'idle', text: 'Connecting…' };
    const s = store.live.status;
    if (s.rejected > 0 || s.unattributed > 0 || !s.kernel_events_protected)
      return { tone: 'warn', text: 'Watching · check alerts' };
    return { tone: 'good', text: 'Watching' };
  });

  const PROBLEM_HELP: Record<string, string> = {
    not_running:
      'Install and start it once, as administrator: whereabouts-service --install. It then starts with Windows.',
    access_denied:
      'Only administrators and the account that installed Whereabouts can read its data.',
    untrusted: 'Another program is answering in place of Whereabouts, so this app will not trust it.',
    refused: 'The service only answers its own installed programs. Open Whereabouts from its install folder.',
    other: '',
  };
</script>

<Backdrop />

<div class="shell">
  <nav class="glass topbar">
    <div class="brand">
      <Logo />
      <div>
        <div class="wordmark">Whereabouts</div>
        <div class="tagline">Your network, in plain sight</div>
      </div>
    </div>

    <div class="tabs" role="tablist">
      {#each TABS as tab (tab.id)}
        <button
          role="tab"
          type="button"
          aria-selected={screen === tab.id}
          class:active={screen === tab.id}
          onclick={() => (screen = tab.id)}
        >
          {tab.label}
        </button>
      {/each}
    </div>

    <div class="right">
      {#if store.demo}
        <span class="chip chip-warn" title="This is the design preview in a browser, with made-up data.">
          <FlaskConical size={13} /> Demo data
        </span>
      {/if}
      <span class="status {health.tone}">
        <span class="dot"></span>
        {health.text}
      </span>
    </div>
  </nav>

  {#if store.problem}
    <div class="glass banner fade-in" role="alert">
      <CircleAlert size={20} />
      <div>
        <strong>{store.problem.message}</strong>
        {#if PROBLEM_HELP[store.problem.kind]}
          <p>{PROBLEM_HELP[store.problem.kind]}</p>
        {/if}
      </div>
    </div>
  {/if}

  <main>
    {#key screen}
      <div class="fade-in">
        {#if screen === 'overview'}
          <Overview onpickapp={openApp} ongo={(s: Screen) => (screen = s)} />
        {:else if screen === 'apps'}
          <Apps bind:selected={selectedApp} />
        {:else if screen === 'connections'}
          <Connections onpickapp={openApp} />
        {:else}
          <Privacy />
        {/if}
      </div>
    {/key}
  </main>

  <footer>
    <span>Whereabouts {store.live?.version ?? ''} · never reads what your apps send</span>
    <span>Company and country data: DB-IP Lite (CC BY 4.0), EasyPrivacy</span>
  </footer>
</div>

<style>
  .shell {
    position: relative;
    z-index: 1;
    max-width: 1360px;
    margin: 0 auto;
    padding: 20px 28px 18px;
    display: flex;
    flex-direction: column;
    gap: 18px;
    min-height: 100vh;
  }
  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
    padding: 12px 18px 12px 20px;
    border-radius: var(--radius-xl);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }
  .wordmark {
    font-family: var(--font-display);
    font-size: 21px;
    font-weight: 600;
    letter-spacing: -0.01em;
    line-height: 1.1;
  }
  .tagline {
    font-size: 9.5px;
    font-weight: 600;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: var(--text-muted);
  }
  .tabs {
    display: flex;
    gap: 4px;
    padding: 4px;
    border-radius: var(--radius-pill);
    background: rgb(3 10 18 / 0.35);
    border: 1px solid var(--glass-border);
  }
  .tabs button {
    padding: 8px 18px;
    border: 0;
    border-radius: var(--radius-pill);
    background: transparent;
    color: var(--text-soft);
    font-weight: 500;
    cursor: pointer;
    transition:
      background 0.25s var(--ease),
      color 0.25s var(--ease);
  }
  .tabs button:hover {
    color: var(--text);
  }
  .tabs button.active {
    background: linear-gradient(180deg, var(--mint), var(--mint-deep));
    color: var(--accent-ink);
    font-weight: 600;
    box-shadow: inset 0 1px 0 rgb(255 255 255 / 0.45);
  }
  .right {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .status {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    height: 32px;
    padding: 0 14px;
    border-radius: var(--radius-pill);
    font-size: 13px;
    font-weight: 500;
    background: var(--glass-strong);
    border: 1px solid var(--glass-border);
  }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--text-muted);
  }
  .good .dot {
    background: var(--accent);
    box-shadow: 0 0 0 0 rgb(95 224 195 / 0.6);
    animation: pulse 2.4s infinite;
  }
  .warn .dot {
    background: var(--warn);
  }
  .bad .dot {
    background: var(--danger);
  }
  @keyframes pulse {
    0% {
      box-shadow: 0 0 0 0 rgb(95 224 195 / 0.55);
    }
    70% {
      box-shadow: 0 0 0 8px rgb(95 224 195 / 0);
    }
    100% {
      box-shadow: 0 0 0 0 rgb(95 224 195 / 0);
    }
  }
  .banner {
    display: flex;
    gap: 14px;
    align-items: flex-start;
    padding: 16px 20px;
    color: var(--warn);
    border-color: rgb(242 196 109 / 0.3);
    background: rgb(242 196 109 / 0.08);
  }
  .banner strong {
    color: var(--text);
    font-weight: 600;
  }
  .banner p {
    margin: 4px 0 0;
    color: var(--text-soft);
  }
  main {
    flex: 1;
  }
  footer {
    display: flex;
    justify-content: space-between;
    gap: 16px;
    padding: 4px 6px 0;
    font-size: 11.5px;
    color: var(--text-faint);
  }
</style>
