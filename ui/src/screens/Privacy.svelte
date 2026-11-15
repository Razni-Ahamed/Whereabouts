<script lang="ts">
  import {
    CircleCheck,
    Clock,
    Download,
    FolderLock,
    LoaderCircle,
    ShieldCheck,
    Trash2,
    TriangleAlert,
    WifiOff,
  } from '@lucide/svelte';
  import { deleteHistory, exportHistory } from '../lib/api';
  import { count } from '../lib/format';
  import { store } from '../lib/state.svelte';

  // What the controls are doing, and the last result to show.
  let busy = $state<'export' | 'delete' | null>(null);
  let outcome = $state<{ tone: 'good' | 'bad'; text: string } | null>(null);

  async function runExport() {
    busy = 'export';
    outcome = null;
    const result = await exportHistory();
    busy = null;
    if (!result.ok) {
      outcome = { tone: 'bad', text: result.problem.message };
    } else if (result.value) {
      outcome = {
        tone: 'good',
        text: `Exported ${count(result.value.rows)} connections to ${result.value.path}. It is a plain CSV file: keep it private.`,
      };
    }
  }

  async function runDelete() {
    busy = 'delete';
    outcome = null;
    const result = await deleteHistory();
    busy = null;
    if (!result.ok) {
      outcome = { tone: 'bad', text: result.problem.message };
    } else if (result.value) {
      outcome = {
        tone: 'good',
        text: 'Everything saved so far is deleted. Whereabouts keeps recording new connections.',
      };
      void store.refreshHistory();
    }
  }

  // Whereabouts watches itself like any other app: its own connections to
  // the internet are counted from the live data, not assumed.
  const OWN = ['whereabouts.exe', 'whereabouts-service.exe'];
  const own = $derived(
    (store.live?.flows ?? []).filter(
      (f) =>
        OWN.includes(f.app.toLowerCase()) &&
        f.owner !== 'local network' &&
        f.owner !== 'multicast',
    ),
  );

  const promises = [
    { title: 'Never reads what is sent', text: 'No messages, pages, files, URL paths or passwords. Only who talks to whom.' },
    { title: 'Only connection details', text: 'App, destination, company, country, and how much was sent and received.' },
    { title: 'Stays on this computer', text: 'Encrypted with SQLCipher; the key is protected by Windows and never leaves this PC.' },
    { title: 'Kept for a limited time', text: 'Each connection for 30 days, then only hourly totals, for 180 days.' },
    { title: 'Browsing stays coarse', text: 'For web browsers, only the main domain of each site is saved, e.g. example.com.' },
    { title: 'Open source', text: 'Anyone can check that the app does what this page says.' },
  ];
</script>

<div class="grid">
  <section class="glass hero">
    <p class="eyebrow">Privacy</p>
    <h1 class="display">Your data stays <span class="accent">yours.</span></h1>
    <p class="lead">
      Whereabouts was built to watch your network without becoming another thing that watches you.
      This is everything it keeps, and everything it never does.
    </p>
    <ul class="list">
      {#each promises as p (p.title)}
        <li>
          <CircleCheck size={20} strokeWidth={1.6} />
          <div><strong>{p.title}</strong><span>{p.text}</span></div>
        </li>
      {/each}
    </ul>
  </section>

  <div class="side">
    <section class="glass stat">
      <WifiOff size={26} strokeWidth={1.4} />
      <div>
        <b class="display">{store.live ? own.length : '—'}</b>
        <span>
          internet connections by Whereabouts itself right now. It watches itself like any other
          app; company and country data are offline lists.
        </span>
      </div>
    </section>

    <section class="glass card">
      <h2><FolderLock size={18} strokeWidth={1.6} /> Where it is kept</h2>
      <p class="path">C:\ProgramData\Whereabouts</p>
      <p class="muted">Readable by administrators and the system only, and encrypted, so copying it to another computer gives nothing readable. We recommend turning on BitLocker.</p>
    </section>

    <section class="glass card">
      <h2><Clock size={18} strokeWidth={1.6} /> Right now</h2>
      <p class="muted">
        {#if store.live}
          {store.live.status.saving ? 'Saving connection history, encrypted.' : 'Not saving history.'}
          {count(store.live.status.tracker_domains)} tracker domains are checked offline.
        {:else}
          Waiting for the Whereabouts service.
        {/if}
      </p>
    </section>

    <section class="glass card">
      <h2><ShieldCheck size={18} strokeWidth={1.6} /> Your controls</h2>
      <p class="muted">Take your history with you, or delete it. Windows asks you to confirm each step.</p>
      <div class="controls">
        <button class="btn btn-ghost" type="button" disabled={busy !== null || !!store.problem} onclick={runExport}>
          {#if busy === 'export'}<LoaderCircle size={16} class="spin" />{:else}<Download size={16} />{/if}
          Export to CSV…
        </button>
        <button class="btn btn-danger" type="button" disabled={busy !== null || !!store.problem} onclick={runDelete}>
          {#if busy === 'delete'}<LoaderCircle size={16} class="spin" />{:else}<Trash2 size={16} />{/if}
          Delete everything…
        </button>
      </div>
      {#if outcome}
        <p class="outcome {outcome.tone}" role="status">
          {#if outcome.tone === 'good'}<CircleCheck size={16} />{:else}<TriangleAlert size={16} />{/if}
          <span>{outcome.text}</span>
        </p>
      {/if}
    </section>
  </div>
</div>

<style>
  .grid {
    display: grid;
    grid-template-columns: 1.35fr 1fr;
    gap: 18px;
    align-items: start;
  }
  .hero {
    padding: 34px 36px;
    border-radius: var(--radius-xl);
  }
  h1 {
    margin: 10px 0 12px;
    font-size: 44px;
    line-height: 1.05;
  }
  .accent {
    color: var(--accent);
  }
  .lead {
    margin: 0 0 22px;
    max-width: 560px;
    color: var(--text-soft);
    font-size: 15px;
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 14px;
  }
  .list li {
    display: flex;
    gap: 14px;
    align-items: flex-start;
  }
  .list :global(svg) {
    color: var(--accent);
    flex: none;
    margin-top: 1px;
  }
  .list strong {
    display: block;
    font-weight: 600;
  }
  .list span {
    color: var(--text-muted);
    font-size: 13.5px;
  }
  .side {
    display: grid;
    gap: 18px;
  }
  .stat {
    display: flex;
    gap: 18px;
    align-items: center;
    padding: 22px 24px;
    color: var(--accent);
  }
  .stat b {
    display: block;
    font-size: 48px;
    line-height: 1;
    color: var(--mint);
  }
  .stat span {
    color: var(--text-soft);
    font-size: 13.5px;
  }
  .card {
    padding: 20px 24px;
  }
  h2 {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 0 0 8px;
    font-size: 15px;
    font-weight: 600;
  }
  h2 :global(svg) {
    color: var(--accent);
  }
  .card p {
    margin: 0 0 8px;
    font-size: 13.5px;
  }
  .path {
    font-family: var(--font-mono);
    color: var(--mint);
  }
  .controls {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 12px;
  }
  .controls .btn {
    height: 38px;
    padding: 0 16px;
    font-size: 13px;
  }
  .controls .btn:disabled {
    opacity: 0.5;
    cursor: default;
    transform: none;
  }
  .btn-danger {
    background: var(--danger-bg);
    border-color: rgb(255 138 122 / 0.35);
    color: var(--danger);
  }
  .btn-danger:hover:not(:disabled) {
    background: rgb(255 138 122 / 0.2);
  }
  .outcome {
    display: flex;
    gap: 8px;
    align-items: flex-start;
    margin: 12px 0 0;
    font-size: 13px;
    overflow-wrap: anywhere;
  }
  .outcome :global(svg) {
    flex: none;
    margin-top: 2px;
  }
  .outcome.good {
    color: var(--accent);
  }
  .outcome.bad {
    color: var(--warn);
  }
  .outcome span {
    color: var(--text-soft);
  }
  :global(.spin) {
    animation: spin 1s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
</style>
