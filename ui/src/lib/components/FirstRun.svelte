<script lang="ts">
  // Asked once: should the app start in the tray at sign-in? (decision D13:
  // ask on first run, suggested on).
  import { BellRing, EyeOff, Feather } from '@lucide/svelte';
  import { store } from '../state.svelte';
  import type { AppSettings } from '../types';

  let { settings }: { settings: AppSettings } = $props();
  let busy = $state(false);

  async function answer(startAtSignIn: boolean) {
    busy = true;
    await store.saveSettings({
      start_at_sign_in: startAtSignIn && settings.can_start_at_sign_in,
      notifications: settings.notifications,
      show_names: settings.show_names,
    });
    busy = false;
  }
</script>

<div class="scrim">
  <div class="glass sheet fade-in" role="dialog" aria-modal="true" aria-labelledby="first-run-title">
    <p class="eyebrow">Welcome</p>
    <h2 id="first-run-title" class="display">Keep Whereabouts in your tray?</h2>
    <p class="lead">
      The Whereabouts service always watches your connections. To tell you when something needs a look,
      this app has to run in the tray.
    </p>
    <ul>
      <li>
        <BellRing size={18} />
        <span>It tells you when an app uses the internet for the first time, or when Whereabouts stops watching.</span>
      </li>
      <li>
        <Feather size={18} />
        <span>It starts when you sign in, without a window, and uses little memory. Close it from the tray icon at any time.</span>
      </li>
      <li>
        <EyeOff size={18} />
        <span>
          Notifications don't name apps or sites unless you allow it on the Privacy screen: Windows keeps a
          history of them and can show them on the lock screen.
        </span>
      </li>
    </ul>
    {#if !settings.can_start_at_sign_in}
      <p class="muted note">This is a developer build, so it can't start at sign-in. The installed app can.</p>
    {/if}
    <div class="actions">
      {#if settings.can_start_at_sign_in}
        <button class="btn btn-primary" type="button" disabled={busy} onclick={() => answer(true)}>
          Yes, start at sign-in
        </button>
        <button class="btn btn-ghost" type="button" disabled={busy} onclick={() => answer(false)}>Not now</button>
      {:else}
        <button class="btn btn-ghost" type="button" disabled={busy} onclick={() => answer(false)}>OK</button>
      {/if}
    </div>
    <p class="muted foot">You can change this any time on the Privacy screen.</p>
  </div>
</div>

<style>
  .scrim {
    position: fixed;
    inset: 0;
    z-index: 25;
    display: grid;
    place-items: center;
    padding: 24px;
    background: rgb(3 8 14 / 0.62);
    backdrop-filter: blur(4px);
  }
  .sheet {
    width: min(540px, 100%);
    padding: 28px 30px 22px;
    border-radius: var(--radius-xl);
    background-color: rgb(11 26 39 / 0.94);
  }
  .eyebrow {
    margin: 0;
  }
  h2 {
    margin: 4px 0 8px;
    font-size: 28px;
  }
  .lead {
    margin: 0 0 14px;
    color: var(--text-soft);
  }
  ul {
    list-style: none;
    margin: 0 0 18px;
    padding: 0;
    display: grid;
    gap: 12px;
  }
  li {
    display: flex;
    gap: 12px;
    align-items: flex-start;
    font-size: 13.5px;
    color: var(--text-soft);
  }
  li :global(svg) {
    flex: none;
    margin-top: 1px;
    color: var(--accent);
  }
  .actions {
    display: flex;
    gap: 10px;
  }
  .btn:disabled {
    opacity: 0.55;
    cursor: default;
    transform: none;
  }
  .note,
  .foot {
    font-size: 12.5px;
  }
  .foot {
    margin: 14px 0 0;
  }
</style>
