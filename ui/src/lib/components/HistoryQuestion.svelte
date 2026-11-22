<script lang="ts">
  // Asked once: should Whereabouts save connection history? On by default;
  // it is saved meanwhile. Turning it off asks (in a native dialog) whether
  // to keep or delete what is saved so far.
  import { History, Radio } from '@lucide/svelte';
  import Toggle from './Toggle.svelte';
  import { store } from '../state.svelte';

  let save = $state(true);
  let busy = $state(false);

  async function answer() {
    busy = true;
    await store.setSaveHistory(save);
    busy = false;
  }
</script>

<div class="scrim">
  <div class="glass sheet fade-in" role="dialog" aria-modal="true" aria-labelledby="history-title">
    <p class="eyebrow">Your history</p>
    <h2 id="history-title" class="display">Save connection history?</h2>
    <p class="lead">
      Whereabouts can keep a list of finished connections on this PC, encrypted, so you can look back later. It is
      never sent anywhere.
    </p>

    <div class="choice">
      <span class="icon"><History size={18} /></span>
      <div class="grow">
        <Toggle
          checked={save}
          label="Save connection history"
          detail="Each connection for 30 days, then hourly totals for 180 days. Needed for the History view, Export and, from version 0.3, learning what is normal for each app."
          onchange={(v) => (save = v)}
        />
      </div>
    </div>
    <div class="choice">
      <span class="icon"><Radio size={18} /></span>
      <p class="muted plain">
        Without it you still see live connections, get alerts and can block apps and sites. Saving writes about 8 MB
        an hour to your disk with ordinary use (more with very busy apps such as torrent clients), far too little to
        wear out an SSD.
      </p>
    </div>

    <p class="muted small">You can change this any time on the Privacy screen.</p>
    <div class="actions">
      <button class="btn btn-primary" type="button" disabled={busy} onclick={answer}>Save</button>
    </div>
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
    width: min(560px, 100%);
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
    margin: 0 0 12px;
    color: var(--text-soft);
  }
  .choice {
    display: flex;
    gap: 12px;
    align-items: flex-start;
    padding: 4px 0;
    border-top: 1px solid rgb(205 230 255 / 0.07);
  }
  .icon {
    flex: none;
    margin-top: 12px;
    color: var(--accent);
  }
  .grow {
    flex: 1;
  }
  .plain {
    margin: 10px 0;
    font-size: 13.5px;
  }
  .small {
    margin: 12px 0 16px;
    font-size: 12.5px;
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
</style>
