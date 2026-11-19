<script lang="ts">
  // Asked once: may Whereabouts keep its lists up to date? (decisions D11,
  // D12: on by default, but nothing is downloaded until this is answered).
  import { CloudDownload, ShieldBan } from '@lucide/svelte';
  import Toggle from './Toggle.svelte';
  import { store } from '../state.svelte';

  let data = $state(true);
  let drop = $state(true);
  let busy = $state(false);

  async function save() {
    busy = true;
    await store.setLists(data, drop);
    busy = false;
  }
</script>

<div class="scrim">
  <div class="glass sheet fade-in" role="dialog" aria-modal="true" aria-labelledby="lists-title">
    <p class="eyebrow">Keeping up to date</p>
    <h2 id="lists-title" class="display">Download list updates?</h2>
    <p class="lead">
      Trackers, companies and risky networks change every week. Whereabouts can download fresh lists. These are
      exactly the downloads, and the only requests Whereabouts makes:
    </p>

    <div class="choice">
      <span class="icon"><CloudDownload size={18} /></span>
      <div class="grow">
        <Toggle
          checked={data}
          label="Whereabouts' lists"
          detail="Tracker, company, country and network lists from Whereabouts' releases on github.com, checked once a day (about 20 MB when there is a new set, usually weekly). Signed by Whereabouts: anything else is refused."
          onchange={(v) => (data = v)}
        />
      </div>
    </div>
    <div class="choice">
      <span class="icon"><ShieldBan size={18} /></span>
      <div class="grow">
        <Toggle
          checked={drop}
          label="Spamhaus' list of criminal networks"
          detail="From spamhaus.org once a day (under 1 MB). Spamhaus doesn't allow it to be passed on, so your computer fetches it itself. Without it, risky-network alerts are off."
          onchange={(v) => (drop = v)}
        />
      </div>
    </div>

    <p class="muted small">
      Each is a plain download of a public file: no ID, no cookies, nothing about you or your apps. Like any website
      you visit, the server sees your IP address. You can change this any time on the Privacy screen.
    </p>
    <div class="actions">
      <button class="btn btn-primary" type="button" disabled={busy} onclick={save}>Save</button>
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
    width: min(580px, 100%);
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
