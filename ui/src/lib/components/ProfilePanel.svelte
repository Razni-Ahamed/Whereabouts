<script lang="ts">
  // What Whereabouts learned is usual for one app: where it connects, how
  // much it sends, when it is active. The user can reset it or say the app
  // goes anywhere (a browser).
  import { RotateCcw } from '@lucide/svelte';
  import Toggle from './Toggle.svelte';
  import { profile as loadProfile, resetProfile, setGoesAnywhere } from '../api';
  import { bytes, countryName } from '../format';
  import { activeHoursBars, daysLeft } from '../profile';
  import { store } from '../state.svelte';
  import type { GoesAnywhereChoice, ProfileItemView, ProfileView } from '../types';

  let { path, app }: { path: string; app: string } = $props();

  const SHOWN = 8;
  type Section = 'sites' | 'companies' | 'countries';

  let view = $state<ProfileView | null>(null);
  let loaded = $state(false);
  /** Why the profile could not be read, shown in the panel with a Try again. */
  let failure = $state<string | null>(null);
  let busy = $state(false);
  let showAll = $state<Record<Section, boolean>>({ sites: false, companies: false, countries: false });

  /** Reads the profile; an answer that arrives after another app was picked is ignored. */
  async function load() {
    const wanted = path;
    failure = null;
    const result = await loadProfile(wanted);
    if (wanted !== path) return;
    if (result.ok) {
      view = result.value;
    } else {
      view = null;
      failure = result.problem.message;
    }
    loaded = true;
  }

  // Load again whenever another app is picked.
  $effect(() => {
    void path;
    view = null;
    loaded = false;
    showAll = { sites: false, companies: false, countries: false };
    void load();
  });

  const date = (secs: number) =>
    new Date(secs * 1000).toLocaleDateString('en', { day: 'numeric', month: 'short', year: 'numeric' });

  async function reset() {
    busy = true;
    const result = await resetProfile(path, app);
    if (!result.ok) store.showNote({ text: result.problem.message, tone: 'bad' });
    else if (result.value) {
      store.showNote({ text: 'Learning again from now.', tone: 'good' });
      view = null;
      loaded = false;
      await load();
    }
    busy = false;
  }

  async function choose(choice: GoesAnywhereChoice) {
    busy = true;
    const result = await setGoesAnywhere(path, choice);
    if (!result.ok) store.showNote({ text: result.problem.message, tone: 'bad' });
    if (result.ok && result.value) view = result.value;
    else await load(); // cancelled or failed: show the real state, not the switch as flipped
    busy = false;
  }

  const sections = $derived.by(() => {
    if (!view) return [];
    const same = (v: string) => v;
    return [
      { key: 'sites' as Section, title: 'Sites', items: view.sites, label: same },
      { key: 'companies' as Section, title: 'Companies', items: view.companies, label: same },
      { key: 'countries' as Section, title: 'Countries', items: view.countries, label: countryName },
    ];
  });
  const bars = $derived(view ? activeHoursBars(view.active_hours) : []);
  const stateNote = (item: ProfileItemView) =>
    item.state === 'allowed' ? 'allowed by you' : item.state === 'pending' ? 'waiting for you' : null;
</script>

<section class="glass panel">
  <h2 class="display">What is normal for this app</h2>

  {#if !loaded}
    <p class="muted">Loading…</p>
  {:else if failure}
    <p class="muted">{failure}</p>
    <div><button class="btn btn-ghost reset" type="button" onclick={load}>Try again</button></div>
  {:else if !view}
    <p class="muted">Nothing learned yet. Whereabouts starts learning when this app next uses the network.</p>
  {:else}
    <p class="since">
      {#if view.learning}
        <span class="chip chip-warn">Learning: {daysLeft(view.learning_ends_secs, Date.now() / 1000)} days left</span>
        <span class="muted">No behaviour warnings for it until then.</span>
      {:else}
        <span class="chip chip-good">Learned since {date(view.learned_since_secs)}</span>
      {/if}
    </p>

    <div class="lists">
      {#each sections as section (section.key)}
        <div class="group">
          <h3>{section.title} <span class="num">{section.items.length}</span></h3>
          {#if section.items.length === 0}
            <p class="muted none">None yet.</p>
          {:else}
            <ul>
              {#each showAll[section.key] ? section.items : section.items.slice(0, SHOWN) as item (item.value)}
                <li title={item.value}>
                  <span class="value">{section.label(item.value)}</span>
                  {#if stateNote(item)}<span class="state">{stateNote(item)}</span>{/if}
                </li>
              {/each}
            </ul>
            {#if section.items.length > SHOWN && !showAll[section.key]}
              <button class="link" type="button" onclick={() => (showAll[section.key] = true)}>
                Show all {section.items.length}
              </button>
            {/if}
          {/if}
        </div>
      {/each}
    </div>

    <div class="usage">
      {#if view.usual_sent_per_hour !== null}
        <p>
          Usually sends about <b class="num">{bytes(view.usual_sent_per_hour)}</b> an hour{#if view.busiest_sent_per_hour !== null}
            {' '}(busiest hour <b class="num">{bytes(view.busiest_sent_per_hour)}</b>){/if}.
        </p>
      {:else}
        <p class="muted">No active hours yet.</p>
      {/if}
      <div class="hours" role="img" aria-label="Share of its active time in each hour of the day">
        {#each bars as level, h (h)}
          <span class="bar" title={`${h}:00`} style:--level={level}></span>
        {/each}
      </div>
      <div class="axis muted" aria-hidden="true"><span>0:00</span><span>12:00</span><span>23:00</span></div>
    </div>

    <div class="settings">
      <Toggle
        checked={view.goes_anywhere}
        disabled={busy}
        label="Goes anywhere"
        detail={view.goes_anywhere_choice === 'auto' && view.recognised_browser
          ? 'New sites, companies and countries are normal for it (recognised as a browser).'
          : 'New sites, companies and countries are normal for it, as for a web browser.'}
        onchange={(on) => choose(on ? 'on' : 'off')}
      />
      {#if view.goes_anywhere_choice !== 'auto'}
        <button class="link" type="button" disabled={busy} onclick={() => choose('auto')}>
          Let Whereabouts decide{view.recognised_browser ? ' (it recognises a browser)' : ''}
        </button>
      {/if}
    </div>

    <div class="foot">
      <button class="btn btn-ghost reset" type="button" disabled={busy} onclick={reset}>
        <RotateCcw size={15} /> Reset
      </button>
      <span class="muted">Forgets what was learned and starts a new 7-day learning period.</span>
    </div>
  {/if}
</section>

<style>
  .panel {
    padding: 22px 26px 22px;
    display: grid;
    gap: 18px;
  }
  h2 {
    margin: 0;
    font-size: 22px;
  }
  .since {
    margin: 0;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
    font-size: 13px;
  }
  .lists {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 18px;
  }
  .group {
    min-width: 0;
  }
  h3 {
    margin: 0 0 6px;
    font-size: 11.5px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    font-weight: 600;
    color: var(--text-muted);
  }
  h3 .num {
    margin-left: 4px;
    color: var(--text-soft);
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 3px;
    font-size: 13.5px;
  }
  li {
    display: flex;
    gap: 8px;
    align-items: baseline;
    min-width: 0;
  }
  .value {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .state {
    flex: none;
    font-size: 11.5px;
    color: var(--warn);
  }
  .none {
    margin: 0;
    font-size: 13px;
  }
  .link {
    margin-top: 6px;
    padding: 0;
    border: 0;
    background: none;
    color: var(--accent);
    font: inherit;
    font-size: 12.5px;
    cursor: pointer;
    text-align: left;
  }
  .link:hover:not(:disabled) {
    text-decoration: underline;
  }
  .link:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .usage p {
    margin: 0 0 10px;
    font-size: 13.5px;
  }
  .hours {
    display: grid;
    grid-template-columns: repeat(24, 1fr);
    gap: 3px;
    align-items: end;
    height: 44px;
  }
  .bar {
    height: calc(var(--level) / 8 * 100%);
    min-height: 3px;
    border-radius: 3px;
    background: var(--accent);
    opacity: calc(0.25 + var(--level) * 0.09);
  }
  .axis {
    display: flex;
    justify-content: space-between;
    margin-top: 4px;
    font-size: 11px;
  }
  .foot {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px;
    font-size: 12.5px;
  }
  .reset {
    height: 36px;
    padding: 0 16px;
    font-size: 13px;
  }
  .reset:hover:not(:disabled) {
    color: var(--danger);
    border-color: rgb(255 138 122 / 0.35);
    background: var(--danger-bg);
  }
  .reset:disabled {
    opacity: 0.5;
    cursor: default;
  }
</style>
