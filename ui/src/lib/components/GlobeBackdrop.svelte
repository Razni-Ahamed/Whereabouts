<script lang="ts">
  // The backdrop: a globe of characters (lib/globe/field.ts). Countries with a
  // connection now glow; a new connection flashes its country, amber for
  // trackers. Only what the live view already shows is used.
  import { onMount } from 'svelte';
  import { startGlobe, type Globe } from '../globe/field.ts';
  import { PingTracker, activeCountries } from '../globe/pings.ts';
  import { isTracking } from '../state.svelte';
  import type { FlowView } from '../types';

  let { flows }: { flows: FlowView[] } = $props();
  let canvas: HTMLCanvasElement | undefined = $state();
  let globe: Globe | undefined = $state();
  const tracker = new PingTracker(isTracking);

  onMount(() => {
    if (!canvas) return;
    const g = startGlobe(canvas);
    globe = g;
    return () => g.stop();
  });

  $effect(() => {
    if (!globe) return;
    for (const p of tracker.update(flows)) globe.ping(p);
    globe.setActive(activeCountries(flows, isTracking));
  });
</script>

<div class="backdrop" aria-hidden="true">
  <canvas bind:this={canvas}></canvas>
  <div class="vignette"></div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: 0;
    pointer-events: none;
    overflow: hidden;
    background:
      radial-gradient(ellipse at 66% 40%, #0b1c2a 0%, transparent 60%),
      radial-gradient(ellipse at 15% 85%, rgb(63 127 208 / 0.08) 0%, transparent 50%),
      var(--ink-950);
  }
  canvas {
    display: block;
  }
  .vignette {
    position: absolute;
    inset: 0;
    background: radial-gradient(ellipse at 50% 45%, transparent 55%, rgb(2 6 12 / 0.6) 100%);
  }
</style>
