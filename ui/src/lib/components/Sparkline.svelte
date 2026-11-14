<script lang="ts">
  // A small area chart of recent throughput.
  let { values, height = 64 }: { values: number[]; height?: number } = $props();

  const WIDTH = 300;
  const path = $derived.by(() => {
    if (values.length < 2) return null;
    const max = Math.max(1, ...values);
    const step = WIDTH / (values.length - 1);
    const points = values.map((v, i) => [i * step, height - 4 - (v / max) * (height - 10)] as const);
    const line = points.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`).join(' ');
    return { line, area: `${line} L${WIDTH} ${height} L0 ${height} Z` };
  });
</script>

<svg viewBox="0 0 {WIDTH} {height}" preserveAspectRatio="none" style:height="{height}px" aria-hidden="true">
  <defs>
    <linearGradient id="spark-fill" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="var(--accent)" stop-opacity="0.35" />
      <stop offset="1" stop-color="var(--accent)" stop-opacity="0" />
    </linearGradient>
  </defs>
  {#if path}
    <path d={path.area} fill="url(#spark-fill)" />
    <path d={path.line} fill="none" stroke="var(--accent)" stroke-width="1.6" vector-effect="non-scaling-stroke" />
  {:else}
    <line x1="0" x2={WIDTH} y1={height - 4} y2={height - 4} stroke="var(--glass-border)" stroke-dasharray="3 5" />
  {/if}
</svg>

<style>
  svg {
    width: 100%;
    display: block;
  }
</style>
