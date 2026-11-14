<script lang="ts">
  // A night chart, drawn in SVG: a coordinate grid, topographic contour
  // lines, and routes flowing from this computer to destinations, which is
  // what Whereabouts shows. Purely decorative; it does not show real data.

  const W = 1600;
  const H = 1000;

  /** Closed, gently irregular contour rings around a centre. */
  function contours(cx: number, cy: number, rings: number, step: number, seed: number): string[] {
    const paths: string[] = [];
    for (let k = 1; k <= rings; k++) {
      const r = k * step;
      const points: string[] = [];
      for (let i = 0; i < 72; i++) {
        const a = (i / 72) * Math.PI * 2;
        const wobble =
          1 +
          0.09 * Math.sin(3 * a + seed + k * 0.35) +
          0.05 * Math.sin(5 * a + seed * 2 - k * 0.2) +
          0.025 * Math.sin(9 * a + seed * 3);
        const x = cx + Math.cos(a) * r * wobble * 1.25;
        const y = cy + Math.sin(a) * r * wobble;
        points.push(`${x.toFixed(1)} ${y.toFixed(1)}`);
      }
      paths.push(`M${points.join(' L')} Z`);
    }
    return paths;
  }

  const rings = [
    ...contours(1240, 300, 11, 34, 0.7),
    ...contours(260, 760, 9, 38, 2.1),
    ...contours(820, 1040, 6, 46, 4.2),
  ];

  // This computer, and where its traffic goes.
  const home = { x: 430, y: 700 };
  const destinations = [
    { x: 1190, y: 220, lift: 0.32 },
    { x: 1430, y: 470, lift: 0.22 },
    { x: 930, y: 150, lift: 0.4 },
    { x: 1310, y: 800, lift: -0.18 },
    { x: 660, y: 280, lift: 0.3 },
    { x: 110, y: 330, lift: -0.25 },
  ];
  const routes = destinations.map((d, i) => {
    const mx = (home.x + d.x) / 2;
    const my = (home.y + d.y) / 2;
    const dx = d.x - home.x;
    const dy = d.y - home.y;
    // Control point: lifted sideways from the midpoint, like a flight path.
    const cx = mx - dy * d.lift;
    const cy = my + dx * d.lift - Math.abs(dx) * 0.12;
    return { id: i, d: `M${home.x} ${home.y} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${d.x} ${d.y}`, to: d };
  });

  const labels = [
    { x: 208, y: 96, t: '51°30′N' },
    { x: 808, y: 96, t: '0°07′W' },
    { x: 1408, y: 96, t: '35°41′N' },
    { x: 1408, y: 896, t: '139°41′E' },
    { x: 8, y: 496, t: '6°55′N' },
  ];
</script>

<div class="backdrop" aria-hidden="true">
  <svg viewBox="0 0 {W} {H}" preserveAspectRatio="xMidYMid slice">
    <defs>
      <radialGradient id="base" cx="0.55" cy="0.35" r="0.85">
        <stop offset="0" stop-color="#0d2131" />
        <stop offset="0.6" stop-color="#07121c" />
        <stop offset="1" stop-color="#040910" />
      </radialGradient>
      <radialGradient id="glow-teal" cx="0.78" cy="0.22" r="0.42">
        <stop offset="0" stop-color="#3fcfb0" stop-opacity="0.2" />
        <stop offset="1" stop-color="#3fcfb0" stop-opacity="0" />
      </radialGradient>
      <radialGradient id="glow-blue" cx="0.18" cy="0.8" r="0.45">
        <stop offset="0" stop-color="#3f7fd0" stop-opacity="0.16" />
        <stop offset="1" stop-color="#3f7fd0" stop-opacity="0" />
      </radialGradient>
      <pattern id="grid" width="100" height="100" patternUnits="userSpaceOnUse">
        <path d="M100 0H0V100" fill="none" stroke="#a6d0f0" stroke-opacity="0.035" />
      </pattern>
      <pattern id="grid-major" width="400" height="400" patternUnits="userSpaceOnUse">
        <path d="M400 0H0V400" fill="none" stroke="#a6d0f0" stroke-opacity="0.06" />
      </pattern>
      {#each routes as r (r.id)}
        <linearGradient
          id="route-{r.id}"
          gradientUnits="userSpaceOnUse"
          x1={home.x}
          y1={home.y}
          x2={r.to.x}
          y2={r.to.y}
        >
          <stop offset="0" stop-color="#5fe0c3" stop-opacity="0.05" />
          <stop offset="1" stop-color="#5fe0c3" stop-opacity="0.6" />
        </linearGradient>
      {/each}
      <radialGradient id="node-glow">
        <stop offset="0" stop-color="#a9f2df" stop-opacity="0.55" />
        <stop offset="1" stop-color="#a9f2df" stop-opacity="0" />
      </radialGradient>
      <filter id="soft" x="-20%" y="-20%" width="140%" height="140%">
        <feGaussianBlur stdDeviation="1.2" />
      </filter>
      <filter id="grain">
        <feTurbulence type="fractalNoise" baseFrequency="0.9" numOctaves="2" stitchTiles="stitch" />
        <feColorMatrix values="0 0 0 0 0.8  0 0 0 0 0.9  0 0 0 0 1  0 0 0 0.045 0" />
      </filter>
    </defs>

    <rect width={W} height={H} fill="url(#base)" />
    <rect width={W} height={H} fill="url(#glow-teal)" />
    <rect width={W} height={H} fill="url(#glow-blue)" />
    <rect width={W} height={H} fill="url(#grid)" />
    <rect width={W} height={H} fill="url(#grid-major)" />

    <g fill="none" stroke="#8cc8ea">
      {#each rings as d, i (i)}
        <path {d} stroke-opacity={i % 4 === 0 ? 0.085 : 0.045} stroke-width={i % 4 === 0 ? 1.1 : 0.8} />
      {/each}
    </g>

    {#each labels as l (l.t)}
      <text x={l.x} y={l.y} class="coord">{l.t}</text>
    {/each}

    <g fill="none" stroke-linecap="round">
      {#each routes as r (r.id)}
        <path d={r.d} stroke="url(#route-{r.id})" stroke-width="1.4" filter="url(#soft)" />
        <path
          d={r.d}
          class="flow"
          stroke="#a9f2df"
          stroke-opacity="0.55"
          stroke-width="1.6"
          stroke-dasharray="2 22"
          style:animation-delay="{r.id * -1.7}s"
        />
      {/each}
    </g>

    {#each routes as r (r.id)}
      <circle cx={r.to.x} cy={r.to.y} r="16" fill="url(#node-glow)" />
      <circle cx={r.to.x} cy={r.to.y} r="3" fill="#a9f2df" />
      <circle cx={r.to.x} cy={r.to.y} r="9" fill="none" stroke="#5fe0c3" stroke-opacity="0.35" />
    {/each}

    <!-- This computer. -->
    <circle cx={home.x} cy={home.y} r="44" fill="url(#node-glow)" />
    <circle cx={home.x} cy={home.y} r="5" fill="#e9f1f6" />
    <circle cx={home.x} cy={home.y} r="14" fill="none" stroke="#a9f2df" stroke-opacity="0.5" />
    <circle class="ping" cx={home.x} cy={home.y} r="14" fill="none" stroke="#a9f2df" />

    <rect width={W} height={H} filter="url(#grain)" />
  </svg>
  <div class="vignette"></div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: 0;
    pointer-events: none;
    overflow: hidden;
  }
  svg {
    width: 100%;
    height: 100%;
    display: block;
  }
  .coord {
    font-family: var(--font-mono);
    font-size: 11px;
    letter-spacing: 0.08em;
    fill: #a6d0f0;
    fill-opacity: 0.16;
  }
  .flow {
    animation: flow 9s linear infinite;
  }
  @keyframes flow {
    to {
      stroke-dashoffset: -480;
    }
  }
  .ping {
    transform-origin: 430px 700px;
    transform-box: view-box;
    animation: ping 3.2s var(--ease) infinite;
  }
  @keyframes ping {
    from {
      transform: scale(1);
      stroke-opacity: 0.5;
    }
    to {
      transform: scale(3.4);
      stroke-opacity: 0;
    }
  }
  .vignette {
    position: absolute;
    inset: 0;
    background: radial-gradient(ellipse at 50% 42%, transparent 50%, rgb(2 6 12 / 0.65) 100%);
  }
</style>
