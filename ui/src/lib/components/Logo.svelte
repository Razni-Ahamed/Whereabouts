<script lang="ts">
  // A location pin sending out signal rings: where your apps' data goes.
  let { size = 34 }: { size?: number } = $props();
</script>

<svg width={size} height={size} viewBox="0 0 48 48" fill="none" aria-hidden="true">
  <path
    d="M20 43c0 0-12-11.3-12-20.7C8 15.4 13.4 10 20 10s12 5.4 12 12.3C32 31.7 20 43 20 43Z"
    stroke="var(--accent)"
    stroke-width="2.3"
    stroke-linejoin="round"
  />
  <circle cx="20" cy="22.3" r="4" fill="var(--mint)" />
  <path d="M33.5 9.5a12 12 0 0 1 4.6 8.6" stroke="var(--mint)" stroke-width="2" stroke-linecap="round" />
  <path d="M35.6 4.2a18 18 0 0 1 7.6 13.4" stroke="var(--mint)" stroke-opacity="0.55" stroke-width="2" stroke-linecap="round" />
</svg>
