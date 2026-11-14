<script lang="ts">
  import { appLabel } from '../format';

  let { app, size = 38 }: { app: string; size?: number } = $props();

  // A calm teal-to-blue hue picked from the name, so each app keeps its colour.
  const hue = $derived.by(() => {
    let h = 0;
    for (const c of app) h = (h * 31 + c.charCodeAt(0)) % 360;
    return 165 + (h % 70);
  });
  const letter = $derived(appLabel(app).charAt(0).toUpperCase() || '?');
</script>

<span
  class="avatar"
  style:width="{size}px"
  style:height="{size}px"
  style:font-size="{size * 0.42}px"
  style:--h={hue}
>
  {letter}
</span>

<style>
  .avatar {
    display: inline-grid;
    place-items: center;
    flex: none;
    border-radius: 32%;
    font-family: var(--font-display);
    font-weight: 600;
    color: hsl(var(--h) 55% 82%);
    background: linear-gradient(
      150deg,
      hsl(var(--h) 38% 34% / 0.75),
      hsl(var(--h) 40% 18% / 0.75)
    );
    border: 1px solid hsl(var(--h) 45% 70% / 0.22);
    box-shadow: inset 0 1px 0 rgb(255 255 255 / 0.12);
  }
</style>
