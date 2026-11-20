// The backdrop: a turning globe drawn in monospace characters on a canvas.
// The cursor stirs the characters near it, a click on the background sends a
// wave, and dragging the globe spins it. Countries with a connection right now
// glow; a new connection flashes its country (amber for trackers). It only
// shows what the app is given (see pings.ts); it never makes activity up.

import { countryCentre, isLand, landMask } from './geo.ts';
import type { Ping } from './pings.ts';

export interface Globe {
  /** Countries with a connection now; true = a tracker (amber). */
  setActive(countries: Map<string, boolean>): void;
  /** Flash a country, with a small wave when it faces the viewer. */
  ping(p: Ping): void;
  stop(): void;
}

const CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const FONT_PX = 12;
const CELL_W = 8;
const CELL_H = 14;
const LEVELS = 16;
const HOVER_RADIUS = 150;
const MAX_RIPPLES = 8;
const PING_GAP_S = 0.35;
const SPIN = 0.07; // radians per second
// Frames per second. The glass above the canvas is recomposited every frame,
// so the globe draws slowly at rest (it turns about three characters a second,
// so nothing is lost) and smoothly only while something moves.
const BUSY_FRAME_S = 1 / 30;
const IDLE_FRAME_S = 1 / 10;
/** Per-frame rates below are tuned for 30 fps and scaled by the real frame time. */
const TUNED_FPS = 30;
const MAX_QUEUE = 8;
const TILT = 0.38;

type Rgb = [number, number, number];
type Stop = [at: number, rgb: Rgb, alpha: number];

// From the app's tokens: ink blue for the faint field, signal teal for land,
// mint to near-white at the brightest; amber (--warn) for trackers.
const TEAL: Stop[] = [
  [0, [64, 98, 128], 0.2],
  [0.3, [78, 140, 165], 0.45],
  [0.62, [95, 224, 195], 0.82],
  [1, [232, 255, 249], 1],
];
const WARN: Stop[] = [
  [0, [120, 98, 66], 0.25],
  [0.35, [196, 156, 88], 0.6],
  [0.7, [242, 196, 109], 0.92],
  [1, [255, 242, 210], 1],
];

function colour(stops: Stop[], f: number): string {
  for (let k = 1; k < stops.length; k++) {
    const [a, ca, aa] = stops[k - 1]!;
    const [b, cb, ab] = stops[k]!;
    if (f <= b) {
      const u = (f - a) / (b - a);
      const c = ca.map((v, j) => Math.round(v + (cb[j]! - v) * u));
      return `rgb(${c[0]} ${c[1]} ${c[2]} / ${(aa + (ab - aa) * u).toFixed(3)})`;
    }
  }
  const [, c, a] = stops[stops.length - 1]!;
  return `rgb(${c[0]} ${c[1]} ${c[2]} / ${a})`;
}

interface Ripple {
  x: number;
  y: number;
  t0: number;
  speed: number;
  life: number;
  strength: number;
  warn: boolean;
}

/** Things the page can click without making a wave. */
const INTERACTIVE = '.glass, button, a, input, select, textarea, label, [role="dialog"]';

export function startGlobe(canvas: HTMLCanvasElement): Globe {
  const ctx = canvas.getContext('2d');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const mask = landMask();

  let dpr = 1, W = 0, H = 0, cols = 0, rows = 0;
  let atlas = document.createElement('canvas');
  let field = new Float32Array(0); // the still background: faint scattered characters
  let base = new Float32Array(0); // field + globe + glows, this frame
  let warmBase = new Float32Array(0); // amber share of `base`
  let heat = new Float32Array(0); // how stirred a character is
  let glyph = new Uint8Array(0);

  let mx = -1e4, my = -1e4, movedAt = -10;
  let ripples: Ripple[] = [];
  let rot = 0.4;
  let drag: { x: number; lastX: number; moved: boolean; onGlobe: boolean } | null = null;
  let raf = 0, last = 0, stopped = false;
  let minimized = false, paused = false;

  let active = new Map<string, boolean>();
  const flashes = new Map<string, { t: number; warn: boolean }>();
  const queue: Ping[] = [];
  let nextPingAt = 0;

  const now = () => performance.now() / 1000;
  const globe = () => {
    const R = Math.min(H * 0.47, W * 0.34);
    return { cx: W * 0.66, cy: H * 0.58, R };
  };

  function buildAtlas() {
    atlas = document.createElement('canvas');
    atlas.width = Math.ceil(CHARS.length * CELL_W * dpr);
    atlas.height = Math.ceil(2 * LEVELS * CELL_H * dpr);
    const a = atlas.getContext('2d');
    if (!a) return;
    a.scale(dpr, dpr);
    a.font = `${FONT_PX}px 'Cascadia Mono', Consolas, ui-monospace, monospace`;
    a.textAlign = 'center';
    a.textBaseline = 'middle';
    [TEAL, WARN].forEach((stops, p) => {
      for (let l = 1; l < LEVELS; l++) {
        a.fillStyle = colour(stops, l / (LEVELS - 1));
        for (let c = 0; c < CHARS.length; c++) {
          a.fillText(CHARS[c]!, c * CELL_W + CELL_W / 2, (p * LEVELS + l) * CELL_H + CELL_H / 2 + 0.5);
        }
      }
    });
  }

  function resize() {
    dpr = window.devicePixelRatio || 1;
    W = window.innerWidth;
    H = window.innerHeight;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    canvas.style.width = `${W}px`;
    canvas.style.height = `${H}px`;
    cols = Math.ceil(W / CELL_W);
    rows = Math.ceil(H / CELL_H);
    const n = cols * rows;
    field = new Float32Array(n);
    base = new Float32Array(n);
    warmBase = new Float32Array(n);
    heat = new Float32Array(n);
    glyph = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      glyph[i] = (Math.random() * CHARS.length) | 0;
      const r = Math.random();
      field[i] = r < 0.5 ? 0.075 + r * 0.09 : 0;
    }
    ripples = [];
    buildAtlas();
    if (reduceMotion) draw(now());
  }

  /** Where a latitude/longitude is on screen, and whether it faces us. */
  function project(latDeg: number, lonDeg: number) {
    const { cx, cy, R } = globe();
    const lat = (latDeg * Math.PI) / 180;
    const lon = (lonDeg * Math.PI) / 180 - rot;
    const x = Math.cos(lat) * Math.sin(lon);
    const yt = Math.sin(lat);
    const zt = Math.cos(lat) * Math.cos(lon);
    const y = yt * Math.cos(TILT) + zt * Math.sin(TILT);
    const z = -yt * Math.sin(TILT) + zt * Math.cos(TILT);
    return { x: cx + x * R, y: cy - y * R, visible: z > 0.12 };
  }

  function drawGlobe() {
    const { cx, cy, R } = globe();
    const lx = -0.45, ly = 0.5, lz = 0.74; // light from the upper left
    const c0 = Math.max(0, Math.floor((cx - R * 1.2) / CELL_W));
    const c1 = Math.min(cols - 1, Math.ceil((cx + R * 1.2) / CELL_W));
    const r0 = Math.max(0, Math.floor((cy - R * 1.2) / CELL_H));
    const r1 = Math.min(rows - 1, Math.ceil((cy + R * 1.2) / CELL_H));
    const ct = Math.cos(TILT), st = Math.sin(TILT);
    for (let row = r0; row <= r1; row++) {
      const ny = (cy - (row * CELL_H + CELL_H / 2)) / R;
      for (let col = c0; col <= c1; col++) {
        const i = row * cols + col;
        const nx = (col * CELL_W + CELL_W / 2 - cx) / R;
        const rr = nx * nx + ny * ny;
        if (rr > 1) {
          const d = Math.sqrt(rr) - 1;
          if (d < 0.12) base[i] = Math.max(base[i]!, 0.2 * (1 - d / 0.12)); // atmosphere
          continue;
        }
        const nz = Math.sqrt(1 - rr);
        const yt = ny * ct - nz * st;
        const zt = ny * st + nz * ct;
        const latD = (Math.asin(Math.max(-1, Math.min(1, yt))) * 180) / Math.PI;
        let lon = Math.atan2(nx, zt) + rot;
        lon = ((((lon + Math.PI) % (2 * Math.PI)) + 2 * Math.PI) % (2 * Math.PI)) - Math.PI;
        const lonD = (lon * 180) / Math.PI;
        const shade = Math.max(0, nx * lx + ny * ly + nz * lz);
        let v: number;
        if (isLand(mask, latD, lonD)) {
          v = 0.3 + 0.62 * shade;
        } else {
          v = 0.08 + 0.14 * shade;
          const gLat = Math.abs(((latD + 180) % 30) - 15), gLon = Math.abs(((lonD + 180) % 30) - 15);
          if (gLat > 14.1 || gLon > 14.1) v += 0.09; // the graticule
          if (rr > 0.9) v += 0.08 * ((rr - 0.9) / 0.1); // the rim
        }
        base[i] = v;
      }
    }
  }

  /** Brighten the characters within `radius` px of a point. */
  function glow(px: number, py: number, radius: number, amount: number, warn: boolean) {
    const c0 = Math.max(0, Math.floor((px - radius) / CELL_W));
    const c1 = Math.min(cols - 1, Math.ceil((px + radius) / CELL_W));
    const r0 = Math.max(0, Math.floor((py - radius) / CELL_H));
    const r1 = Math.min(rows - 1, Math.ceil((py + radius) / CELL_H));
    for (let row = r0; row <= r1; row++) {
      for (let col = c0; col <= c1; col++) {
        const d = Math.hypot(col * CELL_W + CELL_W / 2 - px, row * CELL_H + CELL_H / 2 - py);
        if (d >= radius) continue;
        const i = row * cols + col;
        const v = amount * (1 - (d / radius) * 0.5);
        if (v > base[i]!) base[i] = v;
        if (warn) warmBase[i] = 1;
      }
    }
  }

  function addRipple(x: number, y: number, t: number, opts: Partial<Ripple> = {}) {
    ripples.push({ x, y, t0: t, speed: 520, life: 2.6, strength: 0.95, warn: false, ...opts });
    if (ripples.length > MAX_RIPPLES) ripples.shift();
  }

  function firePing(p: Ping, t: number) {
    flashes.set(p.country, { t, warn: p.warn });
    const centre = countryCentre(p.country);
    if (!centre) return;
    const at = project(centre[0], centre[1]);
    if (at.visible) addRipple(at.x, at.y, t, { speed: 150, life: 2.2, strength: 0.6, warn: p.warn });
  }

  function draw(t: number, dt = 1 / TUNED_FPS) {
    const steps = dt * TUNED_FPS;
    const decay = 0.9 ** steps;
    if (!ctx) return;
    base.set(field);
    warmBase.fill(0);
    drawGlobe();
    const glowing = new Map(active);
    for (const [code, f] of flashes) {
      if (t - f.t > 1.6) flashes.delete(code);
      else glowing.set(code, (glowing.get(code) ?? false) || f.warn);
    }
    for (const [code, warn] of glowing) {
      const centre = countryCentre(code);
      if (!centre) continue;
      const at = project(centre[0], centre[1]);
      if (!at.visible) continue;
      const f = flashes.get(code);
      const boost = f ? Math.max(0, 1 - (t - f.t) / 1.6) : 0;
      glow(at.x, at.y, 9 + 9 * boost, 0.72 + 0.3 * boost, warn);
    }

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    const sw = CELL_W * dpr, sh = CELL_H * dpr;
    ripples = ripples.filter((r) => t - r.t0 < r.life);

    for (let row = 0; row < rows; row++) {
      const y = row * CELL_H + CELL_H / 2;
      for (let col = 0; col < cols; col++) {
        const i = row * cols + col;
        const x = col * CELL_W + CELL_W / 2;
        let v = base[i]!;
        let h = heat[i]! * decay;
        let warm = warmBase[i]!;

        const dh = Math.hypot(x - mx, y - my);
        if (dh < HOVER_RADIUS) {
          const k = (1 - dh / HOVER_RADIUS) ** 2;
          v += k * (0.35 + v * 0.5);
          h += k * 0.12;
        }
        for (const r of ripples) {
          const age = t - r.t0;
          const d = Math.hypot(x - r.x, y - r.y) - age * r.speed;
          if (d > 60 || d < -60) continue;
          const band = Math.exp(-((d / 26) ** 2)) * Math.exp(-age * 1.15) * r.strength;
          v += band * 0.8;
          h += band * 0.5;
          if (r.warn) warm += band;
        }
        heat[i] = h;

        if (!reduceMotion && Math.random() < (0.0015 + h * 0.5) * steps) glyph[i] = (Math.random() * CHARS.length) | 0;
        const level = Math.min(LEVELS - 1, Math.floor(v * LEVELS));
        if (level < 1) continue;
        const p = warm > 0.25 ? 1 : 0;
        ctx.drawImage(atlas, glyph[i]! * sw, (p * LEVELS + level) * sh, sw, sh, col * CELL_W, row * CELL_H, CELL_W, CELL_H);
      }
    }
  }

  function tick(ms: number) {
    raf = requestAnimationFrame(tick);
    const t = ms / 1000;
    const busy = drag !== null || ripples.length > 0 || queue.length > 0 || flashes.size > 0 || t - movedAt < 1.5;
    if (last && t - last < (busy ? BUSY_FRAME_S : IDLE_FRAME_S) - 0.002) return;
    const dt = last ? Math.min(0.1, t - last) : 0;
    last = t;
    if (!drag?.onGlobe) rot += dt * SPIN;
    if (queue.length > 0 && t >= nextPingAt) {
      firePing(queue.shift()!, t);
      nextPingAt = t + PING_GAP_S;
    }
    draw(t, dt || 1 / TUNED_FPS);
  }

  /** Stop drawing while the window is minimised or the page hidden. */
  function updatePaused() {
    const shouldPause = minimized || document.hidden;
    if (shouldPause === paused || stopped) return;
    paused = shouldPause;
    if (paused) {
      cancelAnimationFrame(raf);
    } else {
      last = 0;
      raf = requestAnimationFrame(tick);
    }
  }
  function onMinimized(e: Event) {
    minimized = (e as CustomEvent<boolean>).detail === true;
    updatePaused();
  }

  const isBackground = (target: EventTarget | null) => target instanceof Element && !target.closest(INTERACTIVE);

  function onMove(e: PointerEvent) {
    mx = e.clientX;
    my = e.clientY;
    movedAt = now();
    if (drag && e.buttons === 0) drag = null; // the button came up where we did not hear it
    if (!drag) return;
    if (Math.abs(e.clientX - drag.x) > 4) drag.moved = true;
    if (drag.onGlobe) rot -= (e.clientX - drag.lastX) / globe().R;
    drag.lastX = e.clientX;
  }
  function onDown(e: PointerEvent) {
    if (e.button !== 0 || !isBackground(e.target)) return;
    const { cx, cy, R } = globe();
    drag = { x: e.clientX, lastX: e.clientX, moved: false, onGlobe: Math.hypot(e.clientX - cx, e.clientY - cy) < R };
  }
  function onUp(e: PointerEvent) {
    if (drag && !drag.moved) addRipple(e.clientX, e.clientY, now());
    drag = null;
  }
  function onLeave() {
    mx = my = -1e4;
  }
  /** A drag that ends without a pointerup (a cancelled touch, lost focus). */
  function onCancel() {
    drag = null;
  }

  resize();
  window.addEventListener('resize', resize);
  if (!reduceMotion) {
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerdown', onDown);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onCancel);
    window.addEventListener('blur', onCancel);
    document.documentElement.addEventListener('pointerleave', onLeave);
    window.addEventListener('whereabouts:minimized', onMinimized);
    document.addEventListener('visibilitychange', updatePaused);
    raf = requestAnimationFrame(tick);
  }

  return {
    setActive(countries) {
      active = new Map(countries);
      if (reduceMotion && !stopped) draw(now());
    },
    ping(p) {
      if (reduceMotion) {
        if (!stopped) {
          flashes.set(p.country, { t: now(), warn: p.warn });
          draw(now());
        }
        return;
      }
      queue.push(p);
      if (queue.length > MAX_QUEUE) queue.shift();
    },
    stop() {
      stopped = true;
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerdown', onDown);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onCancel);
      window.removeEventListener('blur', onCancel);
      document.documentElement.removeEventListener('pointerleave', onLeave);
      window.removeEventListener('whereabouts:minimized', onMinimized);
      document.removeEventListener('visibilitychange', updatePaused);
    },
  };
}
