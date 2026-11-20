import { mount } from 'svelte';
import '@fontsource-variable/inter';
import '@fontsource-variable/space-grotesk';
import './app.css';
import App from './App.svelte';

// While the window is minimised (the desktop app says so, see main.rs) or the
// page is hidden, pause CSS animations and transitions too: WebView2 keeps
// compositing the frosted glass for every animated frame, even minimised.
function markOutOfSight() {
  const out = window.__whereaboutsMinimized === true || document.hidden;
  document.documentElement.toggleAttribute('data-out-of-sight', out);
}
window.addEventListener('whereabouts:minimized', markOutOfSight);
document.addEventListener('visibilitychange', markOutOfSight);
markOutOfSight();

const target = document.getElementById('app');
if (!target) throw new Error('missing #app');
export default mount(App, { target });
