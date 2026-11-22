// Moves an element to the end of <body>.
//
// For overlays (`position: fixed`) opened from inside a card: a `.glass` card
// has a `backdrop-filter`, which makes it the box that fixed children are
// placed in, so an overlay inside a long card was centred in the card (far
// off-screen) instead of in the window. At the end of <body> it covers the
// window, above everything.

export function portal(node: HTMLElement): { destroy: () => void } {
  document.body.appendChild(node);
  return {
    destroy() {
      node.remove();
    },
  };
}
