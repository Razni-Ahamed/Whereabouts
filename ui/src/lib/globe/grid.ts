// Small helpers for the globe's character grid, kept apart so Node can test them.

/**
 * A grid of `cols × rows` cells (row by row) resized to `newCols × newRows`:
 * cells that still fit keep their row and column, new cells come from `fresh`.
 * Used so resizing the window does not reshuffle the whole background.
 */
export function regrid<A extends Float32Array | Uint8Array>(
  old: A,
  cols: number,
  rows: number,
  newCols: number,
  newRows: number,
  fresh: () => number,
): A {
  const out = (old instanceof Uint8Array ? new Uint8Array(newCols * newRows) : new Float32Array(newCols * newRows)) as A;
  for (let row = 0; row < newRows; row++) {
    for (let col = 0; col < newCols; col++) {
      out[row * newCols + col] = row < rows && col < cols ? old[row * cols + col]! : fresh();
    }
  }
  return out;
}

/** Whether two "country → tracker" maps say the same thing. */
export function sameCountries(a: Map<string, boolean>, b: Map<string, boolean>): boolean {
  if (a.size !== b.size) return false;
  for (const [code, warn] of a) {
    if (b.get(code) !== warn) return false;
  }
  return true;
}
