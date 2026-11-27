/** What dismissing one alert gave. */
export type DismissOutcome = { ok: true } | { ok: false; message: string };

/** Dismisses each alert in turn (one request at a time, so the service is never flooded). */
export async function dismissEach(
  ids: number[],
  dismissOne: (id: number) => Promise<DismissOutcome>,
): Promise<{ done: number; failed: number; firstError: string | null }> {
  let done = 0;
  let failed = 0;
  let firstError: string | null = null;
  for (const id of ids) {
    const outcome = await dismissOne(id);
    if (outcome.ok) done += 1;
    else {
      failed += 1;
      firstError ??= outcome.message;
    }
  }
  return { done, failed, firstError };
}
