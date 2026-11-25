// Plain-language text for why a behaviour alert was raised.

import { appLabel, bytes, countryName } from './format.ts';
import type { AlertView, ReasonView } from './types.ts';

const finite = (n: number | null): n is number => n !== null && Number.isFinite(n);
const present = (s: string | null): s is string => s !== null && s !== '';

/** One sentence for a reason; a shorter one when the numbers it needs are missing. */
export function reasonText(r: ReasonView): string {
  switch (r.signal) {
    case 'new_site':
      return present(r.value) ? `New site: ${r.value}` : 'Connected to a site it has not used before.';
    case 'new_company':
      return present(r.value) ? `First time using ${r.value}` : 'First time using a company it has not used before.';
    case 'new_country':
      return present(r.value) ? `First connection to ${countryName(r.value)}` : 'First connection to a new country.';
    case 'upload_spike':
      if (finite(r.observed) && finite(r.usual)) {
        return `Uploaded ${bytes(r.observed)} in an hour. Usually about ${bytes(r.usual)}.`;
      }
      return 'Uploaded much more than usual in an hour.';
    case 'ratio_flip':
      return finite(r.observed)
        ? `Sent more than it received this hour (${bytes(r.observed)} sent). It usually mostly downloads.`
        : 'Sent more than it received this hour. It usually mostly downloads.';
    case 'beaconing':
      if (present(r.value) && finite(r.observed) && r.count !== null) {
        return `Connected to ${r.value} every ${Math.round(r.observed)} seconds, ${r.count} times.`;
      }
      return present(r.value) ? `Connected to ${r.value} at regular intervals.` : 'Connected at regular intervals.';
    case 'unusual_time':
      return present(r.value) ? `Active at an hour it rarely is (${r.value}:00).` : 'Active at an hour it rarely is.';
    case 'random_name':
      return present(r.value) ? `Used a random-looking name: ${r.value}` : 'Used a random-looking name.';
    case 'binary_changed':
      return 'Its program file changed and lost its signature, and it reached somewhere new.';
    default:
      return 'Unusual behaviour';
  }
}

/** The headline of a behaviour alert. */
export function alertTitle(a: AlertView): string {
  return `${a.app ? appLabel(a.app) : 'An app'} is behaving differently`;
}
