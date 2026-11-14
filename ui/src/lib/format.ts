// Formatting helpers. Everything runs locally; country names come from the
// browser engine's built-in data, not from the network.

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'];

export function bytes(value: number): string {
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < UNITS.length - 1) {
    size /= 1024;
    unit += 1;
  }
  const digits = unit === 0 || size >= 100 ? 0 : 1;
  return `${size.toFixed(digits)} ${UNITS[unit]}`;
}

export function count(value: number): string {
  return new Intl.NumberFormat('en', { notation: value >= 10_000 ? 'compact' : 'standard' }).format(
    value,
  );
}

export function uptime(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h >= 24) return `${Math.floor(h / 24)}d ${h % 24}h`;
  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`;
  return `${m}m`;
}

const regionNames = new Intl.DisplayNames(['en'], { type: 'region' });

export function countryName(code: string | null): string {
  if (!code) return 'Unknown';
  try {
    return regionNames.of(code.toUpperCase()) ?? code;
  } catch {
    return code;
  }
}

/** Splits "Google · analytics" style owner text into company and kind. */
export function ownerParts(owner: string | null): { name: string; kind: string | null } {
  if (!owner) return { name: 'Unknown network', kind: null };
  const [name, kind] = owner.split(' · ');
  return { name: name ?? owner, kind: kind ?? null };
}

/** Plain-language publisher trust. */
export function publisherState(
  publisher: string,
  confirmed: boolean,
): 'signed' | 'unconfirmed' | 'unsigned' | 'invalid' | 'pending' | 'none' {
  if (publisher === '…') return 'pending';
  if (publisher === '-') return 'none';
  if (publisher === 'UNSIGNED') return 'unsigned';
  if (publisher === 'INVALID SIGNATURE') return 'invalid';
  return confirmed ? 'signed' : 'unconfirmed';
}

export function appLabel(file: string): string {
  return file.replace(/\.exe$/i, '');
}
