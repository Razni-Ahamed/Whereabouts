// Telling host names from IP addresses.

/** Whether `host` is an IPv4 or IPv6 address (optionally in brackets or with a port), not a host name. */
export function isIpLiteral(host: string): boolean {
  const bare = host.replace(/^\[|\]$/g, '').replace(/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/, '$1');
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(bare) || (bare.includes(':') && /^[0-9a-f:.]+$/i.test(bare));
}
