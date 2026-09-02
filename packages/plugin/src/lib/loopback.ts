/**
 * True when `hostname` names the local machine.
 *
 * Loopback hosts are unreachable from anywhere else, so a plaintext HTTP URL on
 * one carries no interception risk and the HTTPS requirement is relaxed for
 * them — the same allowance RFC 8252 §7.3 makes for native-app redirect URIs.
 *
 * `URL.hostname` reports an IPv6 host with its brackets, hence the bracketed
 * form here. Deliberately limited to these three exact hosts rather than the
 * whole 127.0.0.0/8 range or names that merely resolve to it: this gates an
 * HTTPS exemption, so it stays as narrow as the specs require.
 */
export function isLoopbackHostname(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]'
}

/** As {@link isLoopbackHostname}, for an already-parsed URL. */
export function isLoopbackUrl(url: URL): boolean {
  return isLoopbackHostname(url.hostname)
}
