export type Account = { issuer: string; label: string; secret: string; algorithm: 'SHA-1' | 'SHA-256' | 'SHA-512'; digits: 6 | 8; period: number };
export function base32(raw: string): Uint8Array {
  const s = raw.toUpperCase().replace(/\s/g, '').replace(/=+$/, '');
  if (!s || !/^[A-Z2-7]+$/.test(s) || ![0,2,4,5,7].includes(s.length % 8)) throw new Error('Invalid Base32 secret');
  let bits = 0, value = 0; const out: number[] = [];
  for (const c of s) { value = (value << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c); bits += 5; if (bits >= 8) { bits -= 8; out.push((value >>> bits) & 255); } }
  if (bits && (value & ((1 << bits) - 1)) !== 0) throw new Error('Invalid Base32 padding');
  return new Uint8Array(out);
}
export function parseAccount(input: Record<string, unknown>): Account {
  let fields = input;
  if (typeof input.uri === 'string' && input.uri.trim()) {
    const u = new URL(input.uri.trim());
    if (u.protocol !== 'otpauth:' || u.hostname !== 'totp') throw new Error('Use an otpauth://totp URI');
    const label = decodeURIComponent(u.pathname.slice(1)); const split = label.indexOf(':');
    fields = { issuer: u.searchParams.get('issuer') || (split >= 0 ? label.slice(0, split) : ''), label: split >= 0 ? label.slice(split + 1) : label,
      secret: u.searchParams.get('secret'), algorithm: u.searchParams.get('algorithm') || 'SHA1', digits: u.searchParams.get('digits') || 6, period: u.searchParams.get('period') || 30 };
  }
  const algorithm = String(fields.algorithm || 'SHA1').toUpperCase().replace('-', '');
  if (!['SHA1', 'SHA256', 'SHA512'].includes(algorithm)) throw new Error('Unsupported hash algorithm');
  const digits = Number(fields.digits || 6), period = Number(fields.period || 30);
  if (![6, 8].includes(digits) || !Number.isInteger(period) || period < 15 || period > 120) throw new Error('Use 6 or 8 digits and a period of 15–120 seconds');
  const secret = String(fields.secret || '').toUpperCase().replace(/\s/g, '').replace(/=+$/, '');
  const bytes = base32(secret);
  if (bytes.length < 10 || bytes.length > 128) throw new Error('Secret must contain 10–128 bytes');
  const label = String(fields.label || '').trim(), issuer = String(fields.issuer || '').trim();
  if (!label || label.length > 150 || issuer.length > 100) throw new Error('Enter an account name (up to 150 characters)');
  return { issuer, label, secret, algorithm: ({SHA1:'SHA-1',SHA256:'SHA-256',SHA512:'SHA-512'} as const)[algorithm as 'SHA1'|'SHA256'|'SHA512'], digits: digits as 6 | 8, period };
}
export async function totp(a: Account, now = Date.now()): Promise<string> {
  const counter = BigInt(Math.floor(now / 1000 / a.period));
  const message = new Uint8Array(8); new DataView(message.buffer).setBigUint64(0, counter);
  const key = await crypto.subtle.importKey('raw', base32(a.secret) as BufferSource, { name: 'HMAC', hash: a.algorithm }, false, ['sign']);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, message)); const o = h[h.length - 1] & 15;
  const n = ((h[o] & 127) << 24) | (h[o+1] << 16) | (h[o+2] << 8) | h[o+3];
  return String(n % 10 ** a.digits).padStart(a.digits, '0');
}
export function toURI(a: Account): string {
  const label = a.issuer ? `${a.issuer}:${a.label}` : a.label;
  const params = new URLSearchParams({ secret:a.secret, issuer:a.issuer, algorithm:a.algorithm.replace('-',''), digits:String(a.digits), period:String(a.period) });
  return `otpauth://totp/${encodeURIComponent(label)}?${params}`;
}
