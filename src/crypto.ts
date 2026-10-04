export function randomToken(): string { return b64(crypto.getRandomValues(new Uint8Array(32))); }
export function b64(bytes: Uint8Array): string { return btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replace(/=+$/, ''); }
export function unb64(s: string): Uint8Array<ArrayBuffer> { return Uint8Array.from(atob(s.replaceAll('-','+').replaceAll('_','/')), c => c.charCodeAt(0)); }
export async function hash(s: string): Promise<string> { return b64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)))); }
export async function equalSecret(a: string, b: string): Promise<boolean> {
  const aa = unb64(await hash(a)), bb = unb64(await hash(b)); let diff = 0;
  for (let i=0;i<aa.length;i++) diff |= aa[i] ^ bb[i]; return diff === 0;
}
async function key(secret: string): Promise<CryptoKey> {
  const raw = unb64(secret); if (raw.length !== 32) throw new Error('VAULT_KEY must be a Base64-encoded 32-byte key');
  return crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, ['encrypt','decrypt']);
}
export async function encrypt(value: unknown, secret: string, id: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name:'AES-GCM', iv, additionalData:new TextEncoder().encode(id) }, await key(secret), new TextEncoder().encode(JSON.stringify(value)));
  return `${b64(iv)}.${b64(new Uint8Array(data))}`;
}
export async function decrypt<T>(value: string, secret: string, id: string): Promise<T> {
  const [iv, data] = value.split('.');
  return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name:'AES-GCM', iv:unb64(iv) as BufferSource, additionalData:new TextEncoder().encode(id) }, await key(secret), unb64(data) as BufferSource)));
}
