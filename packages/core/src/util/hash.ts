import { createHash } from 'node:crypto';

export function sha256Hex(buf: Uint8Array | string): string {
  return createHash('sha256').update(buf).digest('hex');
}
export function sriHash(buf: Uint8Array | string, algo: 'sha256' | 'sha384' | 'sha512' = 'sha384'): string {
  return `${algo}-${createHash(algo).update(buf).digest('base64')}`;
}
export function mask(value: string, keep = 4): string {
  if (value.length <= keep + 2) return '*'.repeat(value.length);
  return `${value.slice(0, keep)}${'*'.repeat(Math.min(12, value.length - keep - 2))}${value.slice(-2)}`;
}
