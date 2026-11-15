import type { Rng } from './prng';

// IPv4 "numbers-and-dots" notation, as described for inet_aton(3):
// a.b.c.d, a.b.c (c is 16 bits), a.b (b is 24 bits) or a (32 bits),
// where each part may be decimal, octal (leading 0) or hex (leading 0x).
// Different software accepts different subsets of these forms, which is
// exactly why defenders normalize to dotted-quad before comparing indicators.

export function ipToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function intToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

type Radix = 'dec' | 'oct' | 'hex';

function fmt(n: number, radix: Radix, rng: Rng): string {
  if (radix === 'hex') {
    const h = n.toString(16);
    return (rng.bool() ? '0x' : '0X') + (rng.bool() ? h.toUpperCase() : h);
  }
  if (radix === 'oct') return '0' + n.toString(8);
  return n.toString(10);
}

export const IP_FORMS = [
  'hex-octets',
  'octal-octets',
  'dword',
  'hex-dword',
  'mixed-octets',
  'collapsed-3',
  'collapsed-2',
] as const;
export type IpForm = (typeof IP_FORMS)[number];

export const IP_FORM_LABELS: Record<IpForm, string> = {
  'hex-octets': 'four hex octets',
  'octal-octets': 'four octal octets',
  dword: 'a single decimal integer (dotless "dword")',
  'hex-dword': 'a single hex integer',
  'mixed-octets': 'four octets in mixed bases',
  'collapsed-3': 'three parts, with the last two octets collapsed into one 16-bit number',
  'collapsed-2': 'two parts, with the last three octets collapsed into one 24-bit number',
};

export function obfuscateIp(ip: string, form: IpForm, rng: Rng): string {
  const [a, b, c, d] = ip.split('.').map(Number);
  const n = ipToInt(ip);
  switch (form) {
    case 'hex-octets':
      return [a, b, c, d].map((x) => fmt(x, 'hex', rng)).join('.');
    case 'octal-octets':
      return [a, b, c, d].map((x) => fmt(x, 'oct', rng)).join('.');
    case 'dword':
      return String(n);
    case 'hex-dword':
      return fmt(n, 'hex', rng);
    case 'mixed-octets': {
      // Guarantee at least one hex and one octal part so the form is genuinely mixed.
      const radixes: Radix[] = rng.shuffle(['hex', 'oct', rng.pick(['dec', 'hex', 'oct'] as Radix[]), 'dec'] as Radix[]);
      return [a, b, c, d].map((x, i) => fmt(x, radixes[i], rng)).join('.');
    }
    case 'collapsed-3': {
      const last16 = (c << 8) | d;
      return [fmt(a, rng.pick(['dec', 'hex'] as Radix[]), rng), fmt(b, rng.pick(['dec', 'oct'] as Radix[]), rng), fmt(last16, rng.pick(['dec', 'hex'] as Radix[]), rng)].join('.');
    }
    case 'collapsed-2': {
      const last24 = (b << 16) | (c << 8) | d;
      return [fmt(a, rng.pick(['dec', 'hex', 'oct'] as Radix[]), rng), fmt(last24, rng.pick(['dec', 'hex'] as Radix[]), rng)].join('.');
    }
  }
}

function parsePart(p: string): number | null {
  if (/^0[xX][0-9a-fA-F]+$/.test(p)) return parseInt(p.slice(2), 16);
  if (/^0[0-7]*$/.test(p)) return p === '0' ? 0 : parseInt(p, 8);
  if (/^[1-9][0-9]*$/.test(p)) return parseInt(p, 10);
  return null;
}

/** inet_aton-style parse. Returns the 32-bit address, or null if invalid. */
export function parseNumbersAndDots(s: string): number | null {
  const parts = s.trim().split('.');
  if (parts.length < 1 || parts.length > 4) return null;
  const nums = parts.map(parsePart);
  if (nums.some((n) => n === null)) return null;
  const v = nums as number[];
  const max = [0xffffffff, 0xffffff, 0xffff, 0xff];
  for (let i = 0; i < v.length - 1; i++) if (v[i] > 255) return null;
  if (v[v.length - 1] > max[v.length - 1]) return null;
  let n: number;
  switch (v.length) {
    case 1:
      n = v[0];
      break;
    case 2:
      n = (v[0] << 24) | v[1];
      break;
    case 3:
      n = (v[0] << 24) | (v[1] << 16) | v[2];
      break;
    default:
      n = (v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3];
  }
  return n >>> 0;
}

/** Strict dotted-quad check used when grading a student's normalized answer. */
export function isDottedQuad(s: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return false;
  return m.slice(1).every((x) => Number(x) <= 255 && !(x.length > 1 && x.startsWith('0')));
}

/** A random host address from the RFC 5737 documentation ranges. */
export function docIp(rng: Rng, range?: '192.0.2' | '198.51.100' | '203.0.113'): string {
  const prefix = range ?? rng.pick(['198.51.100', '203.0.113'] as const);
  return `${prefix}.${rng.int(10, 250)}`;
}
