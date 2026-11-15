import { isDottedQuad } from './ip';

// Answer normalizers. They are deliberately forgiving about format (case,
// defanging, trailing slashes, stray quotes) and strict about substance.

export function clean(s: string): string {
  return s.trim().replace(/^["'`<(\[]+|["'`>)\].,;]+$/g, '').trim();
}

/** Undo common defanging: hxxp, [.], (.), {.}, [dot], [:], [://]. */
export function refang(s: string): string {
  return s
    .replace(/h[xX]{2}p(s?)/gi, (_m, sec) => `http${sec}`)
    .replace(/\[\s*:\/\/\s*\]/g, '://')
    .replace(/\[\s*:\s*\]/g, ':')
    .replace(/[\[\(\{]\s*(\.|dot)\s*[\]\)\}]/gi, '.')
    .replace(/\s+dot\s+/gi, '.');
}

export function normText(s: string): string {
  return clean(s).toLowerCase().replace(/\s+/g, ' ');
}

export function normUrl(s: string): string {
  let u = refang(clean(s));
  u = u.replace(/\/+$/, '');
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]+)(.*)$/i.exec(u);
  if (!m) return u.toLowerCase();
  return `${m[1].toLowerCase()}://${m[2].toLowerCase()}${m[3]}`.toLowerCase();
}

/** Accepts a bare domain, a URL or an email address, and returns the host. */
export function normDomain(s: string): string {
  let d = refang(clean(s)).toLowerCase();
  d = d.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  if (d.includes('@')) d = d.slice(d.lastIndexOf('@') + 1);
  d = d.split(/[/?#:]/)[0];
  return d.replace(/\.+$/, '');
}

export function normIp(s: string): string | null {
  const ip = refang(clean(s)).replace(/\s+/g, '');
  return isDottedQuad(ip) ? ip : null;
}

/** A single byte written as hex, with or without 0x. Returns null if not one byte. */
export function normHexByte(s: string): number | null {
  const t = clean(s).toLowerCase().replace(/^0x/, '').replace(/h$/, '');
  if (!/^[0-9a-f]{1,2}$/.test(t)) return null;
  return parseInt(t, 16);
}

/** Hostnames: accept short name or FQDN, any case. */
export function normHost(s: string): string {
  return refang(clean(s)).toLowerCase().split('.')[0];
}

/** Account names: accept DOMAIN\user, user@domain or bare user. */
export function normUser(s: string): string {
  let u = clean(s).toLowerCase();
  if (u.includes('\\')) u = u.slice(u.lastIndexOf('\\') + 1);
  if (u.includes('@')) u = u.slice(0, u.indexOf('@'));
  return u;
}

export function normExt(s: string): string {
  return clean(s).toLowerCase().replace(/^\*?\./, '');
}
