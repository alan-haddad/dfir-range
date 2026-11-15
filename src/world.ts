import { Rng } from './lib/prng';
import { docIp, IP_FORMS, type IpForm } from './lib/ip';

// One scenario model per seed. Every artifact renderer reads from this, so
// hostnames, accounts, timestamps, domains and IDs agree across all evidence.
// Everything here is fictional: .example/.test domains and RFC 5737 / private IPs.

export const ORG = {
  name: 'Velmora Logistics',
  domain: 'velmora.example',
  netbios: 'VELMORA',
  hostPrefix: 'VEL-WS',
  adDomain: 'corp.velmora.example',
  mx: 'mx1.velmora.example',
} as const;

const FIRST = ['Dana', 'Marcus', 'Priya', 'Owen', 'Lena', 'Tomas', 'Imani', 'Caleb', 'Rosa', 'Felix', 'Nadia', 'Grant', 'Elise', 'Joaquin', 'Mira', 'Desmond'];
const LAST = ['Whitfield', 'Okafor', 'Brandt', 'Castillo', 'Lindqvist', 'Mercer', 'Halloran', 'Ibarra', 'Sato', 'Pruitt', 'Vance', 'Delacroix', 'Ashby', 'Kowalczyk', 'Renner', 'Thorne'];
const ROLES = [
  { dept: 'Finance', title: 'Accounts Payable Specialist' },
  { dept: 'Procurement', title: 'Procurement Coordinator' },
  { dept: 'Operations', title: 'Freight Operations Analyst' },
  { dept: 'Finance', title: 'Billing Analyst' },
];

const W1 = ['invoice', 'billing', 'remit', 'statement', 'payables', 'docs', 'secure', 'files', 'portal', 'vendor', 'ledger', 'notice'];
const W2 = ['share', 'cloud', 'sync', 'drive', 'vault', 'hub', 'view', 'center', 'desk', 'box', 'link', 'online'];
const C2W1 = ['telemetry', 'update', 'metrics', 'status', 'health', 'edge', 'cache', 'config'];
const C2W2 = ['sync', 'svc', 'relay', 'gateway', 'node', 'check', 'beacon', 'feed'];

export type HomoglyphKind = 'l-to-1' | 'm-to-rn' | 'o-to-0' | 'doubled-letter';
const HOMOGLYPHS: Record<HomoglyphKind, { label: string; domain: string }> = {
  'l-to-1': { label: 'the letter l replaced with the digit 1', domain: 've1mora.example' },
  'm-to-rn': { label: 'the letter m replaced with the pair rn', domain: 'velrnora.example' },
  'o-to-0': { label: 'the letter o replaced with the digit 0', domain: 'velm0ra.example' },
  'doubled-letter': { label: 'a doubled letter (r becomes rr)', domain: 'velmorra.example' },
};

export type ContainmentVariant = 'edr-laptop' | 'no-edr-desktop' | 'server-no-edr';

export interface Person {
  first: string;
  last: string;
  display: string;
  username: string;
  email: string;
  dept: string;
  title: string;
  sid: string;
}

export interface World {
  seed: string;
  victim: Person;
  host: { name: string; fqdn: string; ip: string; os: string };
  attacker: {
    mailDomain: string;
    sendIp: string;
    sendHost: string;
    homoglyph: HomoglyphKind;
    homoglyphLabel: string;
    replyToDomain: string;
    landingDomain: string;
    landingUrl: string;
    fileHostDomain: string;
    fileUrl: string;
    stage1Domain: string;
    stage1Url: string;
    stage2Ip: string;
    stage2Path: string;
    ipForm: IpForm;
    c2Domain: string;
    c2Url: string;
  };
  ids: {
    invoiceNo: string;
    messageId: string;
    stage1Name: string;
    stage2Name: string;
    configDir: string;
    xorKey: number;
    botId: string;
  };
  t: {
    emailReceived: Date;
    clicked: Date;
    downloaded: Date;
    executed: Date;
    stage1: Date;
    stage2: Date;
    configWritten: Date;
    detected: Date;
  };
  containment: ContainmentVariant;
}

function word(rng: Rng, a: readonly string[], b: readonly string[]): string {
  return `${rng.pick(a)}-${rng.pick(b)}`;
}

function addSeconds(d: Date, s: number): Date {
  return new Date(d.getTime() + s * 1000);
}

function uniqueDomains(rng: Rng, n: number): string[] {
  const out = new Set<string>();
  while (out.size < n) {
    const tld = rng.pick(['test', 'test', 'example']);
    const name = rng.bool(0.4) ? `${word(rng, W1, W2)}${rng.int(2, 99)}` : word(rng, W1, W2);
    out.add(`${name}.${tld}`);
  }
  return [...out];
}

export function buildWorld(seed: string): World {
  const rng = new Rng(`world:${seed}`);

  const first = rng.pick(FIRST);
  const last = rng.pick(LAST);
  const role = rng.pick(ROLES);
  const username = `${first[0].toLowerCase()}.${last.toLowerCase()}`;
  const victim: Person = {
    first,
    last,
    display: `${first} ${last}`,
    username,
    email: `${username}@${ORG.domain}`,
    dept: role.dept,
    title: role.title,
    sid: `S-1-5-21-${rng.int(1000000000, 3999999999)}-${rng.int(1000000000, 3999999999)}-${rng.int(1000000000, 3999999999)}-${rng.int(1100, 4999)}`,
  };

  const hostNum = rng.int(1000, 9999);
  const hostName = `${ORG.hostPrefix}-${hostNum}`;
  const host = {
    name: hostName,
    fqdn: `${hostName.toLowerCase()}.${ORG.adDomain}`,
    ip: `10.20.${rng.int(10, 90)}.${rng.int(10, 240)}`,
    os: 'Windows 11 Enterprise',
  };

  const [mailDomain, landingDomain, fileHostDomain, stage1Domain] = uniqueDomains(rng, 4);
  const homoglyph = rng.pick(Object.keys(HOMOGLYPHS) as HomoglyphKind[]);
  const c2Domain = `${word(rng, C2W1, C2W2)}.${rng.pick(['test', 'invalid', 'test'])}`;

  // Separate the two documentation ranges so the stage-2 IP never collides with the mail sender.
  const sendIp = docIp(rng, '203.0.113');
  const stage2Ip = docIp(rng, '198.51.100');

  const invoiceNo = `INV-${rng.int(240000, 289999)}`;
  const stage1Name = rng.pick(['upd', 'svc', 'cfg', 'tmp', 'run']) + rng.alnum(5);
  const stage2Name = rng.pick(['WinCache', 'SysPrep', 'NetCfg', 'PrintSvc', 'UpdTask']) + rng.int(10, 99);
  const configDir = rng.pick(['CacheData', 'SyncState', 'AppSvc', 'NetHelper']) + rng.int(100, 999);

  // Base time: a weekday business afternoon (UTC) sometime in 2026.
  const month = rng.int(0, 9);
  const day = rng.int(3, 26);
  const base = new Date(Date.UTC(2026, month, day, rng.int(13, 20), rng.int(0, 59), rng.int(0, 59)));
  const emailReceived = base;
  const clicked = addSeconds(emailReceived, rng.int(180, 2400));
  const downloaded = addSeconds(clicked, rng.int(8, 40));
  const executed = addSeconds(downloaded, rng.int(20, 140));
  const stage1 = addSeconds(executed, rng.int(2, 6));
  const stage2 = addSeconds(stage1, rng.int(4, 15));
  const configWritten = addSeconds(stage2, rng.int(6, 30));
  const detected = addSeconds(configWritten, rng.int(600, 3600));

  const fileToken = rng.alnum(10);
  const ref = rng.alnum(8);

  return {
    seed,
    victim,
    host,
    attacker: {
      mailDomain,
      sendIp,
      sendHost: `mail.${mailDomain}`,
      homoglyph,
      homoglyphLabel: HOMOGLYPHS[homoglyph].label,
      replyToDomain: HOMOGLYPHS[homoglyph].domain,
      landingDomain,
      landingUrl: `https://${landingDomain}/inv/view?ref=${ref}`,
      fileHostDomain,
      fileUrl: `https://${fileHostDomain}/d/${fileToken}/invoice.pdf.exe`,
      stage1Domain,
      stage1Url: `https://${stage1Domain}/s/${stage1Name}.ps1`,
      stage2Ip,
      stage2Path: `${rng.pick(['b', 'p', 'k', 'm'])}${rng.alnum(4)}.txt`,
      ipForm: rng.pick(IP_FORMS),
      c2Domain,
      c2Url: `https://${c2Domain}/${rng.pick(['api', 'v2', 'gw', 'cdn'])}/${rng.pick(['beat', 'poll', 'checkin', 'sync'])}`,
    },
    ids: {
      invoiceNo,
      messageId: `<${rng.hex(8)}.${rng.hex(4)}@${mailDomain}>`,
      stage1Name,
      stage2Name,
      configDir,
      xorKey: rng.int(1, 255),
      botId: rng.hex(4),
    },
    t: { emailReceived, clicked, downloaded, executed, stage1, stage2, configWritten, detected },
    containment: rng.pick(['edr-laptop', 'no-edr-desktop', 'server-no-edr'] as ContainmentVariant[]),
  };
}

/** Windows event SystemTime: 7 fractional digits, Z suffix. */
export function sysTime(d: Date, rng: Rng): string {
  return d.toISOString().replace(/Z$/, `${String(rng.int(0, 9999)).padStart(4, '0')}Z`);
}

/** Sysmon UtcTime: "YYYY-MM-DD HH:MM:SS.mmm". */
export function sysmonUtc(d: Date): string {
  return d.toISOString().replace('T', ' ').replace('Z', '');
}

/** RFC 5322 date, e.g. "Tue, 14 Apr 2026 15:02:11 +0000". */
export function rfc5322(d: Date): string {
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const p = (n: number) => String(n).padStart(2, '0');
  return `${days[d.getUTCDay()]}, ${p(d.getUTCDate())} ${months[d.getUTCMonth()]} ${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`;
}

export function guid(rng: Rng): string {
  const h = rng.hex(16);
  return `{${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}}`;
}

export const ADDR = { addSeconds };
