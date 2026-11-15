import { bytesToBase64, utf16leBytes, utf8Bytes } from './lib/encode';
import { docIp, IP_FORMS, obfuscateIp } from './lib/ip';
import { normExt, normHexByte, normIp } from './lib/normalize';
import { Rng } from './lib/prng';
import type { ChoiceOption } from './types';

// Fast recognition reps. Each drill generates a fresh item from an Rng.

export interface DrillItem {
  prompt: string;
  display?: string;
  kind: 'text' | 'choice';
  options?: ChoiceOption[];
  placeholder?: string;
  check(answer: string): boolean;
  answer: string;
  explain: string;
}

export interface Drill {
  id: string;
  title: string;
  make(rng: Rng): DrillItem;
}

const PS_SNIPPETS = [
  "Get-Process | Where-Object { $_.CPU -gt 100 }",
  "$s = Get-Service -Name Spooler; $s.Status",
  "Get-ChildItem C:\\Users -Recurse -Filter *.lnk",
  "$env:COMPUTERNAME; whoami /groups",
  "Test-NetConnection -ComputerName 10.20.1.5 -Port 445",
  "$f = Get-Item .\\report.csv; $f.Length",
];

const yesNo: ChoiceOption[] = [
  { id: 'yes', label: 'Yes' },
  { id: 'no', label: 'No' },
];

const ZONES = ['Local machine', 'Local intranet', 'Trusted sites', 'Internet', 'Restricted sites'];

const EVENT_FACTS: { q: string; a: string; distractors: string[] }[] = [
  { q: 'Sysmon Event ID 1', a: 'Process creation', distractors: ['Network connection', 'File created', 'Image loaded'] },
  { q: 'Sysmon Event ID 3', a: 'Network connection', distractors: ['Process creation', 'DNS query', 'Process access'] },
  { q: 'Sysmon Event ID 7', a: 'Image (DLL) loaded', distractors: ['File created', 'Process creation', 'Registry value set'] },
  { q: 'Sysmon Event ID 8', a: 'CreateRemoteThread', distractors: ['Process access', 'Image loaded', 'Network connection'] },
  { q: 'Sysmon Event ID 10', a: 'Process access (one process opening another)', distractors: ['CreateRemoteThread', 'Process creation', 'File created'] },
  { q: 'Sysmon Event ID 11', a: 'File created', distractors: ['File deleted', 'Image loaded', 'Registry value set'] },
  { q: 'Sysmon Event ID 13', a: 'Registry value set', distractors: ['Registry key created', 'File created', 'Process access'] },
  { q: 'Sysmon Event ID 22', a: 'DNS query', distractors: ['Network connection', 'Process creation', 'File created'] },
  { q: 'Security Event 4624', a: 'Successful logon', distractors: ['Failed logon', 'Process creation', 'Scheduled task created'] },
  { q: 'Security Event 4625', a: 'Failed logon', distractors: ['Successful logon', 'Account locked out', 'Logoff'] },
  { q: 'Security Event 4688', a: 'New process created', distractors: ['Successful logon', 'Service installed', 'Scheduled task created'] },
  { q: 'Security Event 4698', a: 'Scheduled task created', distractors: ['Service installed', 'New process created', 'Successful logon'] },
  { q: 'System Event 7045', a: 'A service was installed', distractors: ['Scheduled task created', 'New process created', 'Successful logon'] },
];

const VOLATILITY = ['CPU registers and cache', 'Memory, running processes and network state', 'Temporary file systems', 'Disk', 'Remote logs and monitoring data', 'Physical configuration and network topology', 'Archival media (backups)'];

const DOUBLE_EXT = [
  { name: 'invoice.pdf.exe', ext: 'exe' },
  { name: 'Q3-report.docx.lnk', ext: 'lnk' },
  { name: 'photo_0417.jpg.scr', ext: 'scr' },
  { name: 'shipping-label.pdf.js', ext: 'js' },
  { name: 'payroll.xlsx.hta', ext: 'hta' },
  { name: 'notes.txt.vbs', ext: 'vbs' },
  { name: 'contract.pdf.iso', ext: 'iso' },
];

function choiceOpts(rng: Rng, correct: string, wrong: string[]): ChoiceOption[] {
  return rng.shuffle([correct, ...wrong]).map((label, i) => ({ id: `o${i}`, label }));
}

export const DRILLS: Drill[] = [
  {
    id: 'b64-utf16',
    title: 'Spot UTF-16LE Base64',
    make(rng) {
      const text = rng.pick(PS_SNIPPETS);
      const isUtf16 = rng.bool();
      const b64 = bytesToBase64(isUtf16 ? utf16leBytes(text) : utf8Bytes(text));
      return {
        prompt: 'Is this Base64 string UTF-16LE text (as -EncodedCommand expects)?',
        display: b64,
        kind: 'choice',
        options: yesNo,
        check: (a) => a === (isUtf16 ? 'yes' : 'no'),
        answer: isUtf16 ? 'Yes' : 'No',
        explain: isUtf16
          ? 'The repeating A characters come from the 0x00 high byte after every ASCII character. Decoded, it is: ' + text
          : 'No regular A pattern: this is UTF-8, one byte per character. Decoded, it is: ' + text,
      };
    },
  },
  {
    id: 'ip-normalize',
    title: 'Normalize an obfuscated IP',
    make(rng) {
      const ip = docIp(rng);
      const form = rng.pick(IP_FORMS);
      const shown = obfuscateIp(ip, form, rng);
      return {
        prompt: 'Normalize this host to dotted-quad.',
        display: shown,
        kind: 'text',
        placeholder: 'a.b.c.d',
        check: (a) => normIp(a) === ip,
        answer: ip,
        explain: 'Each part: 0x means hex, a leading 0 means octal. With fewer than four parts, the last part fills the remaining bytes.',
      };
    },
  },
  {
    id: 'xor-crib',
    title: 'XOR key from a crib',
    make(rng) {
      const key = rng.int(1, 255);
      const bytes = Array.from(utf8Bytes('http'), (b) => (b ^ key).toString(16).padStart(2, '0')).join(' ');
      return {
        prompt: 'These four bytes decrypt to "http" under a single-byte XOR key. What is the key, in hex?',
        display: bytes,
        kind: 'text',
        placeholder: '0x..',
        check: (a) => normHexByte(a) === key,
        answer: `0x${key.toString(16).padStart(2, '0')}`,
        explain: `key = cipher XOR plain. 0x${bytes.slice(0, 2)} XOR 0x68 ('h') = 0x${key.toString(16).padStart(2, '0')}. Check it against the other three bytes.`,
      };
    },
  },
  {
    id: 'zone-id',
    title: 'ZoneId meaning',
    make(rng) {
      const id = rng.int(0, 4);
      return {
        prompt: `A Zone.Identifier stream says ZoneId=${id}. Which zone is that?`,
        kind: 'choice',
        options: ZONES.map((z, i) => ({ id: String(i), label: z })),
        check: (a) => a === String(id),
        answer: ZONES[id],
        explain: 'URLZONE values: 0 Local machine, 1 Local intranet, 2 Trusted sites, 3 Internet, 4 Restricted sites.',
      };
    },
  },
  {
    id: 'event-ids',
    title: 'Event IDs',
    make(rng) {
      const f = rng.pick(EVENT_FACTS);
      const options = choiceOpts(rng, f.a, f.distractors);
      const correctId = options.find((o) => o.label === f.a)!.id;
      return {
        prompt: `What does ${f.q} record?`,
        kind: 'choice',
        options,
        check: (a) => a === correctId,
        answer: f.a,
        explain: `${f.q}: ${f.a}.`,
      };
    },
  },
  {
    id: 'spf-dmarc',
    title: 'SPF vs DMARC',
    make(rng) {
      const scenarios = [
        {
          q: 'Authentication-Results: spf=pass smtp.mailfrom=billing-hub.test; dmarc=fail header.from=velmora.example. Does the SPF pass mean the From address is authentic?',
          a: 'no',
          e: 'SPF authenticated billing-hub.test, the envelope domain, not velmora.example in the visible From. DMARC, which checks alignment with the From, failed.',
        },
        {
          q: 'Authentication-Results: spf=pass smtp.mailfrom=velmora.example; dkim=pass header.d=velmora.example; dmarc=pass header.from=velmora.example. Is the visible From domain authenticated?',
          a: 'yes',
          e: 'DMARC passed with aligned SPF and DKIM for the same domain as the visible From. That authenticates the domain, though not necessarily the intent: a compromised internal account would also pass.',
        },
        {
          q: 'dmarc=fail (p=NONE) header.from=velmora.example. Did the domain owner ask receivers to reject the message?',
          a: 'no',
          e: 'p=none means monitoring only: no action requested on failure.',
        },
      ];
      const s = rng.pick(scenarios);
      return { prompt: s.q, kind: 'choice', options: yesNo, check: (a) => a === s.a, answer: s.a === 'yes' ? 'Yes' : 'No', explain: s.e };
    },
  },
  {
    id: 'volatility',
    title: 'Order of volatility',
    make(rng) {
      const i = rng.int(0, VOLATILITY.length - 2);
      const j = rng.int(i + 1, VOLATILITY.length - 1);
      const pair = rng.shuffle([VOLATILITY[i], VOLATILITY[j]]);
      const options = pair.map((label, k) => ({ id: `o${k}`, label }));
      const correctId = options.find((o) => o.label === VOLATILITY[i])!.id;
      return {
        prompt: 'Which is more volatile, so you collect it first?',
        kind: 'choice',
        options,
        check: (a) => a === correctId,
        answer: VOLATILITY[i],
        explain: 'RFC 3227 order: registers and cache → routing table, ARP cache, process table, kernel statistics and memory → temporary file systems → disk → remote logging and monitoring data → physical configuration and network topology → archival media.',
      };
    },
  },
  {
    id: 'double-ext',
    title: 'Double extensions',
    make(rng) {
      const f = rng.pick(DOUBLE_EXT);
      return {
        prompt: 'With "hide extensions for known file types" on, the user sees a document. What is the true file type (extension)?',
        display: f.name,
        kind: 'text',
        placeholder: 'ext',
        check: (a) => normExt(a) === f.ext,
        answer: f.ext,
        explain: 'Windows acts on the last extension. Everything before it is just part of the name.',
      };
    },
  },
];
