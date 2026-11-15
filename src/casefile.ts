import { evidenceFor } from './evidence';
import { normDomain, normIp, normText, normUrl, normUser } from './lib/normalize';
import { authScenario } from './modules/m04';
import { dnsScenario } from './modules/m06';
import { discoveryScenario } from './modules/m09';
import { persistenceScenario } from './modules/m12';
import { deviceCodeScenario } from './modules/m14';
import { asText, shuffled } from './modules/helpers';
import { ISOLATION_OPTIONS, isolationAnswer } from './modules/m11';
import type { ModuleInstance } from './types';
import type { World } from './world';

// Interview mode: one case file that stitches the v1 modules into a single incident.

/** Which concept (module) each case-file question exercises, for the weak-spots report. */
export const CASE_CONCEPT: Record<string, string> = {
  user: 'm08',
  time: 'm08',
  vector: 'm05',
  filehost: 'm05',
  ip: 'm02',
  c2: 'm03',
  persist: 'm12',
  exfil: 'm06',
  svc: 'm04',
  cloudip: 'm14',
  contain: 'm11',
};

export const CASE_PROMPT = 'Go through this and walk me through your thought process.';

export const CASE_RUBRIC: string[] = [
  'Started from the alert and said what you thought was going on before diving into artifacts.',
  'Built a timeline in order: email → click → download → execution → PowerShell stages → config written.',
  'Read the email headers bottom-up and named DMARC failure on the company\'s own domain as the key indicator.',
  'Separated HostUrl (the download source) from ReferrerUrl (the landing page).',
  'Decoded the encoded command as UTF-16LE and explained the null bytes.',
  'Normalized the obfuscated IP and explained the notation.',
  'Recovered the XOR key with a known-plaintext crib and read the whole config.',
  'Listed indicators to hunt fleet-wide: domains, IP, file names, paths, the sender.',
  'Followed the intruder after the payload: discovery commands, the planted persistence, and DNS tunneling out.',
  'Connected the parallel identity activity: the service-account login and the device-code phish against the same user.',
  'Proposed containment that preserves evidence: keep it on, memory first, and revoke the user\'s cloud tokens.',
  'Said what you would do next and what you were still unsure about.',
];

export const CASE_FOLLOWUPS: string[] = [
  'Who else received this email, and how would you find out quickly?',
  'What would you put in a detection so this chain is caught earlier next time?',
  'Which of your conclusions are confirmed by evidence, and which are assumptions?',
  'How would you explain this incident to a non-technical manager in two sentences?',
  'If the attacker deleted settings.dat before you collected, where else could you recover the C2?',
];

function parseUtc(s: string): Date | null {
  const t = s.trim().replace(/\s*(utc|z)$/i, '').replace(' ', 'T');
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?$/.exec(t);
  if (!m) return null;
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], m[6] ? +m[6] : 0));
}

export function buildCaseFile(w: World): ModuleInstance {
  const ev = evidenceFor(w);
  const vectorOpts = [
    { id: 'link-download', label: 'A phishing link led to a browser download of a double-extension executable that the user ran' },
    { id: 'macro', label: 'A malicious macro in an Office attachment' },
    { id: 'driveby', label: 'A drive-by browser exploit with no user action' },
    { id: 'usb', label: 'A USB drive' },
    { id: 'rdp', label: 'An exposed remote desktop service' },
  ];
  const execTime = w.t.executed;
  const p = ev.paths;
  const disc = discoveryScenario(w);
  const pers = persistenceScenario(w);
  const dns = dnsScenario(w);
  const auth = authScenario(w);
  const dc = deviceCodeScenario(w);
  return {
    artifacts: [
      ...[p.caseBrief, p.eml, p.zone, p.sysmonXml, p.sysmonJsonl, p.script, p.config].map((path) => ev.artifacts.find((a) => a.path === path)!),
      { path: `${w.host.name}/live-response/edr-process-events.txt`, content: disc.text, title: 'EDR process events (one minute, one host)' },
      ...pers.artifacts,
      { path: 'sensors/zeek/dns.log', content: dns.text, title: 'Zeek dns.log excerpt' },
      { path: 'tenant/sso-gateway.log', content: auth.text, title: 'SSO / VPN gateway authentication log' },
      { path: 'tenant/entra-signins.json', content: dc.text, title: 'Entra ID sign-in logs (interactive and non-interactive)' },
      ev.artifacts.find((a) => a.path === p.containmentBrief)!,
    ],
    questions: [
      { id: 'user', prompt: 'Which user account ran the payload?', kind: 'text', placeholder: 'username', why: 'The User field on the Event ID 1 for invoice.pdf.exe.' },
      {
        id: 'time',
        prompt: 'When (UTC) did the payload first run? Give the time to the second, e.g. 2026-04-14 15:02:11.',
        kind: 'text',
        placeholder: 'YYYY-MM-DD HH:MM:SS',
        why: 'UtcTime on the Event ID 1 whose Image is invoice.pdf.exe. Answers within 60 seconds are accepted.',
      },
      {
        id: 'vector',
        prompt: 'What was the initial access vector?',
        kind: 'choice',
        options: shuffled(w.seed, 'cf.vector', vectorOpts),
        why: 'The email links to the landing page (ReferrerUrl); the file came from HostUrl and carries MOTW; explorer.exe launched it from Downloads.',
      },
      { id: 'filehost', prompt: 'Which domain served the payload?', kind: 'text', placeholder: 'domain', why: 'HostUrl in the Zone.Identifier stream.' },
      { id: 'ip', prompt: 'What is the stage-2 host as a dotted-quad IPv4 address?', kind: 'text', placeholder: 'a.b.c.d', why: 'The obfuscated host in the downloaded script, normalized.' },
      { id: 'c2', prompt: 'What is the C2 URL?', kind: 'text', placeholder: 'https://…', why: 'The c2 field in settings.dat once the XOR key is removed.' },
      { id: 'persist', prompt: 'What is the name of the persistence the intruder planted (task, service or WMI consumer)?', kind: 'text', placeholder: 'name', why: 'The only task, service or WMI consumer running a hidden PowerShell script from ProgramData, created minutes after the compromise.' },
      { id: 'exfil', prompt: 'Which domain is the host tunneling data to over DNS?', kind: 'text', placeholder: 'domain', why: 'TXT queries with unique random labels under one parent domain, all from the patient-zero host.' },
      { id: 'svc', prompt: 'Which service account was compromised the same day?', kind: 'text', placeholder: 'account', why: 'The service account that succeeds from an external IP without MFA right after failures.' },
      { id: 'cloudip', prompt: 'From which IP did the attacker use the user\'s stolen cloud tokens?', kind: 'text', placeholder: 'a.b.c.d', why: 'Non-interactive sign-ins right after the device-code sign-in, same session, new IP and country.' },
      {
        id: 'contain',
        prompt: 'Using the containment scenario, how do you isolate the affected host?',
        kind: 'choice',
        options: shuffled(w.seed, 'cf.contain', ISOLATION_OPTIONS),
        why: 'Pick the method that cuts off the attacker and keeps memory intact, given which tools work on that host.',
      },
    ],
    expected: {
      user: w.victim.username,
      time: execTime.toISOString().replace('T', ' ').slice(0, 19),
      vector: 'link-download',
      filehost: w.attacker.fileHostDomain,
      ip: w.attacker.stage2Ip,
      c2: w.attacker.c2Url,
      persist: pers.name,
      exfil: dns.tunnel,
      svc: auth.svcBad,
      cloudip: dc.attackerIp,
      contain: isolationAnswer(w),
    },
    check(qid, a) {
      const t = asText(a);
      switch (qid) {
        case 'user':
          return normUser(t) === w.victim.username;
        case 'time': {
          const d = parseUtc(t);
          return !!d && Math.abs(d.getTime() - execTime.getTime()) <= 60_000;
        }
        case 'vector':
          return t === 'link-download';
        case 'filehost':
          return normDomain(t) === w.attacker.fileHostDomain;
        case 'ip':
          return normIp(t) === w.attacker.stage2Ip;
        case 'c2':
          return normUrl(t) === normUrl(w.attacker.c2Url);
        case 'persist':
          return normText(t).replace(/^\\+/, '') === pers.name.toLowerCase();
        case 'exfil':
          return normDomain(t) === dns.tunnel;
        case 'svc':
          return normUser(t) === auth.svcBad;
        case 'cloudip':
          return normIp(t) === dc.attackerIp;
        case 'contain':
          return t === isolationAnswer(w);
      }
      return false;
    },
  };
}

export function aiGradingPrompt(w: World, notes: string, answers: Record<string, string>): string {
  return [
    'You are a senior SOC / incident response interviewer. Grade my walkthrough of a practice case honestly. Be specific and do not flatter me.',
    '',
    'The case: a user received a phishing email spoofing their own company\'s Accounts Payable address (DMARC fail, p=none, look-alike Reply-To). The link led to a download of invoice.pdf.exe (Mark-of-the-Web ZoneId=3; HostUrl differs from ReferrerUrl). Running it launched PowerShell with a UTF-16LE Base64 -EncodedCommand that downloaded a script to TEMP. That script used an irm | iex cradle to a host written in obfuscated IPv4 notation. A single-byte XOR-encoded config with a C2 URL was then written to ProgramData. The intruder then ran discovery commands, planted persistence (a scheduled task, service or WMI subscription) and tunneled data out over DNS. The same day, a service account was compromised from an external IP without MFA, and the user fell for a device-code phish that gave the attacker cloud tokens. The final question was how to contain the host while preserving evidence.',
    '',
    'What a strong answer covers:',
    ...CASE_RUBRIC.map((r) => `- ${r}`),
    '',
    'My answers to the structured questions:',
    ...Object.entries(answers).map(([k, v]) => `- ${k}: ${v || '(blank)'}`),
    '',
    'My walkthrough notes (what I said, or would say, out loud):',
    notes.trim() || '(no notes)',
    '',
    'Please give me: (1) a score out of 10 for an entry-level SOC/IR interview, (2) the three most important things I missed or got wrong, (3) one follow-up question an interviewer would ask me next, and (4) a model two-minute answer.',
    '',
    `(Practice case seed: ${w.seed}. All data is synthetic.)`,
  ].join('\n');
}
