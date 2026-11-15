import { evidenceFor } from './evidence';
import { bytesToHex } from './lib/encode';
import { normText } from './lib/normalize';
import { authScenario } from './modules/m04';
import { dnsScenario } from './modules/m06';
import { discoveryScenario } from './modules/m09';
import { injectionScenario } from './modules/m10';
import { persistenceScenario } from './modules/m12';
import { sideloadScenario } from './modules/m13';
import { deviceCodeScenario } from './modules/m14';
import { moduleById } from './modules';
import { asText, shuffled } from './modules/helpers';
import { ISOLATION_OPTIONS, isolationAnswer } from './modules/m11';
import type { Answer, ChoiceOption } from './types';
import { ORG, type World } from './world';

// Assessment mode: the format of a real skills assessment. Fifteen short questions
// on one page, each with a small inline snippet and a "then explain out loud" part.
// Answers are mostly free text so they can't be guessed from a list.

export interface AssessItem {
  n: number;
  concept: string;
  prompt: string;
  snippet?: string;
  kind: 'text' | 'choice' | 'order';
  options?: ChoiceOption[];
  slots?: number;
  placeholder?: string;
  /** What to say out loud after answering; this is what interviewers grade. */
  sayOutLoud: string;
  expected: string;
  why: string;
  check(a: Answer): boolean;
}

function inst(id: string, w: World) {
  return moduleById(id)!.build(w);
}

export function buildAssessment(w: World): AssessItem[] {
  const ev = evidenceFor(w);
  const m01 = inst('m01', w);
  const m02 = inst('m02', w);
  const m03 = inst('m03', w);
  const m05 = inst('m05', w);
  const m15 = inst('m15', w);
  const auth = authScenario(w);
  const dns = dnsScenario(w);
  const disc = discoveryScenario(w);
  const inj = injectionScenario(w);
  const pers = persistenceScenario(w);
  const side = sideloadScenario(w);
  const dc = deviceCodeScenario(w);

  // 2: the cradle as one EDR command line.
  const script = ev.artifacts.find((a) => a.path === ev.paths.script)!.content as string;
  const cmdline = `"C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\PowerShell.exe" ${script.trim().split(/\r?\n/).join(';')}`;

  // 6: a few tunnel queries plus the summary an analyst would compute.
  const rows = dns.text.split('\n').filter((l) => l && !l.startsWith('#')).map((l) => l.split('\t'));
  const tunnelRows = rows.filter((r) => r[9].endsWith(dns.tunnel));
  const t0 = Number(tunnelRows[0][0]);
  const t1 = Number(tunnelRows[tunnelRows.length - 1][0]);
  const fmt = (ts: string) => new Date(Number(ts) * 1000).toISOString().slice(11, 19);
  const avgLen = Math.round(tunnelRows.reduce((s, r) => s + Number(r[21].split(' ')[1]), 0) / tunnelRows.length);
  const perMin = Math.round((tunnelRows.length / Math.max(1, t1 - t0)) * 60);
  const dnsSnippet = [
    ...tunnelRows.slice(0, 5).map((r) => `${fmt(r[0])}  qtype=TXT  ${r[9]}`),
    `(one host, ${r2(perMin)} queries/min to this domain; ${Math.round((new Set(tunnelRows.map((r) => r[9])).size / tunnelRows.length) * 100)}% unique names; TXT answers averaging ${avgLen} bytes)`,
  ].join('\n');

  // 7: the header block.
  const eml = ev.artifacts.find((a) => a.path === ev.paths.eml)!.content as string;
  const headers = eml.split('\r\n\r\n')[0].split('\r\n').filter((l) => !/^(MIME-Version|Content-Type|Message-ID|To|Date):/.test(l) && !/mbx02/.test(l));
  const headerSnippet = headers.filter((l, i, arr) => !(l.startsWith('Received: from ' + ORG.mx) || (arr[i - 1]?.startsWith('Received: from ' + ORG.mx) && l.startsWith('\t')))).join('\n').replace(/\t/g, '  ');

  // 12: autoruns-style listing.
  const nameW = Math.max(...pers.items.map((i) => i.name.length)) + 2;
  const persSnippet = pers.items.map((i) => `${i.type.padEnd(15)} ${i.name.padEnd(nameW)} ${i.command}`).join('\n');

  // 13: stack count of image loads.
  const combos = new Map<string, Set<string>>();
  for (const line of side.text.split('\n').filter(Boolean)) {
    const o = JSON.parse(line);
    const d = o.winlog.event_data;
    const key = `${d.ImageLoaded}  signed=${d.Signed}`;
    if (!combos.has(key)) combos.set(key, new Set());
    combos.get(key)!.add(o.host.name);
  }
  const sideSnippet = ['hosts  ImageLoaded (Image = QuorvaneSync.exe)', ...[...combos.entries()].sort((a, b) => b[1].size - a[1].size).map(([k, hs]) => `${String(hs.size).padStart(5)}  ${k}`)].join('\n');

  // 14: condensed sign-ins.
  const signins = JSON.parse(dc.text).value as Record<string, any>[];
  const dcSnippet = [
    'time (UTC)            user                         protocol    interactive  ip               country',
    ...signins.map((s) => `${s.createdDateTime.slice(0, 19).replace('T', ' ')}   ${String(s.userPrincipalName).padEnd(28)} ${String(s.authenticationProtocol).padEnd(11)} ${String(s.isInteractive).padEnd(12)} ${String(s.ipAddress).padEnd(16)} ${s.location.countryOrRegion}`),
  ].join('\n');

  const containment = ev.artifacts.find((a) => a.path === ev.paths.containmentBrief)!.content as string;

  const items: Omit<AssessItem, 'n'>[] = [
    {
      concept: 'm01', kind: 'text', prompt: 'Decode this PowerShell -EncodedCommand and paste the URL it reaches out to.', snippet: ev.derived.encodedB64, placeholder: 'https://…',
      sayOutLoud: 'Why the decoded bytes have a null between every character, and what the command does with the URL.',
      expected: String(m01.expected.url), why: 'Base64-decode, then read it as UTF-16LE: PowerShell requires UTF-16LE for -EncodedCommand.', check: (a) => m01.check('url', a),
    },
    {
      concept: 'm02', kind: 'text', prompt: 'An EDR flagged this PowerShell execution. The download host is obfuscated: paste the real IPv4 the payload is pulled from.', snippet: cmdline, placeholder: 'a.b.c.d',
      sayOutLoud: 'What irm | iex does, and how you converted the host.',
      expected: String(m02.expected.ip), why: '0x means hex, a leading 0 means octal, and with fewer than four parts the last part fills the remaining bytes.', check: (a) => m02.check('ip', a),
    },
    {
      concept: 'm03', kind: 'text', prompt: 'This hex blob came out of a malware config. It is single-byte-XOR encoded: recover the plaintext and paste the URL.', snippet: bytesToHex(ev.artifacts.find((a) => a.path === ev.paths.config)!.content as Uint8Array), placeholder: 'https://…',
      sayOutLoud: 'How you found the key (a known-plaintext crib such as "http").',
      expected: String(m03.expected.c2), why: `The key is ${m03.expected.key}: XOR the bytes that decrypt to "http" against those letters and every position gives the same value.`, check: (a) => m03.check('c2', a),
    },
    {
      concept: 'm04', kind: 'text', prompt: 'Below are authentication events. Which line number is the compromise?', snippet: auth.text.trimEnd(), placeholder: 'line number',
      sayOutLoud: 'Every tell you stacked, and why each decoy is not it.',
      expected: String(auth.line), why: `Service account, external IP, no MFA, unusual country, right after failures from the same IP.`, check: (a) => normText(asText(a)).replace(/^line\s*/, '') === String(auth.line),
    },
    {
      concept: 'm05', kind: 'text', prompt: 'A flagged file\'s Zone.Identifier stream (Mark-of-the-Web) is shown. Where was the file actually downloaded from? Paste the host.', snippet: `PS> Get-Content .\\invoice.pdf.exe -Stream Zone.Identifier\n${(ev.artifacts.find((a) => a.path === ev.paths.zone)!.content as string).trimEnd().replace(/\r\n/g, '\n')}`, placeholder: 'host',
      sayOutLoud: 'HostUrl vs ReferrerUrl, what ZoneId=3 means, and the double extension.',
      expected: String(m05.expected.host), why: 'HostUrl is where the bytes came from; ReferrerUrl is only the page that linked to it.', check: (a) => m05.check('host', a),
    },
    {
      concept: 'm06', kind: 'text', prompt: 'In a few words: what technique is this DNS activity?', snippet: dnsSnippet, placeholder: 'technique',
      sayOutLoud: 'Two signals that confirm it, and how you would rule out a busy CDN.',
      expected: 'DNS tunneling', why: 'One host, near-100% unique random labels, TXT answers near maximum size: data is moving through DNS.', check: (a) => /tunnel/i.test(asText(a)) || (/exfil|c2|command/i.test(asText(a)) && /dns/i.test(asText(a))),
    },
    {
      concept: 'm07', kind: 'text', prompt: 'This email was reported as phishing. From the headers, name the single strongest technical indicator that it is spoofed.', snippet: headerSnippet, placeholder: 'indicator',
      sayOutLoud: 'Why that indicator outranks the others, and why the message was delivered anyway.',
      expected: `dmarc=fail for header.from=${ORG.domain}`, why: 'DMARC is the only check tied to the visible From. SPF passed for the attacker\'s own domain, which proves nothing.', check: (a) => /dmarc/i.test(asText(a)),
    },
    {
      concept: 'm08', kind: 'text', prompt: 'In a host investigation, which Sysmon Event ID gives you a process execution with its full command line AND its parent?', placeholder: 'event ID',
      sayOutLoud: 'The fields you key on, and how Security 4688 differs.',
      expected: '1', why: 'Sysmon Event ID 1: CommandLine, ParentImage, ParentCommandLine, ProcessGuid. Security 4688 needs command-line auditing and has no parent command line.', check: (a) => normText(asText(a)).replace(/^(sysmon\s*)?(event\s*id|eid|id)?\s*/, '') === '1',
    },
    {
      concept: 'm09', kind: 'text', prompt: 'An EDR captured this command sequence from a single host in under a minute. Which MITRE ATT&CK tactic is it? Give the tactic ID.', snippet: disc.text.split('\n').slice(2).join('\n').trimEnd(), placeholder: 'TA00xx',
      sayOutLoud: 'What the attacker is doing, and two technique mappings.',
      expected: 'TA0007 (Discovery)', why: 'A burst of built-in enumeration tools from one interactive session is Discovery, TA0007.', check: (a) => /TA0007|discovery/i.test(asText(a)),
    },
    {
      concept: 'm10', kind: 'text', prompt: 'An EDR captured this API sequence. Which technique is it? Give the ATT&CK ID.', snippet: inj.trace.trimEnd(), placeholder: 'T1xxx',
      sayOutLoud: 'What in the sequence gives it away, and which Sysmon events would show it.',
      expected: 'T1055 (Process Injection)', why: 'RWX memory allocated in another process, written to, then a remote thread started at that address.', check: (a) => /T1055/i.test(asText(a)) || /injection/i.test(asText(a)),
    },
    {
      concept: 'm11', kind: 'choice', prompt: 'You need to isolate the compromised host but keep it live for forensics. How do you isolate it?', snippet: containment.replace(/^# .*\n\n/, '').replace(/\*\*/g, '').trimEnd(), options: shuffled(w.seed, 'as.contain', ISOLATION_OPTIONS),
      sayOutLoud: 'What you preserve first, and why (order of volatility).',
      expected: ISOLATION_OPTIONS.find((o) => o.id === isolationAnswer(w))!.label, why: 'Cut the attacker off without powering down, so memory survives; use EDR containment only if EDR works on that host.', check: (a) => asText(a) === isolationAnswer(w),
    },
    {
      concept: 'm12', kind: 'text', prompt: 'One of these startup items is the attacker\'s persistence. Name it.', snippet: persSnippet, placeholder: 'name',
      sayOutLoud: 'Why it is malicious, and where that artifact lives on disk or in the registry.',
      expected: pers.name, why: 'It runs hidden PowerShell with execution policy bypassed from a ProgramData folder; the others are vendor or IT tooling.', check: (a) => normText(asText(a)).replace(/^\\+/, '') === pers.name.toLowerCase(),
    },
    {
      concept: 'm13', kind: 'text', prompt: `Hunting for DLL side-loading across ${side.hostCount} hosts, you stack-count what a vendor's signed sync client loads. Which DLL is being side-loaded?`, snippet: sideSnippet, placeholder: 'name.dll',
      sayOutLoud: 'How you would run this hunt at fleet scale, and what makes the outlier suspicious.',
      expected: side.dll, why: 'It loads from a user Temp folder, unsigned, on one host: a DLL that normally comes from System32.', check: (a) => normText(asText(a)).replace(/^.*\\/, '') === side.dll,
    },
    {
      concept: 'm14', kind: 'text', prompt: 'These are Entra ID sign-ins. One user fell for a device-code phish. From which IP did the attacker use the stolen tokens?', snippet: dcSnippet, placeholder: 'a.b.c.d',
      sayOutLoud: 'How device-code phishing works end to end, and why the deviceCode sign-in itself shows the victim\'s IP.',
      expected: dc.attackerIp, why: 'Non-interactive sign-ins seconds after the deviceCode sign-in, same user, from a new country.', check: (a) => asText(a).replace(/\[\.\]/g, '.').trim() === dc.attackerIp,
    },
    {
      concept: 'm15', kind: 'order', prompt: 'A host is suspected of hands-on-keyboard intrusion. Pick the first three artifacts to collect, in order.', options: m15.questions[0].options, slots: 3,
      sayOutLoud: 'Why that order: order of volatility, and what each item gives you.',
      expected: 'Memory image → Live-response snapshot → Targeted triage (the first two may swap)', why: 'Most volatile first: memory and live state, then a targeted triage collection; disk images and off-host logs later.', check: (a) => m15.check('order', a),
    },
  ];
  return items.map((it, i) => ({ ...it, n: i + 1 }));
}

function r2(n: number): number {
  return Math.round(n / 10) * 10 || n;
}
