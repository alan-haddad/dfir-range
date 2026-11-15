import { Rng } from '../lib/prng';
import { normText } from '../lib/normalize';
import type { ModuleDef } from '../types';
import { eventsXml, PROVIDERS, type WinEvent } from '../winevt';
import { guid, ORG, sysmonUtc, type World } from '../world';
import { asText, MITRE, shuffled } from './helpers';

// The "shellcode" is an inert placeholder: a NOP sled, a marker string and INT3 padding.
const MARKER = 'DFIR-RANGE INERT PLACEHOLDER - NOT CODE';

export function injectionScenario(w: World) {
  const rng = new Rng(`m10:${w.seed}`);
  const word = { pid: rng.int(3000, 15000), guid: guid(rng), image: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE' };
  const explorer = { pid: rng.int(900, 2900), guid: guid(rng), image: 'C:\\Windows\\explorer.exe' };
  const base = (0x1c0000 + rng.int(0x10, 0x7f0) * 0x10000) >>> 0;
  const size = rng.pick([0x1000, 0x2000, 0x3000]);
  const written = rng.int(280, 900);
  const t0 = new Date(w.t.configWritten.getTime() + rng.int(2700, 4200) * 1000 + rng.int(0, 999));
  const t1 = new Date(t0.getTime() + rng.int(40, 400));
  const user = `${ORG.netbios}\\${w.victim.username}`;
  const h = (n: number) => `0x${n.toString(16).toUpperCase()}`;

  const trace = [
    `EDR API trace  host=${w.host.name}  source=WINWORD.EXE (PID ${word.pid})  user=${user}`,
    ``,
    `  OpenProcess( dwDesiredAccess=PROCESS_ALL_ACCESS, dwProcessId=${explorer.pid} [explorer.exe] ) -> hProcess`,
    `  VirtualAllocEx( hProcess, lpAddress=NULL, dwSize=${h(size)}, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE ) -> ${h(base)}`,
    `  WriteProcessMemory( hProcess, ${h(base)}, <${written} bytes>, ${written} ) -> TRUE`,
    `  CreateRemoteThread( hProcess, NULL, 0, lpStartAddress=${h(base)}, NULL, 0 ) -> hThread`,
    ``,
  ].join('\n');

  const sys = PROVIDERS.sysmon;
  const events: WinEvent[] = [
    {
      ...sys,
      eventId: 10,
      version: 3,
      task: 10,
      computer: w.host.fqdn,
      time: t0,
      data: [
        ['RuleName', '-'],
        ['UtcTime', sysmonUtc(t0)],
        ['SourceProcessGUID', word.guid],
        ['SourceProcessId', String(word.pid)],
        ['SourceThreadId', String(rng.int(1000, 9999))],
        ['SourceImage', word.image],
        ['TargetProcessGUID', explorer.guid],
        ['TargetProcessId', String(explorer.pid)],
        ['TargetImage', explorer.image],
        ['GrantedAccess', '0x1FFFFF'],
        ['CallTrace', `C:\\Windows\\SYSTEM32\\ntdll.dll+${rng.hex(3)}|C:\\Windows\\System32\\KERNELBASE.dll+${rng.hex(3)}|UNKNOWN(${h(base + 0x10000).slice(2)})`],
        ['SourceUser', user],
        ['TargetUser', user],
      ],
    },
    {
      ...sys,
      eventId: 8,
      version: 2,
      task: 8,
      computer: w.host.fqdn,
      time: t1,
      data: [
        ['RuleName', '-'],
        ['UtcTime', sysmonUtc(t1)],
        ['SourceProcessGuid', word.guid],
        ['SourceProcessId', String(word.pid)],
        ['SourceImage', word.image],
        ['TargetProcessGuid', explorer.guid],
        ['TargetProcessId', String(explorer.pid)],
        ['TargetImage', explorer.image],
        ['NewThreadId', String(rng.int(1000, 9999))],
        ['StartAddress', h(base)],
        ['StartModule', '-'],
        ['StartFunction', '-'],
        ['SourceUser', user],
        ['TargetUser', user],
      ],
    },
  ];

  const bytes = [...Array(32).fill(0x90), ...Array.from(MARKER, (c) => c.charCodeAt(0)), ...Array(16).fill(0xcc)];
  const dump: string[] = [];
  for (let i = 0; i < 80; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    dump.push(`${h(base + i).toLowerCase().padEnd(12)} ${chunk.map((b) => b.toString(16).padStart(2, '0')).join(' ')}   ${chunk.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join('')}`);
  }
  const malfind = [
    'Memory analysis of a live capture, malfind-style output (private, executable, writable regions with no backing file)',
    '',
    'PID   Process       Start VPN     End VPN       Tag   Protection              CommitCharge  PrivateMemory',
    `${String(explorer.pid).padEnd(6)}explorer.exe  ${h(base).toLowerCase().padEnd(14)}${h(base + size - 1).toLowerCase().padEnd(14)}VadS  PAGE_EXECUTE_READWRITE  ${String(size / 0x1000).padEnd(14)}1`,
    '',
    ...dump,
    '',
  ].join('\n');

  return { trace, sysmonXml: eventsXml(events, rng, rng.int(700000, 990000)), malfind, explorerPid: explorer.pid, base };
}

export const m10: ModuleDef = {
  id: 'm10',
  number: 10,
  title: 'Process injection',
  short: 'OpenProcess, VirtualAllocEx RWX, WriteProcessMemory, CreateRemoteThread: name it and the giveaway.',
  tracks: ['t2'],
  difficulty: 2,
  objective: 'Recognize classic remote-thread process injection from an EDR API trace, corroborate it with Sysmon and a memory finding, and explain which part of the sequence gives it away.',
  background: [
    'Classic injection runs code inside another, trusted process. Four calls do it: **OpenProcess** with full access to the target, **VirtualAllocEx** to allocate memory in the target (here with `PAGE_EXECUTE_READWRITE`), **WriteProcessMemory** to copy code into it, and **CreateRemoteThread** to start a thread at that address. MITRE ATT&CK calls this Process Injection, **T1055**.',
    '**The giveaway is the combination**: one process allocating memory that is both writable and executable inside a *different* process, writing into it, and starting a thread at exactly that address. Each call alone has legitimate uses; together, with an Office application as the source and `explorer.exe` as the target, they are hard to explain.',
    '**Where the evidence comes from:** Sysmon does not log `VirtualAllocEx` or `WriteProcessMemory`. You see the open (Event ID 10, ProcessAccess, with `GrantedAccess` `0x1FFFFF`, which is PROCESS_ALL_ACCESS) and the remote thread (Event ID 8, CreateRemoteThread, with a `StartAddress`). The allocation and write are inferred, or seen by EDR API telemetry, and confirmed in memory: a private RWX region with no backing file, which is what Volatility\'s `malfind` looks for.',
    'Link the three sources: the `StartAddress` in Event ID 8 falls inside the RWX region that the memory analysis flags, in the same target PID. That correlation is the strongest argument you can make out loud.',
  ],
  evidenceNote: 'An EDR API trace, the matching Sysmon events (IDs 10 and 8) and a malfind-style memory finding from the target process. The bytes in memory are an inert placeholder.',
  hints: [
    'Read the four calls in order and say what each one does to the target process.',
    'Which memory protection is unusual for a region in another process, and why?',
    'Match Event ID 8\'s StartAddress to the start of the region in the memory finding.',
  ],
  explainPrompt: 'Name the technique, walk through the four calls, and explain how the Sysmon events and the memory finding confirm it.',
  rubric: {
    listenFor: [
      'Technique named: process injection (T1055), remote thread injection.',
      'Each call explained, in order.',
      'The giveaway: RWX memory in another process, written to, then a thread started at that address.',
      'Evidence linked: Sysmon 10 (GrantedAccess 0x1FFFFF) and 8 (StartAddress), plus the private RWX region in memory.',
      'Next steps: capture memory before containment, check what the injected code did from explorer.exe (network, child processes), and how WINWORD.EXE got there (the document).',
    ],
    weak: '"It\'s malware injecting into explorer."',
    solid: 'Names T1055 and explains the four-call sequence with the RWX allocation as the tell.',
    strong: 'All of that, plus which telemetry sees which step, the StartAddress-to-region correlation, and the evidence-preserving next steps.',
  },
  followUps: [
    'Why would an attacker inject into explorer.exe instead of running their own process?',
    'Which Sysmon events would you alert on, and how would you tune them?',
    'How would you confirm the injected code without running it?',
  ],
  mistakes: [
    'Claiming Sysmon logged VirtualAllocEx or WriteProcessMemory.',
    'Calling it DLL injection without a LoadLibrary call or a DLL path.',
    'Rebooting or killing explorer.exe before capturing memory.',
  ],
  references: [
    MITRE('T1055', 'Process Injection'),
    { label: 'Microsoft: Sysmon (Event IDs 8 and 10)', url: 'https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon' },
    { label: 'Microsoft: Process security and access rights (PROCESS_ALL_ACCESS)', url: 'https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights' },
  ],
  build(w) {
    const sc = injectionScenario(w);
    const giveawayOpts = [
      { id: 'rwx-remote', label: 'RWX memory allocated in another process, written to, then a remote thread started at that address' },
      { id: 'openprocess', label: 'OpenProcess was called at all' },
      { id: 'word', label: 'Word is running' },
      { id: 'explorer', label: 'explorer.exe has a new thread' },
    ];
    const accessOpts = [
      { id: 'all', label: 'PROCESS_ALL_ACCESS: full control of the target process' },
      { id: 'read', label: 'Read-only access to the target\'s memory' },
      { id: 'query', label: 'Permission to query basic process information only' },
      { id: 'terminate', label: 'Permission to terminate the process only' },
    ];
    return {
      artifacts: [
        { path: `${w.host.name}/live-response/edr-api-trace.txt`, content: sc.trace, title: 'EDR API trace from WINWORD.EXE' },
        { path: `${w.host.name}/logs/Sysmon-injection-events.xml`, content: sc.sysmonXml, title: 'Sysmon Event IDs 10 and 8 (XML)' },
        { path: `${w.host.name}/live-response/memory-malfind.txt`, content: sc.malfind, title: 'Memory finding in explorer.exe (malfind-style)' },
      ],
      questions: [
        { id: 'technique', prompt: 'Which MITRE ATT&CK technique is this? Give the ID.', kind: 'text', placeholder: 'T1xxx', why: 'Process Injection, T1055.' },
        { id: 'giveaway', prompt: 'What in the sequence gives it away?', kind: 'choice', options: shuffled(w.seed, 'm10.g', giveawayOpts), why: 'Each call alone can be legitimate; the cross-process RWX allocation, write and thread start together are injection.' },
        { id: 'access', prompt: 'What does GrantedAccess 0x1FFFFF in Event ID 10 mean?', kind: 'choice', options: shuffled(w.seed, 'm10.a', accessOpts), why: '0x1FFFFF is PROCESS_ALL_ACCESS.' },
        { id: 'eid', prompt: 'Which Sysmon Event ID records the remote thread?', kind: 'text', placeholder: 'event ID', why: 'Event ID 8, CreateRemoteThread.' },
        { id: 'pid', prompt: 'What is the PID of the injected process?', kind: 'text', placeholder: 'PID', why: 'explorer.exe is the target in the trace, in Sysmon and in the memory finding.' },
      ],
      expected: { technique: 'T1055', giveaway: 'rwx-remote', access: 'all', eid: '8', pid: String(sc.explorerPid) },
      check(qid, a) {
        const t = normText(asText(a)).toUpperCase();
        if (qid === 'technique') return /^T1055(\.\d{3})?$/.test(t);
        if (qid === 'giveaway') return asText(a) === 'rwx-remote';
        if (qid === 'access') return asText(a) === 'all';
        if (qid === 'eid') return t.replace(/^(EVENT\s*ID|EID|ID)\s*/, '') === '8';
        if (qid === 'pid') return t.replace(/^PID\s*/, '') === String(sc.explorerPid);
        return false;
      },
    };
  },
};
