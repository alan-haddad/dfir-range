import { evidenceFor } from '../evidence';
import { Rng } from '../lib/prng';
import { normText } from '../lib/normalize';
import type { ModuleDef } from '../types';
import { eventsJsonl, eventsXml, hex, PROVIDERS, type WinEvent } from '../winevt';
import { ORG, type World } from '../world';
import { asText, MITRE, pick, shuffled } from './helpers';

export function securityLog(w: World) {
  const ev = evidenceFor(w);
  const rng = new Rng(`m08:${w.seed}`);
  const cmdAuditing = rng.bool(0.6);
  const { payload, psEnc, psFile, explorer } = ev.derived.procs;
  const sec = PROVIDERS.security;
  const mk = (time: Date, p: typeof payload, parent: typeof payload): WinEvent => ({
    ...sec,
    eventId: 4688,
    version: 2,
    task: 13312,
    computer: w.host.fqdn,
    time,
    data: [
      ['SubjectUserSid', w.victim.sid],
      ['SubjectUserName', w.victim.username],
      ['SubjectDomainName', ORG.netbios],
      ['SubjectLogonId', ev.derived.logonId],
      ['NewProcessId', hex(p.pid)],
      ['NewProcessName', p.image],
      ['TokenElevationType', '%%1938'],
      ['ProcessId', hex(parent.pid)],
      ['CommandLine', cmdAuditing ? p.cmd : ''],
      ['TargetUserSid', 'S-1-0-0'],
      ['TargetUserName', '-'],
      ['TargetDomainName', '-'],
      ['TargetLogonId', '0x0'],
      ['ParentProcessName', parent.image],
      ['MandatoryLabel', 'S-1-16-8192'],
    ],
  });
  const events = [mk(ev.derived.times.payload, payload, explorer), mk(ev.derived.times.psEnc, psEnc, payload), mk(ev.derived.times.psFile, psFile, psEnc)];
  const first = rng.int(900000, 2900000);
  return {
    cmdAuditing,
    xml: eventsXml(events, rng, first),
    jsonl: eventsJsonl(events, first),
    payloadGuid: payload.guid,
  };
}

export const m08: ModuleDef = {
  id: 'm08',
  number: 8,
  title: 'Process-creation telemetry',
  short: 'Sysmon Event ID 1 vs Security 4688: command lines, parents and the GUIDs that link them.',
  tracks: ['t1', 't2'],
  difficulty: 1,
  objective: 'Name the telemetry that gives you a process with its full command line and its parent, know the fields you key on, and use ProcessGuid to walk a process tree.',
  background: [
    '**Sysmon Event ID 1** (process creation) records the new process\'s `Image`, full `CommandLine`, `User`, hashes, and its parent: `ParentImage`, `ParentCommandLine` and `ParentProcessGuid`.',
    '**Security Event 4688** ("A new process has been created") is built into Windows, but it only includes `CommandLine` when the policy **"Include command line in process creation events"** is enabled, on top of auditing process creation. It records the parent\'s name (`ParentProcessName`) but **not the parent\'s command line**. Process IDs appear in hex.',
    '**ProcessGuid vs ProcessId:** Windows reuses PIDs, so a PID alone can point at the wrong process later in the day. Sysmon\'s `ProcessGuid` is unique per process, and `ParentProcessGuid` lets you walk the tree reliably.',
    'In an interview, "Sysmon Event ID 1, keyed on CommandLine and ParentImage, walking the tree with ProcessGuid" is a crisp, complete answer. Mention 4688 and its command-line prerequisite to show you know what a default Windows box gives you.',
  ],
  evidenceNote: 'The Sysmon log from the case, plus the Security log from the same host for the same processes.',
  hints: [
    'Compare the same process in both logs. Which fields exist only in Sysmon?',
    'Check whether the 4688 events on this host actually contain command lines.',
    'The encoded PowerShell event carries a ParentProcessGuid. Find the process whose ProcessGuid matches.',
  ],
  explainPrompt: 'Answer the interview question in one sentence, then explain how 4688 differs and why you walk trees by GUID instead of PID.',
  rubric: {
    listenFor: [
      'Sysmon Event ID 1 named, with CommandLine, ParentImage/ParentCommandLine and ProcessGuid/ParentProcessGuid.',
      'Security 4688 named, with its command-line prerequisite and missing parent command line.',
      'PID reuse explained as the reason for GUIDs.',
      'EDR process telemetry mentioned as the other common source.',
    ],
    weak: '"Event logs."',
    solid: '"Sysmon Event ID 1: CommandLine and ParentImage", plus 4688 as the built-in alternative.',
    strong: 'All of that, plus the 4688 command-line policy, the missing parent command line in 4688, and walking the tree with ProcessGuid.',
  },
  followUps: [
    'Your organization does not run Sysmon. What do you turn on, and what will you still be missing?',
    'Why is a PID not enough to identify a process across a day of logs?',
    'Which field would you alert on for an Office application spawning a shell?',
  ],
  mistakes: [
    'Assuming 4688 always contains the command line.',
    'Linking parent and child by PID alone.',
    'Answering "the EDR" with no field names.',
  ],
  references: [
    { label: 'Microsoft: Event 4688, a new process has been created', url: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688' },
    { label: 'Microsoft: Sysmon (event descriptions)', url: 'https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon' },
    MITRE('T1059', 'Command and Scripting Interpreter'),
  ],
  build(w) {
    const ev = evidenceFor(w);
    const sec = securityLog(w);
    const fieldOpts = [
      { id: 'parentcmd', label: 'ParentCommandLine' },
      { id: 'parentname', label: 'The parent process name' },
      { id: 'newname', label: 'The new process name' },
      { id: 'user', label: 'The account that created the process' },
    ];
    const auditOpts = [
      { id: 'yes', label: 'Yes, the 4688 events here include command lines' },
      { id: 'no', label: 'No, CommandLine is empty: "Include command line in process creation events" is not enabled' },
    ];
    return {
      artifacts: [
        ...pick(ev.artifacts, ev.paths.sysmonXml),
        { path: `${w.host.name}/logs/Security.xml`, content: sec.xml, title: 'Security log (XML), process creation events' },
        { path: `${w.host.name}/logs/Security.jsonl`, content: sec.jsonl, title: 'Security log (JSON lines)' },
      ],
      questions: [
        { id: 'sysmon', prompt: 'Which Sysmon Event ID records process creation with the full command line and parent?', kind: 'text', placeholder: 'event ID', why: 'Sysmon Event ID 1, process creation.' },
        { id: 'security', prompt: 'Which Windows Security Event ID records process creation?', kind: 'text', placeholder: 'event ID', why: 'Security Event 4688.' },
        { id: 'field', prompt: 'Which field does Sysmon Event ID 1 have that Security 4688 does not?', kind: 'choice', options: shuffled(w.seed, 'm08.f', fieldOpts), why: '4688 names the parent process but does not record the parent\'s command line.' },
        { id: 'audit', prompt: 'Do the 4688 events on this host include command lines?', kind: 'choice', options: auditOpts, why: sec.cmdAuditing ? 'The CommandLine field is populated, so the policy is enabled.' : 'CommandLine is present but empty, which is what you see when the command-line policy is off.' },
        { id: 'guid', prompt: 'What is the ProcessGuid of the process that launched the encoded PowerShell?', kind: 'text', placeholder: '{xxxxxxxx-…}', why: 'The encoded PowerShell event\'s ParentProcessGuid matches the ProcessGuid of invoice.pdf.exe.' },
      ],
      expected: { sysmon: '1', security: '4688', field: 'parentcmd', audit: sec.cmdAuditing ? 'yes' : 'no', guid: sec.payloadGuid },
      check(qid, a) {
        const t = normText(asText(a)).replace(/^(event\s*id|eid|id)\s*/, '');
        if (qid === 'sysmon') return t === '1';
        if (qid === 'security') return t === '4688';
        if (qid === 'field') return t === 'parentcmd';
        if (qid === 'audit') return t === (sec.cmdAuditing ? 'yes' : 'no');
        if (qid === 'guid') return t.replace(/[{}]/g, '') === sec.payloadGuid.toLowerCase().replace(/[{}]/g, '');
        return false;
      },
    };
  },
};
