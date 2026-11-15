import { escapeXml, utf16leBytes } from '../lib/encode';
import { Rng } from '../lib/prng';
import { normText } from '../lib/normalize';
import type { Artifact, ModuleDef } from '../types';
import { eventsXml, PROVIDERS, type WinEvent } from '../winevt';
import { ORG, sysmonUtc, type World } from '../world';
import { asText, MITRE, shuffled } from './helpers';

export type PersistKind = 'task' | 'service' | 'wmi';

const BAD_TASKS = ['SystemHealthMonitor', 'WindowsCacheCleanup', 'UserProfileSync', 'DisplayDriverCheck'];
const BAD_SERVICES = ['WinHealthSvc', 'NetCacheHost', 'SysPerfMon', 'UsrSyncSvc'];
const BAD_WMI = ['PerfCheckFilter', 'UptimeMonitor', 'SessionAudit', 'CacheRefresh'];

function taskXml(author: string, command: string, args: string, trigger: string): string {
  return [
    '<?xml version="1.0" encoding="UTF-16"?>',
    '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
    '  <RegistrationInfo>',
    `    <Author>${escapeXml(author)}</Author>`,
    '  </RegistrationInfo>',
    '  <Triggers>',
    trigger,
    '  </Triggers>',
    '  <Settings>',
    '    <Hidden>true</Hidden>',
    '    <Enabled>true</Enabled>',
    '  </Settings>',
    '  <Actions Context="Author">',
    '    <Exec>',
    `      <Command>${escapeXml(command)}</Command>`,
    `      <Arguments>${escapeXml(args)}</Arguments>`,
    '    </Exec>',
    '  </Actions>',
    '</Task>',
  ].join('\r\n');
}

export function persistenceScenario(w: World) {
  const rng = new Rng(`m12:${w.seed}`);
  const kind = rng.pick<PersistKind>(['task', 'service', 'wmi']);
  const dir = `C:\\ProgramData\\${w.ids.configDir}`;
  const user = `${ORG.netbios}\\${w.victim.username}`;
  const badTask = rng.pick(BAD_TASKS);
  const badSvc = rng.pick(BAD_SERVICES);
  const badWmi = rng.pick(BAD_WMI);
  const t0 = new Date(w.t.configWritten.getTime() + rng.int(60, 600) * 1000);
  const at = (s: number) => new Date(t0.getTime() + s * 1000);
  const name = kind === 'task' ? badTask : kind === 'service' ? badSvc : badWmi;
  const payloadCmd = `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ${dir}\\${w.ids.stage2Name}.ps1`;

  // Scheduled tasks (Security 4698 + the task file in System32\Tasks).
  const tasks: { name: string; xml: string; time: Date; subject: string }[] = [
    {
      name: '\\Quorvane\\UpdateCheck',
      xml: taskXml('Quorvane Software', 'C:\\Program Files\\Quorvane\\Sync\\QuorvaneUpdate.exe', '/check /silent', '    <CalendarTrigger><StartBoundary>2026-01-05T03:00:00</StartBoundary><ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>'),
      time: at(-86400 * rng.int(20, 90)),
      subject: 'SYSTEM',
    },
  ];
  if (kind === 'task') {
    tasks.push({
      name: `\\${badTask}`,
      xml: taskXml(user, 'powershell.exe', payloadCmd.replace('powershell.exe ', ''), `    <LogonTrigger><Enabled>true</Enabled><UserId>${user}</UserId></LogonTrigger>`),
      time: at(0),
      subject: w.victim.username,
    });
  }
  const sec = PROVIDERS.security;
  const secEvents: WinEvent[] = tasks.map((t) => ({
    ...sec,
    eventId: 4698,
    version: 1,
    task: 12804,
    computer: w.host.fqdn,
    time: t.time,
    data: [
      ['SubjectUserSid', t.subject === 'SYSTEM' ? 'S-1-5-18' : w.victim.sid],
      ['SubjectUserName', t.subject === 'SYSTEM' ? `${w.host.name}$` : t.subject],
      ['SubjectDomainName', ORG.netbios],
      ['SubjectLogonId', t.subject === 'SYSTEM' ? '0x3e7' : `0x${rng.hex(3)}`],
      ['TaskName', t.name],
      ['TaskContent', t.xml],
    ],
  }));

  // Services (System 7045).
  const services: { name: string; path: string; account: string; time: Date }[] = [
    { name: 'Quorvane Sync Service', path: '"C:\\Program Files\\Quorvane\\Sync\\QuorvaneSyncSvc.exe"', account: 'LocalSystem', time: at(-86400 * rng.int(30, 120)) },
    { name: 'Velmora IT Inventory Agent', path: '"C:\\Program Files\\VelmoraIT\\InventoryAgent.exe" --service', account: 'LocalSystem', time: at(-86400 * rng.int(10, 60)) },
  ];
  if (kind === 'service') services.push({ name: badSvc, path: `%COMSPEC% /c start /b ${payloadCmd}`, account: 'LocalSystem', time: at(0) });
  const scm = PROVIDERS.scm;
  const sysEvents: WinEvent[] = services.map((s) => ({
    ...scm,
    eventId: 7045,
    version: 0,
    task: 0,
    qualifiers: 16384,
    computer: w.host.fqdn,
    time: s.time,
    data: [
      ['ServiceName', s.name],
      ['ImagePath', s.path],
      ['ServiceType', 'user mode service'],
      ['StartType', 'auto start'],
      ['AccountName', s.account],
    ],
  }));

  // WMI event subscriptions (Sysmon 19, 20, 21).
  const sysmon = PROVIDERS.sysmon;
  const wmi = (base: Date, filter: string, consumer: string, query: string, dest: string, by: string): WinEvent[] => {
    const common = (id: number, s: number): Pick<WinEvent, 'eventId' | 'version' | 'task' | 'time'> => ({ eventId: id, version: 3, task: id, time: new Date(base.getTime() + s * 1000) });
    return [
      { ...sysmon, ...common(19, 0), computer: w.host.fqdn, data: [['RuleName', '-'], ['EventType', 'WmiFilterEvent'], ['UtcTime', sysmonUtc(base)], ['Operation', 'Created'], ['User', by], ['EventNamespace', '"root\\\\cimv2"'], ['Name', `"${filter}"`], ['Query', `"${query}"`]] },
      { ...sysmon, ...common(20, 1), computer: w.host.fqdn, data: [['RuleName', '-'], ['EventType', 'WmiConsumerEvent'], ['UtcTime', sysmonUtc(new Date(base.getTime() + 1000))], ['Operation', 'Created'], ['User', by], ['Name', `"${consumer}"`], ['Type', 'Command Line'], ['Destination', `"${dest}"`]] },
      { ...sysmon, ...common(21, 2), computer: w.host.fqdn, data: [['RuleName', '-'], ['EventType', 'WmiBindingEvent'], ['UtcTime', sysmonUtc(new Date(base.getTime() + 2000))], ['Operation', 'Created'], ['User', by], ['Consumer', `"CommandLineEventConsumer.Name=\\"${consumer}\\""`], ['Filter', `"__EventFilter.Name=\\"${filter}\\""`]] },
    ];
  };
  const wmiEvents: WinEvent[] = [
    ...wmi(at(-86400 * rng.int(15, 60)), 'VelmoraIT_InventoryFilter', 'VelmoraIT_InventoryConsumer', "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 2", 'powershell.exe -NoProfile -NonInteractive -File C:\\ProgramData\\VelmoraIT\\inventory.ps1', 'NT AUTHORITY\\SYSTEM'),
  ];
  if (kind === 'wmi') {
    wmiEvents.push(...wmi(at(0), `${badWmi}Filter`, badWmi, "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240", payloadCmd, user));
  }
  wmiEvents.sort((a, b) => a.time.getTime() - b.time.getTime());

  const H = w.host.name;
  const artifacts: Artifact[] = [
    { path: `${H}/logs/Security-4698.xml`, content: eventsXml(secEvents.sort((a, b) => a.time.getTime() - b.time.getTime()), rng, rng.int(1000000, 3000000)), title: 'Security log: scheduled task created (4698)' },
    { path: `${H}/logs/System-7045.xml`, content: eventsXml(sysEvents.sort((a, b) => a.time.getTime() - b.time.getTime()), rng, rng.int(40000, 90000)), title: 'System log: service installed (7045)' },
    { path: `${H}/logs/Sysmon-WMI-events.xml`, content: eventsXml(wmiEvents, rng, rng.int(700000, 990000)), title: 'Sysmon WMI events (19, 20, 21)' },
    // Task files on disk are UTF-16LE with a byte-order mark, as Windows writes them.
    ...tasks.map((t) => ({ path: `${H}/files/Windows/System32/Tasks${t.name.replace(/\\/g, '/')}`, content: new Uint8Array([0xff, 0xfe, ...utf16leBytes(t.xml)]), view: t.xml, title: `Task file: ${t.name}`, note: 'Stored as UTF-16LE, like the real files in System32\\Tasks.' })),
  ];
  // A compact, autoruns-style listing of every persistence item, used by Assessment mode.
  const items = [
    ...tasks.map((t) => ({ type: 'Scheduled task', name: t.name.replace(/^\\/, ''), command: /<Command>([^<]*)<\/Command>/.exec(t.xml)![1] + ' ' + /<Arguments>([^<]*)<\/Arguments>/.exec(t.xml)![1].replace(/&amp;/g, '&') })),
    ...services.map((s) => ({ type: 'Service', name: s.name, command: s.path })),
    ...[{ name: 'VelmoraIT_InventoryConsumer', command: 'powershell.exe -NoProfile -NonInteractive -File C:\\ProgramData\\VelmoraIT\\inventory.ps1' }, ...(kind === 'wmi' ? [{ name: badWmi, command: payloadCmd }] : [])].map((x) => ({ type: 'WMI consumer', ...x })),
  ];
  return { kind, name, artifacts, items: rng.shuffle(items) };
}

export const m12: ModuleDef = {
  id: 'm12',
  number: 12,
  title: 'Persistence beyond Run keys',
  short: 'Scheduled task, service or WMI subscription: find the one the attacker planted and where it lives.',
  tracks: ['t2'],
  difficulty: 2,
  objective: 'Review scheduled-task, service and WMI-subscription artifacts, find the persistence the attacker actually planted, and name where that artifact lives.',
  background: [
    'Run keys are the persistence everyone checks first, so attackers often use other mechanisms. Three common ones, and where each leaves evidence:',
    '**Scheduled task:** Security Event **4698** ("A scheduled task was created", when object-access auditing for other object events is enabled) includes the full task XML in `TaskContent`. The task definition is also stored as a file under `C:\\Windows\\System32\\Tasks\\`.',
    '**Service:** System Event **7045** ("A service was installed in the system", from Service Control Manager) records `ServiceName`, `ImagePath`, `StartType` and the account. The configuration lives under `HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>`.',
    '**WMI event subscription:** a filter (what to wait for), a consumer (what to run) and a binding between them, stored in the WMI repository (`root\\subscription`). Sysmon records them as Event IDs **19** (filter), **20** (consumer) and **21** (binding).',
    '**Telling planted from legitimate:** look at *what runs* (hidden PowerShell, `cmd /c`, scripts in ProgramData or AppData), *who created it* (a standard user account versus SYSTEM or an installer), *when* (minutes after the initial compromise), and *names* chosen to look like Windows components.',
  ],
  evidenceNote: 'Task-creation events and task files, service-installation events, and Sysmon WMI events from the case host. Most of it is legitimate software.',
  hints: [
    'Check each item\'s command: what would actually run?',
    'Compare creation times against the compromise timeline from the case brief.',
    'The planted item runs a hidden PowerShell script from a ProgramData folder you have seen before.',
  ],
  explainPrompt: 'Name the mechanism and the item, show the evidence that it is malicious, and say where the artifact lives and how you would remove it safely.',
  rubric: {
    listenFor: [
      'The planted mechanism and item named, with the evidence (command, creator, timing, path).',
      'The artifact location named for that mechanism (Tasks folder, Services key, or WMI repository root\\subscription).',
      'Legitimate items ruled out with reasons.',
      'At least two other mechanisms beyond Run keys named, with their event IDs.',
      'Remediation order: collect first, then remove the persistence, and check for more than one mechanism.',
    ],
    weak: '"Check the Run keys and scheduled tasks."',
    solid: 'Names the planted item, its mechanism and where it lives, with the evidence.',
    strong: 'All of that, plus the event IDs for each mechanism, why the decoys are benign, and a careful removal plan.',
  },
  followUps: [
    'Which other persistence locations would you check on a Windows host?',
    'How would you hunt for this mechanism across the whole fleet?',
    'What could go wrong if you delete the persistence before collecting evidence?',
  ],
  mistakes: [
    'Assuming every new task or service is malicious; software installers create them constantly.',
    'Stopping after the first persistence found; attackers often plant more than one.',
    'Forgetting that 4698 needs the right audit policy, so its absence does not prove no task was created.',
  ],
  references: [
    MITRE('T1053.005', 'Scheduled Task/Job: Scheduled Task'),
    MITRE('T1543.003', 'Create or Modify System Process: Windows Service'),
    MITRE('T1546.003', 'Event Triggered Execution: Windows Management Instrumentation Event Subscription'),
    { label: 'Microsoft: Event 4698, a scheduled task was created', url: 'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4698' },
  ],
  build(w) {
    const sc = persistenceScenario(w);
    const kindOpts = [
      { id: 'task', label: 'Scheduled task' },
      { id: 'service', label: 'Windows service' },
      { id: 'wmi', label: 'WMI event subscription' },
      { id: 'run', label: 'Run key' },
    ];
    const whereOpts = [
      { id: 'task', label: 'C:\\Windows\\System32\\Tasks\\ (and the Security 4698 event)' },
      { id: 'service', label: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\ (and the System 7045 event)' },
      { id: 'wmi', label: 'The WMI repository, root\\subscription namespace (and Sysmon 19, 20, 21)' },
      { id: 'run', label: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' },
    ];
    return {
      artifacts: sc.artifacts,
      questions: [
        { id: 'kind', prompt: 'Which persistence mechanism did the attacker plant?', kind: 'choice', options: shuffled(w.seed, 'm12.k', kindOpts), why: 'It is the only item that runs a hidden PowerShell script from ProgramData, created minutes after the compromise.' },
        { id: 'name', prompt: 'What is the name of the planted item (task name, service name or WMI consumer name)?', kind: 'text', placeholder: 'name', why: `The planted ${sc.kind === 'task' ? 'task' : sc.kind === 'service' ? 'service' : 'WMI consumer'} is ${sc.name}.` },
        { id: 'where', prompt: 'Where does that artifact live?', kind: 'choice', options: shuffled(w.seed, 'm12.w', whereOpts), why: 'Each mechanism has its own storage location and event source.' },
      ],
      expected: { kind: sc.kind, name: sc.name, where: sc.kind },
      check(qid, a) {
        const t = asText(a);
        if (qid === 'kind') return t === sc.kind;
        if (qid === 'where') return t === sc.kind;
        if (qid === 'name') return normText(t).replace(/^\\+/, '') === sc.name.toLowerCase();
        return false;
      },
    };
  },
};
