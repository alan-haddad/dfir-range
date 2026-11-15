import { Rng } from '../lib/prng';
import { normHost, normText } from '../lib/normalize';
import type { ModuleDef } from '../types';
import { ORG, sysmonUtc, type World } from '../world';
import { asText, MITRE, shuffled } from './helpers';

// Fleet-wide Sysmon Event ID 7 (image loaded) for a fictional vendor's signed sync client.

export function sideloadScenario(w: World) {
  const rng = new Rng(`m13:${w.seed}`);
  const nums = new Set<number>();
  while (nums.size < 24) nums.add(rng.int(1000, 9999));
  const hosts = [...nums].map((n) => `${ORG.hostPrefix}-${n}`);
  const outlier = rng.pick(hosts);
  const rareLegit = rng.pick(hosts.filter((h) => h !== outlier));
  const exe = 'C:\\Program Files\\Quorvane\\Sync\\QuorvaneSync.exe';
  const coreHash = rng.hex(32).toUpperCase();
  const coreHashNew = rng.hex(32).toUpperCase();
  const sysHashes: Record<string, string> = {};
  const dll = rng.pick(['version.dll', 'dbghelp.dll', 'winhttp.dll', 'userenv.dll']);
  const sysDlls = ['ntdll.dll', 'kernel32.dll', 'KernelBase.dll', dll];
  for (const d of sysDlls) sysHashes[d] = rng.hex(32).toUpperCase();
  const user = rng.pick(['p.osei', 'k.holt', 'm.lund', 'r.quinn']);
  const tempDir = `C:\\Users\\${user}\\AppData\\Local\\Temp\\${rng.alnum(6)}`;
  let t = w.t.emailReceived.getTime() - rng.int(4, 6) * 3600 * 1000;
  const lines: string[] = [];
  const emit = (host: string, image: string, loaded: string, signed: boolean, signature: string, hash: string) => {
    t += rng.int(200, 4000);
    const time = new Date(t);
    lines.push(
      JSON.stringify({
        '@timestamp': time.toISOString(),
        host: { name: `${host.toLowerCase()}.${ORG.adDomain}` },
        winlog: {
          channel: 'Microsoft-Windows-Sysmon/Operational',
          event_id: 7,
          event_data: {
            UtcTime: sysmonUtc(time),
            Image: image,
            ImageLoaded: loaded,
            Signed: signed ? 'true' : 'false',
            Signature: signature,
            SignatureStatus: signed ? 'Valid' : 'Unavailable',
            Hashes: `SHA256=${hash}`,
          },
        },
      }),
    );
  };
  for (const host of hosts) {
    for (const d of sysDlls) emit(host, exe, `C:\\Windows\\System32\\${d}`, true, 'Microsoft Windows', sysHashes[d]);
    emit(host, exe, 'C:\\Program Files\\Quorvane\\Sync\\qvcore.dll', true, 'Quorvane Software Ltd', host === rareLegit ? coreHashNew : coreHash);
  }
  // The outlier: the same signed executable copied into a user Temp folder, loading an unsigned DLL from its own folder.
  const badExe = `${tempDir}\\QuorvaneSync.exe`;
  for (const d of sysDlls.slice(0, 3)) emit(outlier, badExe, `C:\\Windows\\System32\\${d}`, true, 'Microsoft Windows', sysHashes[d]);
  emit(outlier, badExe, `${tempDir}\\${dll}`, false, '-', rng.hex(32).toUpperCase());
  const shuffled = rng.shuffle(lines);
  shuffled.sort((a, b) => (JSON.parse(a)['@timestamp'] < JSON.parse(b)['@timestamp'] ? -1 : 1));
  return { text: shuffled.join('\n') + '\n', outlier, dll, hostCount: hosts.length };
}

export const m13: ModuleDef = {
  id: 'm13',
  number: 13,
  title: 'DLL side-loading hunt',
  short: 'Fleet-wide image loads: stack-count to find the signed binary loading an unsigned DLL from its own folder.',
  tracks: ['t2'],
  difficulty: 3,
  objective: 'Hunt for DLL side-loading across 24 hosts using image-load events: find the host and the DLL by stack counting rather than by reading every line.',
  background: [
    '**DLL side-loading** abuses the Windows DLL search order: when a program loads a DLL by name, Windows checks the application\'s own directory early in the search. Copy a legitimately signed program into a folder you control, put a malicious DLL with the expected name next to it, and the trusted program loads your code.',
    'The **hunt logic**: (1) a signed, trusted executable running from an **unusual path** (a user Temp or AppData folder instead of Program Files); (2) it loads a DLL from **its own folder** that is **unsigned** or not the expected copy, often one that normally loads from System32 (`version.dll`, `dbghelp.dll` and similar); (3) **prevalence**: across the fleet, that combination appears on one host.',
    '**Stack counting** is how you do this at scale: group image loads by `Image` path, `ImageLoaded` path and signature status, count how many hosts each combination appears on, and read the rarest rows first. Rare is not automatically bad (a host that just updated has a new hash), so you then check path, signature and context.',
    'Sysmon Event ID 7 (image loaded) carries `Image`, `ImageLoaded`, `Signed`, `Signature`, `SignatureStatus` and hashes. It is noisy, so many organizations collect it only for selected processes, which is worth saying in an interview.',
  ],
  evidenceNote: 'Sysmon Event ID 7 from 24 hosts, one JSON object per line, all for one vendor\'s sync client.',
  hints: [
    'Count rows by Image, ImageLoaded and Signed. Which combination appears only once or twice?',
    'One host has a rare hash for a signed DLL in Program Files. Is that suspicious, or an update?',
    "jq: jq -r '[.host.name, .winlog.event_data.Image, .winlog.event_data.ImageLoaded, .winlog.event_data.Signed] | @tsv' fleet.jsonl | cut -f2- | sort | uniq -c | sort -n | head",
  ],
  explainPrompt: 'Explain your hunt as a query you would run, then name the host, the DLL and why the rare-but-legitimate row is not it.',
  rubric: {
    listenFor: [
      'Side-loading explained through the DLL search order.',
      'The hunt as stacking: group by image, loaded DLL and signature, count across hosts, read the rarest.',
      'Unusual path plus unsigned DLL from the application\'s own folder named as the combination.',
      'The decoy (a rare hash of a signed DLL in Program Files) explained as an update.',
      'Next steps: pull the DLL and the copied executable, find how they arrived (EID 11, downloads), look for the DLL hash fleet-wide.',
    ],
    weak: '"Look for unsigned DLLs."',
    solid: 'Stack-counts, then names the host and the DLL with the path and signature reasoning.',
    strong: 'All of that, plus the search-order explanation, why rare is not automatically bad, and the follow-up collection plan.',
  },
  followUps: [
    'Image-load logging is noisy. What would you collect, and from which processes?',
    'How would the hunt change if the attacker signed their DLL with a stolen certificate?',
    'What else would you check on the outlier host?',
  ],
  mistakes: [
    'Flagging every unsigned DLL in the fleet instead of the combination.',
    'Treating the rare-but-signed update as malicious.',
    'Hunting by DLL name alone: version.dll in System32 is normal.',
  ],
  references: [
    MITRE('T1574.001', 'Hijack Execution Flow: DLL'),
    { label: 'Microsoft: Dynamic-link library search order', url: 'https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order' },
  ],
  build(w) {
    const sc = sideloadScenario(w);
    const whyOpts = [
      { id: 'searchorder', label: 'Windows checks the application\'s own folder for the DLL before System32, so a DLL placed next to the program is loaded' },
      { id: 'signed', label: 'Signed programs can load any DLL without restriction' },
      { id: 'registry', label: 'The DLL path is configured in a Run key' },
      { id: 'kernel', label: 'The kernel injects missing DLLs automatically' },
    ];
    return {
      artifacts: [{ path: 'fleet/sysmon-image-loads.jsonl', content: sc.text, title: `Sysmon Event ID 7 from ${sc.hostCount} hosts (JSON lines)` }],
      questions: [
        { id: 'host', prompt: 'Which host shows the side-loading?', kind: 'text', placeholder: 'hostname', why: 'Only one host runs the vendor executable from a user Temp folder and loads an unsigned DLL from that folder.' },
        { id: 'dll', prompt: 'Which DLL is side-loaded?', kind: 'text', placeholder: 'name.dll', why: `${sc.dll} normally loads from System32; on the outlier it loads, unsigned, from the program\'s own folder.` },
        { id: 'why', prompt: 'Why does side-loading work?', kind: 'choice', options: shuffled(w.seed, 'm13.w', whyOpts), why: 'The DLL search order checks the application directory early.' },
      ],
      expected: { host: sc.outlier, dll: sc.dll, why: 'searchorder' },
      check(qid, a) {
        const t = asText(a);
        if (qid === 'host') return normHost(t) === sc.outlier.toLowerCase();
        if (qid === 'dll') return normText(t).replace(/^.*\\/, '') === sc.dll;
        if (qid === 'why') return t === 'searchorder';
        return false;
      },
    };
  },
};
