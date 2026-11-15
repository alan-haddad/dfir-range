import { evidenceFor } from '../evidence';
import { IP_FORM_LABELS } from '../lib/ip';
import { normIp } from '../lib/normalize';
import type { ModuleDef } from '../types';
import { asText, MITRE, pick, shuffled } from './helpers';

export const m02: ModuleDef = {
  id: 'm02',
  number: 2,
  title: 'Obfuscated download cradle',
  short: 'Explain an irm | iex cradle and normalize a host written in hex, octal or collapsed notation.',
  tracks: ['t1', 't2'],
  difficulty: 2,
  objective:
    'Read the script the encoded command downloaded, explain what its last line does, and normalize the obfuscated host to a dotted-quad IPv4 address.',
  background: [
    '`irm` is a built-in alias for `Invoke-RestMethod` and `iex` is an alias for `Invoke-Expression`. Piped together, they fetch text from a URL and run it as PowerShell **in memory**. The next stage is never written to disk, which is why this pattern is called a download cradle and why disk-only forensics can miss it.',
    'The host is written in **numbers-and-dots notation**, the format the classic `inet_aton` parser accepts. Each part can be decimal, octal (leading `0`) or hex (leading `0x`). With fewer than four parts, the last part fills the remaining bytes: in `a.b.c`, `c` is a 16-bit number; in `a.b`, `b` is 24 bits; a single number is the whole 32-bit address.',
    'A detection that string-matches `198.51.100.23` will not match `0xC6.063.25623`, even though they can be the same address. Watch the **leading-zero trap**: `010` is octal, so it equals 8, not 10.',
    "Parsers differ: browsers, curl, .NET and libc each accept different subsets of these forms. Don't argue about whether a form would work. Normalize it and hunt for the canonical value.",
    'Junk variables are there to break signatures and waste your time. Trace only the variables that reach the network call.',
  ],
  evidenceNote: 'Open the .ps1.txt recovered from the user\'s Temp folder. The Sysmon log shows how it got there and what ran it.',
  hints: [
    'Ignore every line that does not feed the irm call. Find the variable that holds the host.',
    'Split the host on dots and count the parts. Fewer than four means the last part covers more than one byte.',
    'Convert each part (0x means hex; a leading 0 means octal), then split a combined last part into bytes, e.g. c → c >> 8 and c & 255. On Linux or macOS, Python\'s socket.inet_ntoa(socket.inet_aton(s)) applies the same rules.',
  ],
  explainPrompt: 'Explain what the cradle line does, how you converted the host, and why fileless execution changes your evidence plan.',
  rubric: {
    listenFor: [
      'irm/iex named: fetch text, execute it in memory.',
      'Only the relevant variables traced; junk dismissed quickly.',
      'Conversion method stated, including how a collapsed last part is split into bytes.',
      'The leading-zero octal trap mentioned.',
      'Next steps: hunt the canonical IP in proxy, firewall and EDR network events; recover what iex ran (script block logging 4104, memory).',
    ],
    weak: '"It downloads something from a weird IP."',
    solid: 'Explains irm | iex as download-and-execute in memory and converts the host correctly to dotted-quad.',
    strong:
      'All of that, plus why defenders normalize indicators, why fileless stages push you toward memory and script block logs, and which logs would show the connection.',
  },
  followUps: [
    'Why does fileless execution matter for your evidence-collection plan?',
    'How would you hunt for this IP if some of your logs store hosts as raw strings?',
    'Which PowerShell logging would show you the code that iex ran?',
  ],
  mistakes: [
    'Reading 010 as ten instead of octal eight.',
    'Treating a collapsed last part (e.g. 25623) as one octet instead of two or three bytes.',
    'Spending time decoding junk variables that never reach the network call.',
  ],
  references: [
    { label: 'inet(3) manual page: numbers-and-dots notation', url: 'https://man7.org/linux/man-pages/man3/inet_aton.3.html' },
    { label: 'Microsoft: Invoke-Expression', url: 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression' },
    MITRE('T1059.001', 'Command and Scripting Interpreter: PowerShell'),
    MITRE('T1105', 'Ingress Tool Transfer'),
    MITRE('T1027.010', 'Command Obfuscation'),
  ],
  build(w) {
    const ev = evidenceFor(w);
    const actOpts = [
      { id: 'exec-memory', label: 'Downloads text from the host and runs it as PowerShell in memory' },
      { id: 'save-run', label: 'Downloads an executable to disk and schedules it to run at logon' },
      { id: 'upload', label: 'Uploads collected data to the host' },
      { id: 'check', label: 'Only checks whether the host is reachable' },
    ];
    return {
      artifacts: pick(ev.artifacts, ev.paths.script, ev.paths.sysmonXml, ev.paths.sysmonJsonl),
      questions: [
        {
          id: 'ip',
          prompt: 'What is the stage-2 host as a dotted-quad IPv4 address?',
          kind: 'text',
          placeholder: 'a.b.c.d',
          why: `The host was written as ${IP_FORM_LABELS[w.attacker.ipForm]}.`,
        },
        {
          id: 'action',
          prompt: 'What does the last line of the script do?',
          kind: 'choice',
          options: shuffled(w.seed, 'm02.action', actOpts),
          why: 'irm (Invoke-RestMethod) fetches the response body; piping it to iex (Invoke-Expression) runs it as code without saving it.',
        },
      ],
      expected: { ip: w.attacker.stage2Ip, action: 'exec-memory' },
      check(qid, a) {
        const t = asText(a);
        if (qid === 'ip') return normIp(t) === w.attacker.stage2Ip;
        if (qid === 'action') return t === 'exec-memory';
        return false;
      },
    };
  },
};
