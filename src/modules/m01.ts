import { evidenceFor } from '../evidence';
import { normText, normUrl } from '../lib/normalize';
import type { ModuleDef } from '../types';
import { asText, MITRE, pick, shuffled } from './helpers';

export const m01: ModuleDef = {
  id: 'm01',
  number: 1,
  title: 'PowerShell -EncodedCommand',
  short: 'Decode a Base64 PowerShell command, explain UTF-16LE, extract the URL.',
  tracks: ['t1', 't2'],
  difficulty: 1,
  objective:
    'Find the PowerShell process launched with an encoded command, decode it, explain why the decoded bytes have a null between every character, and pull out the URL it fetches.',
  background: [
    "PowerShell's `-EncodedCommand` parameter takes a Base64 string and runs what it decodes to. PowerShell also accepts unambiguous abbreviations such as `-enc`, `-ec` and `-e`. Microsoft's documentation states that the string must be UTF-16LE before it is Base64-encoded.",
    'Admin tools use encoded commands to avoid quoting problems. Attackers use them because the command line no longer contains readable keywords for detections to match. **Base64 is transport, not encryption**: anyone can reverse it, so the analyst move is always to decode first and reason about what the command does.',
    '**Why the null bytes appear:** UTF-16LE stores each ASCII character as two bytes: the character, then `0x00`. Decode the Base64 and look at it as raw bytes or UTF-8 and every other byte is `00` (dots in a hexdump). That is not corruption. It is the tell that you should decode the text as UTF-16LE.',
    'A tell you can spot before decoding: an encoded command that starts with `JAB` usually begins with `$` followed by a letter, because that is how `$` plus a null byte plus a letter looks in Base64.',
    '**Where you see it:** Sysmon Event ID 1 (process creation) records the full `CommandLine` and the parent process. Security Event 4688 records it too, but only when "Include command line in process creation events" is enabled. PowerShell script block logging (Event 4104) records script text as PowerShell compiles it.',
  ],
  evidenceNote: 'Use the Sysmon log (XML or JSON lines; they hold the same events). Find the powershell.exe process whose command line carries a long Base64 argument.',
  hints: [
    'Filter to Event ID 1 where the Image ends in powershell.exe. Several PowerShell processes ran; only one has a long Base64 argument.',
    'Base64-decode the argument. If a dot or 00 appears between every character, decode it as UTF-16LE instead of UTF-8.',
    "In CyberChef: From Base64, then Decode text with UTF-16LE (1200). In Python: base64.b64decode(s).decode('utf-16-le'). Then read the ParentImage field of the same event.",
  ],
  explainPrompt: 'Explain out loud what the encoded command does, why you decoded it as UTF-16LE, and what you would pivot to next.',
  rubric: {
    listenFor: [
      'Base64 is encoding, not encryption, so you decode before judging.',
      'UTF-16LE explained: two bytes per character, the second is 0x00 for ASCII.',
      'What the decoded command does: downloads a script to TEMP and runs it hidden with -ExecutionPolicy Bypass.',
      'The parent process: PowerShell was launched by a file in the Downloads folder.',
      'Next pivots: the file it wrote (Sysmon EID 11), the domain in DNS/proxy logs across the fleet, and script block logging (4104).',
    ],
    weak: '"It\'s Base64. I decoded it and there\'s a URL."',
    solid: 'Decodes as UTF-16LE and explains the null bytes, extracts the URL, and notes it was launched by invoice.pdf.exe from Downloads.',
    strong:
      'All of that, plus: encoded commands are suspicious but not proof (admin tools use them); what the command does step by step; and the next three pivots, in priority order, with the evidence each one would give.',
  },
  followUps: [
    'How would you find every host that ran an encoded PowerShell command this week?',
    'What is the difference between Sysmon Event ID 1 and Security Event 4688 for this investigation?',
    'Is -EncodedCommand always malicious? What would make you close this as benign?',
    'What does -ExecutionPolicy Bypass actually protect against?',
  ],
  mistakes: [
    'Decoding as UTF-8, seeing dots or garbage, and concluding the blob is encrypted or corrupted.',
    'Stopping at the URL without saying what the command does with it.',
    'Ignoring the parent process, which is what turns "PowerShell ran" into "a downloaded file launched PowerShell".',
    'Treating execution policy as a security boundary. Microsoft documents that it is not one.',
  ],
  references: [
    { label: 'Microsoft: about_PowerShell_exe (-EncodedCommand)', url: 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe' },
    { label: 'Microsoft: about_Execution_Policies', url: 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies' },
    MITRE('T1059.001', 'Command and Scripting Interpreter: PowerShell'),
    MITRE('T1027.010', 'Command Obfuscation'),
    MITRE('T1140', 'Deobfuscate/Decode Files or Information'),
  ],
  build(w) {
    const ev = evidenceFor(w);
    const encOpts = [
      { id: 'utf16le', label: 'UTF-16LE' },
      { id: 'utf8', label: 'UTF-8' },
      { id: 'ascii', label: 'ASCII' },
      { id: 'utf32', label: 'UTF-32' },
    ];
    return {
      artifacts: pick(ev.artifacts, ev.paths.caseBrief, ev.paths.sysmonXml, ev.paths.sysmonJsonl),
      questions: [
        {
          id: 'url',
          prompt: 'What URL does the decoded command download from?',
          kind: 'text',
          placeholder: 'https://…  (defanged is fine)',
          why: 'The decoded command passes this URL to a WebClient DownloadFile call, saves the result to TEMP and runs it.',
        },
        {
          id: 'encoding',
          prompt: 'Which text encoding does the decoded command use?',
          kind: 'choice',
          options: shuffled(w.seed, 'm01.encoding', encOpts),
          why: 'PowerShell requires UTF-16LE for -EncodedCommand. That is why every ASCII character is followed by a 0x00 byte.',
        },
        {
          id: 'parent',
          prompt: 'What is the file name of the process that launched the encoded PowerShell?',
          kind: 'text',
          placeholder: 'e.g. something.exe',
          why: 'ParentImage on the same Event ID 1 shows the downloaded invoice.pdf.exe started PowerShell.',
        },
      ],
      expected: { url: w.attacker.stage1Url, encoding: 'utf16le', parent: 'invoice.pdf.exe' },
      check(qid, a) {
        const t = asText(a);
        if (qid === 'url') return normUrl(t) === normUrl(w.attacker.stage1Url);
        if (qid === 'encoding') return t === 'utf16le';
        if (qid === 'parent') {
          const v = normText(t).replace(/^.*\\/, '');
          return v === 'invoice.pdf.exe';
        }
        return false;
      },
    };
  },
};
