import { evidenceFor } from '../evidence';
import { normDomain, normExt } from '../lib/normalize';
import type { ModuleDef } from '../types';
import { asText, MITRE, pick, shuffled } from './helpers';

export const m05: ModuleDef = {
  id: 'm05',
  number: 5,
  title: 'Mark-of-the-Web',
  short: 'Read a Zone.Identifier: HostUrl vs ReferrerUrl, ZoneId=3 and the double extension.',
  tracks: ['t1', 't2'],
  difficulty: 1,
  objective: 'Use the Zone.Identifier stream on the downloaded file to find where it really came from, explain ZoneId=3, and identify the file\'s true type.',
  background: [
    'When a browser saves a file from the internet onto an NTFS volume, Windows attaches an alternate data stream named `Zone.Identifier`: the **Mark-of-the-Web (MOTW)**. SmartScreen and Office Protected View use it to decide how much to trust the file.',
    '`ZoneId` is a value from the URLZONE enumeration: `0` Local machine, `1` Local intranet, `2` Trusted sites, `3` Internet, `4` Restricted sites.',
    '`ReferrerUrl` is the page the user was on when the download started. `HostUrl` is the URL the file actually came from. They often differ: a landing page links to a file hosted somewhere else. **HostUrl is the download source**, so it is the one to block and hunt; ReferrerUrl leads you back to how the user got there.',
    '**Double extension:** Windows hides extensions for known file types by default, so `invoice.pdf.exe` is displayed as `invoice.pdf`. The last extension decides how Windows opens the file.',
    'Attackers try to avoid MOTW, for example by delivering files inside containers that do not pass the mark on to their contents. A missing Zone.Identifier on a file that clearly came from the internet is itself worth noting.',
  ],
  evidenceNote: 'The Zone.Identifier stream of invoice.pdf.exe (collected as a separate text file), plus the Sysmon log.',
  hints: [
    'There are two URLs in the stream. Only one of them served the file.',
    'Look up the ZoneId value in the URLZONE list in the background section.',
    'Read the file name from right to left. Which extension does Windows act on?',
  ],
  explainPrompt: 'Explain the difference between HostUrl and ReferrerUrl, what ZoneId=3 means for the user, and why the user thought this was a PDF.',
  rubric: {
    listenFor: [
      'HostUrl identified as the download source, and ReferrerUrl as the page the user came from.',
      'ZoneId 3 = Internet zone, and what MOTW triggers (SmartScreen, Protected View).',
      'Double extension plus hidden known extensions explains why the user thought it was a PDF.',
      'Next steps: proxy logs for both domains, the email that linked to the referrer, other users who visited, block the file host.',
    ],
    weak: '"It came from the internet, ZoneId 3."',
    solid: 'Names the HostUrl domain as the source, explains ZoneId 3 and the double extension.',
    strong: 'All of that, plus how ReferrerUrl links the download back to the phishing email, and what a missing MOTW would have meant.',
  },
  followUps: [
    'If this file had no Zone.Identifier at all, what could explain that?',
    'How would you find the email that led to this download?',
    'What would you block, and where?',
  ],
  mistakes: [
    'Reporting the ReferrerUrl domain as the download source.',
    'Calling ZoneId 3 "Restricted" or "untrusted". That is ZoneId 4.',
    'Missing the double extension.',
  ],
  references: [
    { label: 'Microsoft: URLZONE enumeration', url: 'https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms537175(v=vs.85)' },
    MITRE('T1553.005', 'Subvert Trust Controls: Mark-of-the-Web Bypass'),
    MITRE('T1036.007', 'Masquerading: Double File Extension'),
    MITRE('T1204.002', 'User Execution: Malicious File'),
  ],
  build(w) {
    const ev = evidenceFor(w);
    const zoneOpts = [
      { id: 'internet', label: 'Internet zone' },
      { id: 'restricted', label: 'Restricted sites zone' },
      { id: 'intranet', label: 'Local intranet zone' },
      { id: 'trusted', label: 'Trusted sites zone' },
      { id: 'local', label: 'Local machine zone' },
    ];
    return {
      artifacts: pick(ev.artifacts, ev.paths.zone, ev.paths.sysmonXml),
      questions: [
        {
          id: 'host',
          prompt: 'Which domain actually served the file?',
          kind: 'text',
          placeholder: 'domain (defanged is fine)',
          why: 'HostUrl records where the bytes came from. ReferrerUrl is only the page that linked to it.',
        },
        {
          id: 'zone',
          prompt: 'What does ZoneId=3 mean?',
          kind: 'choice',
          options: shuffled(w.seed, 'm05.zone', zoneOpts),
          why: 'In the URLZONE enumeration, 3 is URLZONE_INTERNET.',
        },
        {
          id: 'ext',
          prompt: 'What is the file\'s true extension?',
          kind: 'text',
          placeholder: 'e.g. docx',
          why: 'Windows acts on the last extension. ".pdf" is part of the name, chosen to fool a user with extensions hidden.',
        },
      ],
      expected: { host: w.attacker.fileHostDomain, zone: 'internet', ext: 'exe' },
      check(qid, a) {
        const t = asText(a);
        if (qid === 'host') return normDomain(t) === w.attacker.fileHostDomain;
        if (qid === 'zone') return t === 'internet';
        if (qid === 'ext') return normExt(t) === 'exe';
        return false;
      },
    };
  },
};
