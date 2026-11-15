import { evidenceFor } from '../evidence';
import type { ModuleDef } from '../types';
import { asList, pick, shuffled } from './helpers';

const ACCEPTED: string[][] = [
  ['memory', 'live', 'triage'],
  ['live', 'memory', 'triage'],
];

export const m15: ModuleDef = {
  id: 'm15',
  number: 15,
  title: 'Collection order',
  short: 'For a hands-on-keyboard intrusion, choose the first three artifacts to collect and justify the order.',
  tracks: ['t2'],
  difficulty: 2,
  objective: 'Choose the first three things to collect from a host with a live intruder, in order, and justify the order.',
  background: [
    'RFC 3227 orders evidence from most to least volatile: registers and cache; routing table, ARP cache, process table, kernel statistics and memory; temporary file systems; disk; remote logging and monitoring data; physical configuration and network topology; archival media.',
    'With a **hands-on-keyboard** intruder, the most valuable evidence is what is happening right now: running processes, network connections, logged-on sessions, and whatever exists only in memory (injected code, fileless stages, decrypted configs, command history in a live shell).',
    'Practitioners disagree on the first step. Some take a memory image first, because every live-response tool you run changes memory. Others grab a quick snapshot of processes and connections first, because it takes seconds and a memory image can take many minutes. **Both are defensible**; what matters is that you say why.',
    'After volatile data, a **targeted triage collection** (event logs, registry hives, prefetch, Amcache, the MFT) answers most questions in minutes. A full disk image takes hours and can wait.',
    'Network-device logs (proxy, firewall, DNS) live off the host and are retained centrally, so they are not at risk from the intruder\'s next move on this machine. Collect them, but not first.',
    'Record what you ran and when (chain of custody), and use trusted tools, not the binaries on the compromised host.',
  ],
  evidenceNote: 'Read the collection scenario, then build your order from the list.',
  hints: [
    'Which of these disappear when the process exits, the connection closes or the machine restarts?',
    'Memory and live state both go first and second, in either order, if you can justify it. What comes third?',
    'Between a full disk image and a targeted triage collection, which answers the most questions fastest?',
  ],
  explainPrompt: 'Explain your order, what each item gives you, and what running your collection tools changes on the host.',
  rubric: {
    listenFor: [
      'Order of volatility named and applied, with RFC 3227 as the source.',
      'Memory and live state first, with a reason for which comes first.',
      'Targeted triage before a full disk image, and why (speed to answers).',
      'Off-host logs placed later, because they are retained centrally.',
      'Awareness that collection changes the system: trusted tools, documented times, chain of custody.',
    ],
    weak: '"Image the hard drive first so we have everything."',
    solid: 'Memory and live state first in a defensible order, then triage, with order of volatility as the reason.',
    strong: 'All of that, plus what each item answers in this scenario, the tool-footprint trade-off, and chain-of-custody notes.',
  },
  followUps: [
    'Why not image the full disk first?',
    'What changes on the host when you run live-response tools?',
    'How do you document chain of custody for remote collection?',
  ],
  mistakes: [
    'Taking a full disk image first and losing the live state while it runs.',
    'Pulling network-device logs first: they are not going anywhere in the next hour.',
    'Rebooting to install a collection tool.',
  ],
  references: [
    { label: 'RFC 3227: Guidelines for Evidence Collection and Archiving', url: 'https://datatracker.ietf.org/doc/rfc3227/' },
    { label: 'NIST SP 800-86: Integrating Forensic Techniques into Incident Response', url: 'https://csrc.nist.gov/pubs/sp/800/86/final' },
  ],
  build(w) {
    const ev = evidenceFor(w);
    const opts = [
      { id: 'memory', label: 'Memory image' },
      { id: 'live', label: 'Live-response snapshot: running processes, network connections, logged-on users' },
      { id: 'triage', label: 'Targeted triage: event logs, registry hives, prefetch, Amcache, MFT' },
      { id: 'disk', label: 'Full disk image' },
      { id: 'netlogs', label: 'Proxy and firewall logs from the network team' },
      { id: 'mail', label: 'Email gateway logs' },
    ];
    return {
      artifacts: pick(ev.artifacts, ev.paths.collectionBrief),
      questions: [
        {
          id: 'order',
          prompt: 'Choose the first three things to collect, in order.',
          kind: 'order',
          slots: 3,
          options: shuffled(w.seed, 'm15.order', opts),
          why: 'Most volatile first: memory and live state (either order, if justified), then a targeted triage collection. The full disk image and off-host logs come later.',
        },
      ],
      expected: { order: ACCEPTED[0] },
      check(qid, a) {
        if (qid !== 'order') return false;
        const list = asList(a);
        return ACCEPTED.some((acc) => acc.length === list.length && acc.every((x, i) => x === list[i]));
      },
    };
  },
};
