import { evidenceFor } from '../evidence';
import type { ModuleDef } from '../types';
import type { World } from '../world';
import { asText, pick, shuffled } from './helpers';

export function isolationAnswer(w: World): 'edr' | 'network' {
  return w.containment === 'edr-laptop' ? 'edr' : 'network';
}

export const ISOLATION_OPTIONS = [
  { id: 'edr', label: 'Use EDR network containment: the host stays on and keeps only its EDR management channel' },
  { id: 'network', label: 'Isolate at the network layer (shut the switch port, move it to a quarantine VLAN, or block it at the firewall) and leave it running' },
  { id: 'shutdown', label: 'Shut the host down cleanly from the Start menu' },
  { id: 'unplug', label: 'Pull the power cable' },
  { id: 'reimage', label: 'Reimage the host straight away' },
  { id: 'account', label: 'Only disable the user\'s account and leave the host connected' },
];

export const m11: ModuleDef = {
  id: 'm11',
  number: 11,
  title: 'Containment while preserving evidence',
  short: 'Pick an isolation method that stops the attacker without destroying volatile evidence.',
  tracks: ['t2'],
  difficulty: 2,
  objective: 'Given the scenario, choose how to isolate the host, what power state to leave it in, and what to preserve first.',
  background: [
    'Containment has two jobs that pull against each other: **stop the damage** (beaconing, spread, data theft) and **keep the evidence** you need to scope the intrusion.',
    'Powering a machine off destroys volatile evidence: running processes, network connections, injected code, decrypted configs and fileless stages that only ever existed in memory. That is why "pull the plug" is usually the wrong first move.',
    '**With a healthy EDR agent**, network containment cuts the host off from everything except the EDR management channel, so you can still collect memory and run live response remotely.',
    '**Without working EDR**, isolate at the network layer instead: shut the switch port, move the host to a quarantine VLAN, or block it at the firewall. Leave it powered on.',
    'Preserve in **order of volatility** (RFC 3227): memory and live system state before disk. Avoid logging in interactively with privileged domain credentials on a compromised host, because that can expose those credentials to the attacker.',
    'There is no universal answer: a scenario detail (is EDR healthy? is it a critical server?) changes the right call. Interviewers want to hear you reason from those details.',
  ],
  evidenceNote: 'Read the containment scenario. The details that matter are which tools work on this host and what kind of host it is.',
  hints: [
    'First question to ask: do you still have a working remote tool on this host?',
    'Whatever you choose, ask what happens to the contents of memory.',
    'RFC 3227 lists memory before disk. Which evidence disappears first?',
  ],
  explainPrompt: 'Explain your containment choice, what you would do immediately before and after it, and what you would avoid.',
  rubric: {
    listenFor: [
      'Reasoning starts from the scenario: EDR health and host role.',
      'Keeps the host powered on and explains what would be lost otherwise.',
      'Memory first, then live state, then disk triage.',
      'Coordination: incident commander, network team, business owner for a critical server.',
      'Credential hygiene: no interactive privileged logons on the compromised host.',
    ],
    weak: '"Unplug it from the network and shut it down."',
    solid: 'Picks the right isolation method for the scenario, keeps it on, and preserves memory first.',
    strong: 'All of that, plus timing (collect memory before or right after isolating, depending on the risk), the tip-off risk, and who needs to be in the loop.',
  },
  followUps: [
    'When might you deliberately delay containment?',
    'Could isolating the host tip off the attacker? What would you do about that?',
    'How would you collect memory from a host you have just isolated?',
  ],
  mistakes: [
    'Pulling the plug or shutting down first, which loses memory.',
    'Reimaging before collecting evidence.',
    'Logging in with a domain admin account to "take a look".',
  ],
  references: [
    { label: 'RFC 3227: Guidelines for Evidence Collection and Archiving', url: 'https://datatracker.ietf.org/doc/rfc3227/' },
    { label: 'NIST SP 800-61r3: Incident Response Recommendations', url: 'https://csrc.nist.gov/pubs/sp/800/61/r3/final' },
  ],
  build(w) {
    const ev = evidenceFor(w);
    const powerOpts = [
      { id: 'on', label: 'Leave it powered on and logged in as it is' },
      { id: 'off', label: 'Power it off' },
      { id: 'reboot', label: 'Reboot it to kill the malware process' },
      { id: 'sleep', label: 'Put it to sleep' },
    ];
    const firstOpts = [
      { id: 'memory', label: 'A memory image' },
      { id: 'disk', label: 'A full disk image' },
      { id: 'logs', label: 'The event logs' },
      { id: 'browser', label: 'Browser history' },
    ];
    return {
      brief: undefined,
      artifacts: pick(ev.artifacts, ev.paths.containmentBrief),
      questions: [
        {
          id: 'isolate',
          prompt: 'How do you isolate the host in this scenario?',
          kind: 'choice',
          options: shuffled(w.seed, 'm11.isolate', ISOLATION_OPTIONS),
          why:
            w.containment === 'edr-laptop'
              ? 'EDR is healthy, so EDR network containment isolates the host while keeping a channel for remote memory collection and live response.'
              : 'There is no working remote tool, so isolate at the network layer and leave the host running to keep memory.',
        },
        {
          id: 'power',
          prompt: 'What power state do you leave it in?',
          kind: 'choice',
          options: shuffled(w.seed, 'm11.power', powerOpts),
          why: 'Powering off, rebooting or sleeping risks losing or changing memory, the most volatile evidence.',
        },
        {
          id: 'first',
          prompt: 'What do you preserve first?',
          kind: 'choice',
          options: shuffled(w.seed, 'm11.first', firstOpts),
          why: 'Memory is the most volatile evidence on the list (RFC 3227); disk and logs survive longer.',
        },
      ],
      expected: { isolate: isolationAnswer(w), power: 'on', first: 'memory' },
      check(qid, a) {
        const t = asText(a);
        if (qid === 'isolate') return t === isolationAnswer(w);
        if (qid === 'power') return t === 'on';
        if (qid === 'first') return t === 'memory';
        return false;
      },
    };
  },
};
