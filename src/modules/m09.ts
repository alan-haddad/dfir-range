import { Rng } from '../lib/prng';
import { normText } from '../lib/normalize';
import type { ModuleDef } from '../types';
import { ORG, type World } from '../world';
import { asText, MITRE, shuffled } from './helpers';

interface Cmd {
  cmd: (w: World) => string;
  techniques: string[];
  name: string;
}

const POOL: Cmd[] = [
  { cmd: () => 'whoami /all', techniques: ['T1033'], name: 'System Owner/User Discovery' },
  { cmd: () => 'net group "Domain Admins" /domain', techniques: ['T1069.002', 'T1069'], name: 'Permission Groups Discovery: Domain Groups' },
  { cmd: () => `nltest /dclist:${ORG.netbios.toLowerCase()}`, techniques: ['T1018'], name: 'Remote System Discovery' },
  { cmd: () => 'nltest /domain_trusts', techniques: ['T1482'], name: 'Domain Trust Discovery' },
  { cmd: () => 'systeminfo', techniques: ['T1082'], name: 'System Information Discovery' },
  { cmd: () => 'ipconfig /all', techniques: ['T1016'], name: 'System Network Configuration Discovery' },
  { cmd: () => 'arp -a', techniques: ['T1016', 'T1018'], name: 'System Network Configuration / Remote System Discovery' },
  { cmd: () => 'net view /all', techniques: ['T1135', 'T1018'], name: 'Network Share / Remote System Discovery' },
  { cmd: () => 'tasklist /v', techniques: ['T1057'], name: 'Process Discovery' },
  { cmd: () => 'net user /domain', techniques: ['T1087.002', 'T1087'], name: 'Account Discovery: Domain Account' },
  { cmd: () => 'quser', techniques: ['T1033'], name: 'System Owner/User Discovery' },
  { cmd: () => 'net share', techniques: ['T1135'], name: 'Network Share Discovery' },
];

export function discoveryScenario(w: World) {
  const rng = new Rng(`m09:${w.seed}`);
  const cmds = rng.shuffle(POOL).slice(0, rng.int(6, 8));
  let t = new Date(w.t.configWritten.getTime() + rng.int(1200, 2400) * 1000);
  const lines = cmds.map((c) => {
    t = new Date(t.getTime() + rng.int(3, 9) * 1000);
    return `${t.toISOString().replace('T', ' ').slice(0, 19)}Z  ${w.host.name}  ${ORG.netbios}\\${w.victim.username}  cmd.exe > ${c.cmd(w)}`;
  });
  const asked = rng.pick(cmds);
  const text = ['EDR process events, single host, parent process cmd.exe (interactive session)', '', ...lines, ''].join('\n');
  return { text, asked, askedCmd: asked.cmd(w) };
}

export const m09: ModuleDef = {
  id: 'm09',
  number: 9,
  title: 'Discovery burst',
  short: 'A minute of enumeration commands from one host: name the activity, the tactic and the techniques.',
  tracks: ['t1', 't2'],
  difficulty: 1,
  objective: 'Recognize a burst of enumeration commands as hands-on-keyboard discovery, map it to the MITRE ATT&CK tactic, and map individual commands to techniques.',
  background: [
    'After landing on a host, an intruder needs to learn where they are: who they are, what privileges they have, what the domain looks like, which machines and shares are reachable. Built-in tools (`whoami`, `net`, `nltest`, `systeminfo`, `arp`, `ipconfig`) do the job and blend in with admin activity.',
    'In MITRE ATT&CK this is the **Discovery** tactic, **TA0007**. Individual commands map to techniques: `whoami` to System Owner/User Discovery (T1033), `net group "Domain Admins" /domain` to Permission Groups Discovery (T1069.002), `nltest /domain_trusts` to Domain Trust Discovery (T1482), `systeminfo` to System Information Discovery (T1082), and so on.',
    'The tell is the **burst**: many different enumeration commands from one interactive session within a minute or two, from a user who does not normally run them. One `ipconfig` is noise; this sequence is a person (or script) taking inventory.',
    'Some commands map to more than one technique (for example `arp -a` shows network configuration and reveals remote systems). Interviewers care that you can justify a mapping, not that you recite one ID.',
  ],
  evidenceNote: 'EDR process events from one host, all launched from an interactive cmd.exe.',
  hints: [
    'What question is each command answering for the person typing it?',
    'There is one ATT&CK tactic that covers "learning about the environment".',
    'Look up the highlighted command on attack.mitre.org; the technique pages list example commands.',
  ],
  explainPrompt: 'Say what the attacker is doing, the tactic and its ID, map two or three commands to techniques, and say what you would expect them to do next.',
  rubric: {
    listenFor: [
      'Activity named: post-compromise discovery or reconnaissance of the host and domain.',
      'Tactic named with its ID: Discovery, TA0007.',
      'Two or three commands mapped to techniques, with reasons.',
      'Burst and context explained: one interactive session, many tools, short window, unusual user.',
      'What comes next: privilege escalation or lateral movement toward what they found (domain admins, DCs, shares).',
    ],
    weak: '"They are running commands."',
    solid: 'Discovery, TA0007, plus a few correct technique mappings.',
    strong: 'All of that, plus why the burst pattern matters, what the attacker learned, and the likely next move.',
  },
  followUps: [
    'An admin runs some of these daily. How do you tell admin work from an intruder?',
    'What would you check next on this host and in the domain?',
    'How would you detect this as a pattern rather than per command?',
  ],
  mistakes: [
    'Naming a technique instead of the tactic, or confusing the tactic with Lateral Movement.',
    'Treating each command as a separate alert instead of reading the sequence.',
    'Forgetting the user and session context, which separates admins from intruders.',
  ],
  references: [
    { label: 'MITRE ATT&CK TA0007: Discovery', url: 'https://attack.mitre.org/tactics/TA0007/' },
    MITRE('T1033', 'System Owner/User Discovery'),
    MITRE('T1069.002', 'Permission Groups Discovery: Domain Groups'),
    MITRE('T1482', 'Domain Trust Discovery'),
  ],
  build(w) {
    const sc = discoveryScenario(w);
    const actOpts = [
      { id: 'discovery', label: 'Enumerating the user, host, network and domain after gaining access' },
      { id: 'exfil', label: 'Exfiltrating data' },
      { id: 'persist', label: 'Setting up persistence' },
      { id: 'admin', label: 'Routine scheduled maintenance by IT' },
    ];
    return {
      artifacts: [{ path: `${w.host.name}/live-response/edr-process-events.txt`, content: sc.text, title: 'EDR process events (one minute, one host)' }],
      questions: [
        { id: 'activity', prompt: 'What is the attacker doing?', kind: 'choice', options: shuffled(w.seed, 'm09.a', actOpts), why: 'A burst of built-in enumeration tools from one interactive session is discovery.' },
        { id: 'tactic', prompt: 'Which MITRE ATT&CK tactic is this? Give the tactic ID.', kind: 'text', placeholder: 'TA00xx', why: 'Discovery is TA0007.' },
        { id: 'technique', prompt: `Which ATT&CK technique ID fits \`${sc.askedCmd}\`?`, kind: 'text', placeholder: 'T1xxx', why: `${sc.asked.name}: ${sc.asked.techniques.join(' or ')}.` },
      ],
      expected: { activity: 'discovery', tactic: 'TA0007', technique: sc.asked.techniques[0] },
      check(qid, a) {
        const t = normText(asText(a)).toUpperCase();
        if (qid === 'activity') return asText(a) === 'discovery';
        if (qid === 'tactic') return t === 'TA0007' || t === 'DISCOVERY' || t.startsWith('TA0007');
        if (qid === 'technique') return sc.asked.techniques.some((x) => t === x || t.startsWith(`${x} `));
        return false;
      },
    };
  },
};

export const _pool = POOL;
