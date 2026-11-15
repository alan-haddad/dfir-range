import { Rng } from '../lib/prng';
import { docIp } from '../lib/ip';
import { normText } from '../lib/normalize';
import type { ModuleDef } from '../types';
import type { World } from '../world';
import { asText, MITRE, shuffled } from './helpers';

const FIRST = ['k', 'm', 'r', 't', 'j', 'a', 'p', 'l'];
const LAST = ['holt', 'navarro', 'quinn', 'osei', 'brandt', 'farris', 'lund', 'okoro'];
const SVC = ['svc-backup', 'svc-sqlrpt', 'svc-scan', 'svc-sftp', 'svc-print', 'svc-etl'];
const FOREIGN = ['RO', 'NL', 'VN', 'BR', 'SG', 'ZA', 'LT', 'MD'];

interface Line {
  t: Date;
  ok: boolean;
  user: string;
  src: string;
  mfa: 'yes' | 'no';
  geo: string;
  bad?: boolean;
}

export function authScenario(w: World) {
  const rng = new Rng(`m04:${w.seed}`);
  const users = rng.shuffle(FIRST.map((f, i) => `${f}${LAST[i]}`)).slice(0, 3);
  const [svcBad, svcGood] = rng.shuffle(SVC);
  const internal = () => `10.20.${rng.int(2, 60)}.${rng.int(10, 240)}`;
  const attacker = docIp(rng, '203.0.113');
  const home = docIp(rng, '198.51.100');
  const batchServer = `10.20.5.${rng.int(10, 40)}`;
  const geo = rng.pick(FOREIGN);
  let t = new Date(w.t.emailReceived.getTime() - rng.int(3, 9) * 3600 * 1000);
  const step = () => (t = new Date(t.getTime() + rng.int(25, 190) * 1000));

  const benign: Omit<Line, 't'>[] = [
    { ok: true, user: users[0], src: internal(), mfa: 'yes', geo: 'US' },
    { ok: false, user: users[1], src: internal(), mfa: 'no', geo: 'US' },
    { ok: true, user: users[1], src: internal(), mfa: 'yes', geo: 'US' },
    { ok: true, user: users[2], src: home, mfa: 'yes', geo: 'US' },
    { ok: true, user: svcGood, src: batchServer, mfa: 'no', geo: 'US' },
  ];
  const attack: Omit<Line, 't'>[] = [
    { ok: false, user: svcBad, src: attacker, mfa: 'no', geo },
    { ok: false, user: svcBad, src: attacker, mfa: 'no', geo },
    { ok: true, user: svcBad, src: attacker, mfa: 'no', geo, bad: true },
  ];
  // Splice the attack burst into the benign sequence at a random point; keep the failures right before the success.
  const at = rng.int(1, benign.length - 1);
  const ordered = [...benign.slice(0, at), ...attack, ...benign.slice(at)];
  // Keep the second user's success right after their own failure.
  const lines: Line[] = ordered.map((l) => ({ ...l, t: new Date(step().getTime()) }));
  const badIndex = lines.findIndex((l) => l.bad);
  const userW = Math.max(...lines.map((l) => l.user.length)) + 5;
  const srcW = Math.max(...lines.map((l) => l.src.length)) + 4;
  const text =
    lines
      .map((l, i) => {
        const hh = l.t.toISOString().slice(11, 19);
        return `${String(i + 1).padStart(2)}  ${hh}Z  ${l.ok ? 'auth ok  ' : 'auth fail'}  ${`user=${l.user}`.padEnd(userW + 1)}  ${`src=${l.src}`.padEnd(srcW)}  mfa=${l.mfa.padEnd(3)}  geo=${l.geo}`;
      })
      .join('\n') + '\n';
  return { text, line: badIndex + 1, svcBad, attacker, geo };
}

export const m04: ModuleDef = {
  id: 'm04',
  number: 4,
  title: 'Authentication anomaly',
  short: 'Pick the one compromised login out of a short auth log by stacking the tells.',
  tracks: ['t1', 't2'],
  difficulty: 1,
  objective: 'Find the single line that is the compromise in a short SSO/VPN gateway log, and say out loud which tells make it stand out from the decoys.',
  background: [
    'No single field proves a compromise. An external IP alone is a remote employee; no MFA alone is a service account on a batch server; a failed login alone is a typo. **Stack the tells**: the line that combines several is the one to escalate.',
    'Tells worth stacking: a **service account** (it should never log in interactively from the internet), **no MFA**, an **external source** where the account normally authenticates internally, a **geography** the organization does not operate in, and **timing**: a success immediately after failures from the same source looks like a password guessed or sprayed.',
    'Service accounts are a favorite target because they are often exempt from MFA, have passwords that rarely change, and hold broad permissions. "This account never logs in from outside" is the baseline that makes the anomaly visible.',
    'Geo and ASN fields come from IP enrichment in your SIEM or identity provider. Treat them as a strong hint, not proof, since VPNs and proxies move people around.',
  ],
  evidenceNote: 'One SSO/VPN gateway log. Each line is one authentication: result, account, source IP, whether MFA was satisfied, and enriched country.',
  hints: [
    'Rule out each decoy with a reason: who is internal, who used MFA, which account types are expected to skip MFA.',
    'Look for lines that share a source IP. Failures right before a success matter.',
    'The compromise combines a service account, an external source, no MFA and an unusual country, right after failures from the same IP.',
  ],
  explainPrompt: 'Say which line it is and walk through every tell, then explain why each decoy is not it.',
  rubric: {
    listenFor: [
      'The line number, plus the tells stacked together, not just one.',
      'Decoys explained away: internal service account without MFA, remote employee with MFA, internal typo.',
      'The failure-then-success pattern from the same source called out as guessing or spraying.',
      'Next steps: disable or reset the service account, review what it touched after the login, hunt the source IP across other accounts, check where else the password is used.',
    ],
    weak: '"Line X, because it is from a foreign country."',
    solid: 'Names the line and stacks service account, external source, no MFA, unusual geo and the preceding failures.',
    strong: 'All of that, plus why each decoy is benign, the immediate containment for a service account, and how to scope what the account did next.',
  },
  followUps: [
    'The service account is used by a nightly job. How do you contain it without breaking the business?',
    'What would you look for in the minutes after the successful login?',
    'How would you detect this automatically without alerting on every remote employee?',
  ],
  mistakes: [
    'Picking the first failure, or any external IP, without stacking tells.',
    'Flagging the internal service account that skips MFA, which is normal for a batch server.',
    'Treating geo enrichment as proof rather than a strong hint.',
  ],
  references: [MITRE('T1078', 'Valid Accounts'), MITRE('T1110.003', 'Brute Force: Password Spraying')],
  build(w) {
    const sc = authScenario(w);
    const tellOpts = [
      { id: 'stack', label: 'A service account, from an external IP, without MFA, from an unusual country, right after failures from the same IP' },
      { id: 'foreign', label: 'Any login from outside the US' },
      { id: 'nomfa', label: 'Any login without MFA' },
      { id: 'fail', label: 'The first failed login in the log' },
    ];
    return {
      artifacts: [{ path: 'tenant/sso-gateway.log', content: sc.text, title: 'SSO / VPN gateway authentication log' }],
      questions: [
        { id: 'line', prompt: 'Which line number is the compromise?', kind: 'text', placeholder: 'line number', why: `Line ${sc.line}: ${sc.svcBad} succeeds from ${sc.attacker} with no MFA, geo=${sc.geo}, right after failures from the same IP.` },
        { id: 'tell', prompt: 'What makes it the compromise?', kind: 'choice', options: shuffled(w.seed, 'm04.tell', tellOpts), why: 'Each tell alone has a benign explanation; together they do not.' },
      ],
      expected: { line: String(sc.line), tell: 'stack' },
      check(qid, a) {
        const t = asText(a);
        if (qid === 'line') return normText(t).replace(/^line\s*/, '') === String(sc.line);
        if (qid === 'tell') return t === 'stack';
        return false;
      },
    };
  },
};
