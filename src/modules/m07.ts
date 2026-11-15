import { evidenceFor } from '../evidence';
import { normDomain } from '../lib/normalize';
import type { ModuleDef } from '../types';
import { ORG } from '../world';
import { asText, MITRE, pick, shuffled } from './helpers';

export const m07: ModuleDef = {
  id: 'm07',
  number: 7,
  title: 'Phishing header analysis',
  short: 'Spoofed From on your own domain, look-alike Reply-To, SPF vs DMARC: name the strongest indicator.',
  tracks: ['t1', 't2'],
  difficulty: 2,
  objective:
    'Read the raw headers of the email the user received, name the single strongest indicator that the From address is forged, find the look-alike Reply-To domain, and explain why the message was delivered anyway.',
  background: [
    'An email carries more than one sender identity. The **envelope sender** (`Return-Path`, also called RFC5321.MailFrom) is what SPF checks. The **DKIM signing domain** (`d=`) is what DKIM checks. The **visible From** (RFC5322.From) is what the user sees.',
    '**SPF and DKIM authenticate their own domains, not the visible From.** An attacker who sends from their own domain can pass SPF for that domain. `spf=pass` on an attacker domain proves nothing about who wrote the message.',
    '**DMARC** is the check that ties authentication to the visible From through *alignment*: SPF or DKIM must pass for a domain that matches the From domain. `dmarc=fail` with `header.from=` your own domain means the message claims to come from you, and nothing authenticated that claim.',
    'The DMARC policy (`p=`) is the domain owner\'s request for what receivers should do with failures. `p=none` means monitoring only: no requested action, so the message is delivered. DMARC is now specified in RFC 9989 (May 2026), which replaced RFC 7489; `p=none` still means monitoring.',
    'Other indicators are real but weaker on their own: a different `Return-Path` is normal for bulk mail services; a different `Reply-To` happens with ticketing systems. A look-alike Reply-To domain is strong evidence of intent, because replies go to the attacker. Read `Received` headers **bottom-up**: the lowest one is the first hop, closest to the sender.',
  ],
  evidenceNote: 'The .eml from the user\'s mailbox. Open it as text to see every header. The link text in the HTML part and the actual link target are worth comparing.',
  hints: [
    'List each header that names a domain: Return-Path, From, Reply-To, smtp.mailfrom and header.from in Authentication-Results.',
    'Ask of each result: which domain did this check actually authenticate? Only one result is about the From domain the user sees.',
    'Find p= in the dmarc result. What does that policy tell the receiving server to do?',
  ],
  explainPrompt: 'Walk through the headers from the bottom up, then explain why DMARC outranks the other indicators and why the email still reached the inbox.',
  rubric: {
    listenFor: [
      'The three identities distinguished: envelope (SPF), DKIM d=, visible From (DMARC).',
      'spf=pass explained as authenticating the attacker\'s own domain, not the From.',
      'dmarc=fail on header.from = the company\'s own domain, named as the strongest indicator, with the reason.',
      'Look-alike Reply-To domain spotted and its purpose explained (replies go to the attacker).',
      'p=none explains delivery, followed by a recommendation (move to quarantine/reject after fixing legitimate senders).',
      'Received headers read bottom-up; link text vs href mismatch noted.',
    ],
    weak: '"The sender looks fake and the link is suspicious."',
    solid: 'Names DMARC fail on the company\'s own domain as the strongest indicator, finds the look-alike Reply-To and explains p=none.',
    strong: 'All of that, plus why spf=pass is meaningless here, the scoping steps (message trace by sender IP, Return-Path domain, subject and URL) and the DMARC recommendation for the mail team.',
  },
  followUps: [
    'How would you find everyone else who received this email?',
    'What would you recommend to the email team, and what has to happen before p=reject is safe?',
    'Is spf=pass a good sign? When does it mean something?',
  ],
  mistakes: [
    'Treating spf=pass as evidence the message is legitimate.',
    'Reading Received headers top-down and calling the internal hop the origin.',
    'Picking the display name as the strongest indicator: display names are free text and prove nothing either way.',
  ],
  references: [
    { label: 'RFC 9989: DMARC (current standard)', url: 'https://datatracker.ietf.org/doc/rfc9989/' },
    { label: 'RFC 7208: SPF', url: 'https://datatracker.ietf.org/doc/rfc7208/' },
    { label: 'RFC 6376: DKIM', url: 'https://datatracker.ietf.org/doc/rfc6376/' },
    { label: 'RFC 8601: Authentication-Results header', url: 'https://datatracker.ietf.org/doc/rfc8601/' },
    MITRE('T1566.002', 'Phishing: Spearphishing Link'),
  ],
  build(w) {
    const ev = evidenceFor(w);
    const indicatorOpts = [
      { id: 'dmarc', label: `dmarc=fail for header.from=${ORG.domain}` },
      { id: 'spf', label: `spf=pass for ${w.attacker.mailDomain}` },
      { id: 'returnpath', label: 'Return-Path domain differs from the From domain' },
      { id: 'replyto', label: 'Reply-To domain differs from the From domain' },
      { id: 'display', label: 'Display name "Accounts Payable"' },
    ];
    const deliveredOpts = [
      { id: 'pnone', label: `${ORG.domain} publishes a DMARC policy of p=none, so no action was requested on failure` },
      { id: 'spfpass', label: 'SPF passed, which overrides a DMARC failure' },
      { id: 'nodkim', label: 'Unsigned mail is always delivered' },
      { id: 'internal', label: 'The message came from an internal server' },
    ];
    return {
      artifacts: pick(ev.artifacts, ev.paths.eml),
      questions: [
        {
          id: 'indicator',
          prompt: 'Which is the single strongest indicator that the From address is forged?',
          kind: 'choice',
          options: shuffled(w.seed, 'm07.indicator', indicatorOpts),
          why: 'DMARC is the only result tied to the visible From. A failure for your own domain means nothing authenticated that the message came from you.',
        },
        {
          id: 'replyto',
          prompt: 'What is the look-alike domain in the Reply-To header?',
          kind: 'text',
          placeholder: 'domain',
          why: `The Reply-To domain uses ${w.attacker.homoglyphLabel}, so replies go to the attacker.`,
        },
        {
          id: 'delivered',
          prompt: 'Why was the message delivered despite failing DMARC?',
          kind: 'choice',
          options: shuffled(w.seed, 'm07.delivered', deliveredOpts),
          why: 'p=none is monitoring mode. The domain owner requested no action on failure, so the receiver delivered it.',
        },
      ],
      expected: { indicator: 'dmarc', replyto: w.attacker.replyToDomain, delivered: 'pnone' },
      check(qid, a) {
        const t = asText(a);
        if (qid === 'indicator') return t === 'dmarc';
        if (qid === 'replyto') return normDomain(t) === w.attacker.replyToDomain;
        if (qid === 'delivered') return t === 'pnone';
        return false;
      },
    };
  },
};
