import { Rng } from '../lib/prng';
import { docIp } from '../lib/ip';
import { normIp, normUser } from '../lib/normalize';
import type { ModuleDef } from '../types';
import { guid, ORG, type World } from '../world';
import { asText, MITRE, shuffled } from './helpers';

// Entra ID sign-in records (Microsoft Graph signIn resource shape), synthetic.
// The device-code sign-in shows the victim's own IP, because the victim enters the code
// in their own browser; the attacker's IP appears on the non-interactive sign-ins that
// redeem and use the resulting tokens.

const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
const OFFICE_APP = { appDisplayName: 'Microsoft Office', appId: 'd3590ed6-52b3-4102-aeff-aad2292ab01c' };
const CLI_APP = { appDisplayName: 'Microsoft Azure CLI', appId: '04b07795-8ddb-461a-bbee-02f9e1bf7b46' };
const FOREIGN = [
  { city: 'Bucharest', countryOrRegion: 'RO' },
  { city: 'Amsterdam', countryOrRegion: 'NL' },
  { city: 'Singapore', countryOrRegion: 'SG' },
  { city: 'Vilnius', countryOrRegion: 'LT' },
];

export function deviceCodeScenario(w: World) {
  const rng = new Rng(`m14:${w.seed}`);
  const corpIp = docIp(rng, '192.0.2');
  const attackerIp = docIp(rng, '203.0.113');
  const foreign = rng.pick(FOREIGN);
  const victimUpn = w.victim.email;
  const engineer = rng.pick(['t.farris', 'j.okoro', 'a.lund']);
  const engineerUpn = `${engineer}@${ORG.domain}`;
  const corpLoc = { city: 'Cleveland', state: 'Ohio', countryOrRegion: 'US' };
  let t = w.t.emailReceived.getTime() - rng.int(5, 8) * 3600 * 1000;
  const next = (s: number) => new Date((t += s * 1000)).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const rows: Record<string, unknown>[] = [];
  const add = (o: Record<string, unknown>) => rows.push({ id: guid(rng).slice(1, -1), ...o, status: { errorCode: 0, failureReason: null }, conditionalAccessStatus: 'notApplied' });
  const victimSession = guid(rng).slice(1, -1);
  const engSession = guid(rng).slice(1, -1);
  const dcCorrelation = guid(rng).slice(1, -1);

  // Normal history for the victim.
  for (let i = 0; i < 2; i++)
    add({ createdDateTime: next(rng.int(1800, 7200)), userPrincipalName: victimUpn, userDisplayName: w.victim.display, ...OFFICE_APP, ipAddress: corpIp, location: corpLoc, autonomousSystemNumber: 64500, clientAppUsed: 'Browser', userAgent: BROWSER_UA, isInteractive: true, signInEventTypes: ['interactiveUser'], authenticationProtocol: 'none', originalTransferMethod: 'none', resourceDisplayName: 'Office 365 Exchange Online', correlationId: guid(rng).slice(1, -1), sessionId: victimSession });

  // Decoy: an engineer's legitimate device-code sign-in; tokens are then used from the same corporate IP.
  add({ createdDateTime: next(rng.int(600, 1800)), userPrincipalName: engineerUpn, userDisplayName: engineer, ...CLI_APP, ipAddress: corpIp, location: corpLoc, autonomousSystemNumber: 64500, clientAppUsed: 'Mobile Apps and Desktop clients', userAgent: BROWSER_UA, isInteractive: true, signInEventTypes: ['interactiveUser'], authenticationProtocol: 'deviceCode', originalTransferMethod: 'deviceCodeFlow', resourceDisplayName: 'Windows Azure Service Management API', correlationId: guid(rng).slice(1, -1), sessionId: engSession });
  add({ createdDateTime: next(rng.int(30, 120)), userPrincipalName: engineerUpn, userDisplayName: engineer, ...CLI_APP, ipAddress: corpIp, location: corpLoc, autonomousSystemNumber: 64500, clientAppUsed: 'Mobile Apps and Desktop clients', userAgent: 'python/3.12 azure-cli', isInteractive: false, signInEventTypes: ['nonInteractiveUser'], authenticationProtocol: 'none', originalTransferMethod: 'deviceCodeFlow', resourceDisplayName: 'Windows Azure Service Management API', correlationId: guid(rng).slice(1, -1), sessionId: engSession });

  // The phish: the victim enters the attacker's code in their own browser, from the usual office IP.
  add({ createdDateTime: next(rng.int(1200, 5400)), userPrincipalName: victimUpn, userDisplayName: w.victim.display, ...OFFICE_APP, ipAddress: corpIp, location: corpLoc, autonomousSystemNumber: 64500, clientAppUsed: 'Mobile Apps and Desktop clients', userAgent: BROWSER_UA, isInteractive: true, signInEventTypes: ['interactiveUser'], authenticationProtocol: 'deviceCode', originalTransferMethod: 'deviceCodeFlow', resourceDisplayName: 'Microsoft Graph', correlationId: dcCorrelation, sessionId: victimSession });
  // Seconds later the attacker's client redeems and uses the tokens from a new country and network.
  const resources = ['Microsoft Graph', 'Office 365 Exchange Online', 'Office 365 SharePoint Online'];
  for (const r of resources)
    add({ createdDateTime: next(rng.int(8, 90)), userPrincipalName: victimUpn, userDisplayName: w.victim.display, ...OFFICE_APP, ipAddress: attackerIp, location: { city: foreign.city, state: null, countryOrRegion: foreign.countryOrRegion }, autonomousSystemNumber: 64510, clientAppUsed: 'Mobile Apps and Desktop clients', userAgent: 'python-requests/2.32.3', isInteractive: false, signInEventTypes: ['nonInteractiveUser'], authenticationProtocol: 'none', originalTransferMethod: 'deviceCodeFlow', resourceDisplayName: r, correlationId: r === 'Microsoft Graph' ? dcCorrelation : guid(rng).slice(1, -1), sessionId: victimSession });

  const text = JSON.stringify({ value: rows }, null, 2) + '\n';
  return { text, victimUpn, attackerIp, engineerUpn };
}

export const m14: ModuleDef = {
  id: 'm14',
  number: 14,
  title: 'Device-code phishing',
  short: 'OAuth device code flow abused: find the phished sign-in and the IP split that gives it away.',
  tracks: ['t1', 't2'],
  difficulty: 3,
  objective: 'Walk through a device-code phishing attack end to end, then find the phished user and the attacker\'s IP in Entra ID sign-in logs, ruling out a legitimate device-code user.',
  background: [
    '**The device code flow** (OAuth 2.0 Device Authorization Grant, RFC 8628) lets a device without a keyboard sign in: the device shows a short code, and the user enters it at the identity provider\'s verification page on another device. Whoever started the flow receives the tokens.',
    '**The attack, end to end:** (1) the attacker starts a device code flow for a first-party client and gets a user code; (2) they send it to the victim with a pretext (join a meeting, verify a document, re-register MFA); (3) the victim goes to the genuine sign-in page, enters the code and completes MFA; (4) the attacker\'s client, polling all along, receives an access and refresh token for the victim. No password is stolen and MFA is satisfied, which is why it works.',
    '**What the logs show:** the interactive sign-in has `authenticationProtocol` = `deviceCode` (Graph also records `originalTransferMethod` = `deviceCodeFlow`), and its IP is the **victim\'s own**, because the victim entered the code in their browser. The attacker shows up on **non-interactive** sign-ins seconds later: same user, same session, a **new IP, country and network**, often an automation user agent.',
    '**Device code alone is not the alert:** admins and developer tools use it legitimately. The tell is the split: a device-code sign-in followed by token use from somewhere the user has never been.',
    '**Response:** revoke the user\'s sessions and refresh tokens (resetting the password alone does not invalidate issued tokens), review what the tokens accessed, and restrict the device code flow with a Conditional Access authentication-flows policy for users who do not need it.',
  ],
  evidenceNote: 'Entra ID sign-in records (interactive and non-interactive) for two users, in the Microsoft Graph signIn shape.',
  hints: [
    'Filter to authenticationProtocol = deviceCode. Two users used it. Which one is normal for?',
    'For each device-code sign-in, look at the non-interactive sign-ins right after it for the same user: same IP or a new one?',
    'Compare ipAddress, location, autonomousSystemNumber and userAgent between the device-code sign-in and what follows.',
  ],
  explainPrompt: 'Walk through the attack end to end, then point to the two log entries that prove it and say what you would do first.',
  rubric: {
    listenFor: [
      'The flow explained: attacker starts it, victim enters the code on the genuine page, attacker receives the tokens.',
      'Why MFA does not help: the victim completes it for the attacker.',
      'The log tell: deviceCode sign-in from the victim\'s normal IP, then non-interactive sign-ins from a new IP, country and ASN in the same session.',
      'The legitimate device-code user ruled out.',
      'Response: revoke sessions and refresh tokens, review token activity, restrict device code flow with Conditional Access.',
    ],
    weak: '"They phished the password."',
    solid: 'Explains the flow and identifies the phished user and the attacker IP from the IP split.',
    strong: 'All of that, plus why the device-code sign-in itself looks normal, the decoy, and the token-focused response.',
  },
  followUps: [
    'Why does resetting the user\'s password not end the attacker\'s access?',
    'How would you write a detection that does not fire on every developer using device code?',
    'What would you check in the audit logs after this?',
  ],
  mistakes: [
    'Expecting the device-code sign-in to come from the attacker\'s IP.',
    'Alerting on every device-code sign-in.',
    'Resetting the password and stopping there.',
  ],
  references: [
    { label: 'RFC 8628: OAuth 2.0 Device Authorization Grant', url: 'https://datatracker.ietf.org/doc/rfc8628/' },
    { label: 'Microsoft Graph: signIn resource type', url: 'https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta' },
    { label: 'Microsoft: Conditional Access authentication flows (device code)', url: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows' },
    MITRE('T1528', 'Steal Application Access Token'),
    MITRE('T1566', 'Phishing'),
  ],
  build(w) {
    const sc = deviceCodeScenario(w);
    const tellOpts = [
      { id: 'split', label: 'A deviceCode sign-in from the user\'s usual IP, then non-interactive sign-ins in the same session from a new IP, country and ASN' },
      { id: 'devicecode', label: 'Any sign-in with authenticationProtocol = deviceCode' },
      { id: 'fail', label: 'A failed MFA prompt' },
      { id: 'browser', label: 'A browser user agent' },
    ];
    const actOpts = [
      { id: 'revoke', label: 'Revoke the user\'s sessions and refresh tokens, then review what the tokens accessed' },
      { id: 'password', label: 'Reset the user\'s password and close the case' },
      { id: 'mfa', label: 'Re-register the user\'s MFA method' },
      { id: 'nothing', label: 'Nothing: MFA was satisfied, so the sign-in is legitimate' },
    ];
    return {
      artifacts: [{ path: 'tenant/entra-signins.json', content: sc.text, title: 'Entra ID sign-in logs (interactive and non-interactive)' }],
      questions: [
        { id: 'user', prompt: 'Which user was phished?', kind: 'text', placeholder: 'user principal name', why: 'Their device-code sign-in is followed by token use from a new country and network.' },
        { id: 'ip', prompt: 'What IP did the attacker use the tokens from?', kind: 'text', placeholder: 'a.b.c.d', why: 'The non-interactive sign-ins right after the device-code sign-in, same user and session, from a new IP.' },
        { id: 'tell', prompt: 'What gives the attack away in the logs?', kind: 'choice', options: shuffled(w.seed, 'm14.t', tellOpts), why: 'Device code is used legitimately too; the IP split between the code entry and the token use is the tell.' },
        { id: 'action', prompt: 'What do you do first?', kind: 'choice', options: shuffled(w.seed, 'm14.a', actOpts), why: 'The attacker holds tokens, so revoke them; a password reset alone does not invalidate issued tokens.' },
      ],
      expected: { user: sc.victimUpn, ip: sc.attackerIp, tell: 'split', action: 'revoke' },
      check(qid, a) {
        const t = asText(a);
        if (qid === 'user') return normUser(t) === w.victim.username;
        if (qid === 'ip') return normIp(t) === sc.attackerIp;
        if (qid === 'tell') return t === 'split';
        if (qid === 'action') return t === 'revoke';
        return false;
      },
    };
  },
};
