import { Rng } from '../lib/prng';
import { normDomain, normIp } from '../lib/normalize';
import type { ModuleDef } from '../types';
import type { World } from '../world';
import { asText, MITRE, shuffled } from './helpers';

const TUN1 = ['cdn-metrics', 'telemetry', 'sync-api', 'update-feed', 'edge-stats', 'status-check'];
const TUN2 = ['relay', 'cloud', 'hub', 'net', 'svc', 'io'];

const ZEEK_HEADER = [
  '#separator \\x09',
  '#set_separator\t,',
  '#empty_field\t(empty)',
  '#unset_field\t-',
  '#path\tdns',
  '#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected',
  '#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tinterval\tstring\tcount\tstring\tcount\tstring\tcount\tstring\tbool\tbool\tbool\tbool\tcount\tvector[string]\tvector[interval]\tbool',
];

export function dnsScenario(w: World) {
  const rng = new Rng(`m06:${w.seed}`);
  const tunnel = `${rng.pick(TUN1)}-${rng.pick(TUN2)}.${rng.pick(['test', 'invalid'])}`;
  const decoy = `edge-telemetry.quorvane.example`;
  const cdn = `assets.velmora-cdn.example`;
  const resolver = '10.20.0.53';
  const src = w.host.ip;
  const others = Array.from({ length: 9 }, () => `10.20.${rng.int(2, 90)}.${rng.int(10, 240)}`);
  let ts = (w.t.configWritten.getTime() + rng.int(5400, 10800) * 1000) / 1000;
  const rows: string[] = [];
  let tunnelCount = 0;
  const uid = () => 'C' + rng.alnum(17);
  // Hex-encoded payload chunks, as many DNS tunneling tools use.
  const txt = (len: number) => rng.hex(Math.ceil(len / 2)).slice(0, len);
  for (let i = 0; i < 90; i++) {
    ts += rng.int(80, 420) / 1000;
    const r = rng.next();
    let host: string, query: string, qtype: number, qname: string, answers: string, ttl: string;
    if (r < 0.55) {
      tunnelCount++;
      host = src;
      query = `${rng.hex(rng.int(14, 24))}.${tunnel}`;
      qtype = 16;
      qname = 'TXT';
      const n = rng.int(180, 250);
      answers = `TXT ${n} ${txt(n)}`;
      ttl = '0.000000';
    } else if (r < 0.85) {
      host = rng.pick(others);
      query = decoy;
      qtype = 1;
      qname = 'A';
      answers = `192.0.2.${rng.int(10, 40)}`;
      ttl = '300.000000';
    } else {
      host = rng.pick([...others, src]);
      query = cdn;
      qtype = rng.bool() ? 1 : 28;
      qname = qtype === 1 ? 'A' : 'AAAA';
      answers = qtype === 1 ? `192.0.2.${rng.int(50, 90)}` : `2001:db8::${rng.int(10, 99)}`;
      ttl = '120.000000';
    }
    rows.push([ts.toFixed(6), uid(), host, rng.int(49152, 65535), resolver, 53, 'udp', rng.int(1, 65535), (rng.int(1, 40) / 1000).toFixed(6), query, 1, 'C_INTERNET', qtype, qname, 0, 'NOERROR', 'F', 'F', 'T', 'T', 0, answers, ttl, 'F'].join('\t'));
  }
  const text = [...ZEEK_HEADER, ...rows].join('\n') + '\n';
  return { text, tunnel, src, decoy, tunnelCount };
}

export const m06: ModuleDef = {
  id: 'm06',
  number: 6,
  title: 'DNS tunneling',
  short: 'Spot TXT-heavy, high-entropy subdomains under one domain and confirm with signals, not a hunch.',
  tracks: ['t1', 't2'],
  difficulty: 2,
  objective: 'Name the technique in this DNS traffic, identify the tunneling domain and the source host, and name the signals that confirm it while ruling out the high-volume decoy.',
  background: [
    'DNS tunneling hides data inside DNS queries and responses. The client encodes data into subdomain labels (`<encoded-chunk>.attacker-domain`) and the attacker\'s authoritative server answers, often with **TXT** records that can carry far more data than an A record.',
    'Confirming signals: a **high query rate** from **one source host**; a **unique-subdomain ratio** near 100% (every query is a new label, so caching never helps); **long, high-entropy labels** (hex or Base32/Base64-looking); **TXT** (or NULL) query types; **large responses**; and **zero or very low TTLs**.',
    '**Rule out the decoy**: telemetry and CDN domains are high-volume too, but they ask the same few names over and over, from many hosts, with normal record types and TTLs. Volume alone is not the tell; uniqueness and entropy are.',
    'The log is in Zeek\'s `dns.log` format: tab-separated, with a `#fields` header naming each column. `id.orig_h` is the client, `query` the name asked for, `qtype_name` the record type, `answers` and `TTLs` the response.',
  ],
  evidenceNote: 'A Zeek dns.log excerpt from the network sensor. Use the #fields line to find the columns.',
  hints: [
    'Group queries by their parent domain (the last two labels) and count them.',
    'For each busy domain, ask: how many distinct names, how many source hosts, which record type, how big are the answers?',
    "Shell: grep -v '^#' dns.log | cut -f3,10,14 | awk -F'\\t' '{n=split($2,a,\".\"); print a[n-1]\".\"a[n], $1, $3}' | sort | uniq -c | sort -rn | head",
  ],
  explainPrompt: 'Name the technique, the domain and host, and give at least three signals, explaining why the busy telemetry domain is not tunneling.',
  rubric: {
    listenFor: [
      'Technique named: DNS tunneling, used for command and control or exfiltration.',
      'Signals counted, not guessed: one source, near-100% unique names, long random labels, TXT, large answers, TTL 0.',
      'The high-volume decoy ruled out by its repetition and many hosts.',
      'Next steps: block or sinkhole the domain, isolate the source host, check what process on the host made the queries, look for the same pattern on other hosts.',
    ],
    weak: '"Lots of DNS, so it is tunneling."',
    solid: 'Names the technique, the domain and the source host, and gives several confirming signals.',
    strong: 'All of that, plus a quantitative argument (counts, uniqueness ratio, answer sizes) and why the telemetry decoy is benign.',
  },
  followUps: [
    'How would you write a detection for this that does not fire on CDNs?',
    'Which endpoint telemetry would tell you which process made these queries?',
    'Could the attacker avoid the TXT tell? What would you look at then?',
  ],
  mistakes: [
    'Calling the highest-volume domain malicious without checking uniqueness and record type.',
    'Ignoring the source: one internal host making nearly all the suspicious queries is the scoping lead.',
    'Stopping at the network: the process behind the queries is on the host.',
  ],
  references: [
    MITRE('T1071.004', 'Application Layer Protocol: DNS'),
    MITRE('T1048', 'Exfiltration Over Alternative Protocol'),
    { label: 'Zeek documentation: dns.log', url: 'https://docs.zeek.org/en/master/logs/dns.html' },
  ],
  build(w) {
    const sc = dnsScenario(w);
    const techOpts = [
      { id: 'tunnel', label: 'DNS tunneling (C2 or exfiltration over DNS)' },
      { id: 'dga', label: 'Domain generation algorithm lookups failing (NXDOMAIN noise)' },
      { id: 'amp', label: 'DNS amplification DDoS' },
      { id: 'cdn', label: 'Normal CDN and telemetry traffic' },
    ];
    return {
      artifacts: [{ path: 'sensors/zeek/dns.log', content: sc.text, title: 'Zeek dns.log excerpt' }],
      questions: [
        { id: 'technique', prompt: 'What technique is this?', kind: 'choice', options: shuffled(w.seed, 'm06.t', techOpts), why: 'One host, nearly every name unique, long random labels, TXT answers near maximum size and TTL 0.' },
        { id: 'domain', prompt: 'Which parent domain carries the tunnel?', kind: 'text', placeholder: 'domain', why: `${sc.tunnelCount} TXT queries, every one a new random label under this domain.` },
        { id: 'src', prompt: 'Which internal host IP is sending it?', kind: 'text', placeholder: 'a.b.c.d', why: 'id.orig_h on every tunnel query is the same host.' },
      ],
      expected: { technique: 'tunnel', domain: sc.tunnel, src: sc.src },
      check(qid, a) {
        const t = asText(a);
        if (qid === 'technique') return t === 'tunnel';
        if (qid === 'domain') return normDomain(t).replace(/^\*\./, '') === sc.tunnel;
        if (qid === 'src') return normIp(t) === sc.src;
        return false;
      },
    };
  },
};
