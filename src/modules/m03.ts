import { evidenceFor } from '../evidence';
import { normHexByte, normUrl } from '../lib/normalize';
import type { ModuleDef } from '../types';
import { asText, MITRE, pick } from './helpers';

export const m03: ModuleDef = {
  id: 'm03',
  number: 3,
  title: 'Single-byte XOR config',
  short: 'Brute-force a one-byte XOR key with a known-plaintext crib and recover the C2 URL.',
  tracks: ['t2'],
  difficulty: 2,
  objective: 'Recover the single-byte XOR key protecting a malware config file, then read the command-and-control (C2) URL out of it.',
  background: [
    'Single-byte XOR combines every byte of the data with the same one-byte key. XOR is its own inverse, so the same operation decrypts. There are only 255 useful keys (0 changes nothing), so trying them all takes milliseconds.',
    '**Known-plaintext crib:** if you can guess part of the plaintext, you don\'t need to brute-force at all: `key = cipher_byte XOR plain_byte`. Malware configs almost always contain a URL, so `http` is a good crib. Find four consecutive bytes that all give the same key against `h`, `t`, `t`, `p`.',
    'Tells that you are looking at single-byte XOR: the file is the size you would expect for a small text config, and repeated plaintext characters (quotes, colons, commas in JSON) show up as the same repeated cipher byte.',
    'The config is worth reading fully: `sleep` and `jitter` tell you how often the implant beacons, which is what network detections key on.',
  ],
  evidenceNote: 'settings.dat from ProgramData. The viewer shows a hexdump; download the file to work on the raw bytes. The Sysmon log shows which process wrote it.',
  hints: [
    'Work on the bytes, not the hexdump text: the offset column and the ASCII column on the right are not part of the data.',
    "XOR the first few bytes against every key from 1 to 255 and look for readable output. Or use the crib: the config contains 'http' somewhere.",
    "CyberChef: From Hex (or open the file), then XOR Brute Force with crib http. Python: data = open('settings.dat','rb').read(); then try bytes(b ^ k for b in data) for k in range(1, 256).",
  ],
  explainPrompt: 'Explain how you found the key, why single-byte XOR is weak, and what the config tells you about detecting the implant.',
  rubric: {
    listenFor: [
      'Why single-byte XOR is weak: a tiny key space, and XOR is symmetric.',
      'A crib used deliberately (http), not just random guessing.',
      'Key and C2 URL reported correctly, with the key in hex.',
      'Config fields interpreted: sleep and jitter mean a beacon interval to hunt for.',
      'Next steps: hunt the C2 domain in DNS and proxy logs; look for the same config path on other hosts; check memory if the file had been deleted.',
    ],
    weak: '"I ran XOR brute force and found a URL."',
    solid: 'Explains the crib, gives the key in hex and the C2 URL.',
    strong: 'All of that, plus what sleep and jitter mean for network detection and where to look for the same config fleet-wide.',
  },
  followUps: [
    'What changes if the key is multi-byte?',
    'What do sleep and jitter tell you about detecting this beacon on the network?',
    'Where else could this config exist if it was never written to disk?',
  ],
  mistakes: [
    'Reporting the key in decimal when hex was asked for, or mixing the two up.',
    'Feeding the hexdump text (offsets and the ASCII column) into the decoder as if it were data.',
    'Stopping after the first readable fragment instead of reading the whole config.',
  ],
  references: [
    MITRE('T1027', 'Obfuscated Files or Information'),
    MITRE('T1140', 'Deobfuscate/Decode Files or Information'),
    MITRE('T1071.001', 'Application Layer Protocol: Web Protocols'),
  ],
  build(w) {
    const ev = evidenceFor(w);
    return {
      artifacts: pick(ev.artifacts, ev.paths.config, ev.paths.sysmonXml),
      questions: [
        {
          id: 'key',
          prompt: 'What is the XOR key, in hex?',
          kind: 'text',
          placeholder: 'e.g. 0x4f',
          why: 'XORing the bytes that decrypt to "http" against those letters gives the same value at every position: the key.',
        },
        {
          id: 'c2',
          prompt: 'What C2 URL is in the config?',
          kind: 'text',
          placeholder: 'https://…  (defanged is fine)',
          why: 'With the key applied, the file is a small JSON config whose c2 field is the beacon URL.',
        },
      ],
      expected: { key: `0x${w.ids.xorKey.toString(16).padStart(2, '0')}`, c2: w.attacker.c2Url },
      check(qid, a) {
        const t = asText(a);
        if (qid === 'key') return normHexByte(t) === w.ids.xorKey;
        if (qid === 'c2') return normUrl(t) === normUrl(w.attacker.c2Url);
        return false;
      },
    };
  },
};
