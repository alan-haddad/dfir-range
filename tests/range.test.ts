import { describe, expect, it } from 'vitest';
import { artifactBytes, buildZip } from '../src/bundle';
import { buildCaseFile } from '../src/casefile';
import { DRILLS } from '../src/drills';
import { evidenceFor } from '../src/evidence';
import { bytesToHex } from '../src/lib/encode';
import { IP_FORMS, intToIp, obfuscateIp, parseNumbersAndDots } from '../src/lib/ip';
import { normDomain, normHexByte, normIp, normUrl, normUser, refang } from '../src/lib/normalize';
import { Rng } from '../src/lib/prng';
import { MODULES } from '../src/modules';
import type { ChoiceOption } from '../src/types';
import { buildWorld } from '../src/world';

const SEEDS = Array.from({ length: 60 }, (_v, i) => `t${i}x${(i * 7919) % 1000}`);

describe('determinism', () => {
  it('same seed gives byte-identical bundles', async () => {
    const a = await buildZip(evidenceFor(buildWorld('repeat1')).artifacts, 'repeat1');
    // Fresh world object, bypassing the per-seed cache, must produce the same bytes.
    const { buildEvidence } = await import('../src/evidence');
    const b = await buildZip(buildEvidence(buildWorld('repeat1')).artifacts, 'repeat1');
    expect(bytesToHex(a)).toEqual(bytesToHex(b));
  });

  it('different seeds give different answers', () => {
    const urls = new Set(SEEDS.map((s) => buildWorld(s).attacker.stage1Url));
    expect(urls.size).toBeGreaterThan(SEEDS.length * 0.9);
  });
});

describe('IPv4 numbers-and-dots', () => {
  it('every obfuscated form round-trips', () => {
    const rng = new Rng('ip-tests');
    for (let i = 0; i < 500; i++) {
      const ip = intToIp(rng.int(0, 0xffffffff) >>> 0);
      for (const form of IP_FORMS) {
        const shown = obfuscateIp(ip, form, rng);
        expect(intToIp(parseNumbersAndDots(shown)!), `${form}: ${shown}`).toBe(ip);
      }
    }
  });

  it('treats leading zeros as octal', () => {
    expect(intToIp(parseNumbersAndDots('010.0.0.1')!)).toBe('8.0.0.1');
    expect(intToIp(parseNumbersAndDots('226.000.000.037')!)).toBe('226.0.0.31');
    expect(intToIp(parseNumbersAndDots('0x7f.1')!)).toBe('127.0.0.1');
  });
});

describe('normalizers', () => {
  it('refangs common styles', () => {
    expect(refang('hxxps://evil[.]test/a')).toBe('https://evil.test/a');
    expect(refang('hXXp://a(.)b[:]80')).toBe('http://a.b:80');
  });
  it('accepts reasonable variants', () => {
    expect(normUrl('HXXPS://Billing-Desk[.]test/s/x.ps1/')).toBe(normUrl('https://billing-desk.test/s/x.ps1'));
    expect(normDomain('https://notice-cloud[.]test/d/x')).toBe('notice-cloud.test');
    expect(normDomain('ap@ve1mora.example')).toBe('ve1mora.example');
    expect(normIp('198[.]51[.]100[.]7')).toBe('198.51.100.7');
    expect(normIp('198.51.100.07')).toBeNull();
    expect(normHexByte('0x4F')).toBe(0x4f);
    expect(normHexByte('4f')).toBe(0x4f);
    expect(normUser('VELMORA\\d.mercer')).toBe('d.mercer');
  });
});

function wrongChoice(options: ChoiceOption[] | undefined, right: string): string {
  return options!.find((o) => o.id !== right)!.id;
}

describe('modules', () => {
  for (const m of MODULES) {
    it(`${m.id} accepts its expected answers and rejects wrong ones across seeds`, () => {
      for (const s of SEEDS) {
        const inst = m.build(buildWorld(s));
        for (const q of inst.questions) {
          const exp = inst.expected[q.id];
          expect(inst.check(q.id, exp), `${m.id}.${q.id} seed ${s}`).toBe(true);
          const wrong = q.kind === 'choice' ? wrongChoice(q.options, exp as string) : q.kind === 'order' ? ['disk', 'netlogs', 'mail'] : 'definitely-wrong.test';
          expect(inst.check(q.id, wrong), `${m.id}.${q.id} wrong`).toBe(false);
        }
      }
    });
  }

  it('every module has three hints, a rubric and references', () => {
    for (const m of MODULES) {
      expect(m.hints).toHaveLength(3);
      expect(m.rubric.listenFor.length).toBeGreaterThan(2);
      expect(m.references.length).toBeGreaterThan(0);
    }
  });
});

describe('case file', () => {
  it('accepts expected answers and a timestamp within a minute', () => {
    for (const s of SEEDS) {
      const w = buildWorld(s);
      const inst = buildCaseFile(w);
      for (const q of inst.questions) expect(inst.check(q.id, inst.expected[q.id]), `case.${q.id}`).toBe(true);
      const t = new Date(w.t.executed.getTime() + 30_000).toISOString().replace('T', ' ').slice(0, 19);
      expect(inst.check('time', `${t} UTC`)).toBe(true);
      expect(inst.check('time', '2020-01-01 00:00:00')).toBe(false);
    }
  });
});

describe('no answer leakage', () => {
  it('decoded-only answers never appear in plain text evidence', () => {
    for (const s of SEEDS) {
      const w = buildWorld(s);
      const text = evidenceFor(w)
        .artifacts.map((a) => new TextDecoder().decode(artifactBytes(a)))
        .join('\n');
      expect(text.includes(w.attacker.stage1Url), `stage-1 URL in plain text, seed ${s}`).toBe(false);
      expect(text.includes(w.attacker.stage2Ip), `stage-2 IP in plain text, seed ${s}`).toBe(false);
      expect(text.includes(w.attacker.c2Url), `C2 URL in plain text, seed ${s}`).toBe(false);
      expect(text.includes(w.attacker.c2Domain), `C2 domain in plain text, seed ${s}`).toBe(false);
    }
  });
});

describe('drills', () => {
  it('every generated item accepts its own answer', () => {
    const rng = new Rng('drill-tests');
    for (const d of DRILLS) {
      for (let i = 0; i < 200; i++) {
        const item = d.make(rng);
        const ans = item.kind === 'choice' ? item.options!.find((o) => item.check(o.id))?.id : item.answer;
        expect(ans, `${d.id}: no option is correct`).toBeDefined();
        expect(item.check(ans!), `${d.id}: ${item.prompt}`).toBe(true);
        if (item.kind === 'choice') expect(item.options!.filter((o) => item.check(o.id))).toHaveLength(1);
      }
    }
  });
});
