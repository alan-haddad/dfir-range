import type { Answer, Artifact, ChoiceOption } from '../types';
import { Rng } from '../lib/prng';

export function asText(a: Answer): string {
  return Array.isArray(a) ? a.join(',') : a;
}

export function asList(a: Answer): string[] {
  return Array.isArray(a) ? a : a.split(',').map((s) => s.trim()).filter(Boolean);
}

/** Shuffle options deterministically per seed + question so position never gives the answer away. */
export function shuffled(seed: string, qid: string, opts: ChoiceOption[]): ChoiceOption[] {
  return new Rng(`opts:${seed}:${qid}`).shuffle(opts);
}

export function pick(artifacts: Artifact[], ...paths: string[]): Artifact[] {
  return paths.map((p) => {
    const a = artifacts.find((x) => x.path === p);
    if (!a) throw new Error(`missing artifact ${p}`);
    return a;
  });
}

export const MITRE = (id: string, name: string) => ({
  label: `MITRE ATT&CK ${id}: ${name}`,
  url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`,
});
