import { zipSync } from 'fflate';
import { sha256Hex, utf8Bytes } from './lib/encode';
import type { Artifact } from './types';

// Evidence bundle: every artifact plus a SHA-256 manifest, zipped in memory.
// Runs the same in the browser and in Node (CLI and CI).

export function artifactBytes(a: Artifact): Uint8Array {
  return typeof a.content === 'string' ? utf8Bytes(a.content) : a.content;
}

export async function manifest(artifacts: Artifact[], seed: string): Promise<string> {
  const files = [];
  for (const a of artifacts) {
    const b = artifactBytes(a);
    files.push({ path: a.path, bytes: b.length, sha256: await sha256Hex(b) });
  }
  return JSON.stringify({ generator: 'dfir-range', seed, note: 'Synthetic, inert training evidence. All organizations, people and infrastructure are fictional.', files }, null, 2) + '\n';
}

export async function buildZip(artifacts: Artifact[], seed: string, root = `dfir-range-${seed}`): Promise<Uint8Array> {
  const entries: Record<string, Uint8Array> = {};
  for (const a of artifacts) entries[`${root}/${a.path}`] = artifactBytes(a);
  entries[`${root}/manifest.json`] = utf8Bytes(await manifest(artifacts, seed));
  // Fixed mtime keeps the zip byte-identical for the same seed.
  return zipSync(entries, { level: 6, mtime: new Date('2026-01-01T00:00:00Z') });
}
