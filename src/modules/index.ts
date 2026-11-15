import type { ModuleDef } from '../types';
import { m01 } from './m01';
import { m02 } from './m02';
import { m03 } from './m03';
import { m05 } from './m05';
import { m07 } from './m07';
import { m11 } from './m11';
import { m15 } from './m15';

export const MODULES: ModuleDef[] = [m01, m02, m03, m05, m07, m11, m15];

/** Concepts on the roadmap, listed so candidates can see full coverage. */
export const PLANNED: { number: number; title: string }[] = [
  { number: 4, title: 'Authentication anomaly' },
  { number: 6, title: 'DNS tunneling' },
  { number: 8, title: 'Process-creation telemetry (Sysmon 1 vs 4688)' },
  { number: 9, title: 'Discovery burst (ATT&CK TA0007)' },
  { number: 10, title: 'Process injection' },
  { number: 12, title: 'Persistence beyond Run keys' },
  { number: 13, title: 'DLL side-loading hunt' },
  { number: 14, title: 'Device-code phishing (Entra ID)' },
];

export function moduleById(id: string): ModuleDef | undefined {
  return MODULES.find((m) => m.id === id);
}
