import type { ModuleDef } from '../types';
import { m01 } from './m01';
import { m02 } from './m02';
import { m03 } from './m03';
import { m04 } from './m04';
import { m05 } from './m05';
import { m06 } from './m06';
import { m07 } from './m07';
import { m08 } from './m08';
import { m09 } from './m09';
import { m10 } from './m10';
import { m11 } from './m11';
import { m12 } from './m12';
import { m13 } from './m13';
import { m14 } from './m14';
import { m15 } from './m15';

export const MODULES: ModuleDef[] = [m01, m02, m03, m04, m05, m06, m07, m08, m09, m10, m11, m12, m13, m14, m15];

/** Concepts on the roadmap, listed so candidates can see full coverage. */
export const PLANNED: { number: number; title: string }[] = [];

export function moduleById(id: string): ModuleDef | undefined {
  return MODULES.find((m) => m.id === id);
}
