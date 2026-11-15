// Progress lives only in this browser. Every access is wrapped because
// storage can be disabled, full or unavailable (private modes, sandboxes).

const KEY = 'dfir-range:v1';

export interface Attempt {
  correct: boolean;
  at: number;
}

export type Confidence = 'sure' | 'guess' | 'idk';
export type Source = 'learn' | 'assessment' | 'case';

/** One graded answer, with how confident the person was. Used for the weak-spots report. */
export interface ResultRecord {
  concept: string; // module id, e.g. "m07"
  qid: string;
  seed: string;
  source: Source;
  correct: boolean;
  confidence: Confidence;
  at: number;
}

export interface State {
  attempts: Record<string, Record<string, Record<string, Attempt>>>; // module -> seed -> question -> attempt
  explain: Record<string, string>; // module -> notes
  records: ResultRecord[];
  findOut: Record<string, string>; // "how would you find out" notes, keyed by concept:qid
  drillBest: number;
  hints: boolean;
  track: 'all' | 't1' | 't2';
}

const MAX_RECORDS = 3000;

const DEFAULT: State = { attempts: {}, explain: {}, records: [], findOut: {}, drillBest: 0, hints: true, track: 'all' };

let memory: State | null = null;

export function load(): State {
  if (memory) return memory;
  try {
    const raw = localStorage.getItem(KEY);
    memory = raw ? { ...DEFAULT, ...JSON.parse(raw) } : { ...DEFAULT };
  } catch {
    memory = { ...DEFAULT };
  }
  return memory!;
}

export function save(next: State): void {
  memory = next;
  try {
    localStorage.setItem(KEY, JSON.stringify(next));
  } catch {
    /* storage unavailable: keep progress for this session only */
  }
}

export function update(fn: (s: State) => void): State {
  const s = load();
  fn(s);
  save(s);
  return s;
}

export function recordAttempt(moduleId: string, seed: string, qid: string, correct: boolean): void {
  update((s) => {
    s.attempts[moduleId] ??= {};
    s.attempts[moduleId][seed] ??= {};
    const prev = s.attempts[moduleId][seed][qid];
    s.attempts[moduleId][seed][qid] = { correct: correct || !!prev?.correct, at: Date.now() };
  });
}

export function recordResult(r: Omit<ResultRecord, 'at'>): void {
  update((s) => {
    s.records ??= [];
    s.records.push({ ...r, at: Date.now() });
    if (s.records.length > MAX_RECORDS) s.records.splice(0, s.records.length - MAX_RECORDS);
  });
}

export function hasAttempted(moduleId: string): boolean {
  const m = load().attempts[moduleId];
  return !!m && Object.keys(m).length > 0;
}

export function solvedCount(moduleId: string): number {
  const m = load().attempts[moduleId] ?? {};
  return Object.values(m).filter((qs) => Object.values(qs).length > 0 && Object.values(qs).every((a) => a.correct)).length;
}

export function exportProgress(): string {
  return JSON.stringify(load(), null, 2);
}

export function importProgress(json: string): boolean {
  try {
    const parsed = JSON.parse(json);
    if (typeof parsed !== 'object' || parsed === null || typeof parsed.attempts !== 'object') return false;
    save({ ...DEFAULT, ...parsed, records: Array.isArray(parsed.records) ? parsed.records : [] });
    return true;
  } catch {
    return false;
  }
}

export function resetProgress(): void {
  save({ ...DEFAULT });
}
