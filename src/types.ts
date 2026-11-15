import type { World } from './world';

export interface Artifact {
  /** Path inside the evidence bundle, e.g. "VEL-WS-1234/logs/Sysmon-Operational.xml". */
  path: string;
  /** Text, or raw bytes for binary files. */
  content: string | Uint8Array;
  /** Optional text shown in the viewer instead of raw bytes (e.g. a hexdump). */
  view?: string;
  title: string;
  note?: string;
}

export interface ChoiceOption {
  id: string;
  label: string;
}

export interface Question {
  id: string;
  prompt: string;
  kind: 'text' | 'choice' | 'order';
  placeholder?: string;
  options?: ChoiceOption[];
  /** For kind "order": how many ordered picks. */
  slots?: number;
  /** Shown after a correct answer: why it is right. */
  why: string;
}

export type Answer = string | string[];

export interface ModuleInstance {
  artifacts: Artifact[];
  questions: Question[];
  /** Canonical answers, used by tests and by the "show answer" reveal after an attempt. */
  expected: Record<string, Answer>;
  check(questionId: string, answer: Answer): boolean;
  /** Extra scenario text shown above the evidence (briefs for reasoning modules). */
  brief?: string;
}

export interface Rubric {
  listenFor: string[];
  weak: string;
  solid: string;
  strong: string;
}

export interface Reference {
  label: string;
  url: string;
}

export type Track = 't1' | 't2';

export interface ModuleDef {
  id: string;
  number: number;
  title: string;
  short: string;
  tracks: Track[];
  difficulty: 1 | 2 | 3;
  objective: string;
  background: string[];
  evidenceNote: string;
  hints: [string, string, string];
  explainPrompt: string;
  rubric: Rubric;
  followUps: string[];
  mistakes: string[];
  references: Reference[];
  build(world: World): ModuleInstance;
}
