import type { Confidence, ResultRecord } from './store';

// Turns graded answers plus confidence into a diagnosis.
//   correct + sure     -> strength
//   correct + guessing -> lucky (counts as a weakness: you did not know it)
//   wrong   + sure     -> misconception (highest priority: confidently wrong costs interviews)
//   wrong   + guessing -> gap
//   "I don't know"     -> gap

export type Outcome = 'strength' | 'lucky' | 'misconception' | 'gap';

export function classify(correct: boolean, confidence: Confidence): Outcome {
  if (confidence === 'idk') return 'gap';
  if (correct) return confidence === 'sure' ? 'strength' : 'lucky';
  return confidence === 'sure' ? 'misconception' : 'gap';
}

export const OUTCOME_TEXT: Record<Outcome, { label: string; note: string }> = {
  strength: { label: 'Strength', note: 'Correct and you were sure.' },
  lucky: { label: 'Lucky guess', note: 'Correct, but you were guessing, so it counts as a weak spot. Read the explanation until you could explain it.' },
  misconception: { label: 'Misconception', note: 'Wrong while sure. This is the top priority: confidently wrong answers are what cost interviews.' },
  gap: { label: 'Gap', note: 'Something to learn. In an interview, say what you would do to find out, then go learn it.' },
};

export interface ConceptReport {
  concept: string;
  counts: Record<Outcome, number>;
  total: number;
  priority: number;
  status: Outcome | 'untested';
  lastSeen: number;
}

/** Only the first answer to each question in each scenario counts; retries after feedback don't hide a weakness. */
export function firstTries(records: ResultRecord[]): ResultRecord[] {
  const seen = new Set<string>();
  const out: ResultRecord[] = [];
  for (const r of records) {
    const key = `${r.source}|${r.concept}|${r.seed}|${r.qid}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  return out;
}

export function report(records: ResultRecord[], concepts: string[], recentPerConcept = 12): ConceptReport[] {
  const firsts = firstTries(records);
  return concepts
    .map((concept) => {
      const recent = firsts.filter((r) => r.concept === concept).slice(-recentPerConcept);
      const counts: Record<Outcome, number> = { strength: 0, lucky: 0, misconception: 0, gap: 0 };
      for (const r of recent) counts[classify(r.correct, r.confidence)]++;
      const total = recent.length;
      const priority = total === 0 ? -1 : (counts.misconception * 3 + counts.gap * 2 + counts.lucky * 2) / total;
      let status: ConceptReport['status'] = 'untested';
      if (total) {
        if (counts.misconception) status = 'misconception';
        else if (counts.gap >= counts.lucky && counts.gap > 0) status = 'gap';
        else if (counts.lucky) status = 'lucky';
        else status = 'strength';
      }
      return { concept, counts, total, priority, status, lastSeen: recent.length ? recent[recent.length - 1].at : 0 };
    })
    .sort((a, b) => b.priority - a.priority || a.concept.localeCompare(b.concept));
}
