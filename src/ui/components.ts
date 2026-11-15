import { buildZip, artifactBytes } from '../bundle';
import type { Answer, Artifact, ModuleInstance, Question } from '../types';
import { copyText, download, h, md, p } from './dom';
import { load, recordAttempt, recordResult, update, type Source } from './store';
import { classify, OUTCOME_TEXT, type Outcome } from './weakness';
import { randomSeed } from '../lib/prng';

export function seedBar(seed: string, onNew: (seed: string) => void): HTMLElement {
  const input = h('input', { type: 'text', value: seed, 'aria-label': 'Scenario seed', spellcheck: 'false', class: 'seed-input' });
  const share = h('button', { class: 'btn ghost', type: 'button' }, 'Copy link');
  share.addEventListener('click', () => copyText(location.href, share));
  return h(
    'div',
    { class: 'seedbar' },
    h('span', { class: 'muted' }, 'Scenario seed'),
    input,
    h('button', { class: 'btn ghost', type: 'button', onclick: () => onNew(input.value.trim().toLowerCase()) }, 'Load'),
    h('button', { class: 'btn', type: 'button', onclick: () => onNew(randomSeed()) }, 'New scenario'),
    share,
  );
}

function mimeFor(path: string): string {
  if (path.endsWith('.xml')) return 'application/xml';
  if (path.endsWith('.jsonl') || path.endsWith('.json')) return 'application/json';
  if (path.endsWith('.eml')) return 'message/rfc822';
  if (path.endsWith('.md') || path.endsWith('.txt') || path.endsWith('Zone.Identifier')) return 'text/plain';
  return 'application/octet-stream';
}

export function artifactViewer(a: Artifact): HTMLElement {
  const text = a.view ?? (typeof a.content === 'string' ? a.content : '');
  const copyBtn = h('button', { class: 'btn ghost small', type: 'button' }, 'Copy');
  copyBtn.addEventListener('click', () => copyText(typeof a.content === 'string' ? a.content : text, copyBtn));
  const name = a.path.split('/').pop()!;
  return h(
    'details',
    { class: 'artifact' },
    h('summary', {}, h('span', { class: 'artifact-title' }, a.title), h('code', { class: 'artifact-path' }, a.path)),
    a.note ? p(a.note, 'muted small') : null,
    h(
      'div',
      { class: 'artifact-actions' },
      typeof a.content === 'string' ? copyBtn : null,
      h('button', { class: 'btn ghost small', type: 'button', onclick: () => download(name, artifactBytes(a), mimeFor(a.path)) }, 'Download file'),
    ),
    h('pre', { class: 'artifact-body', tabindex: '0' }, text.replace(/\r\n/g, '\n')),
  );
}

export function evidencePanel(artifacts: Artifact[], seed: string, label: string): HTMLElement {
  const zipBtn = h('button', { class: 'btn small', type: 'button' }, 'Download evidence bundle (.zip)');
  zipBtn.addEventListener('click', async () => {
    zipBtn.disabled = true;
    try {
      download(`dfir-range-${label}-${seed}.zip`, await buildZip(artifacts, seed), 'application/zip');
    } finally {
      zipBtn.disabled = false;
    }
  });
  return h(
    'section',
    { class: 'evidence' },
    h('div', { class: 'evidence-head' }, h('h3', {}, 'Evidence'), zipBtn),
    ...artifacts.map(artifactViewer),
  );
}

function answerInput(q: Question): { el: HTMLElement; read: () => Answer | null } {
  if (q.kind === 'choice') {
    const name = `q-${q.id}-${Math.random().toString(36).slice(2, 7)}`;
    const radios = q.options!.map((o) => {
      const r = h('input', { type: 'radio', name, value: o.id });
      return { r, el: h('label', { class: 'choice' }, r, h('span', {}, o.label)) };
    });
    return {
      el: h('div', { class: 'choices', role: 'radiogroup' }, ...radios.map((x) => x.el)),
      read: () => radios.find((x) => x.r.checked)?.r.value ?? null,
    };
  }
  if (q.kind === 'order') {
    const selects = Array.from({ length: q.slots ?? 3 }, (_v, i) => {
      const s = h('select', { 'aria-label': `Choice ${i + 1}` }, h('option', { value: '' }, `${i + 1}. Choose…`), ...q.options!.map((o) => h('option', { value: o.id }, o.label)));
      return s;
    });
    return {
      el: h('div', { class: 'order' }, ...selects),
      read: () => {
        const vals = selects.map((s) => s.value);
        if (vals.some((v) => !v)) return null;
        return vals;
      },
    };
  }
  const input = h('input', { type: 'text', placeholder: q.placeholder ?? '', spellcheck: 'false', autocomplete: 'off' });
  return { el: input, read: () => (input.value.trim() ? input.value.trim() : null) };
}

export interface QuestionListOptions {
  /** Module id used for debrief unlocking ("case" for the case file). */
  moduleId: string;
  seed: string;
  source: Source;
  /** Which concept (module id) a question belongs to, for the weak-spots report. */
  concept: (qid: string) => string;
  /** Text shown after "I don't know": one way to find the answer. */
  findOutHint?: (qid: string) => string | undefined;
  onAttempt: () => void;
}

/** Sure / Guessing toggle. Returns a reader for the current choice. */
export function confidenceToggle(): { el: HTMLElement; read: () => 'sure' | 'guess' | null; reset: () => void } {
  const name = `c-${Math.random().toString(36).slice(2, 8)}`;
  const sure = h('input', { type: 'radio', name, value: 'sure' });
  const guess = h('input', { type: 'radio', name, value: 'guess' });
  return {
    el: h(
      'div',
      { class: 'confidence', role: 'radiogroup', 'aria-label': 'How confident are you?' },
      h('span', { class: 'muted small' }, 'How sure are you?'),
      h('label', { class: 'pill-choice' }, sure, h('span', {}, 'Sure')),
      h('label', { class: 'pill-choice' }, guess, h('span', {}, 'Guessing')),
    ),
    read: () => (sure.checked ? 'sure' : guess.checked ? 'guess' : null),
    reset: () => {
      sure.checked = false;
      guess.checked = false;
    },
  };
}

function expectedText(inst: ModuleInstance, q: Question): string {
  const exp = inst.expected[q.id];
  const label = (id: string) => q.options?.find((o) => o.id === id)?.label ?? id;
  if (Array.isArray(exp)) return exp.map(label).join(' → ');
  return q.kind === 'choice' ? label(exp) : exp;
}

export function outcomeBadge(o: Outcome): HTMLElement {
  return h('span', { class: `outcome ${o}` }, OUTCOME_TEXT[o].label);
}

/** "How would you find out?" prompt shown after "I don't know", saved locally. */
export function findOutBox(key: string, hint?: string): HTMLElement {
  const ta = h('textarea', { rows: '3', placeholder: 'In an interview, "I don\'t know, but here is how I would find out" is a strong answer. How would you find out?' });
  ta.value = load().findOut?.[key] ?? '';
  ta.addEventListener('input', () => update((s) => { s.findOut ??= {}; s.findOut[key] = ta.value; }));
  const box = h('div', { class: 'find-out' }, ta);
  if (hint) {
    const d = h('details', {}, h('summary', {}, 'One way to find out'));
    d.append(p(hint));
    box.append(d);
  }
  return box;
}

/**
 * Renders the questions with a confidence toggle and an "I don't know" button.
 * The first answer to each question is what the weak-spots report counts.
 */
export function questionList(inst: ModuleInstance, o: QuestionListOptions): HTMLElement {
  const wrap = h('ol', { class: 'questions' });
  for (const q of inst.questions) {
    const { el, read } = answerInput(q);
    const conf = confidenceToggle();
    const feedback = h('div', { class: 'feedback', 'aria-live': 'polite' });
    const btn = h('button', { class: 'btn', type: 'button' }, 'Check');
    const idk = h('button', { class: 'btn ghost', type: 'button' }, 'I don\'t know');
    const concept = o.concept(q.id);
    let gaveUp = false;

    btn.addEventListener('click', () => {
      const a = read();
      feedback.replaceChildren();
      if (a === null) {
        feedback.className = 'feedback error';
        feedback.textContent = q.kind === 'order' ? 'Fill every slot first.' : 'Enter an answer first, or choose "I don\'t know".';
        return;
      }
      if (q.kind === 'order' && new Set(a as string[]).size !== (a as string[]).length) {
        feedback.className = 'feedback error';
        feedback.textContent = 'Use each item only once.';
        return;
      }
      const confidence = conf.read();
      if (!confidence) {
        feedback.className = 'feedback error';
        feedback.textContent = 'Pick Sure or Guessing first. It is how your weak spots get found.';
        return;
      }
      const ok = inst.check(q.id, a);
      recordAttempt(o.moduleId, o.seed, q.id, ok);
      recordResult({ concept, qid: q.id, seed: o.seed, source: o.source, correct: ok, confidence });
      const outcome = classify(ok, confidence);
      feedback.className = ok ? 'feedback ok' : 'feedback bad';
      feedback.append(outcomeBadge(outcome), ' ', h('strong', {}, ok ? 'Correct. ' : 'Not quite. '));
      if (ok) {
        feedback.append(md(q.why));
        if (outcome === 'lucky') feedback.append(h('div', { class: 'muted small' }, OUTCOME_TEXT.lucky.note));
      } else {
        feedback.append(gaveUp ? 'Try again with what you learned.' : 'Re-check the evidence and try again, or open a hint. The full answer appears in the debrief.');
        if (outcome === 'misconception') feedback.append(h('div', { class: 'muted small' }, OUTCOME_TEXT.misconception.note));
      }
      conf.reset();
      o.onAttempt();
    });

    idk.addEventListener('click', () => {
      gaveUp = true;
      recordAttempt(o.moduleId, o.seed, q.id, false);
      recordResult({ concept, qid: q.id, seed: o.seed, source: o.source, correct: false, confidence: 'idk' });
      feedback.className = 'feedback gap';
      feedback.replaceChildren(outcomeBadge('gap'), ' ', h('strong', {}, 'Answer: '), h('code', {}, expectedText(inst, q)), ' ');
      feedback.append(md(q.why));
      feedback.append(findOutBox(`${concept}:${q.id}`, o.findOutHint?.(q.id)));
      o.onAttempt();
    });

    if (el instanceof HTMLInputElement) el.addEventListener('keydown', (e) => { if (e.key === 'Enter') btn.click(); });
    const prompt = h('div', { class: 'q-prompt' });
    prompt.append(md(q.prompt));
    wrap.append(h('li', { class: 'question' }, prompt, el, h('div', { class: 'q-row' }, conf.el, btn, idk), feedback));
  }
  return wrap;
}

export function answerKey(inst: ModuleInstance): HTMLElement {
  return h(
    'dl',
    { class: 'answer-key' },
    ...inst.questions.flatMap((q) => {
      const exp = inst.expected[q.id];
      const label = (id: string) => q.options?.find((o) => o.id === id)?.label ?? id;
      const shown = Array.isArray(exp) ? exp.map(label).join(' → ') + (q.kind === 'order' ? '  (memory and live state may swap places)' : '') : q.kind === 'choice' ? label(exp) : exp;
      const dd = h('dd');
      dd.append(h('code', {}, shown), ' ');
      dd.append(md(q.why));
      return [h('dt', {}, q.prompt), dd];
    }),
  );
}
