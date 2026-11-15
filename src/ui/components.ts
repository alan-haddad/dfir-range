import { buildZip, artifactBytes } from '../bundle';
import type { Answer, Artifact, ModuleInstance, Question } from '../types';
import { copyText, download, h, md, p } from './dom';
import { recordAttempt } from './store';
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

/** Renders the questions; calls onAttempt after every check so callers can unlock debriefs. */
export function questionList(inst: ModuleInstance, moduleId: string, seed: string, onAttempt: () => void): HTMLElement {
  const wrap = h('ol', { class: 'questions' });
  for (const q of inst.questions) {
    const { el, read } = answerInput(q);
    const feedback = h('div', { class: 'feedback', 'aria-live': 'polite' });
    const btn = h('button', { class: 'btn', type: 'button' }, 'Check');
    btn.addEventListener('click', () => {
      const a = read();
      feedback.replaceChildren();
      if (a === null) {
        feedback.className = 'feedback error';
        feedback.textContent = q.kind === 'order' ? 'Fill every slot first.' : 'Enter an answer first.';
        return;
      }
      if (q.kind === 'order' && new Set(a as string[]).size !== (a as string[]).length) {
        feedback.className = 'feedback error';
        feedback.textContent = 'Use each item only once.';
        return;
      }
      const ok = inst.check(q.id, a);
      recordAttempt(moduleId, seed, q.id, ok);
      feedback.className = ok ? 'feedback ok' : 'feedback bad';
      feedback.append(h('strong', {}, ok ? 'Correct. ' : 'Not quite. '));
      if (ok) feedback.append(md(q.why));
      else feedback.append('Re-check the evidence and try again, or open a hint. The full answer appears in the debrief after any attempt.');
      onAttempt();
    });
    if (el instanceof HTMLInputElement) el.addEventListener('keydown', (e) => { if (e.key === 'Enter') btn.click(); });
    const prompt = h('div', { class: 'q-prompt' });
    prompt.append(md(q.prompt));
    wrap.append(h('li', { class: 'question' }, prompt, h('div', { class: 'q-row' }, el, btn), feedback));
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
