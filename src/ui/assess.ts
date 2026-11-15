import { buildAssessment, type AssessItem } from '../assessment';
import { randomSeed } from '../lib/prng';
import { MODULES, moduleById } from '../modules';
import type { Answer } from '../types';
import { buildWorld } from '../world';
import { confidenceToggle, findOutBox, outcomeBadge, seedBar } from './components';
import { h, md, p } from './dom';
import { load, recordAttempt, recordResult, type Confidence } from './store';
import { classify, OUTCOME_TEXT, report, type Outcome } from './weakness';
import type { Nav } from './pages';

// ---------------- Assessment ----------------

export function assessmentPage(seed: string, nav: Nav): HTMLElement {
  const items = buildAssessment(buildWorld(seed));
  const root = h('div', { class: 'page assessment' });

  const readers: { item: AssessItem; read: () => Answer | null; conf: () => 'sure' | 'guess' | null; idk: () => boolean; err: HTMLElement }[] = [];

  const form = h('ol', { class: 'assess-list' });
  for (const it of items) {
    let inputEl: HTMLElement;
    let read: () => Answer | null;
    if (it.kind === 'choice') {
      const name = `a-${it.n}`;
      const radios = it.options!.map((o) => ({ o, r: h('input', { type: 'radio', name, value: o.id }) }));
      inputEl = h('div', { class: 'choices' }, ...radios.map(({ o, r }) => h('label', { class: 'choice' }, r, h('span', {}, o.label))));
      read = () => radios.find((x) => x.r.checked)?.r.value ?? null;
    } else if (it.kind === 'order') {
      const selects = Array.from({ length: it.slots ?? 3 }, (_v, i) => h('select', { 'aria-label': `Choice ${i + 1}` }, h('option', { value: '' }, `${i + 1}. Choose…`), ...it.options!.map((o) => h('option', { value: o.id }, o.label))));
      inputEl = h('div', { class: 'order' }, ...selects);
      read = () => (selects.some((s) => !s.value) ? null : selects.map((s) => s.value));
    } else {
      const input = h('input', { type: 'text', placeholder: it.placeholder ?? 'answer', spellcheck: 'false', autocomplete: 'off' });
      inputEl = input;
      read = () => (input.value.trim() ? input.value.trim() : null);
    }
    const conf = confidenceToggle();
    const idkBox = h('input', { type: 'checkbox' });
    idkBox.addEventListener('change', () => {
      inputEl.querySelectorAll('input,select').forEach((x) => ((x as HTMLInputElement).disabled = idkBox.checked));
      if (inputEl instanceof HTMLInputElement) inputEl.disabled = idkBox.checked;
      conf.el.classList.toggle('dim', idkBox.checked);
    });
    const err = h('div', { class: 'feedback error', 'aria-live': 'polite' });
    readers.push({ item: it, read, conf: conf.read, idk: () => idkBox.checked, err });
    const prompt = h('div', { class: 'q-prompt' }, h('span', { class: 'qnum' }, `${it.n}.`), ' ');
    prompt.append(md(it.prompt));
    form.append(
      h(
        'li',
        { class: 'assess-item' },
        prompt,
        it.snippet ? h('pre', { class: 'snippet', tabindex: '0' }, it.snippet) : null,
        inputEl,
        h('div', { class: 'q-row' }, conf.el, h('label', { class: 'toggle idk' }, idkBox, 'I don\'t know')),
        p(`Then say out loud: ${it.sayOutLoud}`, 'muted small'),
        err,
      ),
    );
  }

  const submitErr = h('div', { class: 'feedback error', 'aria-live': 'polite' });
  const submit = h('button', { class: 'btn big', type: 'button' }, 'Submit assessment');
  submit.addEventListener('click', () => {
    let missing = 0;
    for (const r of readers) {
      r.err.textContent = '';
      if (r.idk()) continue;
      const a = r.read();
      if (a === null) {
        r.err.textContent = r.item.kind === 'order' ? 'Fill every slot, or tick "I don\'t know".' : 'Answer this, or tick "I don\'t know".';
        missing++;
      } else if (r.item.kind === 'order' && new Set(a as string[]).size !== (a as string[]).length) {
        r.err.textContent = 'Use each item only once.';
        missing++;
      } else if (!r.conf()) {
        r.err.textContent = 'Pick Sure or Guessing.';
        missing++;
      }
    }
    if (missing) {
      submitErr.textContent = `${missing} question${missing > 1 ? 's need' : ' needs'} attention above. Guessing is allowed, but say so.`;
      return;
    }
    const results = readers.map((r) => {
      const idk = r.idk();
      const a = idk ? null : r.read();
      const confidence: Confidence = idk ? 'idk' : r.conf()!;
      const correct = !idk && a !== null && r.item.check(a);
      recordResult({ concept: r.item.concept, qid: `q${r.item.n}`, seed, source: 'assessment', correct, confidence });
      recordAttempt(r.item.concept, seed, `assess-${r.item.n}`, correct);
      return { item: r.item, answer: a, confidence, correct, outcome: classify(correct, confidence) };
    });
    showResults(results);
  });

  const showResults = (results: { item: AssessItem; answer: Answer | null; confidence: Confidence; correct: boolean; outcome: Outcome }[]) => {
    const count = (o: Outcome) => results.filter((r) => r.outcome === o).length;
    const correct = results.filter((r) => r.correct).length;
    const order: Outcome[] = ['misconception', 'gap', 'lucky'];
    const priorities = results.filter((r) => r.outcome !== 'strength').sort((a, b) => order.indexOf(a.outcome) - order.indexOf(b.outcome));
    const label = (it: AssessItem, a: Answer | null) => {
      if (a === null) return '(I don\'t know)';
      if (Array.isArray(a)) return a.map((id) => it.options?.find((o) => o.id === id)?.label ?? id).join(' → ');
      return it.kind === 'choice' ? it.options?.find((o) => o.id === a)?.label ?? a : a;
    };
    root.replaceChildren(
      h('a', { class: 'back', href: '#/' }, '← Home'),
      h('h1', {}, 'Assessment results'),
      h('p', { class: 'score' }, `${correct} of ${results.length} correct.`),
      matrix(count('strength'), count('lucky'), count('misconception'), count('gap')),
      h('h2', {}, 'Your priorities'),
      priorities.length
        ? h(
            'ol',
            { class: 'priorities' },
            ...priorities.map((r) => {
              const m = moduleById(r.item.concept)!;
              return h('li', {}, outcomeBadge(r.outcome), ' ', h('a', { href: `#/learn/${m.id}?seed=${randomSeed()}` }, `Module ${String(m.number).padStart(2, '0')}: ${m.title}`));
            }),
          )
        : p('Nothing to fix in this run: every answer was correct and you were sure. Try another seed, or Interview mode.'),
      h('h2', {}, 'Question by question'),
      h(
        'ol',
        { class: 'assess-results' },
        ...results.map((r) => {
          const li = h(
            'li',
            { class: `result ${r.outcome}` },
            h('div', { class: 'q-prompt' }, outcomeBadge(r.outcome), ' ', h('span', {}, `${r.item.n}. ${r.item.prompt}`)),
            h('div', { class: 'small' }, h('span', { class: 'muted' }, 'Your answer: '), h('code', {}, label(r.item, r.answer)), r.confidence !== 'idk' ? h('span', { class: 'muted' }, ` (${r.confidence === 'sure' ? 'sure' : 'guessing'})`) : ''),
            h('div', { class: 'small' }, h('span', { class: 'muted' }, 'Expected: '), h('code', {}, r.item.expected)),
          );
          li.append(p(r.item.why, 'small'));
          if (r.outcome !== 'strength') li.append(p(OUTCOME_TEXT[r.outcome].note, 'muted small'));
          if (r.outcome === 'gap' && r.confidence === 'idk') li.append(findOutBox(`${r.item.concept}:assess`, moduleById(r.item.concept)?.hints[2]));
          li.append(p(`Also be ready to say: ${r.item.sayOutLoud}`, 'muted small'));
          return li;
        }),
      ),
      h('div', { class: 'q-row' }, h('button', { class: 'btn', type: 'button', onclick: () => nav(`#/assessment?seed=${randomSeed()}`) }, 'New assessment'), h('a', { class: 'btn ghost', href: '#/progress' }, 'See all my weak spots')),
    );
    window.scrollTo(0, 0);
  };

  root.append(
    h('a', { class: 'back', href: '#/' }, '← Home'),
    h('h1', {}, 'Assessment'),
    seedBar(seed, (s) => nav(`#/assessment?seed=${encodeURIComponent(s)}`)),
    h(
      'div',
      { class: 'prompt-card' },
      h('p', { class: 'eyebrow' }, 'The format of a real skills assessment'),
      p('Answer each question and talk through your reasoning out loud as you go. Use your normal tools (a terminal, CyberChef). There is no time pressure and no hints.'),
      p('**Don\'t guess silently.** For each answer, say whether you are sure or guessing, or tick "I don\'t know". A lucky guess counts as a weak spot, and being confidently wrong is the top priority to fix.', 'muted'),
    ),
    form,
    submitErr,
    h('div', { class: 'q-row' }, submit),
  );
  return root;
}

function matrix(strength: number, lucky: number, miscon: number, gap: number): HTMLElement {
  const cell = (o: Outcome, n: number) => h('div', { class: `cell ${o}` }, h('div', { class: 'n' }, String(n)), h('div', { class: 'l' }, OUTCOME_TEXT[o].label));
  return h('div', { class: 'matrix' }, cell('strength', strength), cell('lucky', lucky), cell('misconception', miscon), cell('gap', gap));
}

// ---------------- Weak spots ----------------

export function progressPage(): HTMLElement {
  const st = load();
  const rep = report(st.records ?? [], MODULES.map((m) => m.id));
  const tested = rep.filter((r) => r.total > 0);
  const totals = tested.reduce((acc, r) => ({ strength: acc.strength + r.counts.strength, lucky: acc.lucky + r.counts.lucky, misconception: acc.misconception + r.counts.misconception, gap: acc.gap + r.counts.gap }), { strength: 0, lucky: 0, misconception: 0, gap: 0 });
  const statusText = (s: Outcome | 'untested') => (s === 'untested' ? 'Not tried yet' : OUTCOME_TEXT[s].label);
  return h(
    'div',
    { class: 'page' },
    h('a', { class: 'back', href: '#/' }, '← Home'),
    h('h1', {}, 'My weak spots'),
    p('Built from the **first** answer you give to each question in Learn, Assessment and Interview modes, together with how sure you said you were. Retrying after feedback does not hide a weakness. Everything stays in this browser.', 'muted'),
    tested.length ? matrix(totals.strength, totals.lucky, totals.misconception, totals.gap) : p('Nothing yet. Take an [assessment](#/assessment) to get a baseline across all 15 concepts.'),
    h(
      'div',
      { class: 'legend small muted' },
      h('div', {}, outcomeBadge('misconception'), ' wrong while sure: fix first'),
      h('div', {}, outcomeBadge('gap'), ' wrong while guessing, or "I don\'t know"'),
      h('div', {}, outcomeBadge('lucky'), ' right, but guessing'),
      h('div', {}, outcomeBadge('strength'), ' right and sure'),
    ),
    h(
      'ol',
      { class: 'weak-list' },
      ...rep.map((r) => {
        const m = moduleById(r.concept)!;
        return h(
          'li',
          { class: `weak ${r.status}` },
          h('div', { class: 'weak-head' }, h('span', { class: 'module-num small' }, String(m.number).padStart(2, '0')), h('strong', {}, m.title), r.status === 'untested' ? h('span', { class: 'outcome untested' }, statusText(r.status)) : outcomeBadge(r.status)),
          r.total ? h('div', { class: 'small muted' }, `Your last ${r.total} first answer${r.total > 1 ? 's' : ''}: ${r.counts.strength} strength · ${r.counts.lucky} lucky · ${r.counts.misconception} misconception · ${r.counts.gap} gap`) : null,
          h('div', { class: 'q-row' }, h('a', { class: 'btn ghost small', href: `#/learn/${m.id}` }, 'Study'), h('a', { class: 'btn small', href: `#/learn/${m.id}?seed=${randomSeed()}` }, 'Retest with a new scenario')),
        );
      }),
    ),
  );
}
