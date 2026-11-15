import { aiGradingPrompt, buildCaseFile, CASE_CONCEPT, CASE_FOLLOWUPS, CASE_PROMPT, CASE_RUBRIC } from '../casefile';
import { DRILLS, type DrillItem } from '../drills';
import { Rng, randomSeed } from '../lib/prng';
import { MODULES, PLANNED, moduleById } from '../modules';
import type { ModuleDef } from '../types';
import { buildWorld } from '../world';
import { answerKey, evidencePanel, questionList, seedBar } from './components';
import { copyText, download, h, md, p, ul } from './dom';
import { exportProgress, hasAttempted, importProgress, load, resetProgress, solvedCount, update } from './store';

const TRACK_LABEL = { t1: 'SOC Tier 1', t2: 'SOC Tier 2 / IR' } as const;
const DIFF_LABEL = ['', 'Foundational', 'Intermediate', 'Advanced'];

export type Nav = (hash: string) => void;

function tags(m: ModuleDef): HTMLElement {
  return h(
    'div',
    { class: 'tags' },
    ...m.tracks.map((t) => h('span', { class: `tag ${t}` }, TRACK_LABEL[t])),
    h('span', { class: 'tag diff' }, DIFF_LABEL[m.difficulty]),
  );
}

// ---------------- Home ----------------

export function homePage(nav: Nav): HTMLElement {
  const st = load();
  const list = h('div', { class: 'module-grid' });
  const render = () => {
    const track = load().track;
    list.replaceChildren(
      ...MODULES.filter((m) => track === 'all' || m.tracks.includes(track)).map((m) => {
        const solved = solvedCount(m.id);
        return h(
          'a',
          { class: 'module-card', href: `#/learn/${m.id}` },
          h('div', { class: 'module-num' }, String(m.number).padStart(2, '0')),
          h('div', {}, h('h3', {}, m.title), h('p', { class: 'muted' }, m.short), tags(m), solved ? h('div', { class: 'solved' }, `Solved ${solved} scenario${solved > 1 ? 's' : ''}`) : null),
        );
      }),
    );
  };
  const filter = h(
    'div',
    { class: 'segmented', role: 'group', 'aria-label': 'Filter by track' },
    ...(['all', 't1', 't2'] as const).map((t) => {
      const b = h('button', { type: 'button', class: st.track === t ? 'active' : '' }, t === 'all' ? 'All' : TRACK_LABEL[t]);
      b.addEventListener('click', () => {
        update((s) => (s.track = t));
        filter.querySelectorAll('button').forEach((x) => x.classList.remove('active'));
        b.classList.add('active');
        render();
      });
      return b;
    }),
  );
  render();
  return h(
    'div',
    { class: 'page' },
    h(
      'section',
      { class: 'hero' },
      h('p', { class: 'eyebrow' }, 'Free · runs in your browser · nothing leaves your machine'),
      h('h1', {}, 'Practice the SOC and incident-response interview.'),
      p('Interviewers drop a link to some evidence and say *"walk me through your thought process."* This range gives you that, with realistic synthetic evidence that changes with every seed, plus debriefs on what a strong answer sounds like. It also tracks how sure you were, so lucky guesses and confident mistakes show up as [weak spots](#/progress) instead of hiding.'),
      h(
        'div',
        { class: 'mode-cards' },
        modeCard('Assessment', 'Fifteen short questions on one page, in the format of a real skills assessment. Say how sure you are, or "I don\'t know", and get a ranked list of weak spots.', 'Take an assessment', () => nav('#/assessment')),
        modeCard('Interview mode', 'One case file and one prompt: walk through it out loud, then answer the structured questions and grade yourself against the rubric.', 'Start a case', () => nav('#/interview')),
        modeCard('Learn', 'One concept per module: background on why each step matters, the evidence, tiered hints, questions and a debrief.', 'Browse modules', () => document.getElementById('modules')?.scrollIntoView({ behavior: 'smooth' })),
        modeCard('Drills', 'Thirty-second recognition reps: spot UTF-16LE Base64, normalize IPs, XOR cribs, event IDs, order of volatility.', 'Start drilling', () => nav('#/drills')),
      ),
    ),
    h('section', { id: 'modules' }, h('div', { class: 'section-head' }, h('h2', {}, 'Modules'), filter), list),
    PLANNED.length === 0
      ? null
      : h(
      'section',
      { class: 'roadmap' },
      h('h2', {}, 'Coming next'),
      p('These concepts are on the roadmap and will join the case file as they ship:', 'muted'),
      h('ul', { class: 'planned' }, ...PLANNED.map((x) => h('li', {}, h('span', { class: 'module-num small' }, String(x.number).padStart(2, '0')), x.title))),
    ),
  );
}

function modeCard(title: string, body: string, cta: string, onClick: () => void): HTMLElement {
  return h('div', { class: 'mode-card' }, h('h3', {}, title), h('p', { class: 'muted' }, body), h('button', { class: 'btn', type: 'button', onclick: onClick }, cta));
}

// ---------------- Learn ----------------

export function learnPage(id: string, seed: string, nav: Nav): HTMLElement {
  const m = moduleById(id);
  if (!m) return notFound(nav);
  const w = buildWorld(seed);
  const inst = m.build(w);
  const st = load();

  const debrief = h('section', { class: 'debrief' });
  const renderDebrief = () => {
    if (!hasAttempted(m.id)) {
      debrief.replaceChildren(h('h2', {}, 'Debrief'), h('div', { class: 'locked' }, h('p', {}, 'The debrief unlocks after you check at least one answer. Commit to an answer first: that is where the learning happens.')));
      return;
    }
    debrief.replaceChildren(
      h('h2', {}, 'Debrief'),
      h('h3', {}, 'Answers for this seed'),
      answerKey(inst),
      h('h3', {}, 'What interviewers listen for'),
      ul(m.rubric.listenFor, 'checklist'),
      h(
        'div',
        { class: 'tiers' },
        h('div', { class: 'tier weak' }, h('h4', {}, 'Weak'), p(m.rubric.weak)),
        h('div', { class: 'tier solid' }, h('h4', {}, 'Solid'), p(m.rubric.solid)),
        h('div', { class: 'tier strong' }, h('h4', {}, 'Strong'), p(m.rubric.strong)),
      ),
      h('h3', {}, 'Follow-up questions to expect'),
      ul(m.followUps),
      h('h3', {}, 'Common mistakes'),
      ul(m.mistakes),
      h('h3', {}, 'References'),
      h('ul', { class: 'refs' }, ...m.references.map((r) => h('li', {}, h('a', { href: r.url, target: '_blank', rel: 'noopener noreferrer' }, r.label)))),
    );
  };
  renderDebrief();

  const notes = h('textarea', { rows: '6', placeholder: 'Write it the way you would say it in the interview.' });
  notes.value = st.explain[m.id] ?? '';
  notes.addEventListener('input', () => update((s) => (s.explain[m.id] = notes.value)));

  const hintsOn = st.hints;
  const idx = MODULES.indexOf(m);
  const prev = MODULES[idx - 1];
  const next = MODULES[idx + 1];

  return h(
    'div',
    { class: 'page module' },
    h('a', { class: 'back', href: '#/' }, '← All modules'),
    h('header', { class: 'module-head' }, h('div', { class: 'module-num big' }, String(m.number).padStart(2, '0')), h('div', {}, h('h1', {}, m.title), tags(m))),
    seedBar(seed, (s) => nav(`#/learn/${m.id}?seed=${encodeURIComponent(s)}`)),
    h('section', {}, h('h2', {}, 'Objective'), p(m.objective)),
    h('section', {}, h('h2', {}, 'Background: why this matters'), ...m.background.map((t) => p(t))),
    h('section', {}, h('h2', {}, 'Where the evidence is'), p(m.evidenceNote), evidencePanel(inst.artifacts, seed, m.id)),
    hintsOn
      ? h('section', {}, h('h2', {}, 'Hints'), ...m.hints.map((t, i) => h('details', { class: 'hint' }, h('summary', {}, `Hint ${i + 1}${i === 2 ? ' (most direct)' : ''}`), p(t))))
      : null,
    h('section', {}, h('h2', {}, 'Explain it'), p(m.explainPrompt, 'muted'), notes, p('Saved in this browser only.', 'muted small')),
    h(
      'section',
      {},
      h('h2', {}, 'Check your answer'),
      p('Say how sure you are before checking, or choose "I don\'t know". Your first answer to each question feeds [your weak spots](#/progress).', 'muted small'),
      questionList(inst, { moduleId: m.id, seed, source: 'learn', concept: () => m.id, findOutHint: () => m.hints[2], onAttempt: renderDebrief }),
    ),
    debrief,
    h('nav', { class: 'pager' }, prev ? h('a', { href: `#/learn/${prev.id}` }, `← ${prev.title}`) : h('span'), next ? h('a', { href: `#/learn/${next.id}` }, `${next.title} →`) : h('a', { href: '#/interview' }, 'Try the full case file →')),
  );
}

// ---------------- Drills ----------------

export function drillsPage(): HTMLElement {
  const rng = new Rng(randomSeed());
  const enabled = new Set(DRILLS.map((d) => d.id));
  let streak = 0;
  const streakEl = h('span', { class: 'streak' });
  const card = h('div', { class: 'drill-card' });

  const updateStreak = () => {
    streakEl.textContent = `Streak ${streak} · Best ${load().drillBest}`;
  };

  const nextItem = () => {
    const pool = DRILLS.filter((d) => enabled.has(d.id));
    if (!pool.length) {
      card.replaceChildren(p('Pick at least one drill type.'));
      return;
    }
    const d = rng.pick(pool);
    renderItem(d.title, d.make(rng));
  };

  const renderItem = (title: string, item: DrillItem) => {
    const feedback = h('div', { class: 'feedback', 'aria-live': 'polite' });
    let read: () => string | null;
    let inputEl: HTMLElement;
    if (item.kind === 'choice') {
      const name = `d-${Math.random().toString(36).slice(2, 7)}`;
      const radios = item.options!.map((o) => ({ o, r: h('input', { type: 'radio', name, value: o.id }) }));
      inputEl = h('div', { class: 'choices' }, ...radios.map(({ o, r }) => h('label', { class: 'choice' }, r, h('span', {}, o.label))));
      read = () => radios.find((x) => x.r.checked)?.r.value ?? null;
    } else {
      const input = h('input', { type: 'text', placeholder: item.placeholder ?? '', spellcheck: 'false', autocomplete: 'off' });
      inputEl = input;
      read = () => (input.value.trim() ? input.value.trim() : null);
      setTimeout(() => input.focus(), 0);
    }
    const nextBtn = h('button', { class: 'btn ghost', type: 'button', onclick: nextItem }, 'Next →');
    const checkBtn = h('button', { class: 'btn', type: 'button' }, 'Check');
    let answered = false;
    checkBtn.addEventListener('click', () => {
      const a = read();
      if (a === null) {
        feedback.className = 'feedback error';
        feedback.textContent = 'Enter an answer first.';
        return;
      }
      if (answered) return;
      answered = true;
      const ok = item.check(a);
      streak = ok ? streak + 1 : 0;
      if (streak > load().drillBest) update((s) => (s.drillBest = streak));
      updateStreak();
      feedback.className = ok ? 'feedback ok' : 'feedback bad';
      feedback.replaceChildren(h('strong', {}, ok ? 'Correct. ' : `Answer: ${item.answer}. `), item.explain);
      checkBtn.disabled = true;
      nextBtn.focus();
    });
    if (inputEl instanceof HTMLInputElement) inputEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') (answered ? nextBtn : checkBtn).click(); });
    card.replaceChildren(
      h('p', { class: 'eyebrow' }, title),
      h('p', { class: 'drill-prompt' }, item.prompt),
      item.display ? h('pre', { class: 'drill-display' }, item.display) : '',
      inputEl,
      h('div', { class: 'q-row' }, checkBtn, nextBtn),
      feedback,
    );
  };

  const toggles = h(
    'div',
    { class: 'drill-toggles' },
    ...DRILLS.map((d) => {
      const cb = h('input', { type: 'checkbox', checked: true });
      cb.addEventListener('change', () => {
        if (cb.checked) enabled.add(d.id);
        else enabled.delete(d.id);
      });
      return h('label', { class: 'toggle' }, cb, d.title);
    }),
  );

  updateStreak();
  nextItem();
  return h('div', { class: 'page' }, h('a', { class: 'back', href: '#/' }, '← Home'), h('h1', {}, 'Drills'), p('Fast recognition reps. Speed matters in interviews: the goal is to recognize these on sight and explain them in one sentence.', 'muted'), toggles, h('div', { class: 'drill-head' }, streakEl), card);
}

// ---------------- Interview ----------------

export function interviewPage(seed: string, nav: Nav): HTMLElement {
  const w = buildWorld(seed);
  const inst = buildCaseFile(w);
  const root = h('div', { class: 'page interview' });
  let timerHandle: number | undefined;
  let recorder: MediaRecorder | null = null;
  let audioUrl: string | null = null;
  const notes = h('textarea', { rows: '10', placeholder: 'Optional: jot down what you said, or type your walkthrough if you can\'t talk out loud right now.' });

  const phase1 = () => {
    const timerSel = h('select', { 'aria-label': 'Timer' }, ...['off', '10', '15', '20', '30'].map((v) => h('option', { value: v }, v === 'off' ? 'No timer' : `${v} minutes`)));
    const timerEl = h('span', { class: 'timer', 'aria-live': 'off' });
    timerSel.addEventListener('change', () => {
      clearInterval(timerHandle);
      timerEl.textContent = '';
      if (timerSel.value === 'off') return;
      const end = Date.now() + Number(timerSel.value) * 60_000;
      const tick = () => {
        const left = Math.max(0, end - Date.now());
        const mm = Math.floor(left / 60000);
        const ss = Math.floor((left % 60000) / 1000);
        timerEl.textContent = `${mm}:${String(ss).padStart(2, '0')}`;
        timerEl.classList.toggle('late', left < 60_000);
        if (left === 0) clearInterval(timerHandle);
      };
      tick();
      timerHandle = window.setInterval(tick, 500);
    });

    const recBtn = h('button', { class: 'btn ghost', type: 'button' }, 'Record my walkthrough');
    const recStatus = h('span', { class: 'muted small' });
    const player = h('div', { class: 'player' });
    const canRecord = typeof MediaRecorder !== 'undefined' && !!navigator.mediaDevices?.getUserMedia;
    if (!canRecord) {
      recBtn.disabled = true;
      recStatus.textContent = 'Recording is not supported in this browser.';
    }
    recBtn.addEventListener('click', async () => {
      if (recorder && recorder.state === 'recording') {
        recorder.stop();
        return;
      }
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        const chunks: Blob[] = [];
        recorder = new MediaRecorder(stream);
        recorder.addEventListener('dataavailable', (e) => chunks.push(e.data));
        recorder.addEventListener('stop', () => {
          stream.getTracks().forEach((t) => t.stop());
          if (audioUrl) URL.revokeObjectURL(audioUrl);
          const blob = new Blob(chunks, { type: recorder?.mimeType || 'audio/webm' });
          audioUrl = URL.createObjectURL(blob);
          recBtn.textContent = 'Record again';
          recStatus.textContent = 'Saved in this tab only. Nothing is uploaded.';
          const del = h('button', { class: 'btn ghost small', type: 'button' }, 'Delete recording');
          del.addEventListener('click', () => {
            if (audioUrl) URL.revokeObjectURL(audioUrl);
            audioUrl = null;
            player.replaceChildren();
            recStatus.textContent = 'Recording deleted.';
          });
          player.replaceChildren(h('audio', { controls: true, src: audioUrl }), h('a', { class: 'btn ghost small', href: audioUrl, download: `walkthrough-${seed}.webm` }, 'Download'), del);
        });
        recorder.start();
        recBtn.textContent = 'Stop recording';
        recStatus.textContent = 'Recording… audio stays in this browser tab.';
      } catch {
        recStatus.textContent = 'Microphone access was denied or is unavailable.';
      }
    });

    root.replaceChildren(
      h('a', { class: 'back', href: '#/' }, '← Home'),
      h('h1', {}, 'Interview mode'),
      seedBar(seed, (s) => nav(`#/interview?seed=${encodeURIComponent(s)}`)),
      h('div', { class: 'prompt-card' }, h('p', { class: 'eyebrow' }, 'Phase 1 of 3 · Open walkthrough'), h('blockquote', {}, `"${CASE_PROMPT}"`), p('Talk through it out loud as if an interviewer were listening: what you look at first, what you think is happening, and how you would confirm it. No hints in this mode.', 'muted')),
      h('div', { class: 'tools-row' }, timerSel, timerEl, recBtn, recStatus),
      player,
      evidencePanel(inst.artifacts, seed, 'case'),
      h('h2', {}, 'Your notes'),
      notes,
      h('div', { class: 'q-row' }, h('button', { class: 'btn', type: 'button', onclick: phase2 }, 'I\'m done talking → structured questions')),
    );
  };

  const answers: Record<string, string> = {};

  const phase2 = () => {
    clearInterval(timerHandle);
    const qs = questionList(
      {
        ...inst,
        check: (qid, a) => {
          answers[qid] = Array.isArray(a) ? a.join(', ') : a;
          return inst.check(qid, a);
        },
      },
      {
        moduleId: 'case',
        seed,
        source: 'case',
        concept: (qid) => CASE_CONCEPT[qid] ?? 'case',
        findOutHint: (qid) => moduleById(CASE_CONCEPT[qid] ?? '')?.hints[2],
        onAttempt: () => {},
      },
    );
    root.replaceChildren(
      h('a', { class: 'back', href: '#/' }, '← Home'),
      h('h1', {}, 'Interview mode'),
      h('div', { class: 'prompt-card' }, h('p', { class: 'eyebrow' }, 'Phase 2 of 3 · Structured questions'), p('These are the questions an interviewer asks after your walkthrough. The evidence is still below.', 'muted')),
      qs,
      h('div', { class: 'q-row' }, h('button', { class: 'btn', type: 'button', onclick: phase3 }, 'Finish → debrief')),
      evidencePanel(inst.artifacts, seed, 'case'),
    );
  };

  const phase3 = () => {
    const checks = CASE_RUBRIC.map((r) => h('label', { class: 'toggle block' }, h('input', { type: 'checkbox' }), r));
    const score = h('p', { class: 'score' });
    const recount = () => {
      const n = checks.filter((c) => (c.querySelector('input') as HTMLInputElement).checked).length;
      score.textContent = `You covered ${n} of ${CASE_RUBRIC.length}.`;
    };
    checks.forEach((c) => c.addEventListener('change', recount));
    recount();
    const promptText = () => aiGradingPrompt(w, notes.value, answers);
    const copyBtn = h('button', { class: 'btn', type: 'button' }, 'Copy grading prompt');
    copyBtn.addEventListener('click', () => copyText(promptText(), copyBtn));
    root.replaceChildren(
      h('a', { class: 'back', href: '#/' }, '← Home'),
      h('h1', {}, 'Interview mode'),
      h('div', { class: 'prompt-card' }, h('p', { class: 'eyebrow' }, 'Phase 3 of 3 · Debrief'), p('Be honest with yourself: tick only what you actually said out loud, not what you knew.', 'muted')),
      h('h2', {}, 'Rubric: what a strong walkthrough covers'),
      h('div', { class: 'checklist-box' }, ...checks),
      score,
      h('h2', {}, 'Answers for this seed'),
      answerKey(inst),
      h('h2', {}, 'Follow-ups an interviewer is likely to ask'),
      ul(CASE_FOLLOWUPS),
      h('h2', {}, 'Grade with your own AI (optional)'),
      p('This builds a prompt containing the rubric, your structured answers and your notes. **Nothing is sent anywhere:** copy it and paste it into any assistant you choose.', 'muted'),
      h('div', { class: 'q-row' }, copyBtn, h('button', { class: 'btn ghost', type: 'button', onclick: () => download(`grading-prompt-${seed}.txt`, promptText(), 'text/plain') }, 'Download as .txt')),
      h('div', { class: 'q-row' }, h('button', { class: 'btn ghost', type: 'button', onclick: () => nav(`#/interview?seed=${randomSeed()}`) }, 'New case'), h('a', { class: 'btn ghost', href: '#/' }, 'Back to modules')),
    );
    window.scrollTo(0, 0);
  };

  phase1();
  return root;
}

// ---------------- About ----------------

export function aboutPage(): HTMLElement {
  const fileInput = h('input', { type: 'file', accept: 'application/json' });
  const status = h('span', { class: 'muted small' });
  fileInput.addEventListener('change', async () => {
    const f = fileInput.files?.[0];
    if (!f) return;
    status.textContent = importProgress(await f.text()) ? 'Progress imported.' : 'That file is not a dfir-range progress export.';
  });
  const hints = h('input', { type: 'checkbox', checked: load().hints });
  hints.addEventListener('change', () => update((s) => (s.hints = hints.checked)));
  return h(
    'div',
    { class: 'page prose' },
    h('a', { class: 'back', href: '#/' }, '← Home'),
    h('h1', {}, 'About and settings'),
    h('h2', {}, 'Settings'),
    h('label', { class: 'toggle' }, hints, 'Show hints in Learn modules'),
    h('div', { class: 'q-row' }, h('button', { class: 'btn ghost', type: 'button', onclick: () => download('dfir-range-progress.json', exportProgress(), 'application/json') }, 'Export progress'), h('label', { class: 'btn ghost file' }, 'Import progress', fileInput), status),
    h('div', { class: 'q-row' }, h('button', { class: 'btn ghost danger', type: 'button', onclick: () => { if (window.confirm('Reset all progress in this browser?')) { resetProgress(); status.textContent = 'Progress reset.'; } } }, 'Reset progress')),
    h('h2', {}, 'Privacy'),
    p('Everything runs in your browser. There are no accounts, no analytics, no trackers and no requests to any third-party server. Progress is stored in this browser\'s local storage, and you can export, import or reset it above. Recordings in Interview mode stay in the open tab unless you download them.'),
    h('h2', {}, 'Safety'),
    p('All evidence is synthetic and inert. There is no real malware and no working payload, and nothing beacons. IP addresses come from the RFC 5737 documentation ranges or private ranges; domains use the reserved `.example`, `.test` and `.invalid` names. The organization, people and infrastructure are fictional.'),
    h('h2', {}, 'Use it offline or locally'),
    p('After the first visit the site works offline. To run it from your own machine, clone the repository, run `npm install` and `npm run build`, then serve the `dist` folder with any static web server. Use the "Download evidence bundle" buttons to work on the files with your own tools (CyberChef, Python, jq, a text editor).'),
    h('h2', {}, 'Contribute'),
    p('Each module is one self-contained file. See CONTRIBUTING.md in the [repository](https://github.com/alan-haddad/dfir-range).'),
    h('h2', {}, 'Disclaimer'),
    p('A personal project for interview practice. It is not affiliated with or endorsed by any employer or organization. Code is MIT-licensed; written content is CC BY 4.0.'),
  );
}

export function notFound(_nav: Nav): HTMLElement {
  return h('div', { class: 'page' }, h('h1', {}, 'Not found'), h('p', {}, h('a', { href: '#/' }, 'Back to the start')));
}

export { md };
