import './styles.css';
import { isValidSeed, randomSeed } from './lib/prng';
import { h } from './ui/dom';
import { assessmentPage, progressPage } from './ui/assess';
import { aboutPage, drillsPage, homePage, interviewPage, learnPage, notFound } from './ui/pages';

const app = document.getElementById('app')!;

function nav(hash: string): void {
  if (location.hash === hash) render();
  else location.hash = hash;
}

function parse(): { path: string[]; seed: string | null } {
  const raw = location.hash.replace(/^#/, '') || '/';
  const [pathPart, query = ''] = raw.split('?');
  const seed = new URLSearchParams(query).get('seed');
  return { path: pathPart.split('/').filter(Boolean), seed };
}

/** Pages that need a seed get one in the URL, so every scenario is shareable and reproducible. */
function withSeed(base: string, seed: string | null): string | null {
  if (seed && isValidSeed(seed)) return seed;
  history.replaceState(null, '', `#${base}?seed=${randomSeed()}`);
  return null;
}

function header(): HTMLElement {
  return h(
    'header',
    { class: 'site-header' },
    h('a', { class: 'brand', href: '#/' }, h('span', { class: 'brand-mark', 'aria-hidden': 'true' }, '◆'), 'dfir-range'),
    h(
      'nav',
      { class: 'site-nav', 'aria-label': 'Main' },
      h('a', { href: '#/' }, 'Modules'),
      h('a', { href: '#/assessment' }, 'Assessment'),
      h('a', { href: '#/interview' }, 'Interview'),
      h('a', { href: '#/drills' }, 'Drills'),
      h('a', { href: '#/progress' }, 'Weak spots'),
      h('a', { href: './cyberchef/', target: '_blank', rel: 'noopener', title: 'Bundled offline copy of CyberChef' }, 'CyberChef'),
      h('a', { href: '#/about' }, 'About'),
    ),
  );
}

function footer(): HTMLElement {
  return h(
    'footer',
    { class: 'site-footer' },
    h('p', {}, 'Synthetic, inert training data. All organizations, people and infrastructure are fictional. A personal project, not affiliated with or endorsed by any employer or organization.'),
    h('p', {}, h('a', { href: 'https://github.com/alan-haddad/dfir-range', target: '_blank', rel: 'noopener noreferrer' }, 'Source on GitHub'), ' · MIT (code) · CC BY 4.0 (content)'),
  );
}

function render(): void {
  const { path, seed } = parse();
  let page: HTMLElement;
  if (path.length === 0) page = homePage(nav);
  else if (path[0] === 'learn' && path[1]) {
    const s = withSeed(`/learn/${path[1]}`, seed);
    if (!s) return render();
    page = learnPage(path[1], s, nav);
  } else if (path[0] === 'interview') {
    const s = withSeed('/interview', seed);
    if (!s) return render();
    page = interviewPage(s, nav);
  } else if (path[0] === 'assessment') {
    const s = withSeed('/assessment', seed);
    if (!s) return render();
    page = assessmentPage(s, nav);
  } else if (path[0] === 'progress') page = progressPage();
  else if (path[0] === 'drills') page = drillsPage();
  else if (path[0] === 'about') page = aboutPage();
  else page = notFound(nav);
  app.replaceChildren(header(), h('main', { id: 'main' }, page), footer());
  window.scrollTo(0, 0);
  document.title = `${page.querySelector('h1')?.textContent ?? 'dfir-range'} · dfir-range`;
}

window.addEventListener('hashchange', render);
render();

if (import.meta.env.PROD && 'serviceWorker' in navigator && (location.protocol === 'https:' || location.hostname === 'localhost')) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch(() => {
      /* offline support is optional */
    });
  });
}
