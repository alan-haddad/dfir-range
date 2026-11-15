type Child = Node | string | null | undefined | false;
type Attrs = Record<string, string | boolean | number | EventListener | undefined>;

/** Tiny DOM builder. Text is always set with textContent, never innerHTML. */
export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: (Child | Child[])[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') {
      el.addEventListener(k.slice(2).toLowerCase(), v as EventListener);
    } else if (k === 'class') {
      el.className = String(v);
    } else if (v === true) {
      el.setAttribute(k, '');
    } else {
      el.setAttribute(k, String(v));
    }
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return el;
}

/**
 * Minimal, safe inline markdown: `code`, **bold**, *italic* and [text](https://link).
 * Builds nodes directly, so content can never inject HTML.
 */
export function md(text: string): DocumentFragment {
  const frag = document.createDocumentFragment();
  const re = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\*[^*]+\*)|(\[[^\]]+\]\(https?:\/\/[^)\s]+\))/g;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    if (m.index > last) frag.append(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith('`')) frag.append(h('code', {}, tok.slice(1, -1)));
    else if (tok.startsWith('**')) frag.append(h('strong', {}, tok.slice(2, -2)));
    else if (tok.startsWith('*')) frag.append(h('em', {}, tok.slice(1, -1)));
    else {
      const lm = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(tok)!;
      frag.append(h('a', { href: lm[2], target: '_blank', rel: 'noopener noreferrer' }, lm[1]));
    }
    last = m.index + tok.length;
  }
  if (last < text.length) frag.append(text.slice(last));
  return frag;
}

export function p(text: string, cls?: string): HTMLParagraphElement {
  const el = h('p', cls ? { class: cls } : {});
  el.append(md(text));
  return el;
}

export function ul(items: string[], cls?: string): HTMLUListElement {
  return h('ul', cls ? { class: cls } : {}, ...items.map((i) => { const li = h('li'); li.append(md(i)); return li; }));
}

export function download(name: string, data: string | Uint8Array, mime = 'application/octet-stream'): void {
  const blob = new Blob([typeof data === 'string' ? data : (data as Uint8Array<ArrayBuffer>)], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function copyText(text: string, btn?: HTMLButtonElement): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    if (btn) {
      const old = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(() => (btn.textContent = old), 1200);
    }
  } catch {
    if (btn) btn.textContent = 'Copy failed';
  }
}
