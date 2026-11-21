#!/usr/bin/env node
// Builds docs/*.md into article pages for the GitHub Pages site. Zero dependencies.
//
//   node scripts/build-docs.mjs <outdir> [--docs <dir>]
//
// Writes <outdir>/docs/index.html (guide list + common scenarios) and
// <outdir>/docs/<slug>/index.html per guide. Styling comes from site/docs.css and
// site/docs.js, which the Pages workflow copies to <outdir>/docs.css and <outdir>/docs.js.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO = 'https://github.com/jagritvats/eyesonly';
const SITE = 'https://jagritvats.github.io/eyesonly';
const OG = `${SITE}/assets/og.png`;

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  if (i === -1) return null;
  const v = args[i + 1];
  args.splice(i, 2);
  return v;
};
const DOCS = path.resolve(opt('--docs') || path.join(ROOT, 'docs'));
const OUT = path.resolve(args[0] || path.join(ROOT, '_site'));

// Guide order and grouping on the index. Guides not listed here go under "More guides".
const GROUPS = [
  { title: 'Get started', slugs: ['github-mode', 'existing-repos', 'choosing-a-mode'] },
  { title: 'Run it', slugs: ['ci', 'server-deployment'] },
  { title: 'Day to day', slugs: ['team-workflows', 'policy-reference'] },
  { title: 'When something breaks', slugs: ['troubleshooting'] },
];
// Short redirect stubs: rendered (so links to them work) but left out of the index and sidebar.
const HIDDEN = new Set(['repo-mode']);

// Common scenarios. Each links to the first h2/h3 matching `match` in the guide(s) named by
// `in` (null = any guide). If none matches, `url` is used when given; otherwise the scenario
// is skipped with a warning (guides are allowed to be missing).
const SCENARIOS = [
  { label: 'Start on GitHub without a server', in: 'github-mode', match: /^start/i },
  { label: 'Choose GitHub mode or the server', in: 'choosing-a-mode', match: /which mode|decide|at a glance/i },
  { label: 'Add Eyes Only to your existing GitHub repo', in: 'existing-repos', match: /add eyes only to your existing/i },
  { label: 'Add a teammate (GitHub mode)', in: 'github-mode', match: /add a teammate/i },
  { label: 'Block bad merges with eyesonly verify', in: 'github-mode', match: /require it in ci/i },
  { label: 'Move a repo onto the Eyes Only server', in: 'existing-repos', match: /move an existing repo onto the eyes only server/i },
  { label: 'Move from GitHub mode to the server', in: 'choosing-a-mode', match: /move from github mode/i },
  { label: 'Onboard a teammate who already has a clone', in: 'existing-repos', match: /onboard a teammate/i },
  { label: 'Add a new teammate (server)', in: 'team-workflows', match: /add a teammate|new teammate|onboard/i },
  { label: 'Start tracking a .env that was gitignored', in: 'existing-repos', match: /\.env|gitignore|start tracking/i },
  { label: 'Give someone access to .env', in: 'team-workflows', match: /github mode: add|who can read|access to/i },
  { label: 'Work on a private branch', in: 'team-workflows', match: /private branch/i },
  { label: 'Offboard someone', in: 'team-workflows', match: /offboard/i },
  { label: 'Rotate a secret', in: 'team-workflows', match: /rotate a secret/i },
  { label: 'Who could read a secret on a date', in: 'team-workflows', match: /who could read a secret/i },
  { label: 'Lost a private key', in: 'team-workflows', match: /lost.*key/i },
  { label: 'Read secrets in CI', in: 'ci', match: /read secrets in ci|create a ci identity/i },
  { label: 'Run the server behind TLS', in: 'server-deployment', match: /tls|caddy|nginx/i },
  { label: 'Back up the server', in: 'server-deployment', match: /backup|back up/i },
  { label: 'Mirror to GitHub (server)', in: null, match: /^mirror(ing)? to|set up (the )?mirror/i, url: `${REPO}#mirroring-to-githubgitlab-server` },
  { label: 'Write a policy', in: 'policy-reference', match: /^example$|write a policy/i },
  { label: 'Sign the policy', in: 'policy-reference', match: /sign and install|signed polic/i },
  { label: 'Fix a rejected push', in: 'troubleshooting', match: /^pushing$|rejected push/i },
];

// ------------------------------------------------------------------ markdown

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/** GitHub-style heading slug, so links written for github.com work here too. */
function slugify(text) {
  return text
    .toLowerCase()
    .replace(/<[^>]+>/g, '')
    .replace(/[^\p{L}\p{N}\s_-]/gu, '')
    .trim()
    .replace(/\s/g, '-');
}

/** Plain text of inline markdown (for headings, titles, TOC). */
function plain(md) {
  return md
    .replace(/!\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\\`/g, '\u0001') // escaped backticks inside a heading's code span
    .replace(/`+([^`]+)`+/g, '$1')
    .replace(/\u0001/g, '`')
    .replace(/(\*\*|__)(.+?)\1/g, '$2')
    .replace(/(\*|_)(.+?)\1/g, '$2')
    .trim();
}

function inline(md, ctx) {
  const stash = [];
  const keep = (html) => `\u0000${stash.push(html) - 1}\u0000`;
  let s = md;
  // code spans first: their content is literal
  s = s.replace(/(`+)([\s\S]*?[^`])\1(?!`)/g, (_, _t, code) => keep(`<code>${esc(code.replace(/^ (.*) $/, '$1'))}</code>`));
  // autolinks
  s = s.replace(/<(https?:\/\/[^>\s]+)>/g, (_, u) => keep(`<a href="${esc(u)}">${esc(u)}</a>`));
  // images and links (link text may contain inline markup)
  s = s.replace(/!\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g, (_, alt, src) => keep(`<img src="${esc(ctx.link(src))}" alt="${esc(alt)}" loading="lazy">`));
  s = s.replace(/\[((?:[^\[\]]|\[[^\]]*\])*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g, (_, text, href) => {
    const url = ctx.link(href);
    const ext = /^https?:/.test(url) && !url.startsWith(SITE) ? ' rel="noopener"' : '';
    return keep(`<a href="${esc(url)}"${ext}>${inline(text, ctx)}</a>`);
  });
  s = esc(s);
  s = s.replace(/(\*\*|__)(?=\S)([\s\S]*?\S)\1/g, '<strong>$2</strong>');
  s = s.replace(/(^|[^\w*])\*(?=\S)([^*]*?\S)\*(?!\w)/g, '$1<em>$2</em>');
  s = s.replace(/(^|[^\w])_(?=\S)([^_]*?\S)_(?!\w)/g, '$1<em>$2</em>');
  s = s.replace(/ {2,}\n/g, '<br>\n');
  return s.replace(/\u0000(\d+)\u0000/g, (_, i) => stash[i]);
}

const LIST_RE = /^( {0,3})([-*+]|\d{1,9}[.)])( +|$)/;
const isFence = (l) => /^ {0,3}(```|~~~)/.test(l);
const isTableSep = (l) => /^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)*\|?\s*$/.test(l) && l.includes('-');
const splitRow = (l) => {
  let t = l.trim();
  if (t.startsWith('|')) t = t.slice(1);
  if (t.endsWith('|') && !t.endsWith('\\|')) t = t.slice(0, -1);
  const cells = [];
  let cur = '';
  let inCode = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (c === '\\' && t[i + 1] === '|') { cur += '|'; i++; continue; }
    if (c === '`') inCode = !inCode;
    if (c === '|' && !inCode) { cells.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  cells.push(cur.trim());
  return cells;
};

function blocks(lines, ctx) {
  const out = [];
  let i = 0;
  const startsBlock = (l, next) =>
    /^ {0,3}#{1,6}\s/.test(l) || isFence(l) || /^ {0,3}>/.test(l) || LIST_RE.test(l) ||
    /^ {0,3}([-*_])( *\1){2,} *$/.test(l) || (l.includes('|') && next !== undefined && isTableSep(next));

  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }

    // fenced code
    const fm = line.match(/^( {0,3})(```+|~~~+)\s*([\w+-]*)/);
    if (fm) {
      const [, ind, fence, lang] = fm;
      const body = [];
      i++;
      while (i < lines.length && !lines[i].trimStart().startsWith(fence)) {
        body.push(lines[i].startsWith(ind) ? lines[i].slice(ind.length) : lines[i].trimStart());
        i++;
      }
      i++;
      out.push(ctx.code(body.join('\n'), lang));
      continue;
    }

    // heading
    const hm = line.match(/^ {0,3}(#{1,6})\s+(.*?)\s*#*\s*$/);
    if (hm) {
      out.push(ctx.heading(hm[1].length, hm[2]));
      i++;
      continue;
    }

    // horizontal rule
    if (/^ {0,3}([-*_])( *\1){2,} *$/.test(line)) { out.push('<hr>'); i++; continue; }

    // table
    if (line.includes('|') && i + 1 < lines.length && isTableSep(lines[i + 1])) {
      const head = splitRow(line);
      const align = splitRow(lines[i + 1]).map((c) => (c.startsWith(':') && c.endsWith(':') ? 'center' : c.endsWith(':') ? 'right' : ''));
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].trim() && lines[i].includes('|')) rows.push(splitRow(lines[i++]));
      const cell = (tag, c, j) => `<${tag}${align[j] ? ` style="text-align:${align[j]}"` : ''}>${inline(c, ctx)}</${tag}>`;
      out.push(
        `<div class="table-wrap"><table><thead><tr>${head.map((c, j) => cell('th', c, j)).join('')}</tr></thead><tbody>` +
          rows.map((r) => `<tr>${head.map((_, j) => cell('td', r[j] ?? '', j)).join('')}</tr>`).join('') +
          '</tbody></table></div>'
      );
      continue;
    }

    // blockquote
    if (/^ {0,3}>/.test(line)) {
      const body = [];
      while (i < lines.length && lines[i].trim() && (/^ {0,3}>/.test(lines[i]) || !startsBlock(lines[i], lines[i + 1]))) {
        body.push(lines[i].replace(/^ {0,3}> ?/, ''));
        i++;
      }
      out.push(`<blockquote>${blocks(body, ctx)}</blockquote>`);
      continue;
    }

    // list
    const lm = line.match(LIST_RE);
    if (lm) {
      const ordered = /\d/.test(lm[2]);
      const base = lm[1].length;
      const start = ordered ? parseInt(lm[2], 10) : 1;
      const items = [];
      let loose = false;
      while (i < lines.length) {
        const m = lines[i].match(LIST_RE);
        if (!m || m[1].length !== base || /\d/.test(m[2]) !== ordered) break;
        const contentIndent = m[0].length || base + m[2].length + 1;
        const item = [lines[i].slice(m[0].length)];
        i++;
        let sawBlank = false;
        while (i < lines.length) {
          const l = lines[i];
          if (!l.trim()) { sawBlank = true; item.push(''); i++; continue; }
          const ind = l.match(/^ */)[0].length;
          const sib = l.match(LIST_RE);
          if (sib && sib[1].length === base) break; // next item
          if (ind >= Math.min(contentIndent, base + 2)) { item.push(l.slice(Math.min(ind, contentIndent))); i++; sawBlank = false; continue; }
          if (sawBlank || startsBlock(l, lines[i + 1])) break; // dedented: list is over
          item.push(l.trim()); // lazy continuation
          i++;
        }
        let trailingBlank = false;
        while (item.length && !item[item.length - 1].trim()) { item.pop(); trailingBlank = true; }
        // a blank line between two items, or between two blocks of one item, makes the list loose
        const next = lines[i]?.match(LIST_RE);
        if (trailingBlank && next && next[1].length === base && /\d/.test(next[2]) === ordered) loose = true;
        let inFence = false;
        for (let k = 1; k < item.length - 1; k++) {
          if (isFence(item[k])) inFence = !inFence;
          if (!inFence && !item[k].trim() && !LIST_RE.test(item[k + 1]) && !/^\s/.test(item[k + 1])) loose = true;
        }
        items.push(item);
      }
      const html = items.map((it) => {
        let inner = blocks(it, ctx);
        if (!loose) inner = inner.replace(/^<p>([\s\S]*?)<\/p>/, '$1');
        return `<li>${inner}</li>`;
      });
      out.push(ordered ? `<ol${start !== 1 ? ` start="${start}"` : ''}>${html.join('')}</ol>` : `<ul>${html.join('')}</ul>`);
      continue;
    }

    // raw HTML block (rare in these docs): pass through comments, escape the rest
    if (/^\s*<!--/.test(line)) {
      while (i < lines.length && !lines[i].includes('-->')) i++;
      i++;
      continue;
    }

    // paragraph
    const para = [];
    while (i < lines.length && lines[i].trim() && !(para.length && startsBlock(lines[i], lines[i + 1]))) {
      para.push(lines[i].replace(/^ {0,3}/, ''));
      i++;
    }
    out.push(`<p>${inline(para.join('\n'), ctx)}</p>`);
  }
  return out.join('\n');
}

// ------------------------------------------------------------------ guides

function readGuides() {
  if (!fs.existsSync(DOCS)) {
    console.warn(`[build-docs] warning: no docs directory at ${DOCS}; building an empty index`);
    return [];
  }
  const files = fs.readdirSync(DOCS).filter((f) => f.endsWith('.md') && f.toLowerCase() !== 'readme.md').sort();
  return files.map((file) => {
    const src = fs.readFileSync(path.join(DOCS, file), 'utf8').replace(/\r\n?/g, '\n');
    const slug = file.replace(/\.md$/, '').toLowerCase();
    const h1 = src.match(/^# +(.+)$/m);
    const headings = [];
    const seen = new Map();
    let inFence = false;
    for (const l of src.split('\n')) {
      if (isFence(l)) inFence = !inFence;
      if (inFence) continue;
      const m = l.match(/^ {0,3}(#{1,6})\s+(.*?)\s*#*\s*$/);
      if (!m) continue;
      const text = plain(m[2]);
      let id = slugify(text);
      const n = seen.get(id) || 0;
      seen.set(id, n + 1);
      if (n) id = `${id}-${n}`;
      headings.push({ level: m[1].length, text, id, md: m[2] });
    }
    // first paragraph after the title = description
    const afterTitle = h1 ? src.slice(src.indexOf(h1[0]) + h1[0].length) : src;
    const firstPara = afterTitle.split(/\n\s*\n/).map((p) => p.trim()).find((p) => p && !/^(#|```|~~~|\||>|[-*+] |\d+\. )/.test(p)) || '';
    return { file, slug, src, title: h1 ? plain(h1[1]) : slug, description: plain(firstPara.replace(/\n/g, ' ')), headings };
  });
}

function makeLinker(guides, depth) {
  // depth: number of directory levels below <outdir>/docs/ the page lives at
  const bySlug = new Set(guides.map((g) => g.slug));
  const up = '../'.repeat(depth);
  return (href) => {
    if (/^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(href)) return href;
    const [p, hash = ''] = href.split('#');
    const anchor = hash ? `#${hash}` : '';
    if (!p) return anchor;
    // resolve relative to docs/ inside the repo
    const resolved = path.posix.normalize(path.posix.join('docs', p));
    const base = path.posix.basename(resolved);
    if (/\.md$/i.test(base)) {
      const slug = base.replace(/\.md$/i, '').toLowerCase();
      // `x.md`, `./x.md`, `../docs/x.md` (relative to docs/) and `docs/x.md` (repo-root style)
      const rootStyle = path.posix.normalize(p.replace(/^\.\//, ''));
      const inDocs = resolved === `docs/${base}` || rootStyle === `docs/${base}`;
      if (inDocs && bySlug.has(slug)) return `${up}${slug}/${anchor}`;
      if (inDocs && slug === 'readme') return `${up}${anchor || ''}` || './';
    }
    // repo file: docs/<p> if it exists there, otherwise the same path from the repo root
    let repoPath = resolved;
    if (!fs.existsSync(path.join(ROOT, repoPath))) {
      const fromRoot = path.posix.normalize(p.replace(/^(\.\.\/)+/, '').replace(/^\.\//, ''));
      if (fs.existsSync(path.join(ROOT, fromRoot)) || !resolved.startsWith('docs/')) repoPath = fromRoot;
    }
    repoPath = repoPath.replace(/^(\.\.\/)+/, '');
    const isDir = fs.existsSync(path.join(ROOT, repoPath)) && fs.statSync(path.join(ROOT, repoPath)).isDirectory();
    return `${REPO}/${isDir ? 'tree' : 'blob'}/main/${repoPath}${anchor}`;
  };
}

function renderGuide(g, guides) {
  const seen = new Map(); // same dedupe rule as readGuides(), so TOC links match
  const ctx = {
    link: makeLinker(guides, 1),
    heading(level, md) {
      let id = slugify(plain(md));
      const n = seen.get(id) || 0;
      seen.set(id, n + 1);
      if (n) id = `${id}-${n}`;
      if (level === 1) return `<h1 id="${id}">${inline(md, ctx)}</h1>`;
      return `<h${level} id="${id}"><a class="anchor" href="#${id}" aria-label="Link to this section">#</a>${inline(md, ctx)}</h${level}>`;
    },
    code(body, lang) {
      return `<div class="codeblock"><pre${lang ? ` data-lang="${esc(lang)}"` : ''}><code>${esc(body)}</code></pre><button class="copy" type="button" aria-label="Copy code">Copy</button></div>`;
    },
  };
  // only fenced blocks are skipped by the heading scan, so render with the same rules
  return blocks(g.src.split('\n'), ctx);
}

// ------------------------------------------------------------------ page shell

function ordered(guides) {
  guides = guides.filter((g) => !HIDDEN.has(g.slug));
  const used = new Set();
  const groups = GROUPS.map((gr) => {
    const list = gr.slugs.map((s) => guides.find((g) => g.slug === s)).filter(Boolean);
    list.forEach((g) => used.add(g.slug));
    return { title: gr.title, list };
  }).filter((gr) => gr.list.length);
  const rest = guides.filter((g) => !used.has(g.slug));
  if (rest.length) groups.push({ title: 'More guides', list: rest });
  return groups;
}

function shell({ title, description, depth, body, sidebar, url, editUrl }) {
  const up = '../'.repeat(depth + 1); // to <outdir>/
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(description)}">
<meta property="og:image" content="${OG}">
<meta property="og:url" content="${url}">
<meta property="og:type" content="article">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="${OG}">
<link rel="canonical" href="${url}">
<link rel="stylesheet" href="${up}docs.css">
</head>
<body>
<header class="top">
  <div class="top-in">
    <a class="logo" href="${up}">eyesonly<span>.</span></a>
    <nav class="top-links">
      <a href="${up}docs/">Guides</a>
      <a href="${REPO}">GitHub</a>
    </nav>
  </div>
</header>
<div class="layout">
  <aside class="side">
    <details class="side-menu" open>
      <summary>Guides</summary>
      ${sidebar}
    </details>
  </aside>
  <main class="content">
${body}
    <footer class="page-foot">
      ${editUrl ? `<a href="${editUrl}">Edit this page on GitHub</a> · ` : ''}<a href="${up}">Eyes Only</a> · <a href="${REPO}">GitHub</a> · alpha, not independently audited
    </footer>
  </main>
</div>
<script src="${up}docs.js" defer></script>
</body>
</html>
`;
}

function sidebarHtml(guides, current, depth) {
  const up = '../'.repeat(depth);
  return ordered(guides)
    .map(
      (gr) =>
        `<div class="side-group"><div class="side-title">${esc(gr.title)}</div><ul>` +
        gr.list
          .map((g) => {
            const here = current && g.slug === current.slug;
            const toc = here
              ? `<ul class="toc">${g.headings
                  .filter((h) => h.level === 2 || h.level === 3)
                  .map((h) => `<li class="l${h.level}"><a href="#${h.id}">${esc(h.text)}</a></li>`)
                  .join('')}</ul>`
              : '';
            return `<li${here ? ' class="here"' : ''}><a href="${up}${g.slug}/"${here ? ' aria-current="page"' : ''}>${esc(g.title)}</a>${toc}</li>`;
          })
          .join('') +
        '</ul></div>'
    )
    .join('\n') + `<div class="side-group"><ul><li><a href="${depth ? up : './'}">All guides &amp; scenarios</a></li></ul></div>`;
}

function findScenario(s, guides, used) {
  const search = (g) => g.headings.find((h) => h.level >= 2 && h.level <= 3 && !used.has(`${g.slug}#${h.id}`) && s.match.test(h.text));
  const pool = s.in === null ? guides : guides.filter((g) => [].concat(s.in).includes(g.slug));
  for (const g of pool) {
    const h = search(g);
    if (h) return { g, h };
  }
  return null;
}

function renderIndex(guides) {
  const scen = [];
  const used = new Set(); // each heading backs at most one scenario
  for (const s of SCENARIOS) {
    const hit = findScenario(s, guides, used);
    if (!hit && s.url) {
      scen.push(`<li><a href="${esc(s.url)}"><span class="scen-label">${esc(s.label)}</span><span class="scen-where">README on GitHub</span></a></li>`);
      continue;
    }
    if (!hit) {
      console.warn(`[build-docs] warning: no heading found for scenario "${s.label}"; skipped`);
      continue;
    }
    used.add(`${hit.g.slug}#${hit.h.id}`);
    scen.push(`<li><a href="${hit.g.slug}/#${hit.h.id}"><span class="scen-label">${esc(s.label)}</span><span class="scen-where">${esc(hit.g.title)}${hit.h.text.toLowerCase() === s.label.toLowerCase() ? '' : ` › ${esc(hit.h.text)}`}</span></a></li>`);
  }
  const groups = ordered(guides)
    .map(
      (gr) =>
        `<h2 id="${slugify(gr.title)}">${esc(gr.title)}</h2><div class="guide-cards">` +
        gr.list
          .map(
            (g) =>
              `<article class="guide-card"><h3><a href="${g.slug}/">${esc(g.title)}</a></h3>` +
              (g.description ? `<p>${esc(g.description)}</p>` : '') +
              `<ul>${g.headings
                .filter((h) => h.level === 2)
                .slice(0, 8)
                .map((h) => `<li><a href="${g.slug}/#${h.id}">${esc(h.text)}</a></li>`)
                .join('')}</ul></article>`
          )
          .join('') +
        '</div>'
    )
    .join('\n');
  const body = `    <article class="doc">
      <h1>Guides</h1>
      <p class="lede">Task-oriented guides for running Eyes Only and using it day to day. Every command block has a Copy button.</p>
      ${scen.length ? `<h2 id="common-scenarios">Common scenarios</h2><ul class="scenarios">${scen.join('')}</ul>` : ''}
      ${groups || '<p>No guides yet.</p>'}
    </article>`;
  return shell({
    title: 'Eyes Only guides',
    description: 'Guides for Eyes Only: move a repo, onboard teammates, run the server, CI, policies and troubleshooting.',
    depth: 0,
    body,
    sidebar: sidebarHtml(guides, null, 0),
    url: `${SITE}/docs/`,
  });
}

// ------------------------------------------------------------------ main

const guides = readGuides();
fs.mkdirSync(path.join(OUT, 'docs'), { recursive: true });
for (const g of guides) {
  const dir = path.join(OUT, 'docs', g.slug);
  fs.mkdirSync(dir, { recursive: true });
  const body = `    <article class="doc">\n${renderGuide(g, guides)}\n    </article>`;
  fs.writeFileSync(
    path.join(dir, 'index.html'),
    shell({
      title: `${g.title} · Eyes Only`,
      description: g.description || `Eyes Only guide: ${g.title}`,
      depth: 1,
      body,
      sidebar: sidebarHtml(guides, g, 1),
      url: `${SITE}/docs/${g.slug}/`,
      editUrl: `${REPO}/edit/main/docs/${g.file}`,
    })
  );
}
fs.writeFileSync(path.join(OUT, 'docs', 'index.html'), renderIndex(guides));
for (const f of ['docs.css', 'docs.js']) {
  const src = path.join(ROOT, 'site', f);
  if (fs.existsSync(src) && path.resolve(OUT) !== path.join(ROOT, 'site')) fs.copyFileSync(src, path.join(OUT, f));
}
console.log(`[build-docs] ${guides.length} guide(s) -> ${path.join(OUT, 'docs')}`);
