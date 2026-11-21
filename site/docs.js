// Eyes Only guides: copy buttons, active TOC entry, collapsed menu on phones.
(function () {
  // Copy: the block verbatim, minus a leading "$ " prompt on each line.
  function textOf(pre) {
    return pre.innerText.replace(/\n$/, '').split('\n').map(function (l) { return l.replace(/^\$ /, ''); }).join('\n');
  }
  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
    return ok;
  }
  document.querySelectorAll('.codeblock').forEach(function (block) {
    var btn = block.querySelector('.copy');
    var pre = block.querySelector('pre');
    if (!btn || !pre) return;
    btn.addEventListener('click', function () {
      var text = textOf(pre);
      var done = function (ok) {
        btn.textContent = ok ? 'Copied' : 'Press Ctrl+C';
        btn.classList.toggle('done', ok);
        if (!ok) {
          var r = document.createRange();
          r.selectNodeContents(pre);
          var s = window.getSelection();
          s.removeAllRanges();
          s.addRange(r);
        }
        setTimeout(function () { btn.textContent = 'Copy'; btn.classList.remove('done'); }, 1600);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(fallbackCopy(text)); });
      } else {
        done(fallbackCopy(text));
      }
    });
  });

  // Phones: start with the guide menu collapsed.
  var menu = document.querySelector('.side-menu');
  if (menu && window.matchMedia('(max-width: 900px)').matches) menu.removeAttribute('open');
  if (menu) menu.addEventListener('click', function (e) {
    if (e.target.closest('a') && window.matchMedia('(max-width: 900px)').matches) menu.removeAttribute('open');
  });

  // Highlight the section being read in the sidebar TOC.
  var links = Array.prototype.slice.call(document.querySelectorAll('.side .toc a'));
  if (!links.length || !('IntersectionObserver' in window)) return;
  var byId = {};
  links.forEach(function (a) { byId[decodeURIComponent(a.getAttribute('href').slice(1))] = a; });
  var heads = Array.prototype.slice.call(document.querySelectorAll('.doc h2[id], .doc h3[id]')).filter(function (h) { return byId[h.id]; });
  var visible = {};
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (en) { visible[en.target.id] = en.isIntersecting; });
    var current = null;
    for (var i = 0; i < heads.length; i++) {
      if (visible[heads[i].id]) { current = heads[i].id; break; }
    }
    if (!current) {
      // nothing in view: the last heading above the viewport
      for (var j = heads.length - 1; j >= 0; j--) {
        if (heads[j].getBoundingClientRect().top < 80) { current = heads[j].id; break; }
      }
    }
    links.forEach(function (a) { a.classList.remove('active'); });
    if (current && byId[current]) byId[current].classList.add('active');
  }, { rootMargin: '-70px 0px -60% 0px' });
  heads.forEach(function (h) { io.observe(h); });
})();
