/* Deep Analysis web UI: shared behaviours.
 *
 * The gateway CSP is script-src 'self' with no 'unsafe-inline' and no
 * 'unsafe-eval' (issue #126), so nothing in a template may be an inline
 * <script> or an on*= handler. This file, loaded with `defer` from base.html
 * before Alpine's CSP build, holds:
 *
 *   1. the Alpine components and stores base.html uses (registered on
 *      alpine:init, which is why this file must load before Alpine);
 *   2. small declarative behaviours that templates opt into with data-*
 *      attributes, wired once through delegated listeners so they also
 *      apply to content htmx swaps in later.
 *
 * Page-specific components live next to their page: dashboard.js,
 * metagame.js, profile_edit.js (loaded via the extra_head block).
 *
 * Alpine's CSP build evaluates x-* expressions with its own parser instead
 * of new Function. It supports property access, assignment, ternaries,
 * comparisons, !, && and ||, method calls, and object/array literals. It
 * refuses statements (if, for), function bodies, and any global (window,
 * Math, document, localStorage). Anything of that shape belongs here.
 */
(function () {
    'use strict';

    function storageGet(key) {
        try { return window.localStorage.getItem(key); } catch (e) { return null; }
    }
    function storageSet(key, value) {
        try { window.localStorage.setItem(key, value); } catch (e) { /* private mode etc. */ }
    }

    // ---- Alpine components and stores ---------------------------------------
    document.addEventListener('alpine:init', function () {
        // <html x-data="themeManager">: dark/light toggle persisted in localStorage.
        Alpine.data('themeManager', function () {
            return {
                isDark: true,
                init: function () {
                    var stored = storageGet('theme');
                    if (stored === 'light') {
                        this.isDark = false;
                    } else if (stored === 'system') {
                        this.isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                    } else {
                        this.isDark = true;
                    }
                },
                toggle: function () {
                    this.isDark = !this.isDark;
                    storageSet('theme', this.isDark ? 'dark' : 'light');
                }
            };
        });

        // $store.sidebar: the authenticated layout's collapsible sidebar.
        Alpine.store('sidebar', {
            open: storageGet('sidebar_open') !== 'false',
            toggle: function () {
                this.open = !this.open;
                storageSet('sidebar_open', this.open);
            },
            // Mobile only: tapping outside the sidebar closes it.
            closeOnMobile: function () {
                if (window.innerWidth < 1024) this.open = false;
            }
        });
    });

    // ---- Declarative behaviours ---------------------------------------------

    function isInteractive(el) {
        return !!(el.closest && el.closest('a, button, input, select, textarea, label'));
    }

    // <form data-confirm="Really?">: ask before submitting. Capture phase so
    // it runs before anything else and can cancel the submit.
    document.addEventListener('submit', function (e) {
        var form = e.target;
        if (!form || !form.dataset || !form.dataset.confirm) return;
        if (!window.confirm(form.dataset.confirm)) e.preventDefault();
    }, true);

    // <select data-autosubmit>: submit the enclosing form on change.
    document.addEventListener('change', function (e) {
        var el = e.target;
        if (el && el.matches && el.matches('[data-autosubmit]') && el.form) el.form.submit();
    });

    // <tr data-href="/path" role="button" tabindex="0">: the whole row is a link.
    document.addEventListener('click', function (e) {
        var row = e.target.closest && e.target.closest('[data-href]');
        if (!row || isInteractive(e.target)) return;
        window.location.href = row.dataset.href;
    });
    document.addEventListener('keydown', function (e) {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        var row = e.target.closest && e.target.closest('[data-href]');
        if (!row || isInteractive(e.target)) return;
        e.preventDefault();
        window.location.href = row.dataset.href;
    });

    // <button data-toggle-target="element-id">: flip the target's hidden attribute.
    document.addEventListener('click', function (e) {
        var btn = e.target.closest && e.target.closest('[data-toggle-target]');
        if (!btn) return;
        var target = document.getElementById(btn.dataset.toggleTarget);
        if (target) target.hidden = !target.hidden;
    });

    // <button data-copy-target="element-id">: copy the target's text to the
    // clipboard and flash "Copied" on the button.
    document.addEventListener('click', function (e) {
        var btn = e.target.closest && e.target.closest('[data-copy-target]');
        if (!btn) return;
        var source = document.getElementById(btn.dataset.copyTarget);
        if (!source) return;
        var text = source.textContent.trim();
        var done = function () {
            var original = btn.textContent;
            btn.textContent = 'Copied';
            setTimeout(function () { btn.textContent = original; }, 1500);
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(done, done);
            return;
        }
        var ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } catch (err) { /* ignore */ }
        document.body.removeChild(ta);
        done();
    });

    // <button data-submit-once="Working...">: disable, relabel, submit the form.
    document.addEventListener('click', function (e) {
        var btn = e.target.closest && e.target.closest('[data-submit-once]');
        if (!btn || !btn.form) return;
        e.preventDefault();
        btn.disabled = true;
        btn.textContent = btn.dataset.submitOnce;
        btn.form.submit();
    });

    // <div data-progress-percent="42">: set the width through the CSSOM.
    // A style="width: 42%" attribute is an inline style and CSP blocks it;
    // assigning element.style.width is not.
    function applyProgressWidths(root) {
        var nodes = (root || document).querySelectorAll('[data-progress-percent]');
        Array.prototype.forEach.call(nodes, function (el) {
            var pct = parseFloat(el.dataset.progressPercent);
            if (isNaN(pct)) return;
            el.style.width = Math.max(0, Math.min(100, pct)) + '%';
        });
    }
    applyProgressWidths(document);
    document.addEventListener('htmx:load', function (e) {
        applyProgressWidths(e.detail && e.detail.elt);
    });
})();
