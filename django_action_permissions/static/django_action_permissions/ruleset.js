/* The ruleset editor of the action permissions' admin (`RulesetWidget`): each input[data-ruleset] is checked as it's
 * typed against the stored predicates (data-validate-url answers `check_ruleset`), shows its canonical form or where
 * it doesn't parse, completes predicate codes (data-predicates), and links to Verify with the ruleset as a draft
 * (data-verify-url). Inputs added later (an inline's "Add another") work too: the events are delegated. */
(function () {
  "use strict";

  const SELECTOR = "input[data-ruleset]";
  const WORD_BEFORE = /[A-Za-z_]\w*$/;
  const WORD_AFTER = /^\w*/;
  const MAX_SUGGESTIONS = 12;
  const state = new WeakMap();
  let ids = 0;

  function stateOf(input) {
    let s = state.get(input);
    if (!s) {
      const box = input.closest(".dap-ruleset");
      let predicates = [];
      try {
        predicates = JSON.parse(input.dataset.predicates || "[]");
      } catch (e) {
        predicates = [];
      }
      s = {
        timer: null,
        seq: 0,
        predicates: predicates,
        status: box && box.querySelector(".dap-status"),
        list: box && box.querySelector(".dap-suggestions"),
        items: [],
        active: -1,
      };
      if (s.list) {
        s.list.id = "dap-suggestions-" + ++ids;
        input.setAttribute("aria-autocomplete", "list");
        input.setAttribute("aria-controls", s.list.id);
      }
      state.set(input, s);
    }
    return s;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // ── the check ──────────────────────────────────────────────────────────────

  function schedule(input) {
    const s = stateOf(input);
    clearTimeout(s.timer);
    s.timer = setTimeout(function () {
      validate(input);
    }, 250);
  }

  function validate(input) {
    const s = stateOf(input);
    const url = input.dataset.validateUrl;
    const expression = input.value;
    const seq = ++s.seq;
    if (!s.status || !url) return;
    if (!expression.trim()) {
      s.status.replaceChildren();
      return;
    }
    fetch(url + "?expression=" + encodeURIComponent(expression), {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    })
      .then(function (response) {
        return response.ok ? response.json() : null;
      })
      .then(function (result) {
        if (result && seq === s.seq) show(input, s, expression, result);
      })
      .catch(function () {
        /* offline, or signed out: the server checks it on save */
      });
  }

  function show(input, s, expression, result) {
    const parts = [];
    if (result.valid) {
      const ok = el("span", "ok", "✓ ");
      ok.append(el("code", "", result.canonical));
      parts.push(ok);
      if (result.canonical !== expression.trim()) parts.push(el("span", "", " (canonical form, saved as such)"));
    } else {
      parts.push(el("span", "error", "✗ " + result.error));
      if (result.position !== null && result.position !== undefined) {
        parts.push(el("span", "caret", expression + "\n" + " ".repeat(result.position) + "^"));
      }
    }
    if (result.unknown && result.unknown.length) {
      const unknown = el("span", "", " Not stored: ");
      result.unknown.forEach(function (code, i) {
        if (i) unknown.append(", ");
        unknown.append(el("code", "unknown", code));
      });
      parts.push(unknown);
    }
    const link = verifyLink(input);
    if (result.valid && link) parts.push(link);
    s.status.replaceChildren.apply(s.status, parts);
  }

  function selectedText(form, name) {
    const field = form && form.elements.namedItem(name);
    if (!field || field.tagName !== "SELECT" || field.selectedIndex < 0 || !field.value) return "";
    return field.options[field.selectedIndex].text;
  }

  function verifyLink(input) {
    const url = input.dataset.verifyUrl;
    if (!url) return null;
    const perm = input.dataset.perm || selectedText(input.form, input.name.replace(/ruleset$/, "action_permission"));
    const group = selectedText(input.form, input.name.replace(/ruleset$/, "group"));
    if (!perm || !group) return null;
    const query = new URLSearchParams({ perm: perm, draft_group: group, draft_ruleset: input.value });
    const link = el("a", "", "Test…");
    link.href = url + "?" + query.toString();
    link.target = "_blank";
    link.rel = "noopener";
    link.title = "Try this ruleset on a user and an object, before saving it";
    return link;
  }

  // ── the completions ────────────────────────────────────────────────────────

  function suggest(input, all) {
    const s = stateOf(input);
    if (!s.list) return;
    const caret = input.selectionStart;
    const match = input.value.slice(0, caret).match(WORD_BEFORE);
    const prefix = match ? match[0] : "";
    if (!prefix && !all) return close(s, input);
    const lower = prefix.toLowerCase();
    const starts = s.predicates.filter(function (p) {
      return p.code.toLowerCase().startsWith(lower);
    });
    const contains = s.predicates.filter(function (p) {
      return !p.code.toLowerCase().startsWith(lower) && p.code.toLowerCase().includes(lower);
    });
    const items = starts.concat(contains).slice(0, MAX_SUGGESTIONS);
    if (!items.length || (items.length === 1 && items[0].code === prefix)) return close(s, input);
    s.items = items;
    s.active = 0;
    s.list.replaceChildren.apply(
      s.list,
      items.map(function (p, i) {
        const li = el("li");
        li.id = s.list.id + "-" + i;
        li.setAttribute("role", "option");
        li.append(el("code", "", p.code));
        if (p.description) li.append(el("span", "dap-quiet", p.description));
        li.addEventListener("mousedown", function (event) {
          event.preventDefault(); // keep the focus in the input
          accept(input, i);
        });
        return li;
      })
    );
    s.list.hidden = false;
    input.setAttribute("aria-expanded", "true");
    highlight(input, s);
  }

  function highlight(input, s) {
    Array.prototype.forEach.call(s.list.children, function (li, i) {
      li.setAttribute("aria-selected", i === s.active ? "true" : "false");
      if (i === s.active) li.scrollIntoView({ block: "nearest" });
    });
    input.setAttribute("aria-activedescendant", s.active >= 0 ? s.list.id + "-" + s.active : "");
  }

  function close(s, input) {
    if (!s.list) return;
    s.list.hidden = true;
    s.items = [];
    s.active = -1;
    input.setAttribute("aria-expanded", "false");
    input.removeAttribute("aria-activedescendant");
  }

  function accept(input, index) {
    const s = stateOf(input);
    const item = s.items[index];
    if (!item) return;
    const value = input.value;
    const caret = input.selectionStart;
    const before = value.slice(0, caret).match(WORD_BEFORE);
    const start = caret - (before ? before[0].length : 0);
    const end = caret + value.slice(caret).match(WORD_AFTER)[0].length;
    input.value = value.slice(0, start) + item.code + value.slice(end);
    const at = start + item.code.length;
    input.setSelectionRange(at, at);
    close(s, input);
    schedule(input);
  }

  // ── the operators (the toolbar) ────────────────────────────────────────────

  const CODE = /^[A-Za-z_]\w*$/;

  function grouped(text) {
    // whether `text` is one pair of parentheses around the rest: "(a | b)", not "(a) | (b)"
    if (text[0] !== "(" || text[text.length - 1] !== ")") return false;
    let depth = 0;
    for (let i = 0; i < text.length; i++) {
      if (text[i] === "(") depth++;
      else if (text[i] === ")") depth--;
      if (depth === 0 && i < text.length - 1) return false;
    }
    return true;
  }

  function edit(input, start, end, text, caret) {
    // replace [start, end) with `text`, the caret `caret` characters into it (at its end by default)
    input.value = input.value.slice(0, start) + text + input.value.slice(end);
    const at = start + (caret === undefined ? text.length : caret);
    input.setSelectionRange(at, at);
    schedule(input);
  }

  function binary(input, symbol) {
    // " & " or " | " after the selection or at the caret: the next predicate follows
    const value = input.value;
    const at = input.selectionEnd;
    const before = value.slice(0, at).replace(/\s+$/, "");
    const after = value.slice(at).replace(/^\s+/, "");
    const text = (before ? " " : "") + symbol + " " + (after ? " " : "");
    edit(input, before.length, value.length - after.length, text, text.trimEnd().length + 1);
    suggest(input, true);
  }

  function negate(input) {
    // ~ before the selection, or the predicate at the caret; on one already negated, ~ removed
    const value = input.value;
    let start = input.selectionStart;
    let end = input.selectionEnd;
    if (start === end) {
      const before = value.slice(0, start).match(WORD_BEFORE);
      start -= before ? before[0].length : 0;
      end += value.slice(end).match(WORD_AFTER)[0].length;
    }
    while (start < end && /\s/.test(value[start])) start++;
    while (end > start && /\s/.test(value[end - 1])) end--;
    const selected = value.slice(start, end);
    if (!selected) {
      edit(input, start, end, "~");
      suggest(input, true);
    } else if (value[start - 1] === "~") {
      edit(input, start - 1, end, selected);
    } else if (selected[0] === "~") {
      edit(input, start, end, selected.slice(1));
    } else {
      edit(input, start, end, CODE.test(selected) || grouped(selected) ? "~" + selected : "~(" + selected + ")");
    }
  }

  function group(input) {
    // parentheses around the selection, or an empty pair with the caret in it
    const start = input.selectionStart;
    const end = input.selectionEnd;
    const selected = input.value.slice(start, end).trim();
    if (selected) {
      edit(input, start, end, "(" + selected + ")");
    } else {
      edit(input, start, end, "()", 1);
      suggest(input, true);
    }
  }

  const OPERATIONS = {
    and: function (input) {
      binary(input, "&");
    },
    or: function (input) {
      binary(input, "|");
    },
    not: negate,
    group: group,
    predicates: function (input) {
      suggest(input, true);
    },
  };

  // a toolbar button keeps the focus (and the selection) in the input
  document.addEventListener("mousedown", function (event) {
    if (event.target.closest && event.target.closest(".dap-tools button")) event.preventDefault();
  });

  document.addEventListener("click", function (event) {
    const button = event.target.closest && event.target.closest(".dap-tools button");
    if (!button) return;
    const input = button.closest(".dap-field").querySelector(SELECTOR);
    const operation = OPERATIONS[button.dataset.op];
    if (!input || !operation || input.disabled || input.readOnly) return;
    input.focus();
    operation(input);
  });

  // ── the events ─────────────────────────────────────────────────────────────

  document.addEventListener("input", function (event) {
    if (!event.target.matches(SELECTOR)) return;
    schedule(event.target);
    suggest(event.target, false);
  });

  // the group or the entry chosen: the Test link follows
  document.addEventListener("change", function (event) {
    const form = event.target.form;
    if (!form || event.target.tagName !== "SELECT") return;
    form.querySelectorAll(SELECTOR).forEach(function (input) {
      if (input.value.trim()) validate(input);
    });
  });

  document.addEventListener("keydown", function (event) {
    const input = event.target;
    if (!input.matches || !input.matches(SELECTOR)) return;
    const s = stateOf(input);
    if (event.key === " " && event.ctrlKey) {
      event.preventDefault();
      suggest(input, true);
      return;
    }
    if (!s.list || s.list.hidden) return;
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      s.active = (s.active + step + s.items.length) % s.items.length;
      highlight(input, s);
    } else if (event.key === "Enter" || event.key === "Tab") {
      event.preventDefault();
      accept(input, s.active);
    } else if (event.key === "Escape") {
      event.preventDefault();
      close(s, input);
    }
  });

  document.addEventListener(
    "blur",
    function (event) {
      if (event.target.matches && event.target.matches(SELECTOR)) close(stateOf(event.target), event.target);
    },
    true
  );

  function init() {
    // the toolbar needs JS: without it, a plain text input
    document.querySelectorAll(".dap-tools").forEach(function (tools) {
      tools.hidden = false;
    });
    document.querySelectorAll(SELECTOR).forEach(function (input) {
      if (input.value.trim()) validate(input);
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
