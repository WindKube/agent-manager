// Client helpers called from datastar expressions. Every datastar expression is
// compiled with `el` in scope, so an option's label is read from its data-label
// attribute rather than interpolated into the expression: the label comes from a
// manifest's keywords, and templ escapes an attribute value but could not escape
// it into a JavaScript string literal (FR-055).
//
// Multi-select state travels as a JSON array in a string signal. datastar's
// signal proxy wraps array elements, so Array.prototype methods on a live array
// signal compare wrappers rather than values; a string is unambiguous in both
// directions and is what the server unmarshals.
(function () {
  "use strict";

  function list(raw) {
    try {
      var parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      return [];
    }
  }

  // amFuzzy is a subsequence match, not a substring match: the needle's
  // characters must appear in order in the haystack but need not be adjacent.
  // Whitespace is stripped from the needle only. This mirrors fuzzy() at
  // docs/design/agent-manager.dc.html line 964 and web.Fuzzy in Go.
  window.amFuzzy = function (needle, haystack) {
    var n = String(needle == null ? "" : needle).toLowerCase().replace(/\s+/g, "");
    if (n === "") {
      return true;
    }
    var h = String(haystack == null ? "" : haystack).toLowerCase();
    var i = 0;
    for (var j = 0; j < h.length && i < n.length; j++) {
      if (h[j] === n[i]) {
        i++;
      }
    }
    return i === n.length;
  };

  window.amHas = function (raw, value) {
    return list(raw).indexOf(value) !== -1;
  };

  window.amToggle = function (raw, value) {
    var values = list(raw);
    var at = values.indexOf(value);
    if (at === -1) {
      values.push(value);
    } else {
      values.splice(at, 1);
    }
    values.sort();
    return JSON.stringify(values);
  };

  window.amAny = function (raw) {
    return list(raw).length > 0;
  };

  // Rendered through data-text, which assigns textContent, so a label is never
  // parsed as markup.
  window.amSummary = function (raw) {
    var values = list(raw);
    if (values.length === 0) {
      return "Any";
    }
    if (values.length === 1) {
      return values[0];
    }
    return values.length + " selected";
  };

  // amNoMatch backs the menu's "No match" state. The option list only exists in
  // the DOM, so the emptiness of the filtered view is read from there; the
  // needle argument is what makes the expression reactive.
  window.amNoMatch = function (el, needle) {
    var options = el.parentElement.querySelectorAll("[data-label]");
    if (options.length === 0) {
      return false;
    }
    for (var i = 0; i < options.length; i++) {
      if (window.amFuzzy(needle, options[i].dataset.label)) {
        return false;
      }
    }
    return true;
  };
})();
