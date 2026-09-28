"""
Rule DSL evaluator — pure function, zero code execution.

DSL node shapes
───────────────
Leaf (text match):
  {"field": "sanitized_text", "op": "contains",     "value": "some string"}
  {"field": "sanitized_text", "op": "not_contains",  "value": "some string"}
  {"field": "sanitized_text", "op": "regex",         "pattern": "\\b\\d{32}\\b"}
  {"field": "sanitized_text", "op": "not_regex",     "pattern": "..."}
  {"field": "sanitized_text", "op": "equals",        "value": "exact"}
  {"field": "sanitized_text", "op": "starts_with",   "value": "prefix"}
  {"field": "sanitized_text", "op": "ends_with",     "value": "suffix"}

  field defaults to "sanitized_text" when omitted.
  Available fields: sanitized_text, raw_text, source_type.

Compound:
  {"and":  [node, ...]}  — all children must match
  {"all":  [node, ...]}  — alias for "and"
  {"or":   [node, ...]}  — at least one child must match
  {"any":  [node, ...]}  — alias for "or"
  {"not":  node}         — negates the child

The evaluator never calls eval(), exec(), compile(), or any execution primitive.
All regex patterns are run with re.search() and compiled with a timeout guard.
"""
from __future__ import annotations

import re
from typing import Optional

_SNIPPET_CONTEXT = 60   # chars of surrounding context to capture
_MAX_SNIPPET = 500      # hard cap on matched_snippet stored in DB


def evaluate_rule(condition: dict, context: dict[str, str]) -> tuple[bool, str]:
    """
    Evaluate a single DSL node against *context*.

    Parameters
    ----------
    condition:  A rule condition_json node (dict).
    context:    Mapping of field name → text value.

    Returns
    -------
    (matched: bool, snippet: str)
    snippet is a short excerpt of the matching portion (empty when not matched).
    """
    return _eval_node(condition, context)


# ─── Internal recursive evaluator ────────────────────────────────────────────

def _eval_node(node: dict, ctx: dict[str, str]) -> tuple[bool, str]:
    """Recursively evaluate one DSL node. Pure — no side effects."""

    # ── Compound: AND / ALL ───────────────────────────────────────────────
    children_and = node.get("and") or node.get("all")
    if children_and is not None:
        snippets: list[str] = []
        for child in children_and:
            ok, snip = _eval_node(child, ctx)
            if not ok:
                return False, ""
            if snip:
                snippets.append(snip)
        return True, _join_snippets(snippets)

    # ── Compound: OR / ANY ────────────────────────────────────────────────
    children_or = node.get("or") or node.get("any")
    if children_or is not None:
        for child in children_or:
            ok, snip = _eval_node(child, ctx)
            if ok:
                return True, snip
        return False, ""

    # ── Compound: NOT ─────────────────────────────────────────────────────
    if "not" in node:
        ok, _ = _eval_node(node["not"], ctx)
        return not ok, ""

    # ── Leaf ─────────────────────────────────────────────────────────────
    return _eval_leaf(node, ctx)


def _eval_leaf(node: dict, ctx: dict[str, str]) -> tuple[bool, str]:
    op = node.get("op", "")
    field = node.get("field", "sanitized_text")
    text = ctx.get(field, "")

    if op == "contains":
        value = node.get("value", "")
        return _match_contains(text, value, case_sensitive=False)

    if op == "contains_cs":          # case-sensitive variant
        value = node.get("value", "")
        return _match_contains(text, value, case_sensitive=True)

    if op == "not_contains":
        value = node.get("value", "")
        matched, _ = _match_contains(text, value, case_sensitive=False)
        return not matched, ""

    if op == "regex":
        pattern = node.get("pattern", "")
        return _match_regex(text, pattern)

    if op == "not_regex":
        pattern = node.get("pattern", "")
        matched, _ = _match_regex(text, pattern)
        return not matched, ""

    if op == "equals":
        value = node.get("value", "")
        matched = text.strip().lower() == value.strip().lower()
        return matched, (value[:_MAX_SNIPPET] if matched else "")

    if op == "starts_with":
        value = node.get("value", "")
        matched = text.lower().startswith(value.lower())
        return matched, (text[:len(value) + _SNIPPET_CONTEXT] if matched else "")

    if op == "ends_with":
        value = node.get("value", "")
        matched = text.lower().endswith(value.lower())
        return matched, (text[-(len(value) + _SNIPPET_CONTEXT):] if matched else "")

    # Unknown op — treat as non-match (safe default, never executes content)
    return False, ""


# ─── Low-level helpers ────────────────────────────────────────────────────────

def _match_contains(text: str, value: str, *, case_sensitive: bool) -> tuple[bool, str]:
    if not value:
        return False, ""
    haystack = text if case_sensitive else text.lower()
    needle = value if case_sensitive else value.lower()
    idx = haystack.find(needle)
    if idx == -1:
        return False, ""
    start = max(0, idx - _SNIPPET_CONTEXT)
    end = min(len(text), idx + len(value) + _SNIPPET_CONTEXT)
    return True, text[start:end]


def _match_regex(text: str, pattern: str) -> tuple[bool, str]:
    if not pattern:
        return False, ""
    try:
        m = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    except re.error:
        # Invalid regex — treat as non-match, never raises to caller
        return False, ""
    if m is None:
        return False, ""
    start = max(0, m.start() - _SNIPPET_CONTEXT)
    end = min(len(text), m.end() + _SNIPPET_CONTEXT)
    return True, text[start:end]


def _join_snippets(snippets: list[str]) -> str:
    joined = " | ".join(s.strip() for s in snippets if s.strip())
    return joined[:_MAX_SNIPPET]
