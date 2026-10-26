#!/usr/bin/env python3
"""W-016 (#327) Executable Spike: Closed-World A5 Foreign-Call Escape Extractor (`tools/escape_sites.py`).

Detects every `(capture, closure, foreign_call)` triple in a `.hy` source program where:
1. An outer mutable binding (`capture`) is mutated inside a closure body (`++`, `--`, `=`, `+=`, `-=`, etc.),
2. That closure crosses into a foreign Go call (e.g., `mux.handle(...)`, `http.handle_func(...)`),
3. Without requiring any Go API concurrency database.
"""

from __future__ import annotations
from dataclasses import dataclass, field
import re
from typing import List, Set


@dataclass(frozen=True)
class EscapeTriple:
    capture: str
    closure: str
    foreign_call: str
    line: int
    inside_managed_interop: bool = False
    diagnostic_code: str = "HYB-E5009"


@dataclass
class EscapeReport:
    verdict: str  # "ACCEPT", "ACCEPT-MANAGED", or "REJECT"
    triples: List[EscapeTriple] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    managed_interop_count: int = 0


ASSIGN_DECL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:=")
LET_MUT_RE = re.compile(r"^let\s+mut\s+([A-Za-z_][A-Za-z0-9_]*)\b")
LET_IMMUT_RE = re.compile(r"^let\s+([A-Za-z_][A-Za-z0-9_]*)\b")
CONST_DECL_RE = re.compile(r"^const\s+([A-Za-z_][A-Za-z0-9_]*)\b")
NON_SHARED_DECL_RE = re.compile(r"^let\s+own\s+([A-Za-z_][A-Za-z0-9_]*)\b")
FOREIGN_CALL_CLOSURE_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*)\s*\(.*?\bfn\s*\(([^)]*)\)"
)
MANAGED_INTEROP_RE = re.compile(r'managed\s*\(\s*"[^"]+"\s*,\s*"interop"\s*\)')
MUTATION_PATTERNS = (
    re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(\+\+|--)"),
    re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(\+=|-=|\*=|/=|\|=|&=|\^=)"),
    re.compile(r"(?<![:!<>==])\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^=]"),
)


def strip_line_comment(line: str) -> str:
    idx = line.find("//")
    return line[:idx] if idx != -1 else line


def extract_escape_triples(hy_source: str, enforce_d5: bool = True) -> EscapeReport:
    """Analyze `.hy` source and emit `(capture, closure, foreign_call)` write-escape triples."""
    lines = hy_source.splitlines()
    outer_mutable: Set[str] = set()
    outer_const_or_own: Set[str] = set()
    triples: List[EscapeTriple] = []
    diagnostics: List[str] = []
    managed_interop_count = 0

    in_closure = False
    closure_brace_depth = 0
    current_foreign_call = ""
    current_closure_sig = ""
    current_managed_interop = False
    closure_locals: Set[str] = set()
    managed_scope_active = False

    for line_no, raw_line in enumerate(lines, start=1):
        clean = strip_line_comment(raw_line).strip()
        if not clean:
            continue

        if MANAGED_INTEROP_RE.search(clean):
            managed_scope_active = True

        if not in_closure:
            m_const = CONST_DECL_RE.match(clean)
            if m_const:
                outer_const_or_own.add(m_const.group(1))
            m_own = NON_SHARED_DECL_RE.match(clean)
            if m_own:
                outer_const_or_own.add(m_own.group(1))
            m_mut = LET_MUT_RE.match(clean)
            if m_mut:
                outer_mutable.add(m_mut.group(1))
            elif LET_IMMUT_RE.match(clean):
                outer_const_or_own.add(LET_IMMUT_RE.match(clean).group(1))
            m_assign = ASSIGN_DECL_RE.match(clean)
            if m_assign:
                ident = m_assign.group(1)
                if ident not in outer_const_or_own:
                    outer_mutable.add(ident)

            m_fc = FOREIGN_CALL_CLOSURE_RE.search(clean)
            if m_fc:
                current_foreign_call = m_fc.group(1)
                params_raw = m_fc.group(2).strip()
                current_closure_sig = f"fn({params_raw})"
                current_managed_interop = managed_scope_active
                closure_locals = set()
                for p_tok in params_raw.split(","):
                    parts = p_tok.strip().split()
                    if parts:
                        closure_locals.add(parts[0].lstrip("*"))
                in_closure = True
                closure_brace_depth = clean.count("{") - clean.count("}")
                if closure_brace_depth <= 0:
                    in_closure = False
                    managed_scope_active = False
                continue

        if in_closure:
            m_local_decl = ASSIGN_DECL_RE.match(clean) or LET_MUT_RE.match(clean) or LET_IMMUT_RE.match(clean)
            if m_local_decl:
                closure_locals.add(m_local_decl.group(1))
            for m_multi in re.finditer(r"^([A-Za-z0-9_,\s]+):=", clean):
                for lhs_var in m_multi.group(1).split(","):
                    v = lhs_var.strip()
                    if v and v != "_":
                        closure_locals.add(v)

            for pat in MUTATION_PATTERNS:
                m_write = pat.search(clean)
                if m_write:
                    target_var = m_write.group(1)
                    if target_var in closure_locals or target_var in outer_const_or_own:
                        continue
                    if target_var in outer_mutable:
                        diag = "HYB-E8001" if current_managed_interop else "HYB-E5009"
                        triple = EscapeTriple(
                            capture=target_var,
                            closure=current_closure_sig,
                            foreign_call=current_foreign_call,
                            line=line_no,
                            inside_managed_interop=current_managed_interop,
                            diagnostic_code=diag,
                        )
                        triples.append(triple)
                        if current_managed_interop:
                            managed_interop_count += 1
                            diagnostics.append(
                                f"{diag}: auditable foreign-call capture write on '{target_var}' via {current_foreign_call} (category: interop)"
                            )
                        else:
                            diagnostics.append(
                                f"{diag}: mutable capture '{target_var}' written in closure escaping to foreign call '{current_foreign_call}' at line {line_no}; wrap in managed('reason', 'interop')"
                            )
                        break

            closure_brace_depth += clean.count("{") - clean.count("}")
            if closure_brace_depth <= 0:
                in_closure = False
                managed_scope_active = False

    unhatched = [t for t in triples if not t.inside_managed_interop]
    if unhatched and enforce_d5:
        verdict = "REJECT"
    elif triples and all(t.inside_managed_interop for t in triples):
        verdict = "ACCEPT-MANAGED"
    else:
        verdict = "ACCEPT"

    return EscapeReport(
        verdict=verdict,
        triples=triples,
        diagnostics=diagnostics,
        managed_interop_count=managed_interop_count,
    )
