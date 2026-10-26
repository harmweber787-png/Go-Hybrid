# W-016 (#327) Spike: Closed-World A5 Foreign-Call Escape Check (`D5`)

## 1. Summary & Ledger Reference
- **Issue:** `#327` (`[wildcard] Make the A5 Go-escape a check-site with no Go API database: a capture-write at a foreign-call boundary takes managed`)
- **Ledger ID:** `W-016` (Slot 16, `$250` M1 + `$250` M2 = `$500` total)
- **Thesis (`D5`):** Every write to an outer mutable binding inside a closure that crosses a foreign Go call boundary (`pkg.fn(...)`) is a closed-world check-site (`HYB-E5009`) requiring either ownership refactoring or an explicit `managed("reason", "interop")` block (`HYB-E8001` `ACCEPT-MANAGED`), with **zero Go API database**.

## 2. Pinned M1 Verification Matrix
| Target File | Triples Found | Diagnostic | Verdict |
|---|---|---|---|
| `examples/06-http-server/program.hy` | `0` | None | `ACCEPT` |
| `tests/checker-corpus/10-a5-http-handler-capture.hy` | `1` (`hits`, `fn(...)`, `mux.handle`) | `HYB-E5009` | `REJECT` |
| `10-a5-http-handler-capture.hy` wrapped in `managed("...", "interop")` | `1` (`hits`, `fn(...)`, `mux.handle`) | `HYB-E8001` (`interop`) | `ACCEPT-MANAGED` |

## 3. Answers to Maintainer Triage Review Questions
1. **False-positive control on thread-local / non-shared captures:**
   - Closure-local bindings declared inside the closure body (`a := ...`, `local_counter := 0`) and closure parameters (`w`, `r`) are tracked in `closure_locals` and never emit a capture-write triple.
   - Outer `const` and `let own` (non-shared isolated) bindings are tracked in `outer_const_or_own` and exempted.
2. **Interaction with A5's off-by-default `--report-escapes` lint:**
   - `extract_escape_triples(hy_source, enforce_d5=False)` emits the exact `(capture, closure, foreign_call)` inventory as non-blocking `HYB-E5009` advisory diagnostics (`verdict="ACCEPT"`), while `enforce_d5=True` upgrades unhatched foreign-escape writes to `verdict="REJECT"`.
3. **Fit with the 4-category `managed("reason", "interop")` taxonomy (`#274` / `W-012`):**
   - When the foreign call is enclosed in `managed("<reason>", "interop")`, the triple is marked `inside_managed_interop=True`, emits `HYB-E8001` under category `interop`, increments `managed_interop_count`, and yields `ACCEPT-MANAGED`.
