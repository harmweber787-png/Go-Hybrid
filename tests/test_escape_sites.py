#!/usr/bin/env python3
"""Unit tests for W-016 (#327): Closed-world A5 foreign-call capture-write check-site."""

import unittest
from tools import escape_sites

EXAMPLE_06_HTTP_SERVER = """
import "net/http"

fn logging(next http.handler) http.handler {
    return fn(w http.response_writer, r *http.request) {
        fmt.eprintln("{r.method} {r.url.path}")
        next.serve_http(w, r)
    }
}

fn main() {
    mux := http.new_serve_mux()

    mux.handle("/hello", http.handler(fn(w, r) {
        fmt.fprintln(w, "hello from Hybrid")
    }))

    mux.handle("/add/", http.handler(fn(w, r) {
        a := strconv.atoi(r.url.query.get("a"))?
        b := strconv.atoi(r.url.query.get("b"))?
        fmt.fprintf(w, "{a}+{b}={a + b}\\n")
    }))
}
"""

CORPUS_10_A5_HANDLER_CAPTURE = """
import "net/http"

fn main() {
    hits := 0

    mux := http.new_serve_mux()
    mux.handle("/ping", http.handler(fn(w http.response_writer, r *http.request) {
        hits++
        fmt.fprintln(w, "pong {hits}")
    }))
}
"""


class TestW016ForeignEscapeCheck(unittest.TestCase):
    def test_01_m1_pinned_example_06_yields_zero_triples(self):
        report = escape_sites.extract_escape_triples(EXAMPLE_06_HTTP_SERVER)
        self.assertEqual(len(report.triples), 0)
        self.assertEqual(report.verdict, "ACCEPT")
        self.assertEqual(report.diagnostics, [])

    def test_02_m1_pinned_corpus_10_yields_exact_hits_triple(self):
        report = escape_sites.extract_escape_triples(CORPUS_10_A5_HANDLER_CAPTURE)
        self.assertEqual(len(report.triples), 1)
        t = report.triples[0]
        self.assertEqual(t.capture, "hits")
        self.assertEqual(t.foreign_call, "mux.handle")
        self.assertEqual(t.diagnostic_code, "HYB-E5009")
        self.assertEqual(report.verdict, "REJECT")

    def test_03_maintainer_review_thread_local_closure_binding_not_flagged(self):
        src = """
        fn main() {
            mux := http.new_serve_mux()
            mux.handle("/local", http.handler(fn(w http.response_writer, r *http.request) {
                local_counter := 0
                local_counter++
                fmt.fprintln(w, "{local_counter}")
            }))
        }
        """
        report = escape_sites.extract_escape_triples(src)
        self.assertEqual(len(report.triples), 0)
        self.assertEqual(report.verdict, "ACCEPT")

    def test_04_maintainer_review_managed_interop_hatch_flips_to_accept_managed(self):
        src = """
        fn main() {
            hits := 0
            mux := http.new_serve_mux()
            managed("request counter behind external mutex", "interop") {
                mux.handle("/ping", http.handler(fn(w http.response_writer, r *http.request) {
                    hits += 1
                }))
            }
        }
        """
        report = escape_sites.extract_escape_triples(src)
        self.assertEqual(len(report.triples), 1)
        self.assertTrue(report.triples[0].inside_managed_interop)
        self.assertEqual(report.triples[0].diagnostic_code, "HYB-E8001")
        self.assertEqual(report.verdict, "ACCEPT-MANAGED")
        self.assertEqual(report.managed_interop_count, 1)

    def test_05_const_and_non_shared_own_captures_exempt(self):
        src = """
        fn main() {
            const max_req = 100
            let own isolated_buf = 0
            mux := http.new_serve_mux()
            mux.handle("/ok", http.handler(fn(w, r) {
                isolated_buf = 1
            }))
        }
        """
        report = escape_sites.extract_escape_triples(src)
        self.assertEqual(len(report.triples), 0)
        self.assertEqual(report.verdict, "ACCEPT")

    def test_06_report_escapes_non_blocking_lint_mode(self):
        report = escape_sites.extract_escape_triples(CORPUS_10_A5_HANDLER_CAPTURE, enforce_d5=False)
        self.assertEqual(len(report.triples), 1)
        self.assertEqual(report.verdict, "ACCEPT")


if __name__ == "__main__":
    unittest.main()
