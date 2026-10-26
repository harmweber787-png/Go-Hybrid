import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from validator import (
    CheckedEffectIR,
    IREffectOp,
    build_certificate,
    evaluate_w013_corpus,
    validate_translation,
)


class TestW013TranslationValidator(unittest.TestCase):
    def setUp(self):
        self.summaries = {"audit.Log": "io_effect", "ledger.Commit": "state_effect", "math.Abs": "pure"}
        self.ir = CheckedEffectIR(
            fn_name="settle_account",
            ops=(
                IREffectOp("EFFECT_CALL", "audit.Log", '"begin"'),
                IREffectOp("STORE_BACK", "accounts[id]", "__hy_loan_0"),
                IREffectOp("MOVE_SEND", "out_ch", "receipt"),
                IREffectOp("MATCH_RELEASE", "__hy_match_tmp", ""),
                IREffectOp("EFFECT_CALL", "ledger.Commit", "id"),
                IREffectOp("EXIT", "return:ok", ""),
            ),
            allow_managed=False,
            expected_exit="return:ok",
        )
        self.valid_go = "\n".join([
            "func settle_account(id string) string {",
            "    __hy_loan_0 := accounts[id]",
            '    audit.Log("begin")',
            "    accounts[id] = __hy_loan_0",
            "    out_ch <- receipt",
            "    __hy_release(__hy_match_tmp)",
            "    ledger.Commit(id)",
            "    return ok",
            "}",
        ])

    def test_valid_lowering_certified(self):
        cert = build_certificate(self.ir, self.valid_go, self.summaries)
        verdict = validate_translation(self.ir, self.valid_go, cert, self.summaries)
        self.assertTrue(verdict.certified)
        self.assertEqual(verdict.code, "CERTIFIED")

    def test_tampered_certificate_rejected(self):
        cert = build_certificate(self.ir, self.valid_go, self.summaries)
        mutated_go = self.valid_go.replace("return ok", "return tampered")
        verdict = validate_translation(self.ir, mutated_go, cert, self.summaries)
        self.assertFalse(verdict.certified)
        self.assertEqual(verdict.code, "TV-E001_DIGEST_MISMATCH")

    def test_all_six_falsifier_mutations_rejected(self):
        report = evaluate_w013_corpus()
        self.assertTrue(report["positive_certified"])
        self.assertTrue(report["all_mutations_rejected"])
        mv = report["mutation_verdicts"]
        self.assertEqual(mv["M1_drop_store_back"], "TV-E003_MISSING_STORE_BACK")
        self.assertEqual(mv["M2_reorder_store_back_across_call"], "TV-E004_EFFECT_ORDER_VIOLATION")
        self.assertEqual(mv["M3_duplicate_effect"], "TV-E005_DUPLICATE_EFFECT")
        self.assertEqual(mv["M4_redirect_exit"], "TV-E006_EXIT_REDIRECT")
        self.assertEqual(mv["M5_unauthorized_managed"], "TV-E007_UNAUTHORIZED_MANAGED")
        self.assertEqual(mv["M6_unmodeled_panic"], "TV-E002_UNSUPPORTED_CONSTRUCT")
        self.assertLess(report["tcb_ratio"], 0.30)


if __name__ == "__main__":
    unittest.main()
