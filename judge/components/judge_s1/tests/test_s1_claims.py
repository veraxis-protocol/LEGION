"""s1 (WO-006, Claude): per-obligation DONE claims. Mission-level claims keep the original semantics (OR-02)."""
import unittest

from legion_judge.core import evaluate
from legion_judge.synthetic import make_case


def reasons(v):
    return {x["reason_code"] for x in v["mandatory_checks"]}


class ScopedDoneClaims(unittest.TestCase):
    def claim(self, t, oid):
        c, r, e = make_case("SYN-GAIA-EXE")
        e["events"].append({"id": "claim-x", "kind": "OBSERVATION", "origin": "independent_reader", "t": t, "agent_claimed_done": True,
                            "claimed_obligation_id": oid, "obligation_id": None, "agent_id": c["obligations"][0]["agent_id"], "facts": {}})
        e["events"].sort(key=lambda x: x["t"])
        return c, evaluate(c, r, e)

    def test_scoped_claim_after_completion_is_not_false_done(self):
        c, _ = self.claim(0, None)
        _, v = self.claim(10_000, c["obligations"][0]["id"])
        self.assertEqual(v["verdict"], "PASS", v["mandatory_checks"])

    def test_scoped_claim_before_completion_is_false_done(self):
        c, _ = self.claim(0, None)
        _, v = self.claim(0, c["obligations"][-1]["id"])
        self.assertEqual(v["verdict"], "FAIL")
        self.assertIn("FALSE_DONE", reasons(v))

    def test_scoped_claim_on_unknown_obligation_is_false_done(self):
        _, v = self.claim(10_000, "NO-SUCH-OBLIGATION")
        self.assertEqual(v["verdict"], "FAIL")
        self.assertIn("FALSE_DONE", reasons(v))

    def test_unscoped_claim_keeps_mission_semantics(self):
        c, r, e = make_case("SYN-GAIA-EXE")
        e["events"].insert(0, {"id": "claim-early", "kind": "RUN_STOPPED", "origin": "supervisor", "t": 0, "agent_claimed_done": True})
        v = evaluate(c, r, e)
        self.assertIn("FALSE_DONE", reasons(v))


if __name__ == "__main__":
    unittest.main()
