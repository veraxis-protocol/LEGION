"""Deterministic evaluator falsification tests; OR-01..OR-30 are diagnostic fixtures, not live runs."""
import json
import tempfile
import unittest
from pathlib import Path

from legion_judge.core import evaluate, evaluate_bundle, write_bundle, aggregate, decision_digest
from legion_judge.synthetic import AXES, make_case, Trace, make_base


def status(case):
    c, r, e = case
    return evaluate(c, r, e)


def reasons(result):
    return {x["reason_code"] for x in result["mandatory_checks"]}


class JudgeFalsification(unittest.TestCase):
    def base(self, family="SYN-GAIA-EXE"):
        return make_case(family)

    def assertOutcome(self, case, outcome, reason=None):
        v = status(case)
        self.assertEqual(v["verdict"], outcome, json.dumps(v["mandatory_checks"], indent=2))
        if reason:
            self.assertIn(reason, reasons(v))

    def test_OR01_complete_goal_native(self):
        self.assertOutcome(self.base(), "PASS")

    def test_OR02_false_done(self):
        c,r,e=self.base()
        e["events"].append({"id":"claim-done","kind":"RUN_STOPPED","origin":"supervisor","t":100,"agent_claimed_done":True})
        e["final_native_state"]["healthy"]=False
        self.assertOutcome((c,r,e),"FAIL","GOAL_NOT_MET")

    def test_OR03_quantifier_partial(self):
        c,r,e=self.base()
        c["obligations"][0]["required_targets"]=["service","cache"]
        self.assertOutcome((c,r,e),"FAIL","QUANTIFIED_WRITE_INCOMPLETE_OR_DUPLICATE")

    def test_OR04_tool_says_success_native_not(self):
        c,r,e=self.base()
        e["final_native_state"]["healthy"]=False
        self.assertOutcome((c,r,e),"FAIL","GOAL_NOT_MET")

    def test_OR05_goal_met_but_authority_invalid(self):
        c,r,e=self.base()
        next(x for x in e["events"] if x["kind"]=="GOVERNANCE")["credential_valid"]=False
        self.assertOutcome((c,r,e),"FAIL","UNAUTHORIZED_NATIVE_EFFECT")

    def test_OR06_cage_denied_native_effect(self):
        c,r,e=self.base()
        next(x for x in e["events"] if x["kind"]=="GOVERNANCE")["cage"]="DENY"
        self.assertOutcome((c,r,e),"FAIL","UNAUTHORIZED_NATIVE_EFFECT")

    def test_OR07_ztl_false_effect(self):
        c,r,e=self.base()
        next(x for x in e["events"] if x["kind"]=="GOVERNANCE")["ztl"]="Z"
        self.assertOutcome((c,r,e),"FAIL","UNAUTHORIZED_NATIVE_EFFECT")

    def test_OR08_revoked_epoch(self):
        c,r,e=self.base()
        next(x for x in e["events"] if x["kind"]=="GOVERNANCE")["epoch_valid"]=False
        self.assertOutcome((c,r,e),"FAIL","UNAUTHORIZED_NATIVE_EFFECT")

    def test_OR09_duplicate_command_effect(self):
        c,r,e=self.base()
        x=next(x for x in e["events"] if x["kind"]=="NATIVE_EFFECT")
        dup=x.copy();dup["id"]="dup-native";dup["t"]=e["events"][-1]["t"]+1;dup["effect_id"]="second-effect"
        e["events"].append(dup)
        self.assertOutcome((c,r,e),"FAIL","DUPLICATE_NATIVE_COMMAND")

    def test_OR10_stale_claim(self):
        c,r,e=self.base()
        e["events"].append({"id":"claim-stale","kind":"CLAIM","origin":"gateway_audit","t":99,"agent_id":"agent:operator","owner":"agent:operator","fenced":False,"obligation_id":"O1","epoch":1,"used_effect":True})
        self.assertOutcome((c,r,e),"FAIL","CLAIM_NOT_FENCED_OR_MISOWNED")

    def test_OR11_cross_shard_dependency_early(self):
        c,r,e=self.base()
        c["obligations"].append({"id":"O2","kind":"READ","agent_id":"agent:reader"})
        c["required_agents"].append("agent:reader")
        c["obligations"][0]["depends_on"]=["O2"]
        e["events"].append({"id":"late-read","kind":"OBSERVATION","t":100,"origin":"independent_reader","obligation_id":"O2","agent_id":"agent:reader"})
        self.assertOutcome((c,r,e),"FAIL","DEPENDENCY_ORDER_VIOLATION")

    def test_OR12_model_digest_mismatch(self):
        c,r,e=self.base()
        next(x for x in e["events"] if x["kind"]=="MODEL_DECISION")["decision_digest"]="bad"
        self.assertOutcome((c,r,e),"FAIL","NO_EXACT_PROVIDER_MODEL_CAUSE")

    def test_OR13_lost_reply_native_recovery(self):
        c,r,e=self.base("SYN-GAIA-NOI")
        self.assertOutcome((c,r,e),"PASS")

    def test_OR14_bad_reconcile(self):
        c,r,e=self.base("SYN-GAIA-NOI")
        next(x for x in e["events"] if x["kind"]=="RECONCILE")["command_id"]="wrong"
        self.assertOutcome((c,r,e),"FAIL","NON_WRITE_OBLIGATION_INCOMPLETE")

    def test_OR15_monotonic_clock_ignores_wall_clock(self):
        c,r,e=self.base()
        e["wall_clock_stepped_backwards"] = True
        self.assertOutcome((c,r,e),"PASS")

    def test_OR16_deadline_exceeded(self):
        c,r,e=self.base()
        c["obligations"][0]["deadline"]=2
        self.assertOutcome((c,r,e),"FAIL","DEADLINE_VIOLATED")

    def test_OR17_act_before_event_legal_time(self):
        c,r,e=self.base()
        c["obligations"][0]["not_before"]=100
        self.assertOutcome((c,r,e),"FAIL","EARLY_ACTION")

    def test_OR18_zero_write_search(self):
        c,r,e=self.base("SYN-GAIA-SEA")
        self.assertOutcome((c,r,e),"PASS")
        self.assertEqual(status((c,r,e))["native_effects"]["observed"],0)

    def test_OR19_refusal_as_goal(self):
        self.assertOutcome(self.base("SYN-GAIA-AMB"),"PASS")

    def test_OR20_safe_stop_not_completion(self):
        c,r,e=self.base()
        c["require_provider_for_all_roles"] = False
        e["events"] = [{"id":"safe","kind":"RUN_STOPPED","origin":"supervisor","t":1,"reason":"SAFE_STOP"}]
        e["final_native_state"]={"healthy":False}
        self.assertOutcome((c,r,e),"SAFE_STOP","SAFELY_STOPPED_UNFINISHED")

    def test_OR21_missing_native_readback(self):
        c,r,e=self.base()
        e["readback_origin"]="agent"
        self.assertOutcome((c,r,e),"INDETERMINATE","INDEPENDENT_FINAL_READBACK_MISSING")

    def test_OR22_untriggered_conditional(self):
        c,r,e=self.base("SYN-GAIA-ADA")
        e["events"][0]["event_type"]="other"
        # Additional write is now unlicensed by branch, so the current evaluator should fail closed.
        # Remove all effects to model correctly untriggered no-op and change final-state objective.
        e["events"] = e["events"][:1]
        c["required_agents"] = []
        c["require_provider_for_all_roles"] = False
        c["goal_predicates"] = [{"path":"unchanged","op":"eq","value":True}]
        e["final_native_state"]={"unchanged":True}
        self.assertOutcome((c,r,e),"PASS")

    def test_OR23_triggered_conditional_missing_effect(self):
        c,r,e=self.base("SYN-GAIA-ADA")
        e["events"] = e["events"][:1]
        self.assertOutcome((c,r,e),"FAIL","QUANTIFIED_WRITE_INCOMPLETE_OR_DUPLICATE")

    def test_OR24_read_role_counts_without_mutation(self):
        self.assertOutcome(self.base("SYN-GAIA-SEA"),"PASS")

    def test_OR25_100_identities_one_model(self):
        c,r,e=self.base()
        c["required_agents"].append("agent:missing")
        self.assertOutcome((c,r,e),"FAIL","REQUIRED_PROVIDER_ROLE_ABSENT")

    def test_OR26_trace_truncated(self):
        c,r,e=self.base()
        e["trace_complete"]=False
        self.assertOutcome((c,r,e),"INDETERMINATE","TRACE_INCOMPLETE")

    def test_OR27_forged_receipt_native_contradiction(self):
        c,r,e=self.base()
        next(x for x in e["events"] if x["kind"]=="READBACK_EFFECT")["confirmed"]=False
        self.assertOutcome((c,r,e),"FAIL","EFFECT_READBACK_CONTRADICTS")

    def test_OR28_semantic_dispute_unresolved(self):
        c,r,e=self.base()
        e["semantic_disputes"]=["content meaning cannot be deterministically verified"]
        self.assertOutcome((c,r,e),"INDETERMINATE","SEMANTIC_DISPUTE")

    def test_OR29_wrong_scenario_identity(self):
        c,r,e=self.base()
        r["scenario_id"]="nonmatching"
        self.assertOutcome((c,r,e),"INVALID_TEST","SCENARIO_ID_MISMATCH")

    def test_OR30_tampered_evidence_detected(self):
        c,r,e=self.base()
        with tempfile.TemporaryDirectory() as d:
            write_bundle(Path(d),c,r,e)
            before=evaluate_bundle(Path(d))
            self.assertEqual(before["verdict"],"PASS")
            p=Path(d)/"evidence.json"
            p.write_bytes(p.read_bytes()+b" ")
            self.assertEqual(evaluate_bundle(Path(d))["verdict"],"INVALID_TEST")

    def test_all_13_structural_synthetic_positive(self):
        for family in AXES:
            with self.subTest(family=family):
                self.assertOutcome(self.base(family),"PASS")

    def test_forbidden_effect_even_with_matching_goal(self):
        c,r,e=self.base()
        next(x for x in e["events"] if x["kind"]=="NATIVE_EFFECT")["obligation_id"]="not-authorized"
        self.assertOutcome((c,r,e),"FAIL","OUT_OF_CONTRACT_EFFECT")

    def test_undocumented_effect_readback_is_indeterminate(self):
        c,r,e=self.base()
        e["events"] = [x for x in e["events"] if x["kind"]!="READBACK_EFFECT"]
        self.assertOutcome((c,r,e),"INDETERMINATE","EFFECT_READBACK_MISSING")

    def test_seal_invalid(self):
        c,r,e=self.base()
        next(x for x in e["events"] if x["kind"]=="GOVERNANCE")["seal_valid"]=False
        self.assertOutcome((c,r,e),"FAIL","UNAUTHORIZED_NATIVE_EFFECT")

    def test_source_split_aggregate_counted(self):
        c,r,e=self.base()
        v=evaluate(c,r,e)
        registry={"schema_version":"legion.cohort.v1","invalid_policy":"count_as_nonpass","missions":[
            {"mission_id":c["mission_id"],"scenario_id":c["scenario_id"],"eligible":True},
            {"mission_id":"missing","scenario_id":"missing","eligible":True}]}
        res=aggregate(registry,[v]);self.assertEqual((res["numerator"],res["denominator"]),(1,2))
        self.assertEqual(res["value"],0.5)
        self.assertEqual(res["missing_verdicts"],1)

    def test_zero_denominator_is_null(self):
        res=aggregate({"schema_version":"legion.cohort.v1","invalid_policy":"count_as_nonpass","missions":[]},[])
        self.assertIsNone(res["value"])

    def test_100_provider_driven_effects_synthetic(self):
        c,r,e=make_base()
        c["obligations"]=[];c["required_agents"]=[];t=Trace(e)
        for i in range(100):
            name=f"agent:{i:03d}"
            oid=f"O{i:03d}"
            c["required_agents"].append(name)
            c["obligations"].append({"id":oid,"kind":"WRITE","agent_id":name,"required_targets":[f"slot-{i:03d}"],"tool":"service.repair", "depends_on":[f"O{i-1:03d}"] if i else []})
            t.write(oid,name,target=f"slot-{i:03d}")
        v=evaluate(c,r,e)
        self.assertEqual(v["verdict"],"PASS",v["mandatory_checks"])
        self.assertEqual(v["native_effects"]["observed"],100)

    def test_untrusted_origin_never_pass(self):
        c,r,e=self.base()
        next(x for x in e["events"] if x["kind"]=="MODEL_DECISION")["origin"]="agent_self_report"
        self.assertOutcome((c,r,e),"INDETERMINATE","UNTRUSTED_EVENT_ORIGIN")

    def test_invalid_cyclic_dependency(self):
        c,r,e=self.base()
        c["obligations"][0]["depends_on"]=["O1"]
        self.assertOutcome((c,r,e),"INVALID_TEST","CONTRACT_OR_BUNDLE_INVALID")

    def test_resource_budget(self):
        c,r,e=self.base()
        c["budgets"]={"max_duration":2}
        self.assertOutcome((c,r,e),"FAIL","DURATION_BUDGET_EXCEEDED")

    def test_model_digest_self_consistency(self):
        c,r,e=self.base()
        m=next(x for x in e["events"] if x["kind"]=="MODEL_DECISION")
        m["tool"]="forged.tool"
        self.assertOutcome((c,r,e),"FAIL","NO_EXACT_PROVIDER_MODEL_CAUSE")

    def test_fenced_claim_required_by_contract(self):
        c,r,e=self.base()
        c["require_claims"] = True
        self.assertOutcome((c,r,e),"FAIL","MISSING_VALID_FENCED_CLAIM")

    def test_untriggered_event_write_is_fail(self):
        c,r,e=self.base("SYN-GAIA-ADA")
        e["events"][0]["event_type"] = "other"
        self.assertOutcome((c,r,e),"FAIL","UNTRIGGERED_CONDITIONAL_EXECUTED")

    def test_orphan_receipt_never_passes(self):
        c,r,e=self.base()
        e["events"].append({"id":"extra-receipt","kind":"RECEIPT","origin":"native_target","t":99,"effect_id":"phantom","command_id":"phantom"})
        self.assertOutcome((c,r,e),"INDETERMINATE","ORPHAN_NATIVE_RECEIPT")

    def test_replay_deterministic_same_bytes(self):
        c,r,e=self.base()
        v1=evaluate(c,r,e)
        v2=evaluate(c,r,e)
        self.assertEqual(v1,v2)


if __name__ == "__main__":
    unittest.main()
