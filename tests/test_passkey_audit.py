"""passkey_audit 的断言测试（unittest）。

覆盖：
- 五个必须复现的业务场景案例 + 规模案例 + 冲突案例的期望输出；
- 引擎与独立穷举器（passkey_audit.brute）在小规模案例与随机案例上的交叉核对；
- 去重、同步依赖、无计数器实例、撤销、格式错误、CLI 与输出确定性。
"""
import json
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from passkey_audit.brute import brute_analyze
from passkey_audit.engine import Engine
from passkey_audit.model import FormatError, parse_case

CASES = ROOT / "cases"


def load_case(name):
    return parse_case((CASES / name).read_text(encoding="utf-8"))


def analyze_file(name):
    return Engine(load_case(name)).analyze()


def analyze_dict(d):
    return Engine(parse_case(json.dumps(d))).analyze()


BASE_INSTANCE = {"id": "I1", "copy": "C1", "generation": "G1",
                 "counterless": False}


def receipt(rid, fp=None, counter=1, copy=None, candidates=None, **kw):
    r = {
        "id": rid,
        "fingerprint": fp or ("F" + rid),
        "counter": counter,
        "signature_ok": True,
        "challenge_ok": True,
        "fixed": False,
        "cost": 1,
    }
    if copy is not None:
        r["copy"] = copy
    else:
        r["candidates"] = candidates if candidates is not None else ["I1"]
    r.update(kw)
    return r


class TestShowcaseCases(unittest.TestCase):
    """五个必须复现的场景 + 规模/冲突案例。"""

    def test_reordered_inbox_explainable(self):
        # 倒序收件但可解释：接收顺序只是旁证
        r = analyze_file("reordered_inbox.json")
        self.assertEqual(r["status"], "ok")
        for rid in ("R1", "R2", "R3"):
            self.assertEqual(r["receipts"][rid]["verdict"], "kept_in_some")
        self.assertEqual(r["optimal"]["anomaly_set"], [])
        self.assertEqual(r["optimal"]["drop_cost"], 0)
        w = r["optimal"]["witness"]
        self.assertEqual(w["order"], ["F1", "F2", "F3"])
        self.assertFalse(w["recv_order_agrees"])  # 收件顺序确实倒序

    def test_shared_counter_from_different_copies(self):
        # 同计数由不同副本签发：不同实例互不共享计数空间
        r = analyze_file("shared_counter_clones.json")
        self.assertEqual(r["receipts"]["R1"]["verdict"], "kept_in_all")
        self.assertEqual(r["receipts"]["R2"]["verdict"], "kept_in_all")
        # 第三条同计数回执无处可放（两个实例的 5 都已出现）
        self.assertEqual(r["receipts"]["R3"]["verdict"], "kept_in_none")
        self.assertEqual(r["optimal"]["anomaly_set"], ["R3"])
        self.assertEqual(r["optimal"]["necessary_anomalies"], ["R3"])

    def test_generation_mixup_after_identity_change(self):
        # 身份更换后副本 ID 重新出现：不得跨代次串计数空间
        r = analyze_file("generation_mixup.json")
        self.assertEqual(r["status"], "ok")
        for rid in ("R1", "R2", "R3"):
            self.assertEqual(r["receipts"][rid]["verdict"], "kept_in_all")
        self.assertEqual(r["optimal"]["anomaly_set"], [])
        w = r["optimal"]["witness"]
        # 旧代次实例在撤销前，新代次实例重新从 1 计数
        self.assertEqual(w["assignment"], {"F1": "I1", "F2": "I2", "F3": "I2"})
        pos = {ev: i for i, ev in enumerate(w["order"])}
        self.assertLess(pos["F1"], pos["V1"])
        self.assertLess(pos["V1"], pos["F2"])

    def test_legitimate_receipt_verdict_depends_on_other_record(self):
        # 合法回执的异常判定取决于另一条记录
        r = analyze_file("dependent_verdict.json")
        self.assertEqual(r["receipts"]["RA"]["verdict"], "kept_in_all")
        self.assertEqual(r["receipts"]["RB"]["verdict"], "kept_in_none")
        self.assertEqual(r["receipts"]["RB"]["detail"], "CONFLICTS_WITH_FIXED")
        self.assertEqual(r["optimal"]["anomaly_set"], ["RB"])
        self.assertEqual(r["optimal"]["necessary_anomalies"], ["RB"])
        # 若没有 RA 这条固定记录，RB 本身完全合法
        case = json.loads((CASES / "dependent_verdict.json").read_text("utf-8"))
        case["receipts"] = [x for x in case["receipts"] if x["id"] != "RA"]
        r2 = analyze_dict(case)
        self.assertEqual(r2["receipts"]["RB"]["verdict"], "kept_in_some")
        self.assertEqual(r2["optimal"]["anomaly_set"], [])

    def test_tied_optima_empty_necessary_set(self):
        # 最低代价解有多种但必要异常为空
        r = analyze_file("tied_optima.json")
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["optimal"]["drop_cost"], 1)
        self.assertEqual(r["optimal"]["drop_count"], 1)
        self.assertEqual(r["optimal"]["optimal_count"], 2)
        self.assertEqual(r["optimal"]["anomaly_set"], ["R1"])  # 升序决胜
        self.assertEqual(r["optimal"]["necessary_anomalies"], [])
        self.assertEqual(r["receipts"]["R1"]["verdict"], "kept_in_some")
        self.assertEqual(r["receipts"]["R2"]["verdict"], "kept_in_some")

    def test_sync_inherited_lower_bound(self):
        r = analyze_file("sync_bound.json")
        self.assertEqual(r["receipts"]["R2"]["verdict"], "kept_in_none")
        self.assertEqual(r["optimal"]["anomaly_set"], ["R2"])
        w = r["optimal"]["witness"]
        pos = {ev: i for i, ev in enumerate(w["order"])}
        self.assertLess(pos["F1"], pos["S1"])
        self.assertLess(pos["S1"], pos["F3"])

    def test_fixed_conflict_infeasible(self):
        r = analyze_file("fixed_conflict.json")
        self.assertEqual(r["status"], "infeasible")
        self.assertIsNone(r["optimal"])
        self.assertEqual(r["conflict"]["fixed_conflicts"], ["R1", "R2"])
        for rep in r["receipts"].values():
            self.assertEqual(rep["verdict"], "kept_in_none")

    def test_fleet36_scale(self):
        r = analyze_file("fleet36.json")
        self.assertEqual(r["status"], "ok")
        self.assertEqual(len(r["receipts"]), 36)
        self.assertEqual(r["optimal"]["anomaly_set"], ["R25", "R34", "R36"])
        self.assertEqual(r["optimal"]["necessary_anomalies"],
                         ["R25", "R34", "R36"])
        self.assertEqual(r["optimal"]["drop_cost"], 8)
        self.assertEqual(r["optimal"]["drop_count"], 3)
        v = r["receipts"]
        self.assertEqual(v["R01"]["verdict"], "kept_in_all")
        self.assertEqual(v["R33"]["verdict"], "kept_in_some")
        self.assertEqual(v["R34"]["detail"], "HARD_INVALID_SIGNATURE")
        # 接收重试去重：R15/R16 同指纹同判定、同分组
        self.assertEqual(v["R15"]["group"], "F15")
        self.assertEqual(v["R15"]["verdict"], v["R16"]["verdict"])
        w = r["optimal"]["witness"]
        self.assertEqual(w["assignment"]["F15"], "I6")   # 无计数器实例
        self.assertEqual(w["assignment"]["F08"], "I4")   # 撤销后只能去新代次
        self.assertEqual(w["assignment"]["F09"], "I4")


class TestWitnessConsistency(unittest.TestCase):
    """见证必须给出一套自洽的全局事件顺序及副本分配。"""

    def check_witness(self, case_dict, witness):
        case = parse_case(json.dumps(case_dict))
        eng = Engine(case)
        order = witness["order"]
        pos = {ev: i for i, ev in enumerate(order)}
        self.assertEqual(len(pos), len(order))
        kept_groups = set(witness["assignment"])
        # 可信偏序被遵守（仅统计两端都保留的边）
        for a, b in case.trusted_order:
            ea = eng.gid_of_receipt.get(a, a)
            eb = eng.gid_of_receipt.get(b, b)
            if ea in kept_groups or ea in eng.static_nodes:
                if eb in kept_groups or eb in eng.static_nodes:
                    self.assertLess(pos[ea], pos[eb], (a, b))
        # 每实例正计数沿事件序严格上升
        counters = {}
        for gid, iid in witness["assignment"].items():
            g = eng.by_gid[gid]
            if g.counter > 0:
                counters.setdefault(iid, []).append((pos[gid], g.counter))
        for iid, lst in counters.items():
            lst.sort()
            vals = [c for _, c in lst]
            self.assertEqual(vals, sorted(vals))
            self.assertEqual(len(set(vals)), len(vals))
        # 分配均在候选集合内
        for gid, iid in witness["assignment"].items():
            self.assertIn(iid, eng.by_gid[gid].candidates)
        # 同步继承下界
        for s in eng.syncs.values():
            if s.parent_gid in kept_groups and \
                    witness["assignment"][s.parent_gid] == s.parent:
                pc = eng.by_gid[s.parent_gid].counter
                for gid, iid in witness["assignment"].items():
                    if iid == s.child:
                        self.assertGreater(eng.by_gid[gid].counter, pc)
        # 撤销节点之前
        for vid, rev in case.revocations.items():
            for gid, iid in witness["assignment"].items():
                if iid == rev.instance:
                    self.assertLess(pos[gid], pos[vid])

    def test_witnesses_of_showcase_cases(self):
        for name in ("reordered_inbox", "shared_counter_clones",
                     "generation_mixup", "dependent_verdict", "tied_optima",
                     "sync_bound", "fleet36"):
            case_dict = json.loads((CASES / f"{name}.json").read_text("utf-8"))
            r = analyze_dict(case_dict)
            self.assertEqual(r["status"], "ok", name)
            self.check_witness(case_dict, r["optimal"]["witness"])


class TestTargetedRules(unittest.TestCase):
    """针对单条业务规则的程序化用例。"""

    def test_retry_dedup_by_fingerprint(self):
        # 同一登录的接收重试以原请求指纹去重：两条回执算一次事件
        case = {
            "case": "dedup",
            "instances": [BASE_INSTANCE],
            "receipts": [
                receipt("R1", fp="FX", counter=3, fixed=True, recv_seq=4),
                receipt("R2", fp="FX", counter=3, fixed=True, recv_seq=7),
                receipt("R3", fp="F3", counter=3),  # 同计数另一条：冲突
            ],
        }
        r = analyze_dict(case)
        self.assertEqual(r["receipts"]["R1"]["verdict"], "kept_in_all")
        self.assertEqual(r["receipts"]["R2"]["verdict"], "kept_in_all")
        self.assertEqual(r["receipts"]["R3"]["verdict"], "kept_in_none")
        self.assertEqual(r["optimal"]["anomaly_set"], ["R3"])
        # 去重组只算一次计数事件，否则 FX 自身就会同计数冲突
        w = r["optimal"]["witness"]
        self.assertEqual(w["assignment"], {"FX": "I1"})
        self.assertEqual(w["kept"], ["R1", "R2"])

    def test_incomplete_sync_dependency(self):
        # 未完成的同步依赖：父回执被剔除后，继承下界不再成立
        case = {
            "case": "sync_incomplete",
            "instances": [
                BASE_INSTANCE,
                {"id": "I2", "copy": "C2", "generation": "G1",
                 "counterless": False},
            ],
            "receipts": [
                receipt("R1", counter=7, candidates=["I1"], cost=10),
                receipt("R2", counter=5, candidates=["I2"], cost=1),
            ],
            "syncs": [{"id": "S1", "child": "I2", "parent": "I1",
                       "parent_receipt": "R1"}],
        }
        r = analyze_dict(case)
        # R1 在则下界 7 生效，R2(5) 违规；剔除 R1 代价更高，最优仍剔 R2
        self.assertEqual(r["optimal"]["anomaly_set"], ["R2"])
        self.assertEqual(r["optimal"]["necessary_anomalies"], ["R2"])
        # 但 R2 并非无可行恢复能保留：存在剔除 R1 的恢复保住 R2
        self.assertEqual(r["receipts"]["R2"]["verdict"], "kept_in_some")
        self.assertEqual(r["receipts"]["R1"]["verdict"], "kept_in_some")

    def test_counterless_rules(self):
        case = {
            "case": "counterless",
            "instances": [
                BASE_INSTANCE,
                {"id": "I2", "copy": "C2", "generation": "G1",
                 "counterless": True},
            ],
            "receipts": [
                receipt("R1", counter=0, candidates=["I1"]),   # 零计数去错实例
                receipt("R2", counter=0, candidates=["I2"], fixed=True),
                receipt("R3", counter=0, candidates=["I2"], fixed=True),
                receipt("R4", counter=5, candidates=["I2"]),   # 无计数器出正计数
            ],
        }
        r = analyze_dict(case)
        self.assertEqual(r["receipts"]["R1"]["verdict"], "kept_in_none")
        self.assertEqual(r["receipts"]["R1"]["detail"], "NO_CANDIDATE")
        self.assertEqual(r["receipts"]["R2"]["verdict"], "kept_in_all")
        self.assertEqual(r["receipts"]["R3"]["verdict"], "kept_in_all")
        self.assertEqual(r["receipts"]["R4"]["verdict"], "kept_in_none")
        self.assertEqual(r["optimal"]["anomaly_set"], ["R1", "R4"])

    def test_revocation_cutoff(self):
        case = {
            "case": "revoke",
            "instances": [BASE_INSTANCE],
            "receipts": [
                receipt("R1", counter=1, fixed=True, window=[1, 5]),
                receipt("R2", counter=2, window=[6, 10]),
            ],
            "revocations": [{"id": "V1", "instance": "I1"}],
            "trusted_order": [["R1", "V1"], ["V1", "R2"]],
        }
        r = analyze_dict(case)
        # R2 跨过撤销节点后不能再用该副本
        self.assertEqual(r["receipts"]["R2"]["verdict"], "kept_in_none")
        self.assertEqual(r["optimal"]["anomaly_set"], ["R2"])

    def test_hard_invalid_cannot_be_repaired(self):
        # 缺失签名/非法挑战绑定不可用任何排序补救
        case = {
            "case": "hard_invalid",
            "instances": [BASE_INSTANCE],
            "receipts": [
                receipt("R1", counter=1, signature_ok=False),
                receipt("R2", counter=1, challenge_ok=False),
                receipt("R3", counter=1, fixed=True),
            ],
        }
        r = analyze_dict(case)
        self.assertEqual(r["receipts"]["R1"]["detail"], "HARD_INVALID_SIGNATURE")
        self.assertEqual(r["receipts"]["R2"]["detail"], "HARD_INVALID_CHALLENGE")
        self.assertEqual(r["receipts"]["R3"]["verdict"], "kept_in_all")
        self.assertEqual(r["optimal"]["anomaly_set"], ["R1", "R2"])
        self.assertEqual(r["optimal"]["necessary_anomalies"], ["R1", "R2"])

    def test_fixed_hard_invalid_singleton_conflict(self):
        case = {
            "case": "fixed_bad",
            "instances": [BASE_INSTANCE],
            "receipts": [
                receipt("R1", counter=1, signature_ok=False, fixed=True),
                receipt("R2", counter=1, fixed=True),
            ],
        }
        r = analyze_dict(case)
        self.assertEqual(r["status"], "infeasible")
        self.assertEqual(r["conflict"]["fixed_conflicts"], ["R1"])


class TestBruteForceCrossCheck(unittest.TestCase):
    """与独立穷举器核对：小规模案例 + 随机案例。"""

    def compare(self, case_dict_or_case):
        if isinstance(case_dict_or_case, dict):
            case = parse_case(json.dumps(case_dict_or_case))
        else:
            case = case_dict_or_case
        eng = Engine(case).analyze()
        bru = brute_analyze(case)
        self.assertEqual(eng["status"], bru["status"])
        for rid, rep in eng["receipts"].items():
            self.assertEqual(rep["verdict"], bru["verdicts"][rid],
                             f"{rid}: {rep['verdict']} != {bru['verdicts'][rid]}")
        if eng["status"] == "ok":
            o, b = eng["optimal"], bru["optimal"]
            self.assertEqual(o["drop_cost"], b["drop_cost"])
            self.assertEqual(o["drop_count"], b["drop_count"])
            self.assertEqual(o["anomaly_set"], b["anomaly_set"])
            self.assertEqual(o["necessary_anomalies"], b["necessary_anomalies"])
            self.assertEqual(o["optimal_count"], b["optimal_count"])

    def test_small_case_files(self):
        for name in ("reordered_inbox", "shared_counter_clones",
                     "generation_mixup", "dependent_verdict", "tied_optima",
                     "sync_bound", "fixed_conflict"):
            self.compare(load_case(f"{name}.json"))

    def test_random_cases(self):
        rng = random.Random(20261122)
        for trial in range(150):
            self.compare(self._random_case(rng), )

    def _random_case(self, rng):
        ninst = rng.randint(2, 3)
        insts = []
        for i in range(ninst):
            insts.append({
                "id": f"I{i}",
                "copy": f"C{rng.randint(0, 1)}",
                "generation": "G1",
                "counterless": rng.random() < 0.2,
            })
        iids = [i["id"] for i in insts]
        ngroups = rng.randint(3, 6)
        receipts = []
        for j in range(ngroups):
            r = {
                "id": f"R{j}",
                "fingerprint": f"F{j}",
                "counter": rng.randint(0, 5),
                "signature_ok": rng.random() > 0.1,
                "challenge_ok": rng.random() > 0.05,
                "candidates": sorted(rng.sample(iids, rng.randint(1, 2))),
                "fixed": rng.random() < 0.3,
                "cost": rng.randint(1, 3),
            }
            if rng.random() < 0.4:
                lo = rng.randint(0, 8)
                r["window"] = [lo, lo + rng.randint(0, 5)]
            receipts.append(r)
        ids = [f"R{j}" for j in range(ngroups)]
        perm = ids[:]
        rng.shuffle(perm)
        edges = []
        for a in range(len(perm)):
            for b in range(a + 1, len(perm)):
                if rng.random() < 0.15:
                    edges.append([perm[a], perm[b]])
        return {"case": "rand", "instances": insts, "receipts": receipts,
                "trusted_order": edges}


class TestFormatErrors(unittest.TestCase):
    """格式问题必须报告字段路径和错误码。"""

    def expect_error(self, mutate, path, code):
        case = {
            "case": "fmt",
            "instances": [BASE_INSTANCE],
            "receipts": [receipt("R1", counter=1)],
        }
        mutate(case)
        try:
            parse_case(json.dumps(case))
        except FormatError as fe:
            pairs = [(e["path"], e["code"]) for e in fe.errors]
            self.assertIn((path, code), pairs)
            return
        self.fail(f"expected FormatError ({path}, {code})")

    def test_counter_type(self):
        self.expect_error(
            lambda c: c["receipts"][0].update(counter="3"),
            "$.receipts[0].counter", "E_TYPE")

    def test_counter_range(self):
        self.expect_error(
            lambda c: c["receipts"][0].update(counter=-1),
            "$.receipts[0].counter", "E_RANGE")

    def test_unknown_candidate(self):
        self.expect_error(
            lambda c: c["receipts"][0].update(candidates=["IX"]),
            "$.receipts[0].candidates[0]", "E_UNKNOWN_REF")

    def test_evidence_xor(self):
        self.expect_error(
            lambda c: c["receipts"][0].update(copy="C1"),
            "$.receipts[0]", "E_EVIDENCE")

    def test_too_many_candidates(self):
        self.expect_error(
            lambda c: c["receipts"][0].update(candidates=["I1", "I1", "I1", "I1"]),
            "$.receipts[0].candidates", "E_RANGE")

    def test_duplicate_receipt_id(self):
        self.expect_error(
            lambda c: c["receipts"].append(receipt("R1", fp="F9")),
            "$.receipts[1].id", "E_DUP_ID")

    def test_trusted_self_via_dedup(self):
        def mutate(c):
            c["receipts"].append(receipt("R2", fp="FR1"))  # 与 R1 同指纹
            c["trusted_order"] = [["R1", "R2"]]
        self.expect_error(mutate, "$.trusted_order[0]", "E_TRUSTED_SELF")

    def test_window_inverted(self):
        self.expect_error(
            lambda c: c["receipts"][0].update(window=[5, 1]),
            "$.receipts[0].window", "E_RANGE")

    def test_bad_json(self):
        try:
            parse_case("{not json")
        except FormatError as fe:
            self.assertEqual(fe.errors[0]["code"], "E_JSON")
            self.assertEqual(fe.errors[0]["path"], "$")
            return
        self.fail("expected FormatError")


class TestCli(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "passkey_audit", *args],
            cwd=ROOT, capture_output=True)

    def test_cli_ok_and_deterministic(self):
        p1 = self.run_cli("cases/fleet36.json")
        p2 = self.run_cli("cases/fleet36.json")
        self.assertEqual(p1.returncode, 0, p1.stderr.decode("utf-8", "replace"))
        self.assertEqual(p1.stdout, p2.stdout)  # 输出确定
        report = json.loads(p1.stdout.decode("utf-8"))
        self.assertEqual(report["schema"], "passkey-audit/1")
        self.assertEqual(report["status"], "ok")

    def test_cli_infeasible_exit_code(self):
        p = self.run_cli("cases/fixed_conflict.json")
        self.assertEqual(p.returncode, 1)
        report = json.loads(p.stdout.decode("utf-8"))
        self.assertEqual(report["status"], "infeasible")

    def test_cli_format_error(self):
        bad = {"case": "bad", "instances": [BASE_INSTANCE],
               "receipts": [receipt("R1", counter=-2)]}
        with tempfile.NamedTemporaryFile(
                "w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump(bad, fh)
            path = fh.name
        try:
            p = self.run_cli(path)
        finally:
            Path(path).unlink()
        self.assertEqual(p.returncode, 2)
        report = json.loads(p.stdout.decode("utf-8"))
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["errors"][0]["path"], "$.receipts[0].counter")
        self.assertEqual(report["errors"][0]["code"], "E_RANGE")


if __name__ == "__main__":
    unittest.main()
