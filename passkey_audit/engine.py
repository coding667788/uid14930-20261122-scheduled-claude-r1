"""约束求解引擎：按业务规则对登录回执做离线取证裁定。

模型要点（详见 README）：

- 同一请求指纹的回执去重为一个逻辑登录事件（组），整组同留同弃；
- 每个被保留的组必须分配到候选副本实例之一；
- 同一实例上的正计数沿恢复出的全局事件序严格上升（零计数只允许出现在
  登记为无计数器的实例上，且不参与排序约束）；
- 可信偏序、观察窗口、同步（继承下界）、撤销节点共同约束全局事件序；
  服务器接收顺序不参与可行性判定，仅在见证中作为旁证给出；
- 固定（fixed）回执必须保留，其余回执可因观测错误剔除并计入代价。
"""
from __future__ import annotations

import heapq
from dataclasses import dataclass

# ---- 回执判定详情码 ----
FORCED = "FORCED"                            # 被所有可行恢复保留
CONTINGENT = "CONTINGENT"                    # 只在部分可行恢复中保留
CONFLICTS_WITH_FIXED = "CONFLICTS_WITH_FIXED"  # 与固定记录/可信约束冲突
NO_FEASIBLE_RECOVERY = "NO_FEASIBLE_RECOVERY"  # 输入整体无可行解释

# 组自身不可保留的原因码
HARD_INVALID_SIGNATURE = "HARD_INVALID_SIGNATURE"
HARD_INVALID_CHALLENGE = "HARD_INVALID_CHALLENGE"
GROUP_COUNTER_MISMATCH = "GROUP_COUNTER_MISMATCH"
GROUP_WINDOW_EMPTY = "GROUP_WINDOW_EMPTY"
NO_CANDIDATE = "NO_CANDIDATE"

OPTIMA_CAP = 10000  # 最优解释计数上限（防止病态输入下计数爆炸）


@dataclass
class Group:
    """同一请求指纹的去重分组：一次逻辑登录。"""

    gid: str            # 即请求指纹
    members: list       # 组内回执 id（升序）
    counter: int        # 组内一致计数（不一致时 keepable=False）
    fixed: bool
    cost: int           # 整组剔除代价 = 成员代价之和
    window: tuple | None
    candidates: list    # 候选实例 id（升序）
    keepable: bool
    reason: str | None  # 不可保留时的原因码
    recv_seq: int | None


@dataclass
class Solution:
    kept_gids: list
    dropped_gids: list
    assignment: dict    # gid -> 实例 id
    order: list         # 全局事件序（事件 id 列表）
    times: dict         # 事件 -> 逻辑时刻
    cost: int
    count: int


def build_groups(case) -> list:
    """按请求指纹去重分组，并计算每组的可保留性与候选实例。"""
    by_fp = {}
    for r in case.receipts:
        by_fp.setdefault(r.fingerprint, []).append(r)
    inst_by_copy = {}
    for inst in case.instances.values():
        inst_by_copy.setdefault(inst.copy, []).append(inst.iid)

    groups = []
    for fp in sorted(by_fp):
        rs = sorted(by_fp[fp], key=lambda r: r.rid)
        members = [r.rid for r in rs]
        counters = {r.counter for r in rs}
        counter = next(iter(counters)) if len(counters) == 1 else None
        sig_ok = all(r.signature_ok for r in rs)
        chal_ok = all(r.challenge_ok for r in rs)
        fixed = any(r.fixed for r in rs)
        cost = sum(r.cost for r in rs)

        lo = hi = None
        for r in rs:
            if r.window is not None:
                lo = r.window[0] if lo is None else max(lo, r.window[0])
                hi = r.window[1] if hi is None else min(hi, r.window[1])
        window = None if lo is None else (lo, hi)

        cand = None
        for r in rs:
            if r.copy is not None:
                ids = set(inst_by_copy[r.copy])
            else:
                ids = set(r.candidates)
            cand = ids if cand is None else cand & ids

        reason = None
        if not sig_ok:
            reason = HARD_INVALID_SIGNATURE
        elif not chal_ok:
            reason = HARD_INVALID_CHALLENGE
        elif counter is None:
            reason = GROUP_COUNTER_MISMATCH
        elif window is not None and window[0] > window[1]:
            reason = GROUP_WINDOW_EMPTY
        if reason is None:
            # 计数为零只许可出现在登记为无计数器的实例上；
            # 无计数器实例也不能出具正计数。
            if counter == 0:
                cand = {i for i in cand if case.instances[i].counterless}
            else:
                cand = {i for i in cand if not case.instances[i].counterless}
            if not cand:
                reason = NO_CANDIDATE

        recv_seqs = [r.recv_seq for r in rs if r.recv_seq is not None]
        groups.append(Group(
            gid=fp,
            members=members,
            counter=counter if counter is not None else -1,
            fixed=fixed,
            cost=cost,
            window=window,
            candidates=sorted(cand) if cand else [],
            keepable=reason is None,
            reason=reason,
            recv_seq=min(recv_seqs) if recv_seqs else None,
        ))
    return groups


def _topo(nodes, edges):
    """Kahn 拓扑排序（堆按事件 id 字典序，保证确定性）；有环返回 None。"""
    indeg = {n: 0 for n in nodes}
    adj = {n: [] for n in nodes}
    for a, b in edges:
        if a in indeg and b in indeg:
            adj[a].append(b)
            indeg[b] += 1
    heap = [n for n in nodes if indeg[n] == 0]
    heapq.heapify(heap)
    out = []
    while heap:
        n = heapq.heappop(heap)
        out.append(n)
        for m in adj[n]:
            indeg[m] -= 1
            if indeg[m] == 0:
                heapq.heappush(heap, m)
    return out if len(out) == len(nodes) else None


def _feasible_times(nodes, edges, windows):
    """差分约束可行性：t_v >= t_u（每条边 u->v），lo <= t <= hi。

    可行时返回一组见证时刻（最长路赋值），否则返回 None。
    """
    dist = {}
    for n in nodes:
        w = windows.get(n)
        dist[n] = w[0] if w is not None else 0
    changed = True
    for _ in range(len(nodes) + 1):
        if not changed:
            break
        changed = False
        for a, b in edges:
            if a in dist and b in dist and dist[b] < dist[a]:
                dist[b] = dist[a]
                changed = True
    if changed:
        return None
    for n in nodes:
        w = windows.get(n)
        if w is not None and dist[n] > w[1]:
            return None
    return dist


class _Ctx:
    """一次搜索的可变状态。"""

    def __init__(self, mode, must_keep, must_drop,
                 budget_cost, budget_count, ignore_fixed):
        self.mode = mode              # 'any' | 'opt'
        self.must_keep = must_keep
        self.must_drop = must_drop
        self.budget_cost = budget_cost
        self.budget_count = budget_count
        self.ignore_fixed = ignore_fixed
        self.assign = {}              # gid -> iid
        self.active = set()           # 已保留的 gid
        self.by_instance = {}         # iid -> [(gid, counter)]
        self.edges = []               # 动态边
        self.result = None            # any 模式：首个可行解
        self.best = None              # opt 模式：(cost, count)
        self.optima = set()           # opt 模式：最优剔除集（回执 id 元组）
        self.lex_min = None
        self.witness = None
        self.capped = False

    def drop_ok(self, cost, count):
        if self.mode == "opt":
            return self.best is None or (cost, count) <= self.best
        if self.budget_cost is not None and cost > self.budget_cost:
            return False
        if self.budget_count is not None and count > self.budget_count:
            return False
        return True


class Engine:
    def __init__(self, case):
        self.case = case
        self.groups = build_groups(case)
        self.by_gid = {g.gid: g for g in self.groups}
        self.gid_of_receipt = {}
        for g in self.groups:
            for rid in g.members:
                self.gid_of_receipt[rid] = g.gid

        # 同步记录：父回执映射到去重组
        self.syncs = {}
        for s in case.syncs.values():
            self.syncs[s.sid] = type("SyncNode", (), {
                "sid": s.sid, "child": s.child, "parent": s.parent,
                "parent_gid": self.gid_of_receipt[s.parent_receipt],
            })()
        self.revs = dict(case.revocations)
        self.static_nodes = set(self.syncs) | set(self.revs)

        # 可信偏序：回执 id 归并到组
        self.trusted_edges = []
        for a, b in case.trusted_order:
            self.trusted_edges.append(
                (self.gid_of_receipt.get(a, a), self.gid_of_receipt.get(b, b)))
        self.trusted_by_node = {}
        for e in self.trusted_edges:
            self.trusted_by_node.setdefault(e[0], []).append(e)
            self.trusted_by_node.setdefault(e[1], []).append(e)

        self.revs_by_instance = {}
        for v in case.revocations.values():
            self.revs_by_instance.setdefault(v.instance, []).append(v.vid)

        self.windows = {g.gid: g.window for g in self.groups if g.window}

        # 搜索顺序：选项最少者优先（确定性）
        def nopts(g):
            n = len(g.candidates) if g.keepable else 0
            if not g.fixed:
                n += 1
            return (n, g.gid)
        self.seq = sorted(self.groups, key=nopts)

    # ------------------------------------------------------------------ 搜索

    def solve(self, must_keep=frozenset(), must_drop=frozenset(),
              budget_cost=None, budget_count=None, ignore_fixed=False):
        """求任一可行恢复；无解返回 None。"""
        must_keep = set(must_keep)
        must_drop = set(must_drop)
        if must_keep & must_drop:
            return None
        for gid in must_keep:
            if not self.by_gid[gid].keepable:
                return None
        if not ignore_fixed:
            for g in self.groups:
                if g.fixed and not g.keepable:
                    return None
        ctx = _Ctx("any", must_keep, must_drop, budget_cost, budget_count,
                   ignore_fixed)
        self._rec(ctx, 0, 0, 0, [])
        return ctx.result

    def solve_optimal(self):
        """求最小异常集；无可行解释返回 None。"""
        ctx = _Ctx("opt", set(), set(), None, None, False)
        self._rec(ctx, 0, 0, 0, [])
        if ctx.best is None:
            return None
        return ctx

    def _rec(self, ctx, i, cost, count, dropped):
        if ctx.mode == "any" and ctx.result is not None:
            return
        if ctx.mode == "opt" and ctx.best is not None \
                and (cost, count) > ctx.best:
            return
        if i == len(self.seq):
            sol = self._leaf(ctx, cost, count, dropped)
            if sol is None:
                return
            if ctx.mode == "any":
                ctx.result = sol
            else:
                self._record_opt(ctx, sol)
            return
        g = self.seq[i]
        if g.keepable and g.gid not in ctx.must_drop:
            for iid in g.candidates:
                added = self._try_assign(ctx, g, iid)
                if added is not None:
                    self._rec(ctx, i + 1, cost, count, dropped)
                    self._unassign(ctx, g, iid, added)
                if ctx.mode == "any" and ctx.result is not None:
                    return
        can_drop = g.gid not in ctx.must_keep and (ctx.ignore_fixed or not g.fixed)
        if can_drop:
            c2 = cost + g.cost
            n2 = count + len(g.members)
            if ctx.drop_ok(c2, n2):
                self._rec(ctx, i + 1, c2, n2, dropped + [g.gid])

    def _try_assign(self, ctx, g, iid):
        """尝试把组 g 分配到实例 iid；可行返回新增边列表，否则 None。"""
        gid = g.gid
        added = []
        # 可信偏序边（对端已激活或为静态事件）
        for a, b in self.trusted_by_node.get(gid, ()):
            other = b if a == gid else a
            if other in ctx.active or other in self.static_nodes:
                added.append((a, b))
        # 计数边：同实例正计数沿事件序严格上升
        for hg, hc in ctx.by_instance.get(iid, ()):
            if hc == g.counter:
                if g.counter != 0:
                    return None  # 同实例同正计数：无法严格上升
            elif hc < g.counter:
                added.append((hg, gid))
            else:
                added.append((gid, hg))
        # 撤销节点：该实例上的回执必须位于撤销之前
        for vid in self.revs_by_instance.get(iid, ()):
            added.append((gid, vid))
        # 同步边与继承下界
        for s in self.syncs.values():
            if s.child == iid:
                added.append((s.sid, gid))
                p = s.parent_gid
                if p in ctx.assign and ctx.assign[p] == s.parent:
                    if not g.counter > self.by_gid[p].counter:
                        return None
            if gid == s.parent_gid and iid == s.parent:
                added.append((gid, s.sid))
                for hg, hc in ctx.by_instance.get(s.child, ()):
                    if not hc > g.counter:
                        return None
        edges = ctx.edges + added
        nodes = ctx.active | self.static_nodes | {gid}
        if _topo(nodes, edges) is None:
            return None
        if _feasible_times(nodes, edges, self.windows) is None:
            return None
        # 提交
        ctx.assign[gid] = iid
        ctx.active.add(gid)
        ctx.by_instance.setdefault(iid, []).append((gid, g.counter))
        ctx.edges.extend(added)
        return added

    def _unassign(self, ctx, g, iid, added):
        gid = g.gid
        del ctx.assign[gid]
        ctx.active.discard(gid)
        lst = ctx.by_instance[iid]
        for k in range(len(lst) - 1, -1, -1):
            if lst[k][0] == gid:
                del lst[k]
                break
        if not lst:
            del ctx.by_instance[iid]
        del ctx.edges[len(ctx.edges) - len(added):]

    def _leaf(self, ctx, cost, count, dropped):
        # 同步继承下界的完整复查（父回执保留且确在父实例上时下界才生效；
        # 否则该同步依赖视为未完成，下界不成立）
        for s in self.syncs.values():
            p = s.parent_gid
            if p in ctx.assign and ctx.assign[p] == s.parent:
                pc = self.by_gid[p].counter
                for hg, hc in ctx.by_instance.get(s.child, ()):
                    if not hc > pc:
                        return None
        nodes = ctx.active | self.static_nodes
        order = _topo(nodes, ctx.edges)
        if order is None:
            return None
        times = _feasible_times(nodes, ctx.edges, self.windows)
        if times is None:
            return None
        return Solution(sorted(ctx.active), sorted(dropped), dict(ctx.assign),
                        order, times, cost, count)

    def _record_opt(self, ctx, sol):
        key = (sol.cost, sol.count)
        rids = tuple(sorted(
            rid for gid in sol.dropped_gids for rid in self.by_gid[gid].members))
        if ctx.best is None or key < ctx.best:
            ctx.best = key
            ctx.optima = {rids}
            ctx.lex_min = rids
            ctx.witness = sol
            ctx.capped = False
        elif key == ctx.best:
            if len(ctx.optima) < OPTIMA_CAP:
                ctx.optima.add(rids)
            else:
                ctx.capped = True
            if rids < ctx.lex_min:
                ctx.lex_min = rids
                ctx.witness = sol

    # ------------------------------------------------------------------ 报告

    def conflict_core(self):
        """固定记录冲突：求一个子集极小的不可行固定组集合，返回回执 id。"""
        core = sorted(g.gid for g in self.groups if g.fixed)
        for gid in list(core):
            trial = [x for x in core if x != gid]
            if self.solve(must_keep=set(trial), ignore_fixed=True) is None:
                core = trial
        return sorted(rid for gid in core for rid in self.by_gid[gid].members)

    def witness_json(self, sol):
        kept_rids = sorted(
            rid for gid in sol.kept_gids for rid in self.by_gid[gid].members)
        dropped_rids = sorted(
            rid for gid in sol.dropped_gids for rid in self.by_gid[gid].members)
        # 服务器接收顺序仅作旁证：见证序与接收序是否一致
        seqs = []
        for ev in sol.order:
            g = self.by_gid.get(ev)
            if g is not None and g.recv_seq is not None:
                seqs.append(g.recv_seq)
        agrees = all(seqs[k] <= seqs[k + 1] for k in range(len(seqs) - 1))
        return {
            "kept": kept_rids,
            "dropped": dropped_rids,
            "assignment": {gid: sol.assignment[gid] for gid in sol.kept_gids},
            "order": list(sol.order),
            "times": {ev: sol.times[ev] for ev in sol.order},
            "recv_order_agrees": agrees,
        }

    def analyze(self):
        base = self.solve()
        receipts = {}
        if base is None:
            for g in self.groups:
                for rid in g.members:
                    receipts[rid] = {
                        "verdict": "kept_in_none",
                        "group": g.gid,
                        "detail": NO_FEASIBLE_RECOVERY,
                        "witness": None,
                    }
            return {
                "status": "infeasible",
                "receipts": receipts,
                "optimal": None,
                "conflict": {"fixed_conflicts": self.conflict_core()},
            }

        for g in self.groups:
            kept_some = self.solve(must_keep={g.gid})
            if kept_some is None:
                verdict = "kept_in_none"
                detail = g.reason or CONFLICTS_WITH_FIXED
                witness = None
            else:
                witness = self.witness_json(kept_some)
                if g.fixed or self.solve(must_drop={g.gid}) is None:
                    verdict = "kept_in_all"
                    detail = FORCED
                else:
                    verdict = "kept_in_some"
                    detail = CONTINGENT
            for rid in g.members:
                receipts[rid] = {
                    "verdict": verdict,
                    "group": g.gid,
                    "detail": detail,
                    "witness": witness,
                }

        opt = self.solve_optimal()
        necessary = []
        for g in self.groups:
            if g.fixed:
                continue
            if self.solve(must_keep={g.gid},
                          budget_cost=opt.best[0],
                          budget_count=opt.best[1]) is None:
                necessary.extend(g.members)
        necessary.sort()
        optimal = {
            "drop_cost": opt.best[0],
            "drop_count": opt.best[1],
            "anomaly_set": list(opt.lex_min),
            "necessary_anomalies": necessary,
            "optimal_count": len(opt.optima),
            "optimal_count_capped": opt.capped,
            "witness": self.witness_json(opt.witness),
        }
        return {
            "status": "ok",
            "receipts": receipts,
            "optimal": optimal,
            "conflict": None,
        }
