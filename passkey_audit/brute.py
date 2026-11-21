"""小规模独立穷举核对器。

与 :mod:`passkey_audit.engine` 的带回溯剪枝搜索完全独立：这里直接枚举
「保留子集 × 副本分配」的全部组合，再逐一检查全部约束。仅适用于小规模
输入（组数与候选数都很小），供测试交叉核对引擎结果。
"""
from __future__ import annotations

from itertools import combinations, product


def _groups(case):
    """独立重建去重分组（规则与 README 一致）。"""
    by_fp = {}
    for r in case.receipts:
        by_fp.setdefault(r.fingerprint, []).append(r)
    copies = {}
    for inst in case.instances.values():
        copies.setdefault(inst.copy, set()).add(inst.iid)
    out = []
    for fp in sorted(by_fp):
        rs = by_fp[fp]
        ok = True
        if not all(r.signature_ok for r in rs):
            ok = False
        if not all(r.challenge_ok for r in rs):
            ok = False
        cs = {r.counter for r in rs}
        counter = next(iter(cs)) if len(cs) == 1 else None
        if counter is None:
            ok = False
        cand = None
        for r in rs:
            ids = set(copies[r.copy]) if r.copy is not None else set(r.candidates)
            cand = ids if cand is None else cand & ids
        lo = hi = None
        for r in rs:
            if r.window is not None:
                lo = r.window[0] if lo is None else max(lo, r.window[0])
                hi = r.window[1] if hi is None else min(hi, r.window[1])
        if lo is not None and lo > hi:
            ok = False
        if counter is not None:
            if counter == 0:
                cand = {i for i in cand if case.instances[i].counterless}
            else:
                cand = {i for i in cand if not case.instances[i].counterless}
        if not cand:
            ok = False
        out.append({
            "gid": fp,
            "members": sorted(r.rid for r in rs),
            "counter": counter,
            "fixed": any(r.fixed for r in rs),
            "cost": sum(r.cost for r in rs),
            "candidates": sorted(cand),
            "keepable": ok,
            "window": (lo, hi) if lo is not None else None,
        })
    return out


def _check(case, groups, kept, assign):
    """检查一个完整的（保留集, 分配）方案；可行返回 (order, times)。"""
    gc = {g["gid"]: g for g in groups}
    gid_of = {}
    for g in groups:
        for rid in g["members"]:
            gid_of[rid] = g["gid"]
    nodes = set(kept) | set(case.syncs) | set(case.revocations)
    edges = []
    for a, b in case.trusted_order:
        ea, eb = gid_of.get(a, a), gid_of.get(b, b)
        if ea in nodes and eb in nodes:
            edges.append((ea, eb))
    by_inst = {}
    for gid in kept:
        by_inst.setdefault(assign[gid], []).append(gid)
    for iid, gs in by_inst.items():
        for x, y in combinations(sorted(gs), 2):
            cx, cy = gc[x]["counter"], gc[y]["counter"]
            if cx == cy:
                if cx != 0:
                    return None
            elif cx < cy:
                edges.append((x, y))
            else:
                edges.append((y, x))
    for v in case.revocations.values():
        for gid in by_inst.get(v.instance, ()):
            edges.append((gid, v.vid))
    for s in case.syncs.values():
        pgid = gid_of[s.parent_receipt]
        anchored = pgid in kept and assign[pgid] == s.parent
        if anchored:
            edges.append((pgid, s.sid))
            pc = gc[pgid]["counter"]
            for gid in by_inst.get(s.child, ()):
                if not gc[gid]["counter"] > pc:
                    return None
        for gid in by_inst.get(s.child, ()):
            edges.append((s.sid, gid))
    # 拓扑（Kahn，无堆——独立性优先于确定性）
    indeg = {n: 0 for n in nodes}
    adj = {n: [] for n in nodes}
    for a, b in edges:
        adj[a].append(b)
        indeg[b] += 1
    queue = [n for n in nodes if indeg[n] == 0]
    order = []
    while queue:
        n = queue.pop()
        order.append(n)
        for m in adj[n]:
            indeg[m] -= 1
            if indeg[m] == 0:
                queue.append(m)
    if len(order) != len(nodes):
        return None
    # 观察窗口（Bellman-Ford 式松弛）
    dist = {}
    for n in nodes:
        w = gc[n]["window"] if n in gc else None
        dist[n] = w[0] if w is not None else 0
    changed = True
    for _ in range(len(nodes) + 1):
        if not changed:
            break
        changed = False
        for a, b in edges:
            if dist[b] < dist[a]:
                dist[b] = dist[a]
                changed = True
    if changed:
        return None
    for n in nodes:
        w = gc[n]["window"] if n in gc else None
        if w is not None and dist[n] > w[1]:
            return None
    return order, dist


def brute_analyze(case):
    """穷举所有可行恢复，返回与引擎报告可比的摘要。"""
    groups = _groups(case)
    droppable = [g for g in groups if not g["fixed"]]
    feasible = []  # (dropped_gid_frozenset, cost, count, dropped_rid_tuple)
    n = len(droppable)
    for mask in range(1 << n):
        dropped = {droppable[i]["gid"] for i in range(n) if mask >> i & 1}
        kept = [g for g in groups if g["gid"] not in dropped]
        if any(not g["keepable"] for g in kept):
            continue
        for combo in product(*(g["candidates"] for g in kept)):
            assign = {g["gid"]: iid for g, iid in zip(kept, combo)}
            if _check(case, groups, [g["gid"] for g in kept], assign) is None:
                continue
            cost = sum(g["cost"] for g in droppable if g["gid"] in dropped)
            count = sum(len(g["members"]) for g in droppable
                        if g["gid"] in dropped)
            rids = tuple(sorted(
                rid for g in droppable if g["gid"] in dropped
                for rid in g["members"]))
            feasible.append((frozenset(dropped), cost, count, rids))

    verdicts = {}
    for g in groups:
        kept_some = any(g["gid"] not in f[0] for f in feasible)
        kept_all = kept_some and all(g["gid"] not in f[0] for f in feasible)
        v = ("kept_in_all" if kept_all
             else "kept_in_some" if kept_some else "kept_in_none")
        for rid in g["members"]:
            verdicts[rid] = v

    if not feasible:
        return {"status": "infeasible", "verdicts": verdicts, "optimal": None}
    best = min((f[1], f[2]) for f in feasible)
    optima = [f for f in feasible if (f[1], f[2]) == best]
    anomaly_set = min(f[3] for f in optima)
    common = set(optima[0][3])
    for f in optima[1:]:
        common &= set(f[3])
    return {
        "status": "ok",
        "verdicts": verdicts,
        "optimal": {
            "drop_cost": best[0],
            "drop_count": best[1],
            "anomaly_set": list(anomaly_set),
            "necessary_anomalies": sorted(common),
            "optimal_count": len({f[3] for f in optima}),
        },
    }
