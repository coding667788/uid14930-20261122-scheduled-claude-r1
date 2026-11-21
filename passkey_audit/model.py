"""输入解析与格式校验。

所有格式问题以 ``{"path": ..., "code": ..., "message": ...}`` 列表汇总在
:class:`FormatError` 中抛出；路径采用类 JSONPath 记法（如 ``$.receipts[3].counter``）。
"""
from __future__ import annotations

import json
from dataclasses import dataclass


class FormatError(Exception):
    """输入格式错误；``errors`` 为 [{path, code, message}, ...]。"""

    def __init__(self, errors):
        super().__init__("input format error(s)")
        self.errors = errors


@dataclass
class Instance:
    """副本实例：(副本 ID, 设备实例) 的二元组在输入中已展开为一个实例记录。"""

    iid: str
    copy: str
    generation: str
    counterless: bool = False


@dataclass
class Receipt:
    rid: str
    fingerprint: str
    counter: int
    signature_ok: bool
    challenge_ok: bool
    copy: str | None
    candidates: list | None
    fixed: bool
    cost: int
    recv_seq: int | None
    window: tuple | None


@dataclass
class Sync:
    sid: str
    child: str
    parent: str
    parent_receipt: str


@dataclass
class Revocation:
    vid: str
    instance: str


@dataclass
class Case:
    name: str
    instances: dict
    receipts: list
    syncs: dict
    revocations: dict
    trusted_order: list


def _err(errors, path, code, message):
    errors.append({"path": path, "code": code, "message": message})


def _is_str(x):
    return isinstance(x, str) and len(x) > 0


def _is_bool(x):
    return isinstance(x, bool)


def _is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def parse_case(text: str) -> Case:
    """解析并校验案件 JSON 文本；格式问题抛出 :class:`FormatError`。"""
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FormatError([{"path": "$", "code": "E_JSON",
                            "message": f"invalid JSON: {exc}"}])
    if not isinstance(raw, dict):
        raise FormatError([{"path": "$", "code": "E_SCHEMA",
                            "message": "top level must be a JSON object"}])

    errors = []
    name = raw.get("case", "")
    if not isinstance(name, str):
        _err(errors, "$.case", "E_TYPE", "case must be a string")
        name = ""

    instances, instances_ok = _parse_instances(raw, errors)
    receipts, receipts_ok = _parse_receipts(raw, errors, instances, instances_ok)
    rids = {r.rid for r in receipts}
    syncs, syncs_ok = _parse_syncs(raw, errors, instances, instances_ok,
                                   rids, receipts_ok)
    revocations, revs_ok = _parse_revocations(raw, errors, instances, instances_ok,
                                              rids, syncs)
    trusted = _parse_trusted(raw, errors, receipts, syncs, revocations,
                             instances_ok and receipts_ok and syncs_ok and revs_ok)

    if errors:
        raise FormatError(errors)
    return Case(name, instances, receipts, syncs, revocations, trusted)


def _parse_instances(raw, errors):
    instances = {}
    items = raw.get("instances")
    if not isinstance(items, list) or not items:
        _err(errors, "$.instances", "E_SCHEMA", "instances must be a non-empty array")
        return instances, False
    ok_all = True
    for i, item in enumerate(items):
        path = f"$.instances[{i}]"
        if not isinstance(item, dict):
            _err(errors, path, "E_TYPE", "instance must be an object")
            ok_all = False
            continue
        iid = item.get("id")
        copy = item.get("copy")
        gen = item.get("generation")
        cl = item.get("counterless", False)
        ok = True
        if not _is_str(iid):
            _err(errors, f"{path}.id", "E_TYPE", "id must be a non-empty string")
            ok = False
        elif iid in instances:
            _err(errors, f"{path}.id", "E_DUP_ID", f"duplicate instance id {iid!r}")
            ok = False
        if not _is_str(copy):
            _err(errors, f"{path}.copy", "E_TYPE", "copy must be a non-empty string")
            ok = False
        if not _is_str(gen):
            _err(errors, f"{path}.generation", "E_TYPE",
                 "generation must be a non-empty string")
            ok = False
        if not _is_bool(cl):
            _err(errors, f"{path}.counterless", "E_TYPE",
                 "counterless must be a boolean")
            ok = False
        if ok:
            instances[iid] = Instance(iid, copy, gen, cl)
        else:
            ok_all = False
    return instances, ok_all


def _parse_receipts(raw, errors, instances, instances_ok):
    receipts = []
    rids = set()
    items = raw.get("receipts")
    if not isinstance(items, list) or not items:
        _err(errors, "$.receipts", "E_SCHEMA", "receipts must be a non-empty array")
        return receipts, False
    copies = {inst.copy for inst in instances.values()}
    ok_all = True
    for i, item in enumerate(items):
        path = f"$.receipts[{i}]"
        if not isinstance(item, dict):
            _err(errors, path, "E_TYPE", "receipt must be an object")
            ok_all = False
            continue
        ok = True
        rid = item.get("id")
        if not _is_str(rid):
            _err(errors, f"{path}.id", "E_TYPE", "id must be a non-empty string")
            ok = False
        elif rid in rids:
            _err(errors, f"{path}.id", "E_DUP_ID", f"duplicate receipt id {rid!r}")
            ok = False
        fp = item.get("fingerprint")
        if not _is_str(fp):
            _err(errors, f"{path}.fingerprint", "E_TYPE",
                 "fingerprint must be a non-empty string")
            ok = False
        counter = item.get("counter")
        if not _is_int(counter):
            _err(errors, f"{path}.counter", "E_TYPE", "counter must be an integer")
            ok = False
        elif counter < 0:
            _err(errors, f"{path}.counter", "E_RANGE", "counter must be >= 0")
            ok = False
        sig = item.get("signature_ok")
        if not _is_bool(sig):
            _err(errors, f"{path}.signature_ok", "E_TYPE",
                 "signature_ok must be a boolean")
            ok = False
        chal = item.get("challenge_ok")
        if not _is_bool(chal):
            _err(errors, f"{path}.challenge_ok", "E_TYPE",
                 "challenge_ok must be a boolean")
            ok = False
        copy = item.get("copy")
        cand = item.get("candidates")
        if (copy is None) == (cand is None):
            _err(errors, path, "E_EVIDENCE",
                 "exactly one of 'copy' and 'candidates' must be given")
            ok = False
        if copy is not None:
            if not _is_str(copy):
                _err(errors, f"{path}.copy", "E_TYPE",
                     "copy must be a non-empty string")
                ok = False
            elif instances_ok and copy not in copies:
                _err(errors, f"{path}.copy", "E_UNKNOWN_REF",
                     f"unknown copy id {copy!r}")
                ok = False
        if cand is not None:
            if (not isinstance(cand, list) or not 1 <= len(cand) <= 3
                    or not all(_is_str(x) for x in cand)):
                _err(errors, f"{path}.candidates", "E_RANGE",
                     "candidates must be an array of 1..3 instance ids")
                ok = False
            elif len(set(cand)) != len(cand):
                _err(errors, f"{path}.candidates", "E_DUP_ID",
                     "duplicate candidate instance id")
                ok = False
            elif instances_ok:
                for j, x in enumerate(cand):
                    if x not in instances:
                        _err(errors, f"{path}.candidates[{j}]", "E_UNKNOWN_REF",
                             f"unknown instance id {x!r}")
                        ok = False
        fixed = item.get("fixed", False)
        if not _is_bool(fixed):
            _err(errors, f"{path}.fixed", "E_TYPE", "fixed must be a boolean")
            ok = False
        cost = item.get("cost", 1)
        if not _is_int(cost):
            _err(errors, f"{path}.cost", "E_TYPE", "cost must be an integer")
            ok = False
        elif cost < 0:
            _err(errors, f"{path}.cost", "E_RANGE", "cost must be >= 0")
            ok = False
        recv = item.get("recv_seq")
        if recv is not None and (not _is_int(recv) or recv < 0):
            _err(errors, f"{path}.recv_seq", "E_RANGE",
                 "recv_seq must be a non-negative integer")
            ok = False
        window = item.get("window")
        if window is not None:
            if (not isinstance(window, list) or len(window) != 2
                    or not all(_is_int(x) for x in window)):
                _err(errors, f"{path}.window", "E_TYPE",
                     "window must be [lo, hi] integers")
                ok = False
            elif window[0] > window[1]:
                _err(errors, f"{path}.window", "E_RANGE",
                     "window lower bound exceeds upper bound")
                ok = False
            else:
                window = (window[0], window[1])
        if ok:
            rids.add(rid)
            receipts.append(Receipt(rid, fp, counter, sig, chal, copy, cand,
                                    fixed, cost, recv, window))
        else:
            ok_all = False
    return receipts, ok_all


def _parse_syncs(raw, errors, instances, instances_ok, rids, receipts_ok):
    syncs = {}
    items = raw.get("syncs", [])
    if not isinstance(items, list):
        _err(errors, "$.syncs", "E_TYPE", "syncs must be an array")
        return syncs, False
    ok_all = True
    for i, item in enumerate(items):
        path = f"$.syncs[{i}]"
        if not isinstance(item, dict):
            _err(errors, path, "E_TYPE", "sync must be an object")
            ok_all = False
            continue
        ok = True
        sid = item.get("id")
        if not _is_str(sid):
            _err(errors, f"{path}.id", "E_TYPE", "id must be a non-empty string")
            ok = False
        elif sid in syncs or (receipts_ok and sid in rids):
            _err(errors, f"{path}.id", "E_DUP_ID", f"duplicate event id {sid!r}")
            ok = False
        child = item.get("child")
        parent = item.get("parent")
        prec = item.get("parent_receipt")
        for field, val in (("child", child), ("parent", parent)):
            if not _is_str(val):
                _err(errors, f"{path}.{field}", "E_TYPE",
                     f"{field} must be an instance id")
                ok = False
            elif instances_ok and val not in instances:
                _err(errors, f"{path}.{field}", "E_UNKNOWN_REF",
                     f"unknown instance id {val!r}")
                ok = False
        if ok and child == parent:
            _err(errors, path, "E_SEMANTIC", "sync child and parent must differ")
            ok = False
        if not _is_str(prec):
            _err(errors, f"{path}.parent_receipt", "E_TYPE",
                 "parent_receipt must be a receipt id")
            ok = False
        elif receipts_ok and prec not in rids:
            _err(errors, f"{path}.parent_receipt", "E_UNKNOWN_REF",
                 f"unknown receipt id {prec!r}")
            ok = False
        if ok:
            syncs[sid] = Sync(sid, child, parent, prec)
        else:
            ok_all = False
    return syncs, ok_all


def _parse_revocations(raw, errors, instances, instances_ok, rids, syncs):
    revocations = {}
    items = raw.get("revocations", [])
    if not isinstance(items, list):
        _err(errors, "$.revocations", "E_TYPE", "revocations must be an array")
        return revocations, False
    ok_all = True
    for i, item in enumerate(items):
        path = f"$.revocations[{i}]"
        if not isinstance(item, dict):
            _err(errors, path, "E_TYPE", "revocation must be an object")
            ok_all = False
            continue
        ok = True
        vid = item.get("id")
        if not _is_str(vid):
            _err(errors, f"{path}.id", "E_TYPE", "id must be a non-empty string")
            ok = False
        elif vid in revocations or vid in rids or vid in syncs:
            _err(errors, f"{path}.id", "E_DUP_ID", f"duplicate event id {vid!r}")
            ok = False
        inst = item.get("instance")
        if not _is_str(inst):
            _err(errors, f"{path}.instance", "E_TYPE",
                 "instance must be an instance id")
            ok = False
        elif instances_ok and inst not in instances:
            _err(errors, f"{path}.instance", "E_UNKNOWN_REF",
                 f"unknown instance id {inst!r}")
            ok = False
        if ok:
            revocations[vid] = Revocation(vid, inst)
        else:
            ok_all = False
    return revocations, ok_all


def _parse_trusted(raw, errors, receipts, syncs, revocations, refs_ok):
    edges = []
    items = raw.get("trusted_order", [])
    if not isinstance(items, list):
        _err(errors, "$.trusted_order", "E_TYPE",
             "trusted_order must be an array of [id_a, id_b] pairs")
        return edges
    known = {r.rid: r.fingerprint for r in receipts}
    known.update({sid: None for sid in syncs})
    known.update({vid: None for vid in revocations})
    for i, item in enumerate(items):
        path = f"$.trusted_order[{i}]"
        if (not isinstance(item, list) or len(item) != 2
                or not all(_is_str(x) for x in item)):
            _err(errors, path, "E_TYPE",
                 "trusted_order entry must be [id_a, id_b]")
            continue
        a, b = item
        if a == b:
            _err(errors, path, "E_TRUSTED_SELF", "self ordering edge")
            continue
        if not refs_ok:
            edges.append((a, b))
            continue
        bad = False
        for x in (a, b):
            if x not in known:
                _err(errors, path, "E_UNKNOWN_REF", f"unknown event id {x!r}")
                bad = True
                break
        if bad:
            continue
        fa, fb = known[a], known[b]
        if fa is not None and fa == fb:
            _err(errors, path, "E_TRUSTED_SELF",
                 "both endpoints belong to the same login (fingerprint dedup)")
            continue
        edges.append((a, b))
    return edges
