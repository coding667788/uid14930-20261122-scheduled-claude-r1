"""命令行入口：``python -m passkey_audit CASE.json``。

退出码：0 = 裁定完成（status ok）；1 = 无可行解释（status infeasible）；
2 = 输入格式或 IO 错误（status error）。报告为确定的 UTF-8 JSON。
"""
from __future__ import annotations

import json
import sys

from . import SCHEMA
from .engine import Engine
from .model import FormatError, parse_case


def _emit(obj):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    json.dump(obj, sys.stdout, ensure_ascii=False, sort_keys=True, indent=2)
    sys.stdout.write("\n")


def main(argv=None):
    argv = sys.argv if argv is None else argv
    if len(argv) != 2 or argv[1] in ("-h", "--help"):
        sys.stderr.write("usage: python -m passkey_audit CASE.json\n")
        return 2
    try:
        with open(argv[1], "r", encoding="utf-8-sig") as fh:
            text = fh.read()
    except OSError as exc:
        _emit({"schema": SCHEMA, "status": "error",
               "errors": [{"path": "$", "code": "E_IO", "message": str(exc)}]})
        return 2
    try:
        case = parse_case(text)
    except FormatError as fe:
        _emit({"schema": SCHEMA, "status": "error", "errors": fe.errors})
        return 2
    report = Engine(case).analyze()
    _emit({"schema": SCHEMA, "case": case.name, **report})
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
