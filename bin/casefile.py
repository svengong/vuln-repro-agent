#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
casefile.py —— 案例文件的校验 / 生成 / 合并

为什么需要它
------------
dashboard 直接读 `data/cases/*.json`，所以案例文件就是"结论的载体"。
手写 JSON 容易漏字段、写错枚举值，导致 web 端要么崩、要么展示不实的结论。
本工具把 schema 固化成可执行的检查，并提供 `scaffold` 快速生成骨架。

子命令
------
  validate <file|dir>   校验（默认对所有案例）
  scaffold             生成一个空骨架到 stdout
  merge <file>         把文件合并进 dashboard/data/cases/

退出码
------
  0 全部通过
  1 有错误（必填缺失 / 枚举非法 / 语义矛盾）
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
CASES_DIR = REPO / "dashboard" / "data" / "cases"

# 产品结论的合法取值。`unevaluated` 与 `miss` 必须分开：
# 前者是"没测成/没起来"，后者是"测了但不成立"。
PRODUCT_STATUS = {"hit", "miss", "control-fail", "unevaluated"}
STAGE_STATUS = {"done", "partial", "todo", "blocked"}

REQUIRED_CASE = ("id", "title")
REQUIRED_PRODUCT = ("name", "status", "result")


def _is_str(v: Any) -> bool:
    return isinstance(v, str) and v.strip() != ""


def validate_case(data: Any, source: str) -> list[str]:
    errs: list[str] = []
    warn: list[str] = []

    if not isinstance(data, dict):
        return [f"{source}: 顶层必须是 JSON 对象"]

    for k in REQUIRED_CASE:
        if not _is_str(data.get(k)):
            errs.append(f"{source}: 缺少必填字段 {k}")

    cid = data.get("id")
    if _is_str(cid) and not isinstance(cid, str):
        errs.append(f"{source}: id 必须是字符串")

    # CVE 与 hasCve 的一致性：写了 cve 却标 hasCve=false 是自相矛盾。
    cves = data.get("cves")
    if cves is not None and not isinstance(cves, list):
        errs.append(f"{source}: cves 必须是数组")
        cves = []
    cves = cves or []
    has_cve = data.get("hasCve")
    if has_cve is True and not cves:
        errs.append(f"{source}: hasCve=true 但 cves 为空（无 CVE 案例应写 hasCve=false）")
    if has_cve is False and cves:
        errs.append(f"{source}: hasCve=false 但 cves 非空，互相矛盾")

    sev = data.get("severity")
    if sev is not None:
        if not isinstance(sev, dict):
            errs.append(f"{source}: severity 必须是对象")
        else:
            for k in ("v31", "v40"):
                v = sev.get(k)
                if v is not None and not isinstance(v, (int, float)):
                    errs.append(f"{source}: severity.{k} 必须是数字")

    stages = data.get("stages")
    if stages is not None and not isinstance(stages, list):
        errs.append(f"{source}: stages 必须是数组")
        stages = []
    for i, s in enumerate(stages or []):
        if not isinstance(s, dict):
            errs.append(f"{source}: stages[{i}] 必须是对象")
            continue
        if not _is_str(s.get("name")):
            errs.append(f"{source}: stages[{i}] 缺少 name")
        st = s.get("status")
        if st is not None and st not in STAGE_STATUS:
            errs.append(f"{source}: stages[{i}].status='{st}' 非法（允许: {sorted(STAGE_STATUS)}）")

    products = data.get("products")
    if products is not None and not isinstance(products, list):
        errs.append(f"{source}: products 必须是数组")
        products = []
    products = products or []
    for i, p in enumerate(products):
        if not isinstance(p, dict):
            errs.append(f"{source}: products[{i}] 必须是对象")
            continue
        for k in REQUIRED_PRODUCT:
            if not _is_str(p.get(k)):
                errs.append(f"{source}: products[{i}] 缺少 {k}")
        st = p.get("status")
        if st is not None and st not in PRODUCT_STATUS:
            errs.append(f"{source}: products[{i}].status='{st}' 非法（允许: {sorted(PRODUCT_STATUS)}）")

    # 结论质量门禁：这些是"结果不稳定"的直接来源。
    if products and not any(p.get("status") == "control-fail" for p in products):
        warn.append(f"{source}: 没有任何修复版对照（control-fail），因果不成立")
    if len(products) == 1:
        warn.append(f"{source}: 只有 1 个产品，单产品不构成结论")

    limits = data.get("limits")
    if not isinstance(limits, list) or not limits:
        warn.append(f"{source}: 缺少 limits（能力边界），必须写明未验证/已知限制")

    demo = data.get("demo")
    if demo is not None:
        if not isinstance(demo, dict):
            errs.append(f"{source}: demo 必须是对象")
        elif demo.get("targetKey") is not None and not _is_str(demo.get("targetKey")):
            errs.append(f"{source}: demo.targetKey 必须是非空字符串或省略")

    for w in warn:
        errs.append("WARN " + w)  # 统一返回，由调用方区分严重级别
    return errs


def split_messages(msgs: list[str]) -> tuple[list[str], list[str]]:
    errs = [m for m in msgs if not m.startswith("WARN ")]
    warns = [m[len("WARN "):] for m in msgs if m.startswith("WARN ")]
    return errs, warns


def scaffold() -> dict:
    return {
        "id": "cve-2099-00000",
        "title": "产品名 — 一句话描述",
        "subtitle": "CVE-2099-00000",
        "cves": ["CVE-2099-00000"],
        "hasCve": True,
        "kind": "缺陷类型（如：引擎级内存安全 / 应用层组合链）",
        "severity": {"v31": 0.0, "v40": 0.0, "label": "Critical / High"},
        "baseline": "根因一句话",
        "stages": [
            {"id": "S1", "name": "线索归一", "status": "todo", "summary": "", "evidence": []},
            {"id": "S2", "name": "产品/版本矩阵", "status": "todo", "summary": "", "evidence": []},
            {"id": "S3", "name": "镜像获取", "status": "todo", "summary": "", "evidence": []},
            {"id": "S4", "name": "前提判定", "status": "todo", "summary": "", "evidence": []},
            {"id": "S5", "name": "靶场化验证", "status": "todo", "summary": "", "evidence": []},
            {"id": "S6", "name": "打穿与 exp", "status": "todo", "summary": "", "evidence": []},
            {"id": "S7", "name": "结论与边界", "status": "todo", "summary": "", "evidence": []},
        ],
        "products": [
            {"name": "产品/组件（漏洞版）", "image": "镜像:tag", "runtime": "运行时",
             "status": "hit", "result": "N/N 拿到 uid=…"},
            {"name": "产品/组件（修复版）", "image": "镜像:tag", "runtime": "运行时",
             "status": "control-fail", "result": "N/N 失败（符合预期）"},
        ],
        "productsSummary": {"attempted": 2, "hit": 1, "controlFail": 1},
        "limits": ["未验证：…", "已知限制：…"],
        "demo": {"available": False, "targetKey": "", "targetLabel": "", "detail": ""},
    }


def cmd_validate(args) -> int:
    targets: list[Path] = []
    for t in args.paths:
        p = Path(t)
        if p.is_dir():
            targets.extend(sorted(p.glob("*.json")))
        elif p.is_file():
            targets.append(p)
        else:
            print(f"[!] 不存在: {t}", file=sys.stderr)
            return 1

    if not targets:
        print("[!] 没有找到案例文件", file=sys.stderr)
        return 1

    total_err = 0
    total_warn = 0
    seen_ids: dict[str, str] = {}

    for f in targets:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"❌ {f.name}: JSON 解析失败: {e}")
            total_err += 1
            continue

        msgs = validate_case(data, f.name)
        errs, warns = split_messages(msgs)

        cid = data.get("id") if isinstance(data, dict) else None
        if isinstance(cid, str):
            if cid in seen_ids:
                errs.append(f"{f.name}: id '{cid}' 与 {seen_ids[cid]} 重复")
            else:
                seen_ids[cid] = f.name

        if errs:
            print(f"❌ {f.name}")
            for e in errs:
                print(f"   - {e}")
            total_err += len(errs)
        else:
            print(f"✅ {f.name}")
        for w in warns:
            print(f"   ⚠️  {w}")
            total_warn += 1

    print()
    print(f"合计: {len(targets)} 个文件, 错误 {total_err}, 警告 {total_warn}")
    return 0 if total_err == 0 else 1


def cmd_scaffold(_args) -> int:
    print(json.dumps(scaffold(), ensure_ascii=False, indent=2))
    return 0


def cmd_merge(args) -> int:
    src = Path(args.file)
    if not src.is_file():
        print(f"[!] 不存在: {src}", file=sys.stderr)
        return 1
    data = json.loads(src.read_text(encoding="utf-8"))
    errs, warns = split_messages(validate_case(data, src.name))
    if errs:
        print("[!] 校验未通过，拒绝合并:", file=sys.stderr)
        for e in errs:
            print("   -", e, file=sys.stderr)
        return 1
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    dst = CASES_DIR / src.name
    dst.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"✅ 已写入 {dst}")
    for w in warns:
        print(f"   ⚠️  {w}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="vuln-repro 案例文件工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="校验案例文件")
    v.add_argument("paths", nargs="*", default=[str(CASES_DIR)])
    v.set_defaults(func=cmd_validate)

    s = sub.add_parser("scaffold", help="输出空骨架")
    s.set_defaults(func=cmd_scaffold)

    m = sub.add_parser("merge", help="校验后合并进 dashboard")
    m.add_argument("file")
    m.set_defaults(func=cmd_merge)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
