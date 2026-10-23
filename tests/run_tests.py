#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_tests.py —— 依赖零外部库的测试套件

只测"纪律"本身：门禁是否真的会拦住坏结论，案例 schema 是否真的会拒绝脏数据。
不测具体漏洞利用（那需要靶场，属于集成测试，见 tests/README.md）。
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BIN = REPO / "bin"
PY = sys.executable or "python3"

passed = failed = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}" + (f" — {detail}" if detail else ""))


def run(argv: list[str], expect: int | None = None) -> tuple[int, str]:
    p = subprocess.run([PY] + argv, capture_output=True, text=True, timeout=120)
    out = (p.stdout or "") + (p.stderr or "")
    if expect is not None:
        check(f"exit == {expect}", p.returncode == expect,
              f"got {p.returncode}: {out.strip()[:200]}")
    return p.returncode, out


# ---------------------------------------------------------------------------
print("\n== preflight ==")

rc, out = run([str(BIN / "preflight.py"), "--format", "json"])
try:
    report = json.loads(out)
    check("JSON 可解析", True)
    check("包含 counts", "counts" in report)
    check("包含 checks", isinstance(report.get("checks"), list) and len(report["checks"]) > 0)

    ids = {c["id"] for c in report["checks"]}
    for required in ("docker", "runtimes", "containers", "live-targets"):
        check(f"含检查项 {required}", required in ids)

    check("每项都有 status", all(c.get("status") in
          {"pass", "warn", "fail", "skip"} for c in report["checks"]))
except json.JSONDecodeError:
    check("JSON 可解析", False, out[:200])

# 门禁：单产品必须告警
rc, out = run([str(BIN / "preflight.py"), "--products", "1"])
check("单产品产生 WARN", "gate-products" in out and "只有 1 个产品" in out)

# 门禁：无对照必须告警
rc, out = run([str(BIN / "preflight.py")])
check("无对照提示因果", "gate-control" in out)

# strict 模式有 WARN 时退出码为 2
rc, _ = run([str(BIN / "preflight.py"), "--strict"])
check("strict 下 WARN → exit 2", rc == 2, f"got {rc}")

# ---------------------------------------------------------------------------
print("\n== casefile validate ==")

tmp = Path(tempfile.mkdtemp())


def write_case(name: str, data: dict) -> Path:
    p = tmp / name
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return p


good = {
    "id": "good", "title": "ok", "cves": ["CVE-1"], "hasCve": True,
    "stages": [{"id": "S1", "name": "线索归一", "status": "done"}],
    "products": [
        {"name": "vuln", "status": "hit", "result": "5/5"},
        {"name": "fixed", "status": "control-fail", "result": "0/5"},
    ],
    "limits": ["单 worker"],
}
rc, _ = run([str(BIN / "casefile.py"), "validate", str(write_case("good.json", good))], expect=0)
check("合规案例通过", rc == 0)

# 缺必填
bad1 = {"title": "no id"}
rc, out = run([str(BIN / "casefile.py"), "validate", str(write_case("b1.json", bad1))], expect=1)
check("缺 id 被拒", "缺少必填字段 id" in out)

# hasCve 自相矛盾
bad2 = dict(good, hasCve=False)
rc, out = run([str(BIN / "casefile.py"), "validate", str(write_case("b2.json", bad2))], expect=1)
check("hasCve 矛盾被拒", "互相矛盾" in out)

# 非法枚举
bad3 = {"id": "b3", "title": "t",
        "products": [{"name": "x", "status": "pwned", "result": "y"}]}
rc, out = run([str(BIN / "casefile.py"), "validate", str(write_case("b3.json", bad3))], expect=1)
check("非法 status 被拒", "非法" in out)

# 单产品 → WARN
bad4 = {"id": "b4", "title": "t",
        "products": [{"name": "x", "status": "hit", "result": "y"}],
        "limits": ["x"]}
rc, out = run([str(BIN / "casefile.py"), "validate", str(write_case("b4.json", bad4))], expect=0)
check("单产品只是 WARN 不阻断", "只有 1 个产品" in out and rc == 0)

# 无对照 → WARN
bad5 = {"id": "b5", "title": "t",
        "products": [{"name": "a", "status": "hit", "result": "1"},
                      {"name": "b", "status": "hit", "result": "1"}],
        "limits": ["x"]}
rc, out = run([str(BIN / "casefile.py"), "validate", str(write_case("b5.json", bad5))], expect=0)
check("无对照产生 WARN", "没有任何修复版对照" in out)

# 无 limits → WARN
bad6 = {"id": "b6", "title": "t", "products": [
    {"name": "a", "status": "hit", "result": "1"},
    {"name": "b", "status": "control-fail", "result": "0"}]}
rc, out = run([str(BIN / "casefile.py"), "validate", str(write_case("b6.json", bad6))], expect=0)
check("缺 limits 产生 WARN", "缺少 limits" in out)

# scaffold 可被自己校验（除占位错误外至少能解析）
rc, out = run([str(BIN / "casefile.py"), "scaffold"])
check("scaffold 输出合法 JSON", isinstance(json.loads(out), dict))

# ---------------------------------------------------------------------------
print("\n== 仓库内案例 ==")

cases_dir = REPO / "dashboard" / "data" / "cases"
rc, out = run([str(BIN / "casefile.py"), "validate", str(cases_dir)], expect=0)
files = list(cases_dir.glob("*.json"))
check(f"案例目录有文件（{len(files)}）", len(files) > 0)
check("全部通过校验", rc == 0, out[:300])

# 每个案例都应有 limits（本轮修复的重点）
for f in files:
    d = json.loads(f.read_text(encoding="utf-8"))
    check(f"{f.stem} 有能力边界", bool(d.get("limits")))

# ---------------------------------------------------------------------------
print("\n== CLI ==")

rc, out = run([str(BIN / "vulnrepro"), "status"], expect=0)
check("status 可用", "vuln-repro 状态" in out)
check("status 列出案例", "案例:" in out)

rc, out = run([str(BIN / "vulnrepro"), "--help"], expect=0)
check("--help 可用", "dashboard" in out)

print()
print(f"合计: {passed} 通过, {failed} 失败")
sys.exit(0 if failed == 0 else 1)
