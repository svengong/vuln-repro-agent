#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
preflight.py —— 环境检测（在任何利用之前运行）

目的
----
把"结果不稳定"的根因挡在启动阶段。历史问题都出在这里：
  · 只测了一个产品就下结论（没有版本矩阵）
  · 缺修复版对照（无法证明因果）
  · 靶场没起 / 端口没监听，脚本静默失败被当成"不可利用"
  · 容器名冲突，误伤隔壁项目
  · 需要可写挂载才能落 webshell，但没检查

本脚本只读，不改动任何东西。它输出一份机器可读的 JSON 报告，
`check` 子命令按门禁规则给出 PASS / WARN / FAIL。

用法
----
  python3 preflight.py --format text
  python3 preflight.py --format json
  python3 preflight.py --expect-products 5 --expect-control
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from typing import Any

# ---------------------------------------------------------------------------
# 结果模型
# ---------------------------------------------------------------------------

PASS, WARN, FAIL, SKIP = "pass", "warn", "fail", "skip"


@dataclass
class Check:
    id: str
    title: str
    status: str = SKIP
    detail: str = ""
    hint: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    env: dict[str, Any] = field(default_factory=dict)

    def add(self, c: Check) -> None:
        self.checks.append(c)

    @property
    def counts(self) -> dict[str, int]:
        out = {PASS: 0, WARN: 0, FAIL: 0, SKIP: 0}
        for c in self.checks:
            out[c.status] = out.get(c.status, 0) + 1
        return out

    @property
    def ok(self) -> bool:
        """FAIL 阻断；WARN 不阻断但必须写进结论。"""
        return self.counts[FAIL] == 0


# ---------------------------------------------------------------------------
# 基础探测
# ---------------------------------------------------------------------------

def run(cmd: list[str], timeout: int = 20) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout: {' '.join(cmd)}"


def which(name: str) -> str | None:
    return shutil.which(name)


def port_open(host: str, port: int, timeout: float = 0.6) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# 各项检查
# ---------------------------------------------------------------------------

def check_docker(r: Report) -> None:
    c = Check("docker", "Docker 可用")
    if not which("docker"):
        c.status = FAIL
        c.detail = "未找到 docker 命令"
        c.hint = "安装 Docker 后重试；无 Docker 时只能用本机进程靶场"
        r.add(c)
        return

    code, out, err = run(["docker", "version", "--format", "{{.Server.Version}}"])
    if code != 0:
        c.status = FAIL
        c.detail = f"docker daemon 不可用: {(err or out).strip()[:200]}"
        c.hint = "启动 Docker daemon（或把用户加入 docker 组）"
        r.add(c)
        return

    c.status = PASS
    c.detail = f"server {out.strip()}"
    r.add(c)


def check_containers(r: Report) -> None:
    """列出所有容器：既要发现冲突前缀，也要找到可用的靶场。"""
    c = Check("containers", "容器清单与命名空间")
    code, out, _ = run(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}\t{{.Ports}}"])
    if code != 0:
        c.status = SKIP
        c.detail = "docker 不可用，跳过"
        r.add(c)
        return

    rows = []
    for line in out.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            rows.append({"name": parts[0], "status": parts[1], "ports": parts[2] if len(parts) > 2 else ""})

    running = [x for x in rows if x["status"].startswith("Up")]
    prefixes: dict[str, int] = {}
    for x in rows:
        prefix = x["name"].split("-")[0]
        prefixes[prefix] = prefixes.get(prefix, 0) + 1

    c.data = {"total": len(rows), "running": len(running),
              "prefixes": prefixes, "running_names": [x["name"] for x in running]}
    c.status = PASS if rows else WARN
    c.detail = f"共 {len(rows)} 个容器，运行中 {len(running)}"
    if len(prefixes) > 1:
        c.detail += f"；前缀: {', '.join(f'{k}×{v}' for k, v in sorted(prefixes.items()))}"
    r.add(c)


def check_port_conflicts(r: Report, planned: list[int]) -> None:
    """计划端口是否已被别的进程占用 —— 这是"靶场没起来"的常见伪装。"""
    c = Check("ports", "计划端口占用")
    busy = [p for p in planned if port_open("127.0.0.1", p)]
    c.data = {"planned": planned, "busy": busy}
    if not planned:
        c.status = SKIP
        c.detail = "未指定计划端口"
    elif busy:
        c.status = WARN
        c.detail = f"以下端口已在监听: {busy}"
        c.hint = "若这些是已有靶场可复用；否则换端口，避免误判成靶场已就绪"
    else:
        c.status = PASS
        c.detail = f"{len(planned)} 个端口空闲"
    r.add(c)


def check_runtimes(r: Report) -> None:
    c = Check("runtimes", "所需运行时")
    found = {}
    for name, args in (("python3", ["--version"]), ("node", ["--version"]),
                       ("bash", ["--version"]), ("curl", ["--version"])):
        path = which(name)
        if not path:
            found[name] = None
            continue
        code, out, err = run([name] + args)
        text = (out or err).strip().splitlines()
        found[name] = text[0] if text else "present"
    c.data = found
    missing = [k for k, v in found.items() if not v]
    c.status = FAIL if missing else PASS
    c.detail = "; ".join(f"{k}={v or 'MISSING'}" for k, v in found.items())
    if missing:
        c.hint = f"缺少: {', '.join(missing)}"
    r.add(c)


def check_writable_mount(r: Report, container: str | None) -> None:
    """持久 webshell 需要可写且可访问的目录 —— 没有就只能降级。"""
    c = Check("writable-mount", "可写挂载（决定能否给持久 shell）")
    if not container:
        c.status = SKIP
        c.detail = "未指定容器"
        r.add(c)
        return

    code, out, _ = run(["docker", "inspect", "-f",
                        "{{range .Mounts}}{{.Destination}}={{.RW}} {{end}}", container])
    if code != 0:
        c.status = SKIP
        c.detail = f"容器 {container} 不存在"
        r.add(c)
        return

    mounts = out.strip()
    code2, out2, _ = run(["docker", "exec", container, "sh", "-c",
                          "for d in /var/www/html /app /usr/src/app /out /tmp; do "
                          "test -w $d 2>/dev/null && echo \"$d\"; done"])
    writable = out2.split() if code2 == 0 else []
    c.data = {"mounts": mounts, "writable_candidates": writable}
    if writable:
        c.status = PASS
        c.detail = f"可写目录: {', '.join(writable)}"
        c.hint = "确认这些目录同时可被 Web 访问，否则仍无法落持久 webshell"
    else:
        c.status = WARN
        c.detail = "未发现可写目录"
        c.hint = "只能逐命令 RCE（每条命令重跑利用），必须在结论里写明降级"
    r.add(c)


def check_live_targets(r: Report) -> None:
    """扫出当前真正可达的靶场端口，供 dashboard/矩阵复用。"""
    c = Check("live-targets", "可达靶场探测")
    code, out, _ = run(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"])
    if code != 0:
        c.status = SKIP
        c.detail = "docker 不可用"
        r.add(c)
        return

    targets = []
    for line in out.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name, ports = parts[0], parts[1]
        m = re.search(r"127\.0\.0\.1:(\d+)->(\d+)", ports)
        if not m:
            continue
        host_port = int(m.group(1))
        targets.append({"container": name, "port": host_port, "reachable": port_open("127.0.0.1", host_port)})

    alive = [t for t in targets if t["reachable"]]
    c.data = {"targets": targets, "alive": len(alive)}
    c.status = PASS if alive else WARN
    c.detail = f"{len(alive)}/{len(targets)} 个映射端口可达"
    if not alive:
        c.hint = "靶场未就绪；先起靶场再谈可利用性，别把'没起来'写成'不可利用'"
    r.add(c)


# ---------------------------------------------------------------------------
# 门禁：结论质量规则（这是"结果不稳定"的真正来源）
# ---------------------------------------------------------------------------

def check_conclusion_gates(r: Report, products: int, has_control: bool,
                           has_limits: bool, has_dashboard: bool) -> None:
    c = Check("gate-products", "产品/版本矩阵足够")
    if products <= 0:
        c.status = WARN
        c.detail = "尚未记录任何产品"
        c.hint = "至少覆盖 1 个漏洞版 + 1 个修复版才能证明因果"
    elif products == 1:
        c.status = WARN
        c.detail = "只有 1 个产品"
        c.hint = "单产品结果不构成结论；补 2–5 个产品版本再收尾"
    else:
        c.status = PASS
        c.detail = f"{products} 个产品/版本"
    r.add(c)

    c2 = Check("gate-control", "有修复版对照")
    c2.status = PASS if has_control else WARN
    c2.detail = "已记录修复对照" if has_control else "缺少修复版对照"
    if not has_control:
        c2.hint = "没有修复版对照 = 没有证明因果，只能写「疑似」"
    r.add(c2)

    c3 = Check("gate-limits", "有能力边界声明")
    c3.status = PASS if has_limits else WARN
    c3.detail = "已写能力边界" if has_limits else "未写能力边界"
    if not has_limits:
        c3.hint = "必须写「未验证/已知限制」，禁止把单 worker 结果写成生产可用"
    r.add(c3)

    c4 = Check("gate-dashboard", "结果已进 dashboard")
    c4.status = PASS if has_dashboard else WARN
    c4.detail = "已有案例文件" if has_dashboard else "未生成案例文件"
    if not has_dashboard:
        c4.hint = "跑完必须落 data/cases/<id>.json，否则 web 端看不到"
    r.add(c4)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def collect(args) -> Report:
    r = Report()
    code, out, _ = run(["uname", "-a"])
    r.env = {
        "platform": sys.platform,
        "uname": out.strip() if code == 0 else "",
        "cwd": os.getcwd(),
        "python": sys.version.split()[0],
    }

    check_docker(r)
    check_runtimes(r)
    check_containers(r)
    check_port_conflicts(r, args.ports)
    check_writable_mount(r, args.container)
    check_live_targets(r)
    check_conclusion_gates(r, args.products, args.control, args.limits, args.dashboard)
    return r


def render_text(r: Report) -> str:
    icon = {PASS: "✅", WARN: "⚠️ ", FAIL: "❌", SKIP: "➖"}
    lines = []
    lines.append("=" * 72)
    lines.append("vuln-repro 环境检测（preflight）")
    lines.append("=" * 72)
    lines.append(f"平台: {r.env.get('uname', '?')}")
    lines.append(f"Python: {r.env.get('python')}")
    lines.append("")
    for c in r.checks:
        lines.append(f"{icon.get(c.status, '?')} {c.id:<18} {c.title}")
        if c.detail:
            lines.append(f"    {c.detail}")
        if c.hint and c.status in (WARN, FAIL):
            lines.append(f"    → {c.hint}")
    k = r.counts
    lines.append("")
    lines.append(f"结果: pass={k[PASS]} warn={k[WARN]} fail={k[FAIL]} skip={k[SKIP]}")
    lines.append("结论: " + ("可以开始（WARN 项必须写进最终结论）" if r.ok
                             else "存在 FAIL，先修复再开始"))
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="vuln-repro 环境检测")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--ports", type=int, nargs="*", default=[],
                    help="计划使用的靶场端口")
    ap.add_argument("--container", default=None,
                    help="要检查可写挂载的容器名")
    ap.add_argument("--products", type=int, default=0,
                    help="已记录的产品数量（门禁用）")
    ap.add_argument("--control", action="store_true", help="是否已有修复版对照")
    ap.add_argument("--limits", action="store_true", help="是否已写能力边界")
    ap.add_argument("--dashboard", action="store_true", help="是否已生成案例文件")
    ap.add_argument("--strict", action="store_true",
                    help="把 WARN 也当失败（收尾前用）")
    args = ap.parse_args()

    report = collect(args)

    if args.format == "json":
        payload = {
            "ok": report.ok and not (args.strict and report.counts[WARN] > 0),
            "counts": report.counts,
            "env": report.env,
            "checks": [asdict(c) for c in report.checks],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(render_text(report))

    if not report.ok:
        return 1
    if args.strict and report.counts[WARN] > 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
