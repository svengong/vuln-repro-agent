---
name: vuln-repro
description: 从一条漏洞线索（CVE 编号、GHSA、补丁 commit，或一句模糊描述）出发，做环境检测、判定可利用性、建立多产品版本矩阵、在隔离靶场打穿、产出稳定 exp 与交互式 shell，并把结论写进可交互的 dashboard。用于"线索 → 打穿 → 可演示"的完整链。Use when the user gives a CVE id, advisory, patch, or vague lead and wants verified exploitation evidence with a runnable demo rather than a written report.
whenToUse: 用户给出 CVE 编号/advisory/补丁 commit/一句漏洞线索；或要求"启动 dashboard"、复现将某漏洞、验证可利用性、寻找受影响产品版本、打穿拿 shell、写 exp 或靶场脚本。
---

# vuln-repro — 漏洞线索到可演示打穿

输入是**编号或线索**，输出是**能被点击验证的证据**。

本 skill 的每条规则都来自真实失败：单产品就下结论、缺修复版对照、
靶场没起来被当成"不可利用"、打完不进 dashboard 导致"web 端看不到结果"。

## 0. 立刻可用的三条命令

```bash
# 用户说"启动 dashboard" → 直接跑这条，不要多问
vulnrepro dashboard            # 无子命令时也是默认启动；已在跑则复用

vulnrepro preflight            # 环境检测（开打之前必跑）
vulnrepro doctor               # 一键体检：环境 + 案例 + dashboard
```

**"启动 dashboard" 是一个完整请求**，不需要追问。别的机器上案例库可能是空的，
照常启动即可 —— 空库是合法状态，页面本身能跑。

## 1. 七阶段（每阶段的硬产出）

| 阶段 | 做什么 | 硬产出 | 完成判据 |
|---|---|---|---|
| **S0 环境检测** | 跑 `vulnrepro preflight` | 环境报告 | 无 FAIL；WARN 记入结论 |
| S1 线索归一 | 核对官方公告/修复 diff/版本区间 | 来源列表 + 版本表 | 至少两个独立来源 |
| S2 产品/版本矩阵 | 锁定"组件未修且可获取"的版本 | 产品×版本表 | **≥2 个版本，含修复版** |
| S3 镜像获取 | 拉镜像/取源码，核实真实版本 | 每个 tag 的证据 | 记录构建时间与内置版本 |
| S4 前提判定 | 组件自身缺陷 vs 需要应用层前提 | 分诊结论 | 决定是否值得继续投入 |
| S5 靶场化验证 | 隔离命名空间、N 次统计、修复版对照 | 成功率 + 对照 | **漏洞版 N/N，修复版 0/N** |
| S6 打穿与 exp | 处理命令槽/ASLR/入口/持久 shell | 可重复 exp + 交互式 shell | 能手动敲命令并拿到输出 |
| S7 结案 | 写案例 JSON 并入 dashboard | `data/cases/<id>.json` | 页面能看到并可演示 |

细则见 [reference/flow.md](reference/flow.md)。

## 2. 三个不可让步的判据

### 2.1 必须有修复版对照

没有修复版对照 = 没有证明因果，只能写"疑似"。
`preflight` 和 `casefile validate` 都会对此告警。

### 2.2 单产品不构成结论

至少覆盖 **1 个漏洞版 + 1 个修复版**；真实产品建议 2–5 个版本。
只测一个产品就说"打穿了"，是本类工作最常见的不可靠来源。

### 2.3 打穿必须能手动验证

拿到 RCE 后**尽量交付交互式 shell**，让用户能自己敲 `id`。
拿不到持久通道才降级为逐命令执行，且必须**明说差额**。
已修复的目标**不要给 shell** —— 那里本不该有通道，假装有等于伪造结论。

见 [reference/shell.md](reference/shell.md)。

## 3. 收尾：必须进 dashboard

跑完一条链，**写案例文件并合并**，否则用户看不到结果（这是真实发生过的问题）：

```bash
vulnrepro case scaffold > /tmp/my-case.json   # 生成骨架
# 按实际跑通的程度填写，未知就留空，不要编造
vulnrepro case merge /tmp/my-case.json        # 校验并写入 dashboard
```

只写已知字段是安全的：缺失走默认值，页面不会崩。
**必填只有 `id` 和 `title`**。字段说明见 [reference/casefile.md](reference/casefile.md)。

## 4. 结论必须诚实

`已验证 / 未验证 / 已知限制` 三段分开写。
把"单 worker 打通"写成"生产可用"是最严重的错误。

- CVSS 多口径与 CVE 归属 → [reference/scoring.md](reference/scoring.md)
- 对外报送措辞红线 → [reference/disclosure.md](reference/disclosure.md)

## 5. 参考实现

| 案例 | 类型 | 关键教训 |
|---|---|---|
| [examples/php2shell.md](examples/php2shell.md) | 引擎级内存 CVE | latest 标签会被重建为修复版；cookie 大小即判据 |
| [examples/session-poison.md](examples/session-poison.md) | 应用层链，**无 CVE** | 前提①免费、前提②是门槛；全灭也是有效结论 |
| [examples/react2shell.md](examples/react2shell.md) | 反序列化 CVE | 零应用前提；相邻版本 = 干净单步因果边界 |

## 6. 安全边界

只在**授权的隔离环境**内操作：本地 Docker 靶场、明确授权的测试范围。
默认不触碰生产资产；确需外部目标时先取得书面授权。
靶场命名空间必须带专属前缀，清理脚本只删自己的容器。
