# vuln-repro-agent

从一条漏洞线索（CVE 编号、advisory、补丁 commit，或一句模糊描述）出发，
做**环境检测 → 多产品版本矩阵 → 隔离靶场打穿 → 交互式 shell → 可视化管理台**的完整 agent。

这不是提示词集合，而是把「结果不稳定」的根因固化成**可执行的门禁**。

---

## 为什么需要它

同一类工作反复出现同几种失败：

| 失败 | 后果 | 本项目的对策 |
|---|---|---|
| 只测一个产品就下结论 | 结论不成立，但页面看起来"已打穿" | `preflight` / `casefile` 对单产品告警 |
| 没有修复版对照 | 无法区分"漏洞生效"与"本来就通" | 强制 `control-fail` 记录 |
| 靶场没起来 / 端口被占 | 静默失败被当成"不可利用" | S0 环境检测，端口与容器清单 |
| 分不清"没测"与"不成立" | 把"没评估"说成"安全" | `unevaluated` 与 `miss` 严格区分 |
| 打完不入库 | web 端看不到，用户以为没做 | S7 强制 `case merge` 并核对 `status` |
| 清理脚本宽匹配 | 误杀无关进程/容器 | 前缀 + cwd 锚定 |

---

## 快速开始

```bash
git clone <this repo>
cd vuln-repro-agent

# 一句话启动（无子命令即启动 dashboard；已在跑则复用）
./bin/vulnrepro

# 新机器上案例库可能是空的 —— 这是合法状态，页面照常可用
```

打开 <http://127.0.0.1:3010>。

---

## 命令

| 命令 | 作用 |
|---|---|
| `vulnrepro` / `vulnrepro dashboard` | 启动 dashboard（幂等） |
| `vulnrepro stop` | 停止由本工具启动的 dashboard |
| `vulnrepro preflight` | 环境检测（**开打之前必跑**） |
| `vulnrepro doctor` | 一键体检：环境 + 案例 + dashboard |
| `vulnrepro status` | 当前状态（案例、容器、dashboard） |
| `vulnrepro case scaffold` | 生成案例文件骨架 |
| `vulnrepro case validate [path]` | 校验案例文件 |
| `vulnrepro case merge <file>` | 校验通过后写入 dashboard |

退出码：`0` 成功 / `1` 失败 / `2` 部分可用（有 WARN）。

---

## 环境要求

| 依赖 | 用途 | 缺失时 |
|---|---|---|
| Python 3.10+ | 所有工具链 | 不可用 |
| Node 18+ | dashboard 服务 | 无法启动 dashboard |
| Docker | 靶场容器 | preflight 报 FAIL；只能走本机进程靶场 |
| curl / bash | 探测与脚本 | preflight 报 FAIL |

dashboard 的靶场位置通过 `VULN_REPRO_LABS` 指定（默认取仓库上一级目录）：

```bash
VULN_REPRO_LABS=/path/to/labs ./bin/vulnrepro
```

没有配置靶场时 dashboard 仍可用，案例照常浏览，只是演示面板会提示"未配置可执行靶场"。

---

## 目录结构

```
vuln-repro-agent/
├── bin/
│   ├── vulnrepro       # 统一入口
│   ├── preflight.py    # 环境检测 + 结论质量门禁
│   └── casefile.py     # 案例 schema 校验 / 骨架 / 合并
├── skill/              # agent 的方法论（SKILL.md + reference/ + examples/）
├── dashboard/          # 可视化 + 真实 EXP 演示（Node，零框架依赖）
├── cordis.patch.yml    # DSH agent preset 声明
├── tests/              # 零外部依赖的测试
└── docs/
```

---

## 七阶段工作流

| 阶段 | 做什么 | 完成判据 |
|---|---|---|
| **S0 环境检测** | `vulnrepro preflight` | 无 FAIL；WARN 记入结论 |
| S1 线索归一 | 核对官方来源与修复 diff | ≥2 个独立来源 |
| S2 产品/版本矩阵 | 锁定"组件未修且可获取"的版本 | **≥2 版本，含修复版** |
| S3 镜像获取 | 核实容器内真实版本 | 记录构建时间与内置版本 |
| S4 前提判定 | 组件缺陷 vs 应用层前提 | 分诊结论 |
| S5 靶场验证 | 隔离命名空间 + N 次统计 + 对照 | 漏洞版 N/N，修复版 0/N |
| S6 打穿与 exp | 处理命令槽/ASLR/入口/持久 shell | 能手动敲命令并拿到输出 |
| S7 结案 | 写案例 JSON 并入 dashboard | 页面可见且可演示 |

方法论细节见 [skill/SKILL.md](skill/SKILL.md)。

---

## 作为 DSH agent 使用

本仓库同时是一个 DeepSeek Harness agent preset bundle：

```bash
# 在 DSH 中安装该 bundle 后，新建会话选择「漏洞复现 (vuln-repro)」
```

preset 的 persona 会把 S0–S7 与三条硬判据写进系统提示，
所以即使不说细节，行为也保持一致：

- "启动 dashboard" → 直接启动，不追问
- 单产品/无对照 → 主动补测或明确标注为"疑似"
- 跑完 → 必须 `case merge` 并核对 `status`

---

## 安全边界

- 只绑定 `127.0.0.1`
- demo 可执行的命令在服务端**白名单**写死，客户端只能传目标 key
- 案例文件不接受任意命令；`targetKey` 必须已在 `TARGETS` 中定义
- 仅用于**授权的隔离环境**（本地 Docker / 明确授权的测试范围）
- 靶场命名空间带专属前缀，清理只删自己的资源

---

## 测试

```bash
python3 tests/run_tests.py
```

覆盖门禁行为（单产品告警、无对照告警、非法枚举拒绝、schema 校验）
与 CLI 可用性，不依赖 Docker。

---

## License

MIT
