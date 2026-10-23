# 案例文件（dashboard 的数据契约）

dashboard 直接读 `dashboard/data/cases/*.json`。**案例文件就是结论的载体**，
所以它有一个被强制校验的 schema。

## 必填 vs 选填

**必填只有两个**：`id`、`title`。

其余全部可选 —— 只写已知字段是安全的，缺失走默认值，页面不会崩。
这条规则是刻意的：新案例往往是"刚跑完、还没写全"，不该因此被卡住。

## 完整字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | **必填**，唯一，用作 URL hash 与文件名 |
| `title` | string | **必填**，一句话标题 |
| `subtitle` | string | 副标题（常见是 CVE 号） |
| `cves` | string[] | CVE 列表 |
| `hasCve` | bool | 必须与 `cves` 一致：有 cve 就别写 false |
| `kind` | string | 缺陷类型 |
| `severity` | object | `{v31, v40, label}`，数字型 |
| `baseline` | string | 根因一句话 |
| `stages` | object[] | S1–S7，见下 |
| `products` | object[] | 产品矩阵，见下 |
| `productsSummary` | object | 汇总计数 |
| `limits` | string[] | **必须写**能力边界 |
| `demo` | object | 演示配置，见下 |

## stages

```json
{ "id": "S1", "name": "线索归一", "status": "done",
  "summary": "一句话", "evidence": ["可追溯的证据行"] }
```

`status` 只能是：`done` / `partial` / `todo` / `blocked`。

## products

```json
{ "name": "产品名", "image": "镜像:tag", "runtime": "组件版本",
  "status": "hit", "result": "N/N 拿到 uid=33" }
```

`status` 四选一，**这四个必须严格区分**：

| 值 | 含义 | 典型措辞 |
|---|---|---|
| `hit` | 打穿 | "5/5 拿到 root" |
| `miss` | 测了，不成立 | "前提②确认缺失" |
| `control-fail` | 修复对照，**预期失败** | "0/5（符合预期）" |
| `unevaluated` | **没能测** | "镜像拉取失败，未评估" |

> `unevaluated` ≠ `miss`。把"没测成"写成"不可利用"会让结论失真，
> 这是本类报告最常见的数据污染。

## demo

```json
{ "available": true, "targetKey": "sp-clean",
  "targetLabel": "展示给用户的描述", "detail": "演示说明",
  "shell": { "kind": "webshell", "available": true, "note": "…" } }
```

`targetKey` 必须在 dashboard 的 `TARGETS` 白名单里（安全设计：不接受任意命令）。
没有可执行靶场时就省略 `targetKey`，页面会明确提示"未配置靶场"。

## 校验与合并

```bash
vulnrepro case scaffold > /tmp/c.json   # 生成骨架
vulnrepro case validate /tmp/c.json     # 单独校验
vulnrepro case merge /tmp/c.json        # 校验通过后写入 dashboard
```

校验会拦截：

- 缺必填字段
- `hasCve` 与 `cves` 自相矛盾
- `status` 枚举非法
- `id` 重复
- **质量警告**：单产品、无修复对照、无 limits

## 为什么这些检查存在

这不是形式主义。以下每一个都真实导致过"结果不可靠"：

| 问题 | 后果 |
|---|---|
| 只写一个产品 | 结论不成立，但页面看起来像"已打穿" |
| 没有 control-fail | 无法区分"漏洞生效"与"本来就通" |
| 没写 limits | 单 worker 结果被当成生产可用 |
| unevaluated 写成 miss | 把"没测"说成"安全" |
| 打完不写文件 | web 端看不到，用户以为工作没做 |
