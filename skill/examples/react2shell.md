# 案例三：React2Shell — 反序列化 CVE

> CVE-2025-55182，CVSS 9.8 / 10.0，CISA KEV 已收录。
> 价值：**零应用前提**的组件级缺陷，以及一条干净的单步因果边界。

## S1 线索归一

直接核对 npm registry 与修复提交，**纠正了一条广泛误传**：

| 项 | 内容 |
|---|---|
| 受影响 | `react-server-dom-webpack/parcel/turbopack` 19.0.0 / 19.1.0 / 19.1.1 / **19.2.0** |
| 修复 | 19.0.1 / 19.1.2 / **19.2.1**（均在 2025-12-03 的 6 分钟内发布） |

**误传**：`14.2.35 / 15.0.8 / 15.1.12 / 16.0.11` 那一串是 12-11 的 **DoS** 修复线
（CVE-2025-55184 / -55183），**不是**本次 RCE。

RCE 的真实修复线：`15.0.5 / 15.1.9 / 15.2.6 / 15.3.6 / 15.4.8 / 15.5.7 / 16.0.7`。

**`next@14.2.x` stable 不受影响**——其 `dist/compiled` 里没有 Flight reply 解析器。
拿它搭靶场只会得到**必然的假阴性**。

## 根因

反序列化器信任了 JSON 里"描述响应对象自身"的字段：

1. `_response._prefix` / `_formData` / `_chunks` 被打包进模型
2. `"then":"$1:__proto__:then"` 污染 `Object.prototype.then`，使普通对象被当作 thenable
3. `_formData.get` 解析成 `$1:constructor:constructor` → 沿原型链拿到 **`Function`**
4. `_prefix` 作为函数体交给 `new Function(...)` → 进程内任意 JS

19.2.1 三处修复：`hasOwnProperty` 守卫、`__proto__` 特殊处理、
`Chunk._response` 改为 `RESPONSE_SYMBOL` 私有符号。

## S2 干净的单步因果边界

`15.5.4` 与 `15.5.6` 的 Flight 反序列化器**字节完全相同**（同 sha256），
所以 `15.5.6` → `15.5.7` 是单步因果，而不是"两个版本恰好标记数相同"。

| marker | 15.5.4 | 15.5.6 | 15.5.7 |
|---|---|---|---|
| `initializingChunkBlockedModel` | 10 | 10 | **0** |
| `Chunk.prototype.then` | 1 | 1 | **0** |
| `chunk._response` | 1 | 1 | **0** |
| `resolveModelChunk`（同模块对照） | 4 | 4 | 4 |

## S4 前提判定：组件自身缺陷

三条实验证据（不是引述）：

1. **最小引擎宿主**：只调用 `decodeReply()`，无框架无应用代码 → 19.2.0 **5/5**，19.2.1 **0/5**
2. **零 Server Action 的真实产品**：manifest 为空、`grep 'use server'` 零命中 → 仍 **5/5 root**
3. **代码路径**：`decodeReplyFromBusboy()` 在 `getActionModIdOrError()` **之前**执行，
   动作表为空也拦不住反序列化

关闭的反例风险：

- 路径扫描 `/`、`/favicon.ico`、`/api/whatever`、`/nonexistent-deep/path` 均可打 → 端点不是门槛
- 去掉 `Next-Action` 头 → **0/3**，故该头必须存在，但**其值任意**（用 `x` 即可）

## S5 结果

| 目标 | 结果 |
|---|---|
| next 15.5.4 noaction | **5/5 root** |
| next 15.5.4 withaction | 3/3 |
| next 15.5.6 noaction | 5/5 |
| next 15.5.7（相邻修复） | **0/5** |
| next 15.5.10（修复） | 0/5 |
| 引擎 19.2.0 / 19.2.1 | 5/5 / 0/5 |

**判定口径**：成功只以容器内出现含 `id` 输出的文件为准，**绝不以 HTTP 状态码为准**。
中毒 thenable 会让响应永久挂起 —— 这是**症状**不是证据。

修复版对同一请求返回 404 且立即返回（0.01s），不挂起，说明连反序列化都没进去。

## S6 shell

已交付持久 `/bin/sh -i`（`cd`、环境变量跨命令保留），打穿用户为 **root**
（官方 `node:22-bookworm-slim` 默认 root 跑 `next start`）。

## S7 边界

- **单 worker**：无 cluster / 反向代理 / WAF，不可外推生产
- `/404` 路径未命中（路径扫描 4/5），原因未查明
- 仅测 Node.js runtime；Edge、parcel、turbopack、waku、rwsdk 未实测
- 未测 standalone 输出、nginx 前置、多副本负载均衡
- 反向 shell 依赖容器回连 docker bridge 网关，真实环境出网常受限
- gadget 只验证了 `process.mainModule.require('child_process')` 一条

## CVE 归属

组件：**CVE-2025-55182**。
Next.js 侧的 CVE-2025-66478 **已被 REJECT**，是重复项；
依赖扫描器漏报是因为 Next.js vendor 了 React，归属仍挂 -55182。
