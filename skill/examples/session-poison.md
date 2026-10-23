# 案例二：session.upload_progress 投毒 —— 应用层链，**无 CVE**

> CWE-98 / CAPEC-253。这条案例的价值恰在于：**大部分产品打不穿**，
> 而证明"打不穿"同样需要严格方法。

## S1 线索归一

线索只有一句：`session.upload_progress` 投毒 LFI → RCE。

链条拆分：

1. multipart 请求含 `PHP_SESSION_UPLOAD_PROGRESS` 字段 → PHP 把**字段值原样**写进 session 文件
2. 写成 session 的**键名**：`upload_progress_<攻击者可控值>`
3. 发生在 **request startup 阶段、用户代码之前**——应用不调用 `session_start()` 也照样落盘
4. 值里塞 `<?php ... ?>` → 落在 `<save_path>/sess_<sid>`
5. 应用若有用户可控 `include()` → 当作 PHP 代码执行

落盘实测：

```
upload_progress_<?php echo "PWNED:"; system(base64_decode("aWQ=")); ?>|a:5:{s:10:"start_time";i:179...
```

---

## S2 前提判定（本例最重要的一步）

两个前提，成本天差地别：

| 前提 | 内容 | 实测结论 |
|---|---|---|
| ① | `session.upload_progress.enabled=1` + `save_handler=files` | **几乎免费**：11/11 产品全部默认满足（PHP 官方默认值） |
| ② | 存在用户可控路径的 `include()`/`require()` | **真正的门槛**：12 个真实产品全部缺失 |

**这正是本系列最重要的方法论收获**：前提①免费 → 投毒对所有 PHP 站点成立；
但升级为 RCE 必须靠前提②。

---

## S3 产品筛查（14 个应用）

### 打通的两个（都是刻意做出来的漏洞靶场）

| 应用 | 镜像 | 汇点 | 结果 |
|---|---|---|---|
| **DVWA v1.10** | `vulnerables/web-dvwa` | `?page=` 无过滤 | 🎯 RCE 打通 |
| **bWAPP v2.2** | `raesene/bwapp` | `?language=` 无过滤 | 🎯 RCE 打通 |

### 全部不可用的真实产品

WordPress / Drupal / MediaWiki / phpMyAdmin / Kanboard / Roundcube / PrestaShop
——**前提①全部满足，前提②全部缺失**。

源码验证（均返回空）：

```bash
grep -rn 'include\s*(\s*\$\|require\s*(\s*\$' <docroot> --include='*.php' \
  | grep -iE '_GET|_POST|_REQUEST|_COOKIE'
```

原因：成熟框架用 router 分发，不会把 `$_GET['x']` 直接喂给 `include`。

### 三个"看起来有戏"但被防护住的（值得学习）

| 产品 | 防护 | 结果 |
|---|---|---|
| Discuz! | 正则白名单 `/^[\w\d\/_]+$/i`（点号不在内）+ 强制拼 `.php` + `realpath()` 三重 | ❌ 三种穿越全被拦 |
| DedeCMS | `strlen($art_shortname) > 6` 直接 exit，写不下 `../../../..`（需 9 字符） | ❌ 长度卡死 |
| PHPCMS | 走 `template()` 映射表，用户输入不直达 include | ❌ 无直接拼接 |

### 未能评估（**不可**计入否定结论）

Monica（容器启动即退出）、Typecho（镜像不存在）、EMlog（拉取失败）、
OSPOS / Shopware / Moodle（超时）、Lsky Pro（前提①无法确认）、群晖 DSM（不用文件 session）。

---

## S4 靶场

### 命名空间隔离（必做）

本机曾同时存在别的 PHP 靶场，故全部资源带 `sp-` 前缀：

| 资源 | 本项目 | 其他靶场 |
|---|---|---|
| 容器 | `sp-8234` `sp-8335` `sp-8511` `sp-8512` `sp-hard` | `p8234` / `p2shell-target` |
| 端口 | 19234 / 19335 / 19511 / 19512 / 19650 | 18xxx |
| 清理 | `sp_lab_down.sh` **只删 `sp-*`** | — |

### 配置矩阵

| 容器 | 镜像 | cleanup | strict | 说明 |
|---|---|---|---|---|
| `sp-8234` | `php:8.2.34-apache` | 0 | 0 | 投毒留存，可直接打 |
| `sp-8335` | `php:8.3.35-apache` | 0 | 0 | |
| `sp-8511` | `php:8.5.11-apache` | 0 | 0 | |
| `sp-8512` | `php:8.5.12-apache` | 0 | 0 | 修复版对照 |
| `sp-hard` | `php:8.2.34-apache` | **1** | **1** | 最严苛，仅竞态可打 |

---

## S5 两个关键实测结论（推翻常见误解）

### 结论 1：`cleanup=0` **不是**必要条件

| 配置 | 常规模式 | 竞态模式 |
|---|---|---|
| `cleanup=0` | ✅ | ✅ |
| `cleanup=1`（**官方默认**） | ❌ | ✅ |

真实世界绝大多数部署用默认 `cleanup=On`，所以**竞态才是更贴近实际的路径**。
手法：慢速上传拉长窗口 + 并发抢读（`--filler 40`、`--racers 8`）。
已在 PHP 7.4 / 8.2 / 8.3 / 8.5.12 上验证。

### 结论 2：`use_strict_mode=1` **不能**阻断

常被误列为缓解措施。实测：

```
上传时 SID 被服务端替换 → Set-Cookie 把新 SID 直接回显
→ payload 仍落在 sess_<新SID> → include 成功执行
```

strict mode 只让文件名"不可预测"，而响应头当场就告诉了攻击者。
所以 exp 实现**自适应 SID**：检测到 SID 被替换时自动改用服务端返回的那个。

---

## S6 真实应用验证细节

### DVWA

```bash
docker run -d --name dvwa -p 127.0.0.1:19906:80 vulnerables/web-dvwa
# 改 /etc/php/7.0/apache2/php.ini：session.upload_progress.cleanup = 0
# 注意该行行首有 ';'，sed 要匹配 ^;
```

穿越深度：docroot `/var/www/html/vulnerabilities/fi/` → 需 `../../../../../` 到 `/`。

### bWAPP

```bash
# 必须改 /etc/php5/apache2/php.ini（Apache 不读 cli/php.ini）
# 先 DROP DATABASE bWAPP 再访问 install.php?install=yes
```

### 攻击顺序（易错点）

两个靶场的 LFI 模块都要登录后访问，但**投毒可在未登录状态完成**
（upload_progress 在 startup 阶段执行）。真实顺序：

**先匿名投毒 → 再拿到会话 → 最后触发**

---

## S7 结论与边界

### 已验证

- DVWA / bWAPP 上完成「投毒 → LFI → RCE」全链
- `cleanup=1` 下竞态模式可绕过（PHP 7.4 / 8.2 / 8.3 / 8.5.12）
- `use_strict_mode=1` 不构成阻断

### 未验证 / 已知限制

- 未在真实生产站点验证（无授权目标）
- 部分产品因镜像问题**未能评估**，不等于不可利用

### 真实目标画像

不是主流 CMS/框架，而是**手写 PHP 的老式应用**：
`?page=` / `?mod=` / `?tpl=` / `?lang=` 拼路径那种。DVWA 和 bWAPP 能打通，
正因它们刻意还原了这种写法。

### 缓解措施（逐条实测）

| 措施 | 有效性 |
|---|---|
| `session.upload_progress.enabled = 0` | ✅ **唯一有效**（实测：不再产生 session 文件） |
| 修复所有用户可控 `include()` | ✅ 根因治理 |
| `session.use_strict_mode = 1` | ❌ **无效**（Set-Cookie 回显新 SID） |
| `session.upload_progress.cleanup = 1` | ❌ **无效**（竞态可绕过） |
| 限制 `save_path` 目录权限 | ⚠️ 仅削弱 |

### CVE 归属

**没有分配 CVE。** PHP 侧是文档化设计行为；危害来自应用使用了不安全 include，
属 CWE-98，应挂到目标应用自己的漏洞下。详见 [scoring.md](../reference/scoring.md)。
