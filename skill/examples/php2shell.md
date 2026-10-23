# 案例一：PHP2Shell —— 引擎级内存安全 CVE

> CVE-2026-109618 / CVE-2026-109619，CVSS v4.0 9.2，CWE-416。
> 参照实现，不是模板。

## S1 线索归一

修复提交 `31c0ea7d` 的 diff 说明一切：

```
Fix GHSA-w8hw-w9fx-j79w (CVE-2026-109618)
Fix GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)
- Replace bailout on OOM with UnwindExit
- Properly reset various globals that may be accessed during startup
```

`Zend/zend_alloc.c` **+527 / −124**：OOM 的 `longjmp` 换成 `UnwindExit`，
引入 `zend_oom_info` 状态机与 `femalloc/fecalloc/ferealloc` 可失败分配。

修复版本（按分支，不要只记一个）：

| 分支 | 修复版本 |
|---|---|
| 8.5.x | 8.5.12 |
| 8.4.x | 8.4.27 |
| 8.3.x | 8.3.36 |
| 8.2.x | 8.2.35 |

---

## S2–S3 产品/版本矩阵与镜像

### latest 全线失效（核心坑）

漏洞公布后官方镜像重建了所有标签，内置 PHP 全部**恰好等于修复版本号**：

| 镜像 | 内置 PHP | 状态 |
|---|---|---|
| `wordpress:php8.2-apache` | 8.2.35 | 已修复 |
| `drupal:10-apache` | 8.4.27 | 已修复 |
| `mediawiki:lts` | 8.3.36 | 已修复 |
| `joomla:latest` | 8.4.27 | 已修复 |
| `phpmyadmin:latest` | 8.3.36 | 已修复 |

必须找 2026-10 之前构建的旧标签。

### 最终打穿的产品（5/5 全部成功）

| 产品 | 可用标签 | 内置 PHP |
|---|---|---|
| WordPress | `wordpress:6.8-php8.4-apache` | 8.4.15 |
| Drupal | `drupal:10.5-php8.4-apache` | 8.4.23 |
| Joomla | `joomla:6.1.2-php8.4-apache` | 8.4.24 |
| MediaWiki | `mediawiki:1.45` + `php:8.4.15-apache` | 8.4.15 |
| phpMyAdmin | `phpmyadmin:5.2.3-apache` + `php:8.4.15-apache` | 8.4.15 |

后两个产品没有官方 PHP 8.4 标签，用「官方 PHP 基础镜像 + 应用源码叠加」。

---

## S4 前提判定：几乎免费

基准靶场的应用代码只有 `<?php echo "OK\n"; ?>`，**无任何 LFI / 应用层漏洞**，
依然 3/3 打穿。这说明它是**引擎自身缺陷**，不需要应用层前提——可以放心投入。

---

## S5 靶场与判据

### 四条缺一不可的配置

| 配置 | 值 | 不设会怎样 |
|---|---|---|
| `memory_limit` | `8M` | 触发不到 OOM |
| `output_buffering` | `0` | Drupal 镜像默认 true，泄露窗口被破坏 |
| `max_input_vars` | `10000000` | 默认 1000 截断 513+ 字段 |
| 单 worker prefork | `MaxRequestWorkers 1` | 跨请求命中不同进程 |

### 极简判据（强烈推荐）

| PHP 版本 | cookie 泄露 | 判定 |
|---|---|---|
| 8.4.15 / 8.4.23 / 8.4.24 / 8.4.26 / 8.5.11 | **600000 B** | ★ 可利用 |
| 8.3.35 / 8.3.36 / 8.2.28 / 8.1.34 / 8.0.30 | 32 B | 不可利用 |
| 7.4.33 | 32 B（OOM 都没触发） | 不可利用 |

**≈32 字节 = 不可用；≈600000 字节 = 可打穿。**

7.x / 8.2.x / 8.3.x 上这条链结构上不成立（leak 阶段就失败）。

### 对照结果

| 镜像 | 结果 |
|---|---|
| `php:8.4.26-apache` | **3/3 成功，拿到 `uid=33`** |
| `php:8.4.27-apache` | **3/3 在地址泄露阶段失败** |

---

## S6 两个真实踩过的坑

### 坑 1：模块指针识别

原 exploit 用「指针低 12 位 == `zval_ptr_dtor` 低 12 位」识别模块基址。
但 8.4.15 上泄露的是**函数内部地址**：

```
真实基址:  0x79ff72b94000
泄露指针:  0x79ff731d142b
差值:      0x63d42b   (dtor = 0x63d420，多出 0xb)
```

修正：允许 `dtor` 附近小窗口（0..0x3F）+ 基址 4KB 对齐筛选。

```python
MODULE_POINTER_DELTAS = tuple(range(0, 0x40))
for delta in MODULE_POINTER_DELTAS:
    base = pointer - dtor_offset - delta
    if base & 0xFFF == 0:
        modules[base] += 1
```

### 坑 2：`output_buffering` 破坏泄露窗口

```
output_buffering=true  → cookie=32B      无泄露
output_buffering=0     → cookie=600000B  ★ 泄露成立
```

打 Drupal 必须显式设 `output_buffering=0`。

### 坑 3：ASLR 基址范围硬编码

原 exploit 假设库地址以 `0x7f` 开头：

```python
if 0x7F0000000000 <= pointer < 0x800000000000:   # 错误假设
```

实际容器里 `libphp.so` 映射在 `0x72742a7d3000`（**0x72 开头**），真实指针全被过滤。
改成 `0x550000000000 <= pointer < 0x800000000000` 后首次即成功。

**教训**：先读目标 `/proc/<pid>/maps` 的实际布局，不要相信经验值。

### 坑 4：入口选择（phpMyAdmin）

| 入口 | cookie | 原因 |
|---|---|---|
| `/index.php` | 0 B | `common.php` 调用 `session_start()` |
| `/js/messages.php` | 0 B | 注册 shutdown function，与 OOM 清理冲突 |
| **`/show_config_errors.php`** | **600000 B ★** | 只 include 配置，不启动 session |

---

## S7 结论与边界

### 已验证

- 官方 `php:8.4.26-apache` 上 pre-auth RCE，单 worker / `memory_limit=8M`，**3/3 稳定**
- 修复版 `php:8.4.27-apache` **3/3 失败**
- 5 个真实产品（WordPress/Drupal/Joomla/MediaWiki/phpMyAdmin）全部打穿
- 两处 100% 稳定的版本差异（ASAN 构建，各 5/5）

### 未验证 / 已知限制

- **多 worker 生产环境**：命中率显著下降（公开测试 5-worker：leak 6/10、fire 0/20），需 worker saturation
- **其他 PHP 版本**：8.3.x 结构上不可用；8.5.x 需重新校准 layout
- `memory_limit=128M` 内置参数但**本仓库仅实测 8M**
- **纯黑盒**：当前需本地 `libphp.so` 提取符号偏移
- 单次 RCE 限 **14 字节**，长命令需 stager

### 缓解措施

官方明确：**这些只是降低风险，唯一彻底的方案是升级 PHP。**

CVE-2026-109618（OOM 路径）：
- `memory_limit = -1`（放 FPM pool 的 `php_admin_value`，防应用改回）
- `post_max_size` 收紧，保证 `upload_max_filesize < post_max_size`
- cgroup 内存限制兜底（**不要**用 `RLIMIT_AS`/`RLIMIT_DATA`）

CVE-2026-109619（陈旧全局状态）：
- `session.upload_progress.enabled = 0`，写进 php.ini / pool 配置后**重启 worker**
- PHP 8.5 再加 `fatal_error_backtraces = 0`
