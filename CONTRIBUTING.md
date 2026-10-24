# 参与贡献

欢迎提 issue 和 PR。这个项目的核心价值是**可信的结论**，所以对贡献的要求也围绕这一点。

## 最有价值的贡献

1. **新增案例**（`dashboard/data/cases/*.json`）
   按 [skill/reference/casefile.md](skill/reference/casefile.md) 的 schema 填写。
   必须包含**修复版对照**（`control-fail`），否则只能写"疑似"。
2. **新增门禁规则**（`bin/preflight.py`、`bin/casefile.py`）
   如果你发现了"结果不可靠"的新根因，把它变成一条可执行的检查，比写文档更有用。
3. **修正一个不实的结论**
   如果某个案例里的成功率、版本号或边界说错了，直接指出并附证据——这是最高优先级。
4. **可移植性修复**
   在别的机器 / OS / 架构上跑不通，属于 bug。请在 issue 里写明环境。

## 提交前自检

```bash
# 1) 测试必须全绿（不需要 Docker）
python3 tests/run_tests.py

# 2) 案例文件必须通过校验
python3 bin/casefile.py validate

# 3) 环境检测不应有 FAIL
python3 bin/preflight.py
```

## 案例编写纪律

- **`unevaluated` ≠ `miss`**：没测成不等于不可利用，别把"镜像拉不下来"写成"安全"。
- **单产品不构成结论**：至少 1 个漏洞版 + 1 个修复版。
- **成功率写 N/N**，不要只写"成功"。
- **单 worker 结果不外推生产**，必须写进 `limits`。
- 未知就留空，**不要编造**。

## 代码风格

- Python 走标准库，**不引入第三方依赖**（保证任何机器 `python3` 就能跑）。
- dashboard 是零框架的 Node，不要引入构建链。
- 注释写"为什么"，不写"是什么"。

## License

提交 PR 即表示你同意以本仓库的 [MIT License](LICENSE) 授权你的贡献。
