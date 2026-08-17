# 防御评测用攻击案例与公开基准索引

生成日期：2026-04-23

## 存放策略

本目录用于后续防护成果对比实验。考虑到越狱 prompt 和有害请求可能被滥用，本项目默认只保存：

- 公开来源名称
- 论文/仓库链接
- 攻击类型
- 风险类别
- 是否适合做离线评测
- 我们系统应触发的防护动作

不在公开材料中直接保存可复用的高危提示词原文。若后续确需导入原始 benchmark，应放入受控目录并做脱敏展示。

## 已保存的公开基准 README

目录：`F:\srtp\信安赛\attack_cases\public_benchmark_readmes`

| 文件 | 来源 | 说明 |
|---|---|---|
| `JailbreakBench_README.md` | JailbreakBench | 开放越狱鲁棒性评测 |
| `JailbreakBench_artifacts_README.md` | JailbreakBench artifacts | 公开 artifact 说明 |
| `HarmBench_README.md` | HarmBench | 自动红队与拒答鲁棒性评测 |
| `llm_attacks_README.md` | llm-attacks/GCG | GCG 攻击代码仓库说明 |
| `Safety_Prompts_README.md` | THU Safety-Prompts | 中文/多类安全 prompt 资源说明 |
| `StrongREJECT_GitHub_README.md` | StrongREJECT | 越狱鲁棒性与拒答质量评测 |
| `XSTest_Paul_HF_README.md` | XSTest | 过度拒答/安全边界测试 |

说明：README 只用于了解数据结构和评测方式；原始高危样例不默认镜像到本项目。

## 建议纳入的攻击/案例类别

| 类别 | 典型来源 | 用途 | 我们的防护动作 |
|---|---|---|---|
| 直接越狱 | JailbreakBench, HarmBench | 测试单轮越狱拦截 | 输入拦截、风险解释、安全替代回答 |
| 拒答边界测试 | StrongREJECT, XSTest | 测试系统是否过度拦截正常请求 | 正常请求放行、危险请求拒答 |
| 自动化多轮越狱 | PAIR, TAP, Nature 2026 | 测试上下文风险累积 | 多轮风险评分、会话降权、拒答 |
| 对抗后缀/变体攻击 | GCG, AutoDAN | 测试规则绕过能力 | 语义检测、异常 token/混淆检测 |
| 违规内容获取 | OWASP taxonomy, HarmBench | 测试内容安全审计 | 输入和输出双侧审计 |
| 系统提示词泄露 | OWASP System Prompt Leakage | 测试提示词保护 | 拒绝泄露隐藏指令、审计日志 |
| RAG 间接注入 | AgentVigil, POISONCRAFT | 测试不可信上下文隔离 | 文档指令隔离、检索片段净化 |
| 敏感信息泄露 | OWASP Sensitive Information Disclosure | 测试隐私保护 | 脱敏、阻断外发、输出检查 |
| Agent 工具滥用 | OWASP Excessive Agency, OpenClaw docs | 测试行为沙箱 | 权限降级、人工确认、工具调用拦截 |
| MCP/插件攻击 | MCP toolchain attacks | 测试外部工具描述风险 | 插件描述审计、工具白名单 |
| 多模态越狱 | JailBreakV-28K | 后期扩展图文安全 | OCR/图文分类、输入审计 |

## 后续导入规则

1. 对每条原始样例建立 ID，不在文档中暴露完整原文。
2. 展示时只显示“攻击目标、风险类别、模型是否泄露/违规、系统是否拦截”。
3. 对高危输出只保存哈希、风险标签、截断片段和判定结果。
4. 对外展示视频中折叠危险内容，避免传播可操作细节。
5. 建议建立 `attack_cases/restricted_raw/`，该目录不上传、不公开、不放入答辩材料。
