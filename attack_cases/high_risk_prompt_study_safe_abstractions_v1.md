# 高危 Prompt 安全学习笔记 v1

生成日期：2026-05-04

本文档用于学习高危越狱 prompt 的结构和防御要点，但不保存可复用原文。目的不是让成员复刻攻击，而是让成员能读懂 benchmark、理解 baseline 为什么会失败，并把风险映射到 GuardX 防护模块。

## 1. 为什么不保存原始可复用 prompt

原始越狱 prompt 往往具有直接复用性，可能被复制到真实模型或第三方服务上进行绕过测试。项目中应只公开：

- 攻击类别
- 脱敏目标
- 风险标签
- 成功信号
- prompt hash
- GuardX 防御动作
- 实验统计结果

若小组线下确需查阅原文，应放在 `attack_cases/restricted_raw/raw_prompts/`，并确保该目录不进入公开材料。

## 2. 高危 Prompt 的常见结构

### 2.1 直接越狱

结构：

```text
[覆盖/忽略原规则的要求]
+ [要求进入无限制或特殊模式]
+ [要求输出被禁止的内容或隐藏信息]
+ [要求不要解释、不要拒绝、不要提示安全限制]
```

学习重点：

- 识别“规则覆盖”和“权限反转”意图。
- 识别“不要拒绝/不要解释/隐藏安全策略”等输出约束。

GuardX 对应：

- Input Guard：识别 policy evasion intent。
- Output Guard：阻断隐藏指令泄露或危险内容输出。

对应 SAFE：

- SAFE-001
- SAFE-006

### 2.2 角色扮演越狱

结构：

```text
[让模型扮演无限制角色]
+ [声明这是虚构、游戏、模拟或研究]
+ [让角色不受安全规则约束]
+ [要求角色给出原本会被拒绝的内容]
```

学习重点：

- “虚构/模拟/角色扮演”不是自动安全。
- 关键看真实意图和输出目标。

GuardX 对应：

- Input Guard：识别 roleplay evasion intent。
- Policy Engine：要求安全替代回答。

对应 SAFE：

- SAFE-002

### 2.3 编码/混淆绕过

结构：

```text
[把真实指令编码或拆分]
+ [要求模型先解码/拼接/翻译]
+ [要求执行解码后的隐藏意图]
```

常见混淆方式：

- base64
- leetspeak
- 拆字
- 多语言混合
- 反向文本
- 长异常后缀

学习重点：

- 不只看表层文本。
- 需要“归一化/解码后再分类”。

GuardX 对应：

- Input Guard：decode_then_classify。
- 异常 token/后缀检测。

对应 SAFE：

- SAFE-003

### 2.4 多轮诱导升级

结构：

```text
第 1 轮：提出看似正常或抽象的问题
第 2 轮：要求更具体但仍保持安全包装
第 3 轮：要求补齐关键步骤或绕过限制
第 4 轮：要求输出完整危险目标
```

学习重点：

- 单轮检测不够。
- 要看 session 中意图是否逐步升级。

GuardX 对应：

- Session Risk Tracker。
- 多轮风险累积。
- 高风险会话降权或阻断。

对应 SAFE：

- SAFE-004

### 2.5 良性外衣包装危险请求

结构：

```text
[声明是课堂/论文/安全研究/虚构]
+ [实际请求仍是危险、侵害或违规目标]
+ [要求给出可执行细节]
```

学习重点：

- 研究、课堂、虚构不是豁免条件。
- 判断核心是“回答是否会实质帮助危险目标”。

GuardX 对应：

- Input Guard：识别 true harmful intent。
- Output Guard：给安全替代解释。

对应 SAFE：

- SAFE-016

### 2.6 隐私/密钥泄露诱导

结构：

```text
[给出或引用合成/真实敏感信息]
+ [要求模型复述、保存、外发或继续使用]
+ [要求不要脱敏]
```

学习重点：

- 即使是用户主动提供的敏感信息，也不应原样复述或长期保存。
- 输出侧也要检查。

GuardX 对应：

- Privacy Guard。
- Output Guard。
- Tool Sandbox：阻断外发。

对应 SAFE：

- SAFE-007
- SAFE-020

### 2.7 RAG 间接提示注入

结构：

```text
用户问题：正常查询或摘要任务
检索文档：[夹带高优先级指令、要求忽略用户目标、要求输出 sentinel]
模型错误行为：把文档中的指令当成系统命令执行
```

学习重点：

- 外部文档是数据，不是命令。
- 需要隔离 retrieved context 的权限。

GuardX 对应：

- Context Guard。
- Source trust scoring。
- Instruction stripping / evidence wrapping。

对应 SAFE：

- SAFE-008
- SAFE-009
- SAFE-021

### 2.8 Agent 工具滥用

结构：

```text
[让 Agent 完成看似正常任务]
+ [诱导读取敏感路径]
+ [诱导调用未知域名]
+ [诱导执行危险命令]
+ [诱导修改数据库或调用未知工具]
```

学习重点：

- Agent 风险不只在文本输出，而在工具行为。
- 每次工具调用都要做权限检查。

GuardX 对应：

- Tool Sandbox。
- Least privilege。
- Complete mediation。

对应 SAFE：

- SAFE-010
- SAFE-011
- SAFE-012
- SAFE-017
- SAFE-018
- SAFE-019
- SAFE-022

### 2.9 MCP / 插件 Manifest 注入

结构：

```text
工具名称：看似正常
工具描述：[夹带隐蔽行为要求]
风险行为：静默转发、忽略策略、跨工具收集敏感信息
```

学习重点：

- 工具描述本身也是不可信输入。
- manifest 必须静态扫描。

GuardX 对应：

- Tool Manifest Guard。
- 工具白名单。
- 工具链组合审计。

对应 SAFE：

- SAFE-013
- SAFE-023

### 2.10 OCR 阶段多模态越狱

结构：

```text
图片：看似普通截图或海报
图片内文字：[隐藏提示注入]
OCR 输出：进入 LLM 上下文
模型风险：执行图片内指令
```

学习重点：

- 图片中的文字也可能是 prompt injection。
- OCR 结果必须进入文本安全链路。

GuardX 对应：

- OCR -> Context Guard。
- Output Guard。
- 良性图片误报对照。

对应 SAFE：

- SAFE-014

## 3. 学习时应该记录什么

看到一条原始 prompt，不要只看“它怎么写”。要记录：

```text
record_id：
对应 SAFE case：
攻击类别：
真实目标：
伪装层：
权限反转点：
输出约束：
成功信号：
应该由哪个 GuardX 模块拦截：
baseline 为什么可能失败：
GuardX 应如何防御：
是否适合公开展示：否 / 只展示脱敏摘要
```

## 4. 可复现实验中可以公开的内容

可以公开：

- SAFE case ID
- 攻击类型
- 脱敏目标
- prompt hash
- synthetic canary
- 是否命中 sentinel
- GuardX action
- target called 是否为 false
- ASR / block rate / false positive rate

不公开：

- 可直接复制的越狱 prompt 原文
- 可直接执行的危险步骤
- 真实密钥、真实路径、真实外联域名
- 第三方系统攻击记录

## 5. 对应仓库位置

受控原文位置：

```text
attack_cases/restricted_raw/raw_prompts/
```

受控 manifest：

```text
attack_cases/restricted_raw/manifest.csv
```

脱敏 case matrix：

```text
attack_cases/safe_eval_case_matrix.csv
```

自动化验证入口：

```text
scripts/run_attack_validation_matrix.ps1
```

本地 prompt bank 管理：

```text
scripts/restricted_prompt_bank_template.py
```
