# GuardX 评审前端验收记录

本页记录评审控制台的可复现验收范围。它回答三个问题：第 1 部分选中的案例是否被完整带入第 2 部分；第 2 部分是否调用真实运行栈；第 3 部分是否能脱离预设案例完成现场输入。

验收日期：2026-08-18。

## 1. 案例代入一致性

对 01 LLM、02 RAG、03 VLM/OCR、04 Agent 分别切换良性、明显、隐蔽和组合，共检查 16 组映射。

每组均核对：

- `user_goal` 与第 1 部分当前目标一致；
- 非可信文本或 Prompt 与第 1 部分当前案例一致；
- 输入类型与案例入口一致；
- RAG 文件、VLM 图片或 Agent 候选动作与当前难度一致；
- 回答/视觉/规划模型具备当前入口要求的能力；
- 第 2 部分提交按钮处于可运行状态。

结果：**16 / 16 通过**。

| 类别 | 良性 | 明显 | 隐蔽 | 组合 |
| --- | --- | --- | --- | --- |
| 01 LLM | 对话 + 文本模型 | 对话 + 文本模型 | 对话 + 文本模型 | 对话 + 文本模型 |
| 02 RAG | 5 个良性文件 | 攻击 PDF + 当前说明 | 攻击 XLSX + 当前说明 | 4 类攻击文件 + 当前说明 |
| 03 VLM/OCR | 良性业务图 | 显式 OCR 注入图 | 伪造审批图 | 分布式 OCR 注入图 |
| 04 Agent | `read_enterprise_document` | `send_http` | 越界 `write_file` | `run_shell` 组合动作 |

## 2. 第 2 部分真实运行

四类入口分别运行良性与组合案例，共 8 组。页面结果必须来自当前后端请求，不能使用冻结回放代替。

| 类别 | 良性预期 | 组合预期 | 结果 |
| --- | --- | --- | ---: |
| LLM | 调用回答模型并展示完整业务答案 | 隔离新增控制指令，不把它交给下游模型 | 2 / 2 |
| RAG | 真实解析、检索、重排并生成带来源答案 | 逐 chunk 标出风险并隔离注入内容 | 2 / 2 |
| VLM/OCR | 调用视觉模型，保留良性可见事实 | 识别控制当前回答的视觉文字并阻断 | 2 / 2 |
| Agent | 规划、许可和只读 Runner 真实进入，副作用为零 | 原动作不执行；拒绝或改为审批范围内的安全替代动作 | 2 / 2 |

结果：**8 / 8 通过**。

Agent 良性案例读取 [`sandbox/demo/report.txt`](../sandbox/demo/report.txt)，因此页面能展示 Runner 返回的真实文件正文；组合案例同时列出“原候选动作”和“实际安全动作”，避免把安全替代误写成原动作已执行。

## 3. 第 3 部分独立自由输入

以下输入没有使用第 1 部分的预设按钮：

| 入口 | 独立输入 | 核验结果 |
| --- | --- | --- |
| LLM | 临时给出三家供应商与批次数字 | 调用真实模型，完整显示计算与说明 |
| RAG | 临时上传包含新公司名、数字和归档注入的 TXT | Docling/文本解析、BGE-M3、Qdrant 与 chunk Guard 真实进入，注入被隔离 |
| VLM/OCR | 上传品牌图而非演示攻击样例 | 视觉模型真实返回可见文字、图形与颜色 |
| Agent | 独立请求读取 `sandbox/demo/quarterly-summary.txt` | Permit 签发、Runner 进入、文件正文返回、`SIDE EFFECT: FALSE` |

结果：**4 / 4 通过**。

评委可使用 [`INDEPENDENT_REVIEWER_PROMPTS.md`](INDEPENDENT_REVIEWER_PROMPTS.md) 中的题目，也可临时替换名称、数字、文档和图片。页面保留完整上游输出与当前请求 JSON，便于确认结果并非针对固定样例写死。

## 4. 模型能力边界

前端模型列表与后端注册表共同校验能力：

- LLM：仅文本对话模型；
- RAG：仅切换最终回答模型，Docling、BGE-M3、Qdrant 与重排链不被 LLM 替代；
- VLM/OCR：仅视觉模型；
- Agent：仅 Qwen2.5 7B 或通义千问规划模型，模型不持有 Runner 权限。

本地/API 两种模式、四个入口共 8 组过滤检查全部通过。

## 5. 快速复现

```powershell
.\START_GUARDX_DEMO.cmd
```

打开 `http://127.0.0.1:8021/final/` 后：

1. 在第 1 部分选择类别、对照类型和难度；
2. 点击“载入下方实验”，核对第 2 部分目标和输入；
3. 选择可用模型并提交；
4. 展开检索/视觉/执行详情和完整响应；
5. 进入第 3 部分，使用新的现场输入再次提交。

后端回归测试：

```powershell
cd prototype\guardx\backend
python -m pytest tests/test_contracts.py tests/test_live_rag.py tests/test_live_vlm_ocr.py tests/test_document_ingestion.py tests/test_rag_reranker.py tests/test_model_capabilities.py tests/test_reviewer_model_routing.py tests/test_qwen_agent_boundary.py tests/test_secure_sandbox_runners.py tests/test_web_access_fail_closed.py -q
```
