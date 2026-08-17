# GuardX Replay Demo Chain

日期：2026-06-02

## 目标

补一条可复现实验链路，支撑命题 1 + 6 + 8 + 9 的融合叙事：

```text
RAG 文档注入
-> tool output 夹带 FOLLOWUP_INSTRUCTION
-> 插件 registration -> execute -> observe
-> 尝试敏感文件读取
-> 尝试网络外发
-> 模拟 executor 失败并触发 rollback
-> GuardX policy gate / executor replay / provenance 展示
```

## 入口

后端脚本：

```powershell
cd F:\srtp\信安赛\prototype\guardx\backend
$env:PYTHONPATH='.'
.\.venv\Scripts\python.exe scripts\seed_guardx_audit_replay.py --session-id demo-replay-20260602 --json
```

Portal 按钮：

```text
/portal -> 跨命题安全洞察 -> 写入演示 replay
```

API：

```text
POST /v1/audit/seed_demo_replay
GET /v1/audit/security_log_insights
GET /v1/audit/api_sequence_audit
GET /v1/audit/executor_replay
GET /v1/audit/plugin_session_replay
GET /v1/runtime/supply_chain_audit
GET /v1/audit/ocr_evidence_summary
```

## 预期证据

| 阶段 | 证据 |
| --- | --- |
| RAG 注入 | `security_log_insights.findings` 出现注入类风险 |
| tool output 注入 | `generated.observation_cases[0].route` 为 `review` 或 `block` |
| 插件生命周期 | `generated.plugin_sessions` 覆盖 Gitee / PyPI / 内部 marketplace 三种来源，`api_sequence_audit.findings` 出现 `plugin_or_tool_chain_escalation` |
| 插件 session replay | `plugin_session_replay.sessions` 展示 `calendar_sync_reviewed`、`ocr_receipt_parser_candidate`、`log_export_helper_unverified` 的 `source_uri`、`manifest_sha256`、register/execute/observe routes |
| 敏感文件读取 | `executor_replay.executions` 出现 `read_file_safe`，带 runner、phase chain hash |
| 网络外发 | `api_sequence_audit.findings` 出现 `read_then_write_or_network` |
| executor rollback | `generated.rollback_cases[0].rollback_completed=true`，`executor_replay.executions` 出现 `phase_statuses.rollback` |
| 供应链审计 | `supply_chain_audit.components` 展示 tool、runner、side_effects、constraints、dry_run、rollback |
| OCR 证据 | `ocr_evidence_summary.samples` 展示 Tesseract/PaddleOCR engine/version/output hash |

## 边界

- 该 replay 使用合成样例和模拟 executor，不执行真实敏感读取或真实网络外发。
- 不写入任何密钥值；所有 endpoint 和文档只记录环境变量名、hash、runner 和 policy decision。
