# GuardX 真实来源推进卡片

日期：2026-06-02

## 用途

本文件把长 RAG、OCR/VLM、tool-output injection、中文 decoder probe、provenance / executor replay 的来源固定下来，便于后续 gs/zlb/zzh 继续扩展时保持可引用、可复现、可审计。

## 来源总表

| source_id | 来源 | URL | 用途 | 落地方式 | 注意 |
| --- | --- | --- | --- | --- | --- |
| `src_owasp_llm_top10` | OWASP Top 10 for LLM Applications | `https://owasp.org/www-project-top-10-for-large-language-model-applications/` | 长 RAG 安全文档正文、prompt injection / tool misuse / supply-chain 语境 | 只摘取主题和术语，正文由 GuardX 改写；攻击附录自行合成 | 不复制大段原文 |
| `src_nist_ai_rmf_genai` | NIST AI RMF / Generative AI Profile | `https://www.nist.gov/itl/ai-ri%73k-management-framework` | 治理、合规、风险管理长文档 | 用作 RAG 正文风格和治理字段参考 | 引用来源，避免长段粘贴 |
| `src_agentdojo` | AgentDojo | `https://github.com/ethz-spylab/agentdojo` | Agent 工具调用、prompt injection 任务参考 | 参考任务结构，GuardX 自写 tool observation payload | 不直接复制测试集输出 |
| `src_injecagent` | InjecAgent | `https://github.com/uiuc-kang-lab/InjecAgent` | indirect prompt injection、attacker tool / user tool 思路 | 参考攻击链形态，GuardX 自行合成 case | 不使用真实密钥或真实用户数据 |
| `src_garak` | garak | `https://github.com/NVIDIA/garak` | LLM vulnerability scanner payload 风格 | 作为 red-team taxonomy 参考 | 只记来源和攻击类别 |
| `src_promptfoo_agents` | promptfoo agent red-team docs | `https://www.promptfoo.dev/docs/red-team/agents/` | repository / terminal output / secret env read / sandbox escape 风格 | 参考类别，自写 repo_scan/log_scan/npm audit 风格输出 | 不复制危险可执行步骤 |
| `src_docvqa` | DocVQA | `https://www.docvqa.org/datasets/docvqa` | 文档图像、版面、OCR evidence | 下载后记录 image hash、OCR hash、许可和下载时间 | 大文件不入仓 |
| `src_funsd` | FUNSD scanned forms | `https://guillaumejaume.github.io/FUNSD/` | 表单 OCR、noisy scanned form | 作为表单版面来源，隐藏文本由 GuardX 合成 | 不使用真实 PII |
| `src_cord` | CORD receipt dataset | `https://github.com/clovaai/cord` | 票据 OCR、隐私字段样例 | 用 receipt 版式，字段全部合成 | 不使用真实手机号/证件号 |
| `src_paddleocr` | PaddleOCR | `https://paddlepaddle.github.io/PaddleOCR/` | OCR 工具与版本记录 | 记录 OCR engine/version/output hash | OCR 输出可入摘要，不入敏感全文 |
| `src_tesseract` | Tesseract OCR | `https://tesseract-ocr.github.io/` | OCR 复现工具备选 | 记录 engine/version/output hash | 同上 |
| `src_clue` | CLUE benchmark | `https://github.com/CLUEbenchmark/CLUE` | 中文 decoder / embedding probe | 只提交 hash 与聚合指标；可先用自写中文安全短文 smoke | 不提交 decoder 重构明文 |
| `src_cmrc2018` | CMRC 2018 | `https://hfl-rc.github.io/cmrc2018/` | 中文阅读理解段落级 decoder probe | 下载后记录数据版本、hash、聚合指标 | 遵守数据集许可 |
| `src_w3c_prov` | W3C PROV | `https://www.w3.org/TR/prov-overview/` | provenance entity/activity/agent 字段 | 映射 source、tool、runner、artifact 关系 | 作为字段依据 |
| `src_otel_genai` | OpenTelemetry GenAI semantic conventions | `https://opentelemetry.io/docs/specs/semconv/gen-ai/` | LLM / agent / tool trace 字段 | 映射 trace/span/model/tool fields | 作为字段依据 |
| `src_slsa_provenance` | SLSA Provenance | `https://slsa.dev/spec/v1.1/provenance` | 构建/工具来源与 artifact 证明 | 映射 builder、materials、invocation | 作为供应链字段依据 |
| `src_cyclonedx_provenance` | CycloneDX provenance use case | `https://cyclonedx.org/use-cases/provenance/` | SBOM / package provenance | 映射 purl、supplier、component、externalReferences | 作为供应链字段依据 |

## 样例改造规则

| 类型 | 允许 | 禁止 |
| --- | --- | --- |
| 长 RAG | 使用公开来源主题和术语，GuardX 自写正文和恶意附录 | 粘贴大段外部原文、真实内部文件 |
| OCR/VLM | 使用公开图片版面或自制图片，隐藏文字和 PII 全部合成 | 使用真实身份证、手机号、学生信息 |
| Tool output | 使用公开工具输出格式作为外壳，自写注入段 | 运行真实外发命令、记录真实 token |
| 中文 decoder | 使用 CLUE/CMRC 或自写中文安全短文，提交 hash 和聚合指标 | 提交原文、重构明文、成员私人文本 |
| provenance | 记录 source_uri、hash、runner、capability、side_effects | 把 API key、完整请求正文写入字段 |

## 当前已落地

- `configs/experiment_suites.json` 增加 `guardx_source_inspired_probe`。
- `configs/provenance_field_schema.json` 固定 source / executor / supply-chain 字段。
- `configs/chinese_decoder_probe_samples.json` 固定中文 decoder smoke 样例元数据与 hash-only 约束。

## 后续分工

| 成员 | 下一步 |
| --- | --- |
| gs | 根据 DocVQA/FUNSD/CORD 或自制图片补 image hash、OCR engine、OCR output hash。 |
| zlb | 根据 provenance schema 给 executor replay 增加 source、runner、capability、artifact 字段。 |
| zzh | 维护 source cards、suite 映射和聚合实验摘要。 |
