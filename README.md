# GuardX 大模型智能体安全控制面

GuardX 面向 LLM、RAG、VLM/OCR 与 Agent 四类入口，在统一控制链中完成来源标注、风险发现、任务关系判断、策略决策、执行许可和证据封存。仓库包含后端服务、策略配置、评审前端、演示样例与自动化测试。

## 快速体验

评审前端不设置账号或登录步骤。完成下方“本地启动”的依赖准备后，Windows 用户双击仓库根目录的 `START_GUARDX_DEMO.cmd`，服务就绪后浏览器会自动打开：

```text
http://127.0.0.1:8021/final/
```

页面提供两个入口：

- **系统展示**：查看 LLM、RAG、VLM/OCR、Agent 的统一控制链与可核验证据。
- **实时演示**：按 01–04 运行标准样例，或在实验台提交自主输入。

公开仓库可直接浏览；运行服务和浏览评审前端均不需要创建 GuardX 账号。

前端运行地址独立配置在 `reviewer_console/assets/runtime-config.js`。同源部署保持空值；前后端分离时只修改 `apiBaseUrl`，不需要改动业务脚本。容器启动端口读取标准 `PORT` 环境变量，可接入基于 GitHub 主分支的自动部署与预览环境。

每次推送或提交 Pull Request 后，GitHub Actions 会自动检查前端 JavaScript、运行后端合同测试并构建部署容器。前端修改可以先在分支预览，确认后合并到 `main` 发布正式版本。

## 核心能力

| 入口 | 运行组件 | 演示结果 |
| --- | --- | --- |
| LLM | Input Guard + Qwen2.5 任务关系裁判 + 本地/国内 API 模型 | 良性请求返回真实模型答案；任务劫持在下游模型调用前隔离 |
| RAG | Qdrant + BGE-M3 + Context Guard | 展示真实 Top-K 召回、chunk 来源、逐段关系判断与安全回答 |
| VLM/OCR | Qwen2.5-VL 7B + OCR 转写 + 任务关系裁判 | 区分视觉事实、业务文字与面向模型的输出控制 |
| Agent | Action Guard + Execution Permit + 本地只读沙箱 | 良性文件读取真实执行；越权工具请求在 Runner 前阻断 |

任务关系裁判只产生语义证据与 `RiskFinding`，不持有工具权限，也不直接决定放行。最终路由由服务端策略和确定性授权边界共同生成。

## 目录

- `prototype/guardx/backend/app/`：FastAPI 服务、Guard、策略、执行器和证据接口。
- `prototype/guardx/backend/tests/`：合同、路由、RAG、Agent 与策略测试。
- `prototype/guardx/configs/models.yaml`：本地模型与国内 API 路由。
- `configs/`：策略画像、工具权限、任务关系和执行器配置。
- `reviewer_console/`：系统展示与实时演示前端。
- `sandbox/demo/`：Agent 只读演示沙箱。
- `attack_cases/`：LLM、RAG、VLM 与 Agent 测试样例。
- `evidence/`：可复核的运行与评测证据。
- `docs/DEMO_GUIDE.md`：评审演示顺序与可直接使用的输入。

## 本地启动

前置条件：Python 3.11+、Ollama、Docker。

```powershell
ollama pull qwen2.5:7b
ollama pull qwen2.5vl:7b
ollama pull bge-m3
ollama pull deepseek-r1:7b

docker run -d --name guardx-qdrant -p 6333:6333 qdrant/qdrant

cd prototype\guardx\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
cd ..\..\..
.\scripts\start_reviewer_server.ps1 -Port 8021
```

访问：`http://127.0.0.1:8021/final/`

## 国内 API

服务端支持以下环境变量；浏览器不接收、不读取、不显示密钥。

- `DEEPSEEK_API_KEY`
- `MOONSHOT_API_KEY`
- `ZHIPU_API_KEY`
- `DASHSCOPE_API_KEY`

模型路由统一定义在 `prototype/guardx/configs/models.yaml`。未配置云端密钥时，本地 Ollama 路由仍可独立运行。

## 验证

```powershell
cd prototype\guardx\backend
python -m pytest tests/test_contracts.py tests/test_live_rag.py -q
```

页面实时结果包含模型调用状态、响应来源、Qdrant/BGE-M3 检索信息、Execution Permit、Runner 状态、副作用状态和证据编号；LIVE 模式不以回放结果替代后端响应。

## 凭据与执行边界

- API Key 仅从服务端环境变量读取，不进入源码、前端或演示数据。
- 模型权重、数据库、运行日志和本机缓存由 `.gitignore` 排除。
- Agent 良性演示只允许读取 `sandbox/demo/`，路径越界和敏感路径访问在执行前拒绝。
- 被拒绝的工具请求不会取得 Execution Permit，Runner 不调用，副作用为零。
