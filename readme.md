# Scout - 证据驱动的安全评估 Agent

> 五阶段工具编排 + 资产证据关联 + 可解释风险排序 + 历史报告对比。
> AI 可选，结果可追溯；支持零密钥、零扫描的离线演示。

## 先体验，再部署

离线演示只需要 Python 3.10+ 标准库，不安装扫描工具，不读取 API 配置，不访问测试目标：

```bash
git clone https://github.com/ffdba/Scout.git
cd Scout
python main.py --demo --baseline examples/demo_baseline.json -o output/demo
```

生成两份可检查的结果：

```text
output/demo/example_test_report.json     # 原始观察 + 证据图 + 风险排序 + 差异
output/demo/example_test_assessment.md   # 人工审阅报告
```

演示域名使用保留的 `.test`，IP 使用文档地址 `192.0.2.10`。数据为合成样例，不代表真实漏洞。

## 本轮核心升级

| 能力 | 实现 | 解决的问题 |
|------|------|------------|
| 资产与证据关联 | 域名 → IP → 服务，以及资产 → URL / 发现的结构化图 | 结果不再是互不相关的工具输出 |
| 可解释风险排序 | 最高风险信号 + 跨类型佐证加分，保存评分拆解和证据 JSON Pointer | 能说明为什么先处理某个资产 |
| 稳定发现 ID | 按模板、规范化位置和协议生成 ID | 同一发现跨扫描可识别，不依赖输出顺序 |
| 历史报告对比 | 新增、持续存在、本次未观察到、属性变化 | 支持复测和攻击面变化追踪 |
| 数据融合 | 合并重复子域、端口、指纹和发现，保留来源、服务信息与原阶段证据 | 避免计数膨胀和情报丢失 |
| 离线报告 | 兼容原 JSON / JSONL，自动生成 Markdown 评估报告 | 没有模型密钥也能产生有用结果 |
| 受控 AI 输出 | 验证决策字段类型，限制可跳过阶段，保留框架元数据 | 异常模型响应不会改变阶段身份或造成遍历错误 |

**风险边界：**

- 0–100 是启发式处理优先级，不是 CVSS 分数。
- Nuclei 匹配标为 `tool_reported`，不等同于独立确认可利用。
- 开放端口和 HTTP 200 敏感路径标为 `needs_review`，不是已验证漏洞。
- 不把同一 IP 的风险传播给其他域名，避免共享主机 / CDN 误关联。
- 历史发现消失标为 `not_observed`，不是自动确认已修复。
- 阶段有记录不保证所有工具成功；报告显式提示工具级覆盖率尚不可证明。

工程设计与兼容性说明见 [docs/architecture.md](docs/architecture.md)。

---

## 架构总览

```
graph TD
    Root[输入: 根域名/目标资产] --> S1[阶段一: 隐蔽 OSINT]
    subgraph 1_被动情报层
        S1 --> T1_1[crt.sh] & T1_2[360 Quake API] & T1_3[Hunter API] & T1_4[Gitleaks]
        T1_1 & T1_2 & T1_3 & T1_4 --> D1[历史快照/潜在源站IP/历史子域/泄露凭据]
    end
    D1 --> S2[阶段二: 边界拓展与初筛]
    subgraph 2_极速出网层
        S2 --> T2_1[Subfinder] --> T2_2[RustScan / Naabu]
        T2_2 --> D2[当前存活子域/开放端口列表]
    end
    D2 --> S3[阶段三: 指纹深度聚焦]
    subgraph 3_手术刀画像层
        S3 --> T3_1[Nmap 定向服务识别] --> T3_2[Httpx] --> T3_3[Wappalyzer CLI]
        T3_3 --> D3[标准JSON格式 - 操作系统/中间件/CMS指纹]
    end
    D3 --> S4[阶段四: 敏感路径深挖]
    subgraph 4_内容探测层
        S4 --> T4_1[Katana 动态爬网] --> T4_2[Feroxbuster 目录爆破]
        T4_2 --> D4[敏感输入点/备份文件/异常响应路径]
    end
    D4 --> S5[阶段五: 原子化漏洞验证]
    subgraph 5_精准打击层
        S5 --> T5_1{Agent 标签筛选路由} --> T5_2[Nuclei 唯一核心验证器]
        T5_2 --> Output((最终结构化评估报告 JSONL))
    end
```

---

## 快速开始

以下命令会调用真实扫描工具，仅对明确授权的目标使用。

### 方式一：Linux 服务器一键部署（推荐）

```bash
# 1. 上传整个项目到服务器
scp -r Scout/ user@server:/opt/scout/

# 2. SSH 登录服务器
ssh user@server
cd /opt/scout

# 3. 一键部署（安装依赖 + 下载工具 + 配置环境）
bash deploy.sh

# 4. 配置 API Key
vim config/config.yaml    # 或 vim .env

# 5. 运行
source .venv/bin/activate
python main.py example.com
```

### 方式二：手动安装

```bash
# 1. 安装 Python 依赖
pip install -r requirements.txt

# 2. 下载安全工具到 bin/ 目录
bash setup_tools.sh

# 3. 配置 API Key
cp config/config.example.yaml config/config.yaml
vim config/config.yaml

# 4. 运行
python main.py example.com
```

---

## 开箱即用设计

Scout 采用 **`bin/` 目录优先** 的工具查找策略，所有安全工具的预编译二进制都存放在 `bin/` 目录中：

```
Scout/
├── bin/                  # 工具二进制（setup_tools.sh 自动下载）
│   ├── subfinder
│   ├── nuclei
│   ├── httpx
│   ├── naabu
│   ├── katana
│   ├── rustscan
│   ├── feroxbuster
│   └── gitleaks
├── wordlists/            # 字典文件（自动下载）
│   └── raft-medium-directories.txt
└── ...
```

**工具查找优先级：**
1. `bin/` 目录下的预编译二进制 — 最高优先级
2. 系统 PATH 中的工具
3. 工具不存在则跳过并警告

这意味着：**上传整个项目到 Linux 服务器后，运行 `bash deploy.sh` 即可开箱使用**，无需在服务器上安装 Go/Rust 等编译环境。

> nmap 需通过 `apt install nmap` 安装，wappalyzer 需要 Node.js 环境

---

## Agent 思考输出

Scout 在每个阶段执行前会输出 **🧠 Agent 思考过程**，让你实时了解 Agent 的推理逻辑：

### 思考模式

| 模式 | 触发条件 | 说明 |
|------|----------|------|
| **AI 思考** | 配置了 AI API Key | 调用 AI 模型分析当前情报，输出策略推理 |
| **规则思考** | 未配置 AI Key | 基于内置规则引擎输出结构化思考 |

### 输出示例

```
──────────────────────────────────────────────────────────
🧠 Agent 思考 [阶段1: 隐蔽OSINT] [规则] [10:30:15]
──────────────────────────────────────────────────────────
  [情报摘要] 目标 example.com，尚无历史数据
  [攻击面评估] 从零开始被动侦察，需最大化信息收集覆盖面
  [策略] 并行调用 crt.sh/Quake/Hunter 获取历史子域与源站IP，Gitleaks扫描凭据泄露
  [预期] 获取历史子域列表、潜在源站IP、泄露凭据
──────────────────────────────────────────────────────────

  ⚡ [10:30:16] 启动 crt.sh / Quake / Hunter / Gitleaks 并行侦察...
  ⚡ [10:30:18] crt.sh 返回 23 个子域
  ⚡ [10:30:20] Quake 返回 15 个子域
  ⚡ [10:30:22] Hunter 返回 8 个子域
  ⚡ [10:30:25] OSINT 汇总: 46 个子域, 0 处泄露
```

所有思考过程也会保存在最终报告的 `agent_thoughts` 字段中。

---

## Agentic 决策模式

Scout 现在支持受控的 **agentic loop**：不再只是固定跑完五个阶段后总结，而是在每个阶段结束后执行一次“观察-决策-行动”循环。

### 工作方式

1. **Observe**：读取当前阶段产出的子域名、端口、指纹、敏感路径、漏洞和错误信息。
2. **Decide**：AI 根据当前报告生成结构化决策，包括是否继续、是否跳过低价值阶段、优先目标、风险假设和人工验证建议。
3. **Act**：Scout 只会在内置的 1-5 阶段范围内继续、停止或跳过阶段，不会让 AI 任意执行系统命令。
4. **Report**：最终报告会保存每轮 `agent_decisions`，并额外生成 AI 总结分析。

### 运行方式

只要配置了 `AI_API_KEY` 或 `config/config.yaml` 中的 `ai.api_key`，默认启用 agentic 决策：

```bash
python main.py example.com
```

强制使用传统线性流水线：

```bash
python main.py example.com --linear
```

完全禁用 AI：

```bash
python main.py example.com --no-ai
```

### 输出文件

```text
output/example_com_report.json        # 结构化报告，包含 intelligence、agent_decisions 和 ai_analysis
output/example_com_assessment.md      # 本地生成的证据驱动评估报告，无需 AI
output/example_com_report.jsonl       # output.format=jsonl 时追加最终完整快照
output/example_com_ai_analysis.md     # 配置并启用 AI 时生成
```

> Agentic 模式是受控自主：AI 负责规划和分析，工具执行仍限制在授权范围内的固定安全测试阶段中。

---

## 更新说明

### 证据驱动评估更新

- 新增 `--demo`、`--report`、`--baseline` 和 `--output-dir`。
- 报告新增 `schema_version: "2.0"`、`intelligence`，使用历史报告时新增 `comparison`，保留原顶层数据字段。
- 支持重新分析旧 JSON / JSONL；JSONL 默认使用最后一个非空快照。
- 修复 `--no-ai` 仍执行阶段内 AI 请求的问题。
- 所有模式统一在 AI 分析完成后保存报告，修复 Agentic 输出目录未创建及 JSONL 缺少最终分析的问题。
- 修复 Config 单例导致不同调用间配置相互影响的问题。
- `--list-stages` 无需目标和工具依赖；指定阶段只检查相应必需工具。
- 新增离线回归测试及 Linux / Windows CI，不启动监听服务。

### Agentic 模式更新

- 新增阶段后 AI 决策层：每个阶段执行后，AI 会基于当前报告判断是否继续、停止或跳过后续低价值阶段。
- 最终报告新增 `agent_decisions` 和 `ai_analysis` 字段。
- 扫描完成后会额外输出 `*_ai_analysis.md`，用于保存 AI 生成的渗透思路、风险分析和下一轮测试建议。
- 新增 `--linear` 用于回到传统固定流水线，新增 `--no-ai` 用于禁用 AI。
- 修复 Stage2 直接写入临时 `temp` 阶段导致报告重复的问题。
- 修复 Nmap 服务识别结果中的 `product` 字段无法写入 `PortInfo` 的问题。

---

## API 密钥配置详解

### AI 模型配置

Scout 支持通过 AI 对渗透结果进行智能分析，输出风险评级和攻击路径建议。同时 AI 也用于每阶段的思考推理。

**OpenAI（默认）**

```yaml
ai:
  provider: "openai"
  api_key: "sk-xxxxxxxxxxxxxxxx"
  base_url: "https://api.openai.com/v1"
  model: "gpt-4o"
```

获取地址：https://platform.openai.com/api-keys

**DeepSeek**

```yaml
ai:
  provider: "deepseek"
  api_key: "your-deepseek-api-key"
  base_url: "https://api.deepseek.com/v1"
  model: "deepseek-chat"
```

**自定义兼容 OpenAI 的 API**

```yaml
ai:
  provider: "custom"
  api_key: "your-api-key"
  base_url: "https://your-api-endpoint/v1"
  model: "your-model-name"
```

> 环境变量方式：设置 `AI_API_KEY`、`AI_BASE_URL`、`AI_MODEL` 可覆盖配置文件

### 360 Quake API

360 Quake 用于被动子域发现和历史 IP 查询。

```yaml
quake:
  api_key: "your-quake-api-key"
```

**获取方式：**
1. 访问 https://quake.360.net
2. 注册并登录账号
3. 进入「个人中心」→「服务」页面
4. 复制 API Key

> 环境变量：`QUAKE_API_KEY=your-quake-api-key`

### 奇安信 Hunter API

Hunter 用于被动子域发现和资产测绘。

```yaml
hunter:
  api_key: "your-hunter-api-key"
```

**获取方式：**
1. 访问 https://hunter.qianxin.com
2. 注册并登录账号
3. 进入「API 管理」页面
4. 创建并复制 API Key

> 环境变量：`HUNTER_API_KEY=your-hunter-api-key`

### 代理配置（可选）

```yaml
proxy:
  enabled: true
  http: "http://127.0.0.1:7890"
  https: "http://127.0.0.1:7890"
```

> 环境变量：`HTTP_PROXY`、`HTTPS_PROXY`

---

## 五阶段详解

### 阶段一：隐蔽 OSINT（被动情报层）

| 工具 | 数据产出 | 是否需要 API Key |
|------|----------|-----------------|
| crt.sh | 历史证书子域 | ❌ |
| 360 Quake | 历史子域、潜在源站 IP | ✅ |
| Hunter | 历史子域、资产信息 | ✅ |
| Gitleaks | 泄露凭据 | ❌ (需本地仓库路径) |

- crt.sh 和 Quake/Hunter 并行执行，最大化效率
- Quake 额外查询历史 IP，用于发现 CDN 背后的源站
- Gitleaks 扫描指定 Git 仓库中的硬编码凭据

### 阶段二：边界拓展与初筛（极速出网层）

| 工具 | 数据产出 | 说明 |
|------|----------|------|
| Subfinder | 当前存活子域 | 主动枚举，补充阶段一结果 |
| RustScan / Naabu | 开放端口列表 | 在 `config.yaml` 中选择引擎 |

- Subfinder 枚举结果与阶段一结果自动去重
- 端口扫描引擎可通过 `portscan.engine` 切换
- 自动标记高危端口（Redis、MongoDB、MySQL 等）

### 阶段三：指纹深度聚焦（手术刀画像层）

| 工具 | 数据产出 | 说明 |
|------|----------|------|
| Nmap | 服务版本、OS 指纹 | 仅扫描已发现端口，精准定向 |
| Httpx | 存活 URL、状态码、基础技术栈 | 批量 HTTP 探测 |
| Wappalyzer | 深度技术栈识别 | 补充 Httpx 的技术识别 |

- Nmap 仅对阶段二发现的 IP + 端口进行定向扫描，避免全端口重复
- Httpx 和 Wappalyzer 结果自动合并到同一 Fingerprint 对象

### 阶段四：敏感路径深挖（内容探测层）

| 工具 | 数据产出 | 说明 |
|------|----------|------|
| Katana | 爬取路径、JS 端点 | 动态爬网，发现隐藏输入点 |
| Feroxbuster | 备份文件、配置文件、异常路径 | 字典爆破，支持自定义扩展名 |

- Katana 自动分类敏感路径（管理面板、登录入口、API 端点等）
- Feroxbuster 对 401/403 状态码特别标记，提示可能存在绕过
- 字典文件优先从 `wordlists/` 目录查找

### 阶段五：原子化漏洞验证（精准打击层）

| 工具 | 数据产出 | 说明 |
|------|----------|------|
| Agent 标签路由 | Nuclei 模板标签 | 根据指纹自动匹配漏洞模板标签 |
| Nuclei | 模板匹配发现 | 匹配结果仍需审阅，不保证零误报 |

**标签路由机制：** 阶段三识别的技术栈会自动映射到 Nuclei 模板标签：

| 技术栈 | Nuclei 标签 |
|--------|------------|
| WordPress | wordpress |
| Apache | apache |
| Shiro | shiro |
| Fastjson | fastjson |
| ThinkPHP | thinkphp |
| WebLogic | weblogic |
| ... | ... |

---

## 输出格式

最终报告以 JSON 格式保存到 `output/` 目录：

```json
{
  "target": "example.com",
  "generated_at": "2026-05-17T10:30:00",
  "summary": {
    "total_subdomains": 42,
    "total_open_ports": 128,
    "total_fingerprints": 35,
    "total_sensitive_paths": 67,
    "total_vulnerabilities": 5,
    "total_credential_leaks": 2,
    "vulnerability_by_severity": {"critical": 1, "high": 2, "medium": 2}
  },
  "subdomains": [...],
  "ports": [...],
  "fingerprints": [...],
  "sensitive_paths": [...],
  "vulnerabilities": [...],
  "credential_leaks": [...]
}
```

### 离线分析与历史对比

直接分析已有报告，不触发扫描或 AI 请求：

```bash
python main.py --report output/example_com_report.json -o output/review
```

对比两次报告，目标必须一致：

```bash
python main.py --report output/current.json --baseline output/previous.json -o output/comparison
```

对明确授权的目标执行新扫描并对比历史报告：

```bash
python main.py example.com --no-ai --baseline output/previous.json
```

新增数据结构：

```text
intelligence.assets[]                  # 资产画像、技术栈、风险分数与评分拆解
intelligence.findings[]                # 稳定 ID、状态、风险理由、证据位置、处理建议
intelligence.graph.nodes / edges       # 可供其他工具消费的资产证据图
intelligence.coverage / warnings       # 阶段记录与覆盖限制
comparison.assets / findings           # new / persistent / not_observed / changed
```

敏感信息：结构化模型序列化继续省略 secret match、提取内容及响应片段；报告中的 URL、仓库路径、原始工具数据与 AI 文本仍可能敏感，分享前须审阅。

---

## 项目结构

```
Scout/
├── main.py                    # 入口文件
├── requirements.txt           # Python 依赖
├── setup_tools.sh             # 工具下载脚本
├── deploy.sh                  # 一键部署脚本
├── .env.example               # 环境变量模板
├── .gitignore
├── bin/                       # 预编译工具 (开箱即用)
│   ├── subfinder
│   ├── nuclei
│   ├── httpx
│   └── ...
├── wordlists/                 # 字典文件
│   └── raft-medium-directories.txt
├── config/
│   ├── config.example.yaml    # 配置文件模板
│   └── config.yaml            # 你的实际配置 (git忽略)
├── core/
│   ├── agent.py               # Agent 编排器 + AI 分析
│   ├── config.py              # 配置加载器
│   ├── intelligence.py        # 证据图、风险排序、稳定 ID、报告对比（标准库）
│   ├── reporting.py           # 旧报告读取、输入校验、JSON / JSONL / Markdown 导出
│   ├── models.py              # 数据模型
│   ├── pipeline.py            # 流水线引擎
│   └── stage.py               # 阶段基类 (含思考机制)
├── stages/
│   ├── stage1_osint.py        # 阶段一: 隐蔽OSINT
│   ├── stage2_boundary.py     # 阶段二: 边界拓展
│   ├── stage3_fingerprint.py  # 阶段三: 指纹聚焦
│   ├── stage4_content.py      # 阶段四: 敏感路径
│   └── stage5_vuln.py         # 阶段五: 漏洞验证
├── tools/
│   ├── crtsh.py               # crt.sh 封装
│   ├── quake.py               # 360 Quake 封装
│   ├── hunter.py              # Hunter 封装
│   ├── gitleaks.py            # Gitleaks 封装
│   ├── subfinder.py           # Subfinder 封装
│   ├── portscan.py            # RustScan/Naabu 封装
│   ├── nmap.py                # Nmap 封装
│   ├── httpx_tool.py          # Httpx 封装
│   ├── wappalyzer.py          # Wappalyzer 封装
│   ├── katana.py              # Katana 封装
│   ├── feroxbuster.py         # Feroxbuster 封装
│   └── nuclei.py              # Nuclei 封装
├── utils/
│   ├── logger.py              # 日志工具
│   └── runner.py              # 命令执行器 (bin/优先)
└── output/                    # 输出目录 (git忽略)
    └── logs/
```

## 测试

完整回归测试只使用合成数据与 mock，不运行外部扫描工具：

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

覆盖资产融合、证据定位、共享 IP 隔离、风险排序、复测差异、输入校验、离线 CLI、AI 禁用和最终报告保存。CI 在 Linux / Windows 上运行。

---

## 配置优先级

配置值的加载优先级从高到低：

1. **环境变量** (`.env` 文件或系统环境变量) — 最高优先级
2. **配置文件** (`config/config.yaml`)
3. **默认值** (代码内置)

---

## 常见问题

### Q: 没有配置 Quake/Hunter API Key 会怎样？

A: 阶段一会跳过对应的工具，仅使用 crt.sh（免费无需 Key）进行被动枚举。不会报错，但发现量会减少。

### Q: AI 分析必须配置吗？

A: 不是必须的。未配置 AI Key 时，Agent 思考会使用内置规则引擎输出推理过程，不影响五阶段流水线执行。

### Q: 如何只运行特定阶段？

A: 使用 `-s` 参数，如 `-s 1,3,5` 只运行阶段一、三、五。

### Q: 上传到 Linux 服务器后怎么用？

A: 上传整个项目目录，运行 `bash deploy.sh` 一键部署，然后 `python main.py example.com`。

### Q: 工具下载失败怎么办？

A: 可以手动下载对应平台的二进制文件放到 `bin/` 目录并 `chmod +x`。或删除 `bin/` 目录后重新运行 `bash setup_tools.sh`。

---

## 免责声明

本工具仅供授权安全测试和教学研究使用。未经授权对他人系统进行渗透测试属于违法行为。使用者需自行承担所有法律责任，作者不承担任何连带责任。
