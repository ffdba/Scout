# RedAgent - 红队自动化渗透 Agent

> 五阶段流水线式红队自动化侦察与漏洞验证框架

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

### 方式一：Linux 服务器一键部署（推荐）

```bash
# 1. 上传整个项目到服务器
scp -r red/ user@server:/opt/red/

# 2. SSH 登录服务器
ssh user@server
cd /opt/red

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

RedAgent 采用 **`bin/` 目录优先** 的工具查找策略，所有安全工具的预编译二进制都存放在 `bin/` 目录中：

```
red/
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

RedAgent 在每个阶段执行前会输出 **🧠 Agent 思考过程**，让你实时了解 Agent 的推理逻辑：

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

RedAgent 现在支持受控的 **agentic loop**：不再只是固定跑完五个阶段后总结，而是在每个阶段结束后执行一次“观察-决策-行动”循环。

### 工作方式

1. **Observe**：读取当前阶段产出的子域名、端口、指纹、敏感路径、漏洞和错误信息。
2. **Decide**：AI 根据当前报告生成结构化决策，包括是否继续、是否跳过低价值阶段、优先目标、风险假设和人工验证建议。
3. **Act**：RedAgent 只会在内置的 1-5 阶段范围内继续、停止或跳过阶段，不会让 AI 任意执行系统命令。
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
output/example_com_report.json        # 结构化扫描报告，包含 agent_decisions 和 ai_analysis
output/example_com_ai_analysis.md     # AI 生成的 Markdown 渗透思路与风险分析
```

> Agentic 模式是受控自主：AI 负责规划和分析，工具执行仍限制在授权范围内的固定安全测试阶段中。

---

## 更新说明

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

RedAgent 支持通过 AI 对渗透结果进行智能分析，输出风险评级和攻击路径建议。同时 AI 也用于每阶段的思考推理。

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
| Nuclei | 已验证漏洞 | 唯一核心验证器，避免误报 |

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

---

## 项目结构

```
red/
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
