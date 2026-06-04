#!/usr/bin/env bash
# ============================================================
# Scout 一键部署脚本
# 在 Linux 服务器上运行此脚本完成所有初始化
# 用法: bash deploy.sh [--force]
#   --force: 强制重新下载所有工具
# ============================================================
set -euo pipefail

FORCE_DOWNLOAD=false
if [[ "${1:-}" == "--force" ]]; then
    FORCE_DOWNLOAD=true
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[-]${NC} $1"; }
step()  { echo -e "${CYAN}[→]${NC} $1"; }

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

echo ""
echo -e "${CYAN}╦═╗┌─┐┬  ┬┌─┐┌┐┌  ╔╗╔┌─┐─┐ ┬┬ ┬┌─┐${NC}"
echo -e "${CYAN}╠╦╝├─┤└┐┌┘├┤ │││  ║║║├┤ ┌┴┬┘│ │└─┐${NC}"
echo -e "${CYAN}╩╚═┴ ┴ └┘ └─┘┘└┘  ╝╚╝└─┘┴ └─└─┘└─┘${NC}"
echo -e "${CYAN}  Scout 一键部署${NC}"
echo ""

# --- Step 1: 系统依赖 ---
step "Step 1/5: 安装系统依赖"
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq python3 python3-pip python3-venv nmap unzip curl 2>/dev/null
    info "系统依赖安装完成 (apt)"
elif command -v yum &>/dev/null; then
    sudo yum install -y python3 python3-pip nmap unzip curl 2>/dev/null
    info "系统依赖安装完成 (yum)"
else
    warn "无法自动安装系统依赖，请手动安装: python3, pip, nmap, curl"
fi

# --- Step 2: Python 虚拟环境 ---
step "Step 2/5: 创建 Python 虚拟环境"
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    info "虚拟环境已创建"
else
    info "虚拟环境已存在"
fi

source .venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
info "Python 依赖安装完成"

# --- Step 3: 下载安全工具 ---
step "Step 3/5: 下载安全工具到 bin/"
if [ "$FORCE_DOWNLOAD" = true ]; then
    info "强制模式: 删除 bin/ 目录后重新下载所有工具"
    rm -rf bin/
fi
bash setup_tools.sh ${FORCE_DOWNLOAD:+--force}

# --- Step 4: 设置权限 ---
step "Step 4/5: 设置执行权限"
chmod +x bin/* 2>/dev/null || true
chmod +x main.py 2>/dev/null || true
info "权限设置完成"

# --- Step 5: 配置检查 ---
step "Step 5/5: 配置检查"
if [ ! -f "config/config.yaml" ]; then
    cp config/config.example.yaml config/config.yaml
    warn "已创建 config/config.yaml，请编辑填入你的 API Key"
    warn "  必须配置: vi config/config.yaml"
    warn "  或使用环境变量: cp .env.example .env && vi .env"
else
    info "config/config.yaml 已存在"
fi

if [ ! -f ".env" ]; then
    cp .env.example .env
    info "已创建 .env 模板"
fi

# --- 验证 ---
echo ""
info "=========================================="
info "  部署完成！"
info "=========================================="
echo ""

info "工具状态:"
for tool in subfinder nuclei httpx naabu katana rustscan feroxbuster gitleaks; do
    if [ -f "bin/${tool}" ] && [ -x "bin/${tool}" ]; then
        local size=$(stat -c%s "bin/${tool}" 2>/dev/null || stat -f%z "bin/${tool}" 2>/dev/null || echo "?")
        echo -e "  ${GREEN}✓${NC} ${tool} (${size} bytes)"
    elif command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} ${tool} (系统PATH)"
    else
        echo -e "  ${YELLOW}✗${NC} ${tool} (未安装)"
    fi
done

if command -v nmap &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} nmap (系统PATH)"
elif [ -f "bin/nmap" ]; then
    echo -e "  ${GREEN}✓${NC} nmap (bin/)"
else
    echo -e "  ${YELLOW}✗${NC} nmap (需: sudo apt install nmap)"
fi

echo ""
info "快速开始:"
echo "  source .venv/bin/activate"
echo "  python main.py example.com"
echo ""
info "带 AI 分析:"
echo "  python main.py example.com --ai"
echo ""
info "指定阶段:"
echo "  python main.py example.com -s 1,2,3"
echo ""
info "强制重新下载所有工具:"
echo "  bash deploy.sh --force"
