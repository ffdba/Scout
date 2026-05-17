#!/usr/bin/env bash
# ============================================================
# RedAgent 工具下载脚本
# 自动下载所有安全工具的 Linux amd64 预编译二进制到 bin/ 目录
# 用法: bash setup_tools.sh
# ============================================================
set -euo pipefail

BIN_DIR="$(cd "$(dirname "$0")" && pwd)/bin"
mkdir -p "$BIN_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

GHPROXY="https://ghproxy.net"

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[-]${NC} $1"; }

detect_arch() {
    local arch="$(uname -m)"
    case "$arch" in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        armv7l)  echo "armv7" ;;
        *)       echo "amd64" ;;
    esac
}

ARCH=$(detect_arch)
info "检测到架构: $ARCH"

download_github_release() {
    local repo="$1"
    local name_pattern="$2"
    local output_name="$3"

    local api_url="https://api.github.com/repos/${repo}/releases/latest"
    local download_url=""

    info "获取 ${repo} 最新版本..."
    local release_info
    release_info=$(curl -sfL "$api_url" 2>/dev/null) || true

    if [ -z "$release_info" ]; then
        fail "无法获取 ${repo} 的发布信息，请检查网络或手动下载"
        return 1
    fi

    download_url=$(echo "$release_info" | grep -oP '"browser_download_url":\s*"\K[^"]*' | grep -i "$name_pattern" | head -1)

    if [ -z "$download_url" ]; then
        fail "未找到匹配 ${name_pattern} 的下载链接"
        return 1
    fi

    local proxy_url="${GHPROXY}/${download_url}"
    local tmp_file="/tmp/${output_name}.tar.gz"
    info "下载: ${download_url}"
    info "代理: ${proxy_url}"
    curl -sfL -o "$tmp_file" "$proxy_url"

    local tmp_dir="/tmp/${output_name}_extract"
    rm -rf "$tmp_dir" && mkdir -p "$tmp_dir"

    if [[ "$download_url" == *.zip ]]; then
        unzip -qo "$tmp_file" -d "$tmp_dir"
    else
        tar xzf "$tmp_file" -C "$tmp_dir" 2>/dev/null || \
        tar xzf "$tmp_file" -C "$tmp_dir" --strip-components=1 2>/dev/null || \
        cp "$tmp_file" "$tmp_dir/${output_name}"
    fi

    local binary_path
    binary_path=$(find "$tmp_dir" -maxdepth 2 -name "${output_name}" -type f 2>/dev/null | head -1)

    if [ -z "$binary_path" ]; then
        binary_path=$(find "$tmp_dir" -maxdepth 2 -type f -executable 2>/dev/null | head -1)
    fi

    if [ -z "$binary_path" ]; then
        fail "解压后未找到可执行文件: ${output_name}"
        rm -rf "$tmp_dir" "$tmp_file"
        return 1
    fi

    cp "$binary_path" "${BIN_DIR}/${output_name}"
    chmod +x "${BIN_DIR}/${output_name}"
    rm -rf "$tmp_dir" "$tmp_file"
    info "已安装: ${BIN_DIR}/${output_name}"
}

download_direct() {
    local url="$1"
    local output_name="$2"

    info "下载: ${url}"
    curl -sfL -o "${BIN_DIR}/${output_name}" "$url"
    chmod +x "${BIN_DIR}/${output_name}"
    info "已安装: ${BIN_DIR}/${output_name}"
}

echo ""
info "=========================================="
info "  RedAgent 工具下载 - Linux ${ARCH}"
info "  使用代理: ${GHPROXY}"
info "=========================================="
echo ""

# --- ProjectDiscovery 工具 ---
info "--- ProjectDiscovery 工具集 ---"

if [ ! -f "${BIN_DIR}/subfinder" ]; then
    download_github_release "projectdiscovery/subfinder" "linux_${ARCH}" "subfinder"
else
    info "subfinder 已存在，跳过"
fi

if [ ! -f "${BIN_DIR}/nuclei" ]; then
    download_github_release "projectdiscovery/nuclei" "linux_${ARCH}" "nuclei"
else
    info "nuclei 已存在，跳过"
fi

if [ ! -f "${BIN_DIR}/httpx" ]; then
    download_github_release "projectdiscovery/httpx" "linux_${ARCH}" "httpx"
else
    info "httpx 已存在，跳过"
fi

if [ ! -f "${BIN_DIR}/naabu" ]; then
    download_github_release "projectdiscovery/naabu" "linux_${ARCH}" "naabu"
else
    info "naabu 已存在，跳过"
fi

if [ ! -f "${BIN_DIR}/katana" ]; then
    download_github_release "projectdiscovery/katana" "linux_${ARCH}" "katana"
else
    info "katana 已存在，跳过"
fi

# --- RustScan ---
info "--- RustScan ---"

if [ ! -f "${BIN_DIR}/rustscan" ]; then
    download_github_release "RustScan/RustScan" "linux_${ARCH}" "rustscan"
else
    info "rustscan 已存在，跳过"
fi

# --- Feroxbuster ---
info "--- Feroxbuster ---"

if [ ! -f "${BIN_DIR}/feroxbuster" ]; then
    download_github_release "epi052/feroxbuster" "linux-${ARCH}" "feroxbuster"
else
    info "feroxbuster 已存在，跳过"
fi

# --- Gitleaks ---
info "--- Gitleaks ---"

if [ ! -f "${BIN_DIR}/gitleaks" ]; then
    download_github_release "gitleaks/gitleaks" "linux_${ARCH}" "gitleaks"
else
    info "gitleaks 已存在，跳过"
fi

# --- Nmap (通过 apt 安装) ---
info "--- Nmap ---"
if command -v nmap &>/dev/null; then
    info "nmap 已在系统 PATH 中"
elif [ -f "${BIN_DIR}/nmap" ]; then
    info "nmap 已存在于 bin/"
else
    warn "nmap 需要通过系统包管理器安装: sudo apt install -y nmap"
    warn "或手动下载静态编译版本到 bin/nmap"
fi

# --- Wappalyzer CLI ---
info "--- Wappalyzer ---"
if command -v wappalyzer &>/dev/null; then
    info "wappalyzer 已在系统 PATH 中"
elif [ -f "${BIN_DIR}/wappalyzer" ]; then
    info "wappalyzer 已存在于 bin/"
else
    warn "wappalyzer 需要 Node.js: npm install -g wappalyzer"
fi

# --- 下载 SecLists 字典 (Feroxbuster 依赖) ---
info "--- SecLists 字典 ---"
WORDLIST_DIR="$(cd "$(dirname "$0")" && pwd)/wordlists"
if [ ! -f "${WORDLIST_DIR}/raft-medium-directories.txt" ]; then
    mkdir -p "$WORDLIST_DIR"
    info "下载 SecLists Web 字典..."
    local seclists_url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"
    local proxy_seclists_url="${GHPROXY}/${seclists_url}"
    curl -sfL -o "${WORDLIST_DIR}/raft-medium-directories.txt" "$proxy_seclists_url" || \
    curl -sfL -o "${WORDLIST_DIR}/raft-medium-directories.txt" "$seclists_url" || \
    warn "字典下载失败，可手动下载到 wordlists/ 目录"
else
    info "字典已存在，跳过"
fi

# --- Nuclei 模板初始化 ---
info "--- Nuclei 模板 ---"
if [ -f "${BIN_DIR}/nuclei" ]; then
    info "更新 Nuclei 模板..."
    "${BIN_DIR}/nuclei" -update-templates 2>/dev/null || warn "模板更新失败，首次运行时会自动下载"
fi

echo ""
info "=========================================="
info "  工具下载完成！"
info "=========================================="
echo ""
info "已安装工具:"
ls -lh "${BIN_DIR}/" 2>/dev/null | tail -n +2 | while read line; do
    echo "  $line"
done
echo ""
info "使用方法:"
info "  1. 上传整个项目到 Linux 服务器"
info "  2. 运行: bash deploy.sh"
info "  3. 开始: python3 main.py example.com"
