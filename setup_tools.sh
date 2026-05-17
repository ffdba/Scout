#!/usr/bin/env bash
# ============================================================
# RedAgent 工具下载脚本
# 自动下载所有安全工具的 Linux amd64 预编译二进制到 bin/ 目录
# 用法: bash setup_tools.sh [--force]
#   --force: 强制重新下载所有工具，即使已存在
# ============================================================
set -uo pipefail

FORCE_DOWNLOAD=false
if [[ "${1:-}" == "--force" ]]; then
    FORCE_DOWNLOAD=true
fi

BIN_DIR="$(cd "$(dirname "$0")" && pwd)/bin"
mkdir -p "$BIN_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

GHPROXY="https://ghproxy.net"
CURL_OPTS="--connect-timeout 15 --max-time 300 -sfL"

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

should_download() {
    local tool_name="$1"
    if [ "$FORCE_DOWNLOAD" = true ]; then
        return 0
    fi
    local tool_path="${BIN_DIR}/${tool_name}"
    if [ ! -f "$tool_path" ]; then
        return 0
    fi
    if [ ! -x "$tool_path" ]; then
        info "${tool_name} 文件存在但无执行权限，将重新下载"
        return 0
    fi
    local size
    size=$(stat -c%s "$tool_path" 2>/dev/null || stat -f%z "$tool_path" 2>/dev/null || echo "0")
    if [ "$size" -lt 1000 ]; then
        warn "${tool_name} 文件异常 (${size} bytes)，将重新下载"
        return 0
    fi
    return 1
}

get_latest_download_url() {
    local repo="$1"
    local name_pattern="$2"
    local download_url=""

    local api_url="https://api.github.com/repos/${repo}/releases/latest"
    local proxy_api_url="${GHPROXY}/${api_url}"

    info "获取 ${repo} 最新版本 (通过代理)..."
    local release_info
    release_info=$(curl $CURL_OPTS "$proxy_api_url" 2>/dev/null) || true

    if [ -z "$release_info" ]; then
        warn "代理获取失败，尝试直连 GitHub API..."
        release_info=$(curl $CURL_OPTS "$api_url" 2>/dev/null) || true
    fi

    if [ -z "$release_info" ]; then
        echo ""
        return 1
    fi

    download_url=$(echo "$release_info" | grep -oP '"browser_download_url":\s*"\K[^"]*' | grep -i "$name_pattern" | head -1)

    echo "${download_url}"
}

download_and_install() {
    local download_url="$1"
    local output_name="$2"

    local proxy_url="${GHPROXY}/${download_url}"
    local tmp_file="/tmp/${output_name}.download"

    info "下载: ${download_url}"
    info "代理: ${proxy_url}"

    curl $CURL_OPTS --progress-bar -o "$tmp_file" "$proxy_url"
    local curl_exit=$?

    if [ $curl_exit -ne 0 ]; then
        warn "代理下载失败 (exit: ${curl_exit})，尝试直连..."
        curl $CURL_OPTS --progress-bar -o "$tmp_file" "$download_url"
        curl_exit=$?
    fi

    if [ $curl_exit -ne 0 ]; then
        fail "下载失败: ${output_name}"
        rm -f "$tmp_file"
        return 1
    fi

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

    local size
    size=$(stat -c%s "${BIN_DIR}/${output_name}" 2>/dev/null || stat -f%z "${BIN_DIR}/${output_name}" 2>/dev/null)
    info "已安装: ${BIN_DIR}/${output_name} (${size} bytes)"
}

download_github_release() {
    local repo="$1"
    local name_pattern="$2"
    local output_name="$3"

    if ! should_download "$output_name"; then
        info "跳过 ${output_name} (已存在且有效)"
        return 0
    fi

    local download_url
    download_url=$(get_latest_download_url "$repo" "$name_pattern")

    if [ -z "$download_url" ]; then
        fail "无法获取 ${repo} 的下载链接，跳过 ${output_name}"
        warn "可手动下载后放到 ${BIN_DIR}/${output_name}"
        return 0
    fi

    download_and_install "$download_url" "$output_name" || {
        warn "${output_name} 安装失败，跳过 (不影响其他工具)"
        return 0
    }
}

echo ""
info "=========================================="
info "  RedAgent 工具下载 - Linux ${ARCH}"
info "  使用代理: ${GHPROXY}"
info "  强制下载: ${FORCE_DOWNLOAD}"
info "=========================================="
echo ""

# --- ProjectDiscovery 工具 ---
info "--- ProjectDiscovery 工具集 ---"

download_github_release "projectdiscovery/subfinder" "linux_${ARCH}" "subfinder"
download_github_release "projectdiscovery/nuclei" "linux_${ARCH}" "nuclei"
download_github_release "projectdiscovery/httpx" "linux_${ARCH}" "httpx"
download_github_release "projectdiscovery/naabu" "linux_${ARCH}" "naabu"
download_github_release "projectdiscovery/katana" "linux_${ARCH}" "katana"

# --- RustScan ---
info "--- RustScan ---"
download_github_release "RustScan/RustScan" "linux" "rustscan"

# --- Feroxbuster ---
info "--- Feroxbuster ---"
download_github_release "epi052/feroxbuster" "linux-${ARCH}" "feroxbuster"

# --- Gitleaks ---
info "--- Gitleaks ---"
download_github_release "gitleaks/gitleaks" "linux_${ARCH}" "gitleaks"

# --- Nmap (通过 apt 安装) ---
info "--- Nmap ---"
if command -v nmap &>/dev/null; then
    info "nmap 已在系统 PATH 中"
elif [ -f "${BIN_DIR}/nmap" ]; then
    info "nmap 已存在于 bin/"
else
    warn "nmap 需要通过系统包管理器安装: sudo apt install -y nmap"
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
mkdir -p "$WORDLIST_DIR"
if [ ! -f "${WORDLIST_DIR}/raft-medium-directories.txt" ] || \
   [ "$(stat -c%s "${WORDLIST_DIR}/raft-medium-directories.txt" 2>/dev/null || stat -f%z "${WORDLIST_DIR}/raft-medium-directories.txt" 2>/dev/null || echo "0")" -lt 1000 ]; then
    info "下载 SecLists Web 字典..."
    seclists_url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt"
    proxy_seclists_url="${GHPROXY}/${seclists_url}"
    curl $CURL_OPTS --progress-bar -o "${WORDLIST_DIR}/raft-medium-directories.txt" "$proxy_seclists_url" || \
    curl $CURL_OPTS --progress-bar -o "${WORDLIST_DIR}/raft-medium-directories.txt" "$seclists_url" || \
    warn "字典下载失败，可手动下载到 wordlists/ 目录"
else
    info "字典已存在，跳过"
fi

# --- Nuclei 模板初始化 ---
info "--- Nuclei 模板 ---"
if [ -f "${BIN_DIR}/nuclei" ]; then
    info "更新 Nuclei 模板 (需要较长时间)..."
    "${BIN_DIR}/nuclei" -update-templates 2>/dev/null || warn "模板更新失败，首次运行时会自动下载"
fi

echo ""
info "=========================================="
info "  工具下载完成！"
info "=========================================="
echo ""
info "已安装工具:"
for tool in subfinder nuclei httpx naabu katana rustscan feroxbuster gitleaks; do
    if [ -f "${BIN_DIR}/${tool}" ] && [ -x "${BIN_DIR}/${tool}" ]; then
        size=$(stat -c%s "${BIN_DIR}/${tool}" 2>/dev/null || stat -f%z "${BIN_DIR}/${tool}" 2>/dev/null || echo "?")
        echo -e "  ${GREEN}✓${NC} ${tool} (${size} bytes)"
    elif command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} ${tool} (系统PATH)"
    else
        echo -e "  ${YELLOW}✗${NC} ${tool}"
    fi
done
echo ""
info "使用方法:"
info "  1. 运行: bash deploy.sh"
info "  2. 开始: python3 main.py example.com"
