#!/usr/bin/env bash
#
# cloud-r2pan 一键部署脚本（Linux）
#
# 功能：安装系统依赖 → 安装 Node → 从 GitHub 克隆仓库 → 安装 npm 依赖
#       → 登录 Cloudflare → 创建 R2/D1 资源 → 写入 Secret → 部署到 Workers
#
# 用法：
#   1) 在任意 Linux 机器上把本脚本保存为 deploy.sh，然后执行：
#        bash deploy.sh
#   2) 全自动（无浏览器 / CI 环境，推荐）：
#        CLOUDFLARE_API_TOKEN=xxx ADMIN_PASSWORD='你的强密码' bash deploy.sh
#   3) 也可先手动 clone 仓库，再在仓库目录内执行 `bash deploy.sh`（脚本会直接使用当前目录）
#
# 可选环境变量：
#   REPO_URL / REPO_BRANCH   仓库地址与分支（默认官方仓库 / main）
#   WORK_DIR                 克隆目标目录（默认 $HOME/cloud-r2pan）
#   R2_BUCKET / D1_NAME      R2 桶名 / D1 库名（默认 cloud-r2pan）
#   ADMIN_PASSWORD           管理后台密码（必须，非交互环境必填）
#   TURNSTILE_SITEKEY / TURNSTILE_SECRET / TOTP_RECOVERY   可选 Secret
#   CF_CONFIG                配置文件（默认 wrangler.jsonc）
#
set -euo pipefail

# ────────────────────────── 可配置项 ──────────────────────────
REPO_URL="${REPO_URL:-https://github.com/Admin666pro/cloud-r2pan.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"
WORK_DIR="${WORK_DIR:-$HOME/cloud-r2pan}"
R2_BUCKET="${R2_BUCKET:-cloud-r2pan}"
D1_NAME="${D1_NAME:-cloud-r2pan}"
CF_CONFIG="${CF_CONFIG:-wrangler.jsonc}"
NODE_MIN_MAJOR=18
NODE_INSTALL_VERSION=20

# ────────────────────────── 输出工具 ──────────────────────────
info() { printf '\033[1;34m[信息]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[成功]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[警告]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[错误]\033[0m %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# 以 root 权限执行（无 sudo 且非 root 时报错提示）
run_root() {
  if [ "$(id -u)" -eq 0 ]; then "$@"
  elif have sudo; then sudo "$@"
  else die "需要 root/sudo 权限来安装系统依赖，请手动执行：$*"
  fi
}

# ────────────────────────── 1. 系统依赖 ──────────────────────────
ensure_base() {
  local miss=()
  for c in git curl; do have "$c" || miss+=("$c"); done
  [ "${#miss[@]}" -eq 0 ] && return 0
  info "安装系统依赖：${miss[*]}"
  if have apt-get; then
    run_root apt-get update -y
    run_root apt-get install -y git curl ca-certificates
  elif have dnf; then
    run_root dnf install -y git curl ca-certificates
  elif have yum; then
    run_root yum install -y git curl ca-certificates
  elif have apk; then
    run_root apk add --no-cache git curl ca-certificates bash
  else
    die "未识别的包管理器，请手动安装 git 和 curl 后重试"
  fi
}

# ────────────────────────── 2. Node.js ──────────────────────────
ensure_node() {
  if have node; then
    local major
    major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
    if [ "$major" -ge "$NODE_MIN_MAJOR" ]; then
      ok "Node $(node -v) 已满足要求"
      return 0
    fi
    warn "Node $(node -v) 版本过低，需要 >= $NODE_MIN_MAJOR，将安装 Node $NODE_INSTALL_VERSION"
  fi

  info "通过 nvm 安装 Node.js $NODE_INSTALL_VERSION ..."
  export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
  if [ ! -s "$NVM_DIR/nvm.sh" ]; then
    curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash \
      || die "nvm 下载失败，请检查网络后重试（或手动安装 Node.js >= $NODE_MIN_MAJOR）"
  fi
  # nvm 脚本在 set -u 下可能引用未定义变量，临时关闭
  set +u
  # shellcheck disable=SC1090
  . "$NVM_DIR/nvm.sh"
  nvm install "$NODE_INSTALL_VERSION" || { set -u; die "Node.js 安装失败"; }
  nvm use "$NODE_INSTALL_VERSION" || { set -u; die "Node.js 切换失败"; }
  nvm alias default "$NODE_INSTALL_VERSION" >/dev/null 2>&1 || true
  set -u
  have node || die "Node.js 安装后仍不可用"
  ok "Node $(node -v)"
}

# ────────────────────────── 3. 克隆/更新仓库 ──────────────────────────
prepare_repo() {
  if [ -f "$CF_CONFIG" ] && [ -f "package.json" ]; then
    REPO_DIR="$(pwd)"
    info "检测到当前目录已是项目：$REPO_DIR"
  elif [ -d "$WORK_DIR/.git" ]; then
    REPO_DIR="$WORK_DIR"
    info "更新已有仓库：$REPO_DIR"
    git -C "$REPO_DIR" fetch --depth 1 origin "$REPO_BRANCH"
    git -C "$REPO_DIR" checkout "$REPO_BRANCH"
    git -C "$REPO_DIR" merge --ff-only "origin/$REPO_BRANCH" || warn "无法快进合并，改用当前工作区代码"
  else
    REPO_DIR="$WORK_DIR"
    info "从 GitHub 克隆仓库：$REPO_URL → $REPO_DIR"
    git clone --depth 1 -b "$REPO_BRANCH" "$REPO_URL" "$REPO_DIR" \
      || die "克隆失败，请检查仓库地址、分支或网络"
  fi
  cd "$REPO_DIR"
  [ -f "$CF_CONFIG" ] || die "未找到配置文件 $CF_CONFIG"
  ok "工作目录：$(pwd)"
}

# ────────────────────────── 4. 安装 npm 依赖 ──────────────────────────
install_deps() {
  info "安装 npm 依赖（首次可能较慢）..."
  if ! { npm ci --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund; }; then
    die "npm 依赖安装失败"
  fi
  ok "npm 依赖已就绪"
}

# wrangler 包装：显式指定配置文件，避免仓库内同时存在 wrangler.toml 与 wrangler.jsonc 造成歧义
wr() { npx --yes wrangler "$@" --config "$CF_CONFIG"; }

# ────────────────────────── 5. 登录 Cloudflare ──────────────────────────
ensure_auth() {
  if [ -n "${CLOUDFLARE_API_TOKEN:-}" ]; then
    export CLOUDFLARE_API_TOKEN
    ok "使用 CLOUDFLARE_API_TOKEN 进行认证"
    return 0
  fi
  if npx --yes wrangler whoami >/dev/null 2>&1; then
    ok "已登录 Cloudflare"
    return 0
  fi
  info "需要登录 Cloudflare，将打开浏览器授权页"
  info "若为无浏览器服务器，请改用：CLOUDFLARE_API_TOKEN=xxx bash deploy.sh"
  npx --yes wrangler login || die "Cloudflare 登录失败，请改用 CLOUDFLARE_API_TOKEN 方式"
}

# ────────────────────────── 6. 创建 R2 / D1 资源 ──────────────────────────
ensure_r2() {
  info "检查 R2 存储桶：$R2_BUCKET"
  if wr r2 bucket create "$R2_BUCKET" >/dev/null 2>&1; then
    ok "R2 存储桶已创建：$R2_BUCKET"
  elif wr r2 bucket list 2>/dev/null | grep -q "$R2_BUCKET"; then
    ok "R2 存储桶已存在：$R2_BUCKET"
  else
    warn "R2 创建失败（账号可能未开通 R2）。若你使用 S3/WebDAV 存储，可忽略此警告；否则请手动创建后重试。"
  fi
}

ensure_d1() {
  info "检查 D1 数据库：$D1_NAME"
  local id
  id="$(wr d1 list --json 2>/dev/null \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const a=JSON.parse(s);const n=process.argv[1];const m=(Array.isArray(a)?a:[]).find(x=>x.name===n);if(m)process.stdout.write(m.uuid||m.id||"")}catch(e){}})' "$D1_NAME")" || true

  if [ -z "$id" ]; then
    info "创建 D1 数据库：$D1_NAME"
    local out
    out="$(wr d1 create "$D1_NAME" 2>&1 || true)"
    id="$(printf '%s' "$out" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -n1)"
  fi

  [ -n "$id" ] || die "无法获取 D1 database_id，请手动创建数据库并把 id 填入 $CF_CONFIG"
  ok "D1 database_id = $id"

  # 将 database_id 写入配置文件（替换已有的空值/旧值）
  node -e '
    const fs = require("fs");
    const [file, id] = process.argv.slice(1);
    let s = fs.readFileSync(file, "utf8");
    if (/"database_id"\s*:\s*"[^"]*"/.test(s)) {
      s = s.replace(/"database_id"\s*:\s*"[^"]*"/, "\"database_id\": \"" + id + "\"");
      fs.writeFileSync(file, s);
    }
  ' "$CF_CONFIG" "$id"
  ok "已将 database_id 写入 $CF_CONFIG"
}

# ────────────────────────── 7. 写入 Secret ──────────────────────────
set_secret() {
  local name="$1" val="$2"
  [ -z "$val" ] && return 0
  if printf '%s' "$val" | wr secret put "$name" >/dev/null 2>&1; then
    ok "已设置 Secret：$name"
  else
    warn "设置 Secret 失败：$name（可稍后在 Cloudflare 控制台手动添加）"
  fi
}

get_admin_password() {
  [ -n "${ADMIN_PASSWORD:-}" ] && return 0
  if [ -t 0 ]; then
    printf '请输入管理后台密码（输入不回显）: ' >&2
    read -rs ADMIN_PASSWORD; echo >&2
    printf '请再次输入以确认: ' >&2
    local again
    read -rs again; echo >&2
    [ "$ADMIN_PASSWORD" = "$again" ] || die "两次输入不一致"
    [ -n "$ADMIN_PASSWORD" ] || die "密码不能为空"
  else
    die "非交互环境必须通过环境变量提供 ADMIN_PASSWORD，例如：ADMIN_PASSWORD='xxx' bash deploy.sh"
  fi
}

setup_secrets() {
  get_admin_password
  info "写入 Secrets（admin 为必填，其余为空则跳过）"
  set_secret admin "$ADMIN_PASSWORD"
  set_secret totp_recovery "${TOTP_RECOVERY:-}"
  set_secret turnstile_sitekey "${TURNSTILE_SITEKEY:-}"
  set_secret turnstile_secret "${TURNSTILE_SECRET:-}"
}

# ────────────────────────── 8. 部署 ──────────────────────────
do_deploy() {
  info "开始部署到 Cloudflare Workers ..."
  local out
  if ! out="$(wr deploy 2>&1)"; then
    printf '%s\n' "$out"
    die "部署失败，请根据上方日志排查"
  fi
  printf '%s\n' "$out"
  WORKER_URL="$(printf '%s' "$out" | grep -oE 'https://[A-Za-z0-9._-]+\.workers\.dev' | head -n1 || true)"
  ok "部署完成"
}

# ────────────────────────── 主流程 ──────────────────────────
main() {
  info "==================== cloud-r2pan 一键部署 ===================="
  [ "$(id -u)" -eq 0 ] && warn "当前以 root 运行，wrangler 配置将写入 /root"
  ensure_base
  ensure_node
  prepare_repo
  install_deps
  ensure_auth
  ensure_r2
  ensure_d1
  setup_secrets
  do_deploy

  echo
  ok "全部完成！"
  if [ -n "${WORKER_URL:-}" ]; then
    info "访问地址：$WORKER_URL/admin"
  else
    info "请在上方 wrangler 输出中查看部署地址（形如 https://cloud-r2pan.<你的账号>.workers.dev），后台入口为 /admin"
  fi
  info "数据库表会在首次访问时自动创建，无需手动执行 SQL"
}

main "$@"
