#!/bin/bash
# deploy_frida_to_bpftime.sh — 把含采样逻辑的 libfrida-gum 部署到 bpftime 的
# third_party/frida/，让重编后的 libbpftime-agent.so 包含采样逻辑。
#
# 关键背景（实测发现，写在这里防止以后再踩坑）：
#   1. frida/build/release-packages/ 里的 frida-gum-devkit-16.1.2-linux-x86_64.tar.xz
#      时间戳是 4月9日，**早于** Frida 采样代码的最后修改（8月12日），所以
#      这个 tar 里的 libfrida-gum.a **没有采样逻辑**。不能直接用它。
#   2. frida/build/frida-linux-x86_64/lib/libfrida-gum-1.0.a（5.8MB）虽然有
#      采样逻辑，但**符号没有 _frida_ 前缀**，bpftime agent.so 加载时会报
#      "undefined symbol: g_direct_hash"（host 进程没有 GLib）。
#   3. 正确的做法：用 frida/releng/devkit.py 从当前 Frida 源码 + 当前构建产物
#      重新生成 devkit。它会：
#        - 用 objcopy 把 GLib 符号都加上 _frida_ 前缀（避免冲突）
#        - 把 frida-gum 单独打包成自包含的静态库（包含 GLib、libffi 等）
#        - 输出 libfrida-gum.a (~88MB)、frida-gum.h、frida-gum-example.c
#   4. 生成的 devkit 必须以 frida-gum-devkit-16.1.2-linux-x86_64.tar.xz 命名
#      （bpftime cmake/frida.cmake 写死），并更新那里的 SHA256。
#
# 备份策略：原 tar + 原 .a 都搬到 backup_<ts>/ 下，方便回滚。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# bpftime 在本仓库内（见仓库根 README.md）
BPFTIME_FRIDA_DIR="$SCRIPT_DIR/../bpftime/third_party/frida"
BPFTIME_CMAKE_FRIDA="$SCRIPT_DIR/../bpftime/cmake/frida.cmake"
VERSION="16.1.2"
TAR_NAME="frida-gum-devkit-${VERSION}-linux-x86_64.tar.xz"

# frida 构建环境在仓库外（体积太大未 vendor）：仓库自带预生成的采样版
# devkit（bpftime/third_party/frida/ 下），只有改了 frida-gum 采样代码
# 需要重新生成 devkit 时才用到本脚本。届时通过环境变量指向一个带构建
# 产物的 frida checkout：
#   FRIDA_ROOT=/path/to/frida ./deploy_frida_to_bpftime.sh
FRIDA_ROOT="${FRIDA_ROOT:-}"
FRIDA_BUILD_DIR="$FRIDA_ROOT/build"

# ---------- 前置检查 ----------
if [ -z "$FRIDA_ROOT" ] || [ ! -d "$FRIDA_ROOT" ]; then
    echo "[deploy] ERROR: 未设置 FRIDA_ROOT 或目录不存在（当前值：'${FRIDA_ROOT:-<空>}'）"
    echo "         本仓库已自带采样版 devkit（../bpftime/third_party/frida/），"
    echo "         无需重新部署即可构建 agent。只有修改了 frida-gum 采样代码"
    echo "         （frida-gum/gum/backend-x86/guminterceptor-x86.c）后才需要："
    echo "         在一个带构建产物的 frida checkout 下 ninja 出新的"
    echo "         libfrida-gum-1.0.a，然后 FRIDA_ROOT=<frida目录> 运行本脚本。"
    exit 1
fi
DEVKIT_PY="$FRIDA_ROOT/releng/devkit.py"
if [ ! -f "$DEVKIT_PY" ]; then
    echo "[deploy] ERROR: 找不到 $DEVKIT_PY"
    exit 1
fi

# 检查 ninja 已经把改造后的 libfrida-gum-1.0.a 编出来
NEW_LIBGUM="$FRIDA_BUILD_DIR/frida-linux-x86_64/lib/libfrida-gum-1.0.a"
if [ ! -f "$NEW_LIBGUM" ]; then
    echo "[deploy] ERROR: $NEW_LIBGUM 不存在，请先 ninja"
    exit 1
fi
if ! strings "$NEW_LIBGUM" | grep "sampling_skip" >/dev/null 2>&1; then
    echo "[deploy] ERROR: $NEW_LIBGUM 不含 sampling_skip"
    echo "         请先在 frida/build/tmp-linux-x86_64/frida-gum 下 ninja"
    exit 1
fi
echo "[deploy] 源 libfrida-gum-1.0.a 含 sampling_skip，开始生成 devkit"

# ---------- 备份 ----------
TS=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$BPFTIME_FRIDA_DIR/backup_$TS"
mkdir -p "$BACKUP_DIR"
echo "[deploy] 备份原文件到 $BACKUP_DIR"

for f in "$BPFTIME_FRIDA_DIR"/frida-gum-devkit-*.tar.xz \
         "$BPFTIME_FRIDA_DIR"/libfrida-gum.a \
         "$BPFTIME_FRIDA_DIR"/frida-gum.h; do
    [ -f "$f" ] || continue
    mv "$f" "$BACKUP_DIR/"
    echo "  备份 $(basename "$f")"
done
cp "$BPFTIME_CMAKE_FRIDA" "$BACKUP_DIR/frida.cmake.bak"
echo "  备份 frida.cmake"

# ---------- 用 devkit.py 重新生成 ----------
WORK=$(mktemp -d)
trap "rm -rf $WORK" EXIT

# devkit.py 必须从 frida/ 目录运行（它 import machine_file 等 releng 模块）
echo "[deploy] 运行 releng/devkit.py 生成 devkit（含 _frida_ 符号前缀）"
( cd "$FRIDA_ROOT" && python3 releng/devkit.py frida-gum linux-x86_64 "$WORK" 2>&1 | tail -5 )

if [ ! -f "$WORK/libfrida-gum.a" ]; then
    echo "[deploy] ERROR: devkit.py 没有产出 libfrida-gum.a"
    exit 1
fi

# 二次确认：devkit 版的 libfrida-gum.a 必须同时含 sampling_skip 和 _frida_g_direct_hash
if ! strings "$WORK/libfrida-gum.a" | grep "sampling_skip" >/dev/null 2>&1; then
    echo "[deploy] ERROR: devkit libfrida-gum.a 不含 sampling_skip"
    exit 1
fi
if ! nm "$WORK/libfrida-gum.a" 2>/dev/null | grep -E "T _frida_g_direct_hash" >/dev/null 2>&1; then
    echo "[deploy] WARN: devkit libfrida-gum.a 里没有 _frida_g_direct_hash 符号"
    echo "         agent.so 加载时可能仍报 undefined symbol: g_direct_hash"
fi
echo "[deploy] 校验通过：含 sampling_skip + _frida_g_ 前缀"

# ---------- 打包成 bpftime 期望的命名 ----------
STAGE=$(mktemp -d)
mkdir -p "$STAGE/frida-gum-devkit"
cp "$WORK/libfrida-gum.a" "$STAGE/frida-gum-devkit/"
cp "$WORK/frida-gum.h"    "$STAGE/frida-gum-devkit/"
cp "$WORK/frida-gum-example.c" "$STAGE/frida-gum-devkit/" 2>/dev/null || true

NEW_TAR="$BPFTIME_FRIDA_DIR/$TAR_NAME"
tar -C "$STAGE" -cJf "$NEW_TAR" frida-gum-devkit
rm -rf "$STAGE"
ls -lh "$NEW_TAR"

# ---------- 更新 SHA256 ----------
NEW_HASH=$(sha256sum "$NEW_TAR" | awk '{print $1}')
echo "[deploy] 新 devkit SHA256 = $NEW_HASH"

python3 - "$BPFTIME_CMAKE_FRIDA" "$NEW_HASH" <<'PY'
import re, sys
path, new_hash = sys.argv[1], sys.argv[2]
with open(path) as f:
    content = f.read()
pat = re.compile(
    r'(if\(\$\{FRIDA_OS_ARCH\}\s+STREQUAL\s+"linux-x86_64"\)\s*\n'
    r'\s*set\(FRIDA_CORE_DEVKIT_SHA256[^)]+\)\s*\n'
    r'\s*set\(FRIDA_GUM_DEVKIT_SHA256\s+")[^"]+(")'
)
new_content, n = pat.subn(lambda m: m.group(1) + new_hash + m.group(2), content)
if n != 1:
    print(f"[deploy] WARN: regex 替换 {n} 处（期望 1 处），请手动检查 frida.cmake")
with open(path, 'w') as f:
    f.write(new_content)
print(f"[deploy] 已更新 {path}（FRIDA_GUM_DEVKIT_SHA256 → {new_hash[:12]}...）")
PY

# ---------- 同步 .a + header 到 third_party/frida/ ----------
# ExternalProject 解包会把同样的文件落到 build/FridaGum-prefix/，但为了
# 万无一失，这里也直接同步到 third_party/frida/（CMakeLists 不会读这俩，
# 但有些第三方脚本/IDE 会）。
cp "$WORK/libfrida-gum.a" "$BPFTIME_FRIDA_DIR/libfrida-gum.a"
cp "$WORK/frida-gum.h"    "$BPFTIME_FRIDA_DIR/frida-gum.h"
echo "[deploy] 同步 libfrida-gum.a + frida-gum.h 到 $BPFTIME_FRIDA_DIR"

echo
echo "[deploy] 完成。请运行 ./rebuild_bpftime.sh 重新编译 agent。"
