#!/bin/bash
# rebuild_bpftime.sh — 部署完新 Frida devkit 后，重编 bpftime 让
# libbpftime-agent.so 真正链接到带采样逻辑的 libfrida-gum.a。
#
# 关键点：
#   - bpftime 用 CMake 管理。FridaGum-prefix 是 ExternalProject_Add，
#     它在 build/FridaGum-prefix/ 下解包 devkit 并把 libfrida-gum.a 落到
#     build/FridaGum-prefix/src/FridaGum/libfrida-gum.a。CMake 不会自动
#     检测第三方文件变化，所以必须强制删 stamp 重新 configure。
#   - 实践上：删 FridaGum-prefix 整个目录 + 重新 cmake build 即可。
#   - 仅编 agent + syscall-server 两个目标，不必全量 build。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BPFTIME_ROOT="$SCRIPT_DIR/../bpftime"
BUILD_DIR="$BPFTIME_ROOT/build"

if [ ! -d "$BUILD_DIR" ]; then
    echo "[rebuild] ERROR: bpftime build 目录不存在：$BUILD_DIR"
    echo "          请先完成初始构建（见仓库根 README.md）："
    echo "            cmake -S ../bpftime -B ../bpftime/build -DBPFTIME_LLVM_JIT=OFF"
    echo "            cmake --build ../bpftime/build --target bpftime-agent bpftime-syscall-server"
    exit 1
fi

# 1. 删除 FridaGum-prefix 让 CMake 重新解包新 devkit
FRIDA_GUM_PREFIX="$BUILD_DIR/FridaGum-prefix"
if [ -d "$FRIDA_GUM_PREFIX" ]; then
    echo "[rebuild] 删除 $FRIDA_GUM_PREFIX 强制 CMake 重新解包"
    rm -rf "$FRIDA_GUM_PREFIX"
fi
FRIDA_CORE_PREFIX="$BUILD_DIR/FridaCore-prefix"
if [ -d "$FRIDA_CORE_PREFIX" ]; then
    echo "[rebuild] 删除 $FRIDA_CORE_PREFIX 强制 CMake 重新解包"
    rm -rf "$FRIDA_CORE_PREFIX"
fi

# 1b. 检测 CMakeCache 是否残留旧源码路径（bpftime 在历史上被复制/移动过，
# cache 里可能记着 /mnt/disk1/... 之类的老路径，会让 cmake 配置直接报错。
# 一次性扫描 build/ 下所有 CMakeCache.txt（包括 ubpf 等子项目），把含旧路径
# 的 cache 连同所在 CMakeFiles/ 目录一并删除。
STALE_CACHES=$(find "$BUILD_DIR" -name CMakeCache.txt \
    -exec grep -l "/mnt/disk1\|/mnt/disk2/huangkai/apnet/bpftime" {} \; 2>/dev/null || true)
if [ -n "$STALE_CACHES" ]; then
    echo "[rebuild] 发现以下 CMakeCache 残留旧源码路径，将一并清理："
    echo "$STALE_CACHES" | sed 's/^/  /'
    while IFS= read -r cache; do
        [ -z "$cache" ] && continue
        cache_dir=$(dirname "$cache")
        rm -f "$cache"
        rm -rf "$cache_dir/CMakeFiles"
    done <<< "$STALE_CACHES"
fi

# 1c. 处理 libncurses-dev 缺失。bpftime/CMakeLists.txt:10 给所有可执行目标
# 全局加了 `-lncurses`（用于 CLI 工具的 readline），但机器上没装 libncurses-dev
# 时会导致 cmake 在 try_compile 阶段失败。agent.so / syscall-server.so 不需要
# ncurses，所以临时注释掉这一行；编译完成后由 trap 恢复。
BPFTIME_CMAKE_MAIN="$BPFTIME_ROOT/CMakeLists.txt"
# 注：grep BRE 下 `(` 字面匹配，但某些 grep 实现会把 set(...) 里的 ( 当作
# 分组起始而拒绝匹配；改用更宽松的模式 `-lncurses` 然后限定未注释行。
if grep -E '^[^#]*-lncurses' "$BPFTIME_CMAKE_MAIN" >/dev/null; then
    echo "[rebuild] 临时注释掉 CMakeLists.txt:10 的 -lncurses（libncurses-dev 未装）"
    python3 <<EOF
import re
path = "$BPFTIME_CMAKE_MAIN"
with open(path) as f: c = f.read()
c2, n = re.subn(r'^(set\(CMAKE_EXE_LINKER_FLAGS.*-lncurses"\))',
                r'# \1  # disabled by rebuild_bpftime.sh', c, flags=re.M)
open(path, 'w').write(c2)
assert n == 1, f"expected 1 replacement, got {n}"
EOF
    RESTORE_NCURSES=1
else
    RESTORE_NCURSES=0
fi
restore_ncurses() {
    if [ "$RESTORE_NCURSES" = "1" ]; then
        python3 <<EOF
import re
path = "$BPFTIME_CMAKE_MAIN"
with open(path) as f: c = f.read()
c2, n = re.subn(r'^# (set\(CMAKE_EXE_LINKER_FLAGS.*-lncurses"\))  # disabled by rebuild_bpftime.sh',
                r'\1', c, flags=re.M)
open(path, 'w').write(c2)
assert n == 1, f"expected 1 restore, got {n}"
EOF
        echo "[rebuild] 已恢复 CMakeLists.txt 的 -lncurses 行"
    fi
}
trap restore_ncurses EXIT

# 2. 重新配置（让 ExternalProject 重新跑下载/解包步骤）
# 同时禁用 LLVM JIT（agent.so 用 ubpf 后端就够；LLVM 未装会让 configure 失败）
echo "[rebuild] cmake 重新配置（-DBPFTIME_LLVM_JIT=OFF）"
cmake -S "$BPFTIME_ROOT" -B "$BUILD_DIR" -DBPFTIME_LLVM_JIT=OFF 2>&1 | tail -20

# 3. 编译 agent 和 syscall-server（不必全量 build）
echo "[rebuild] 编译 agent + syscall-server（耗时较长，请耐心等待）"
cmake --build "$BUILD_DIR" --target bpftime-agent bpftime-syscall-server -- -j"$(nproc)"

AGENT_SO="$BUILD_DIR/runtime/agent/libbpftime-agent.so"
SYSCALL_SO="$BUILD_DIR/runtime/syscall-server/libbpftime-syscall-server.so"

# 4. 验证采样字符串真的进了 agent.so
# 注意：strings | grep -q 在 set -o pipefail 下会被 SIGPIPE 干扰（grep -q
# 命中后立即退出，strings 收到 SIGPIPE，pipefail 把 pipeline 视为失败）。
# 用 grep 不带 -q + 重定向到 /dev/null 避免这个坑。
echo
echo "[rebuild] 检验改造是否生效 —— libbpftime-agent.so 内是否含 sampling_skip 字符串"
if strings "$AGENT_SO" | grep "sampling_skip" >/dev/null 2>&1; then
    echo "  [OK] sampling_skip 标签已嵌入 agent.so"
else
    echo "  [WARN] 未在 agent.so 里找到 sampling_skip 字符串"
    echo "         这可能意味着 FridaGum-prefix 没有重新解包，或 devkit 部署失败。"
fi

echo
echo "[rebuild] 产物："
ls -lh "$AGENT_SO" "$SYSCALL_SO"
