#!/bin/bash
# run_test.sh — FreeProbe 端到端采样验证测试的主控脚本。
#
# 流程：
#   1. 构建依赖检查（agent.so / syscall-server.so 必须存在）
#   2. 启动 observer，在 syscall-server LD_PRELOAD 下运行；它把 uprobe
#      attach 到 victim 二进制的 target_function
#   3. 启动 victim，在 agent LD_PRELOAD 下运行；victim 内部调用
#      target_function N 次
#   4. victim 退出后，observer 收到 SIGTERM，打印最终 SAMPLE_HITS=<count>
#   5. 比对 SAMPLE_HITS vs. OBSERVED_CALLS / 20，±25% 容忍度内 PASS
#
# 这个测试如果 PASS，证明改造后的 Frida trampoline 在 bpftime userspace
# uprobe 路径里真实生效：~95% 调用走快路径绕过 enter_thunk，~5% 进入慢
# 路径触发 bpftime → eBPF observer。
#
# 如果 SAMPLE_HITS == OBSERVED_CALLS（即 100% 被观测），说明采样没生效，
# 可能是：
#   - bpftime agent 没链接到改造版 libfrida-gum.a（运行 deploy + rebuild）
#   - agent.so 没通过 LD_PRELOAD 注入（检查 LD_PRELOAD 路径）
#   - Frida 改造代码本身没编进去（检查 sampling_skip 是否在 strings）

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ---------- 参数 ----------
TOTAL_CALLS="${1:-10000}"
NUM_THREADS="${2:-1}"
TOLERANCE="${3:-0.25}"   # ±25%，与 sampling_trampoline_test 一致
SAMPLE_RATE=20           # 必须与 guminterceptor-x86.c 的 GUM_SAMPLE_RATE 一致

# ---------- 路径 ----------
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BPFTIME_BUILD="$REPO_ROOT/my_ex/bpftime/build"
AGENT_SO="$BPFTIME_BUILD/runtime/agent/libbpftime-agent.so"
SYSCALL_SO="$BPFTIME_BUILD/runtime/syscall-server/libbpftime-syscall-server.so"

VICTIM_BIN="$SCRIPT_DIR/bin/victim"
OBSERVER_BIN="$SCRIPT_DIR/bin/observer"

# ---------- 前置检查 ----------
check_file() {
    if [ ! -f "$1" ]; then
        echo "[run] ERROR: 找不到 $1"
        if [ "$2" = "agent" ]; then
            echo "       请先在 my_ex/bpftime 下完成初始构建（make build）。"
        fi
        exit 1
    fi
}
check_file "$VICTIM_BIN"
check_file "$OBSERVER_BIN"
check_file "$AGENT_SO" agent
check_file "$SYSCALL_SO" agent

# 采样字符串检查（早期发现部署缺口）
# 用 grep 而非 grep -q 避免 set -o pipefail + SIGPIPE 误判
if ! strings "$AGENT_SO" | grep "sampling_skip" >/dev/null 2>&1; then
    echo "[run] WARN: libbpftime-agent.so 未包含 sampling_skip 字符串。"
    echo "          这意味着采样逻辑没有进 agent.so，测试几乎肯定会失败（SAMPLE_HITS ≈ OBSERVED_CALLS）。"
    echo "          请先运行 ./deploy_frida_to_bpftime.sh + ./rebuild_bpftime.sh"
    echo
fi

# ---------- 构建绝对路径 victim，便于 observer attach ----------
VICTIM_ABS="$VICTIM_BIN"

# ---------- 启动 observer (后台) ----------
# 给 observer 的命令行参数：victim 二进制路径 + 期望被观测的次数（仅用于日志）
# BPFTIME_VM_NAME=ubpf 必须同时给 observer 和 victim —— observer 在创建 handler
# 时把 VM 名写进 shm，victim 端 agent 取 handler 时按这个名查 VM factory。
echo "[run] 启动 observer，victim=$VICTIM_ABS expected_observed=$TOTAL_CALLS"
LD_PRELOAD="$SYSCALL_SO" BPFTIME_VM_NAME=ubpf \
    "$OBSERVER_BIN" "$VICTIM_ABS" "$TOTAL_CALLS" \
    > observer.stdout.log 2> observer.stderr.log &
OBS_PID=$!
echo "[run] observer pid=$OBS_PID"

# 给 observer 一点时间完成 attach（实测 < 1 秒）
sleep 2

# ---------- 启动 victim ----------
echo "[run] 启动 victim: total_calls=$TOTAL_CALLS threads=$NUM_THREADS"
LD_PRELOAD="$AGENT_SO" BPFTIME_VM_NAME=ubpf \
    "$VICTIM_BIN" "$TOTAL_CALLS" "$NUM_THREADS" \
    > victim.stdout.log 2> victim.stderr.log
VIC_RC=$?
echo "[run] victim exited rc=$VIC_RC"

# ---------- 让 observer 收尾 ----------
sleep 1
kill -TERM "$OBS_PID" 2>/dev/null || true
wait "$OBS_PID" 2>/dev/null || true

# ---------- 解析输出 ----------
OBSERVED=$(grep -oE 'OBSERVED_CALLS=[0-9]+' victim.stdout.log | head -1 | cut -d= -f2)
HITS=$(grep -oE 'SAMPLE_HITS=[0-9]+' observer.stdout.log | head -1 | cut -d= -f2)

if [ -z "$OBSERVED" ] || [ -z "$HITS" ]; then
    echo
    echo "=== 解析失败 ==="
    echo "OBSERVED='$OBSERVED'  HITS='$HITS'"
    echo
    echo "--- victim.stdout.log ---"
    cat victim.stdout.log
    echo "--- victim.stderr.log ---"
    cat victim.stderr.log
    echo "--- observer.stdout.log ---"
    cat observer.stdout.log
    echo "--- observer.stderr.log ---"
    cat observer.stderr.log
    exit 2
fi

EXPECTED=$((OBSERVED / SAMPLE_RATE))
LOWER=$(awk -v e="$EXPECTED" -v t="$TOLERANCE" 'BEGIN { printf "%d", e * (1 - t) }')
UPPER=$(awk -v e="$EXPECTED" -v t="$TOLERANCE" 'BEGIN { printf "%d", e * (1 + t) }')

PASS=0
if [ "$HITS" -ge "$LOWER" ] && [ "$HITS" -le "$UPPER" ]; then
    PASS=1
fi

echo
echo "=== FreeProbe 端到端采样验证 ==="
echo "  victim 总调用       = $OBSERVED"
echo "  observer 触发次数   = $HITS"
echo "  期望触发 (~1/$SAMPLE_RATE)  = $EXPECTED (容忍 [$LOWER, $UPPER])"
echo "  实测采样率          = $(awk -v h="$HITS" -v o="$OBSERVED" 'BEGIN { printf "%.4f", h / o }')"
echo "  目标采样率          = $(awk -v r="$SAMPLE_RATE" 'BEGIN { printf "%.4f", 1 / r }')"
echo
echo "  判定: $([ $PASS -eq 1 ] && echo PASS || echo FAIL)"

if [ "$HITS" -eq 0 ]; then
    echo
    echo "!! SAMPLE_HITS=0：observer 一次都没被触发。可能原因："
    echo "   - uprobe attach 失败（看 observer.stderr.log 里 'failed to attach'）"
    echo "   - victim 没在 LD_PRELOAD=libbpftime-agent.so 下运行"
    echo "   - 符号 target_function 没找到（检查 nm victim/victim | grep target_function）"
elif [ "$HITS" -ge "$OBSERVED" ]; then
    echo
    echo "!! SAMPLE_HITS == OBSERVED_CALLS：采样完全没有生效。可能原因："
    echo "   - bpftime agent.so 链接的是未改造 libfrida-gum.a（运行 deploy + rebuild）"
    echo "   - Frida 改造代码本身有 bug（先跑 ./../sampling_trampoline_test 排除）"
fi

[ $PASS -eq 1 ] && exit 0 || exit 1
