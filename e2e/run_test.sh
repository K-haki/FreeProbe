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
#   6. （可选）DUMP_TRAMPOLINE=1 时，测量结束后重新走一遍 attach，用
#      gdb attach 到长驻的插桩 victim，打印 trampoline / thunk 代码，
#      输出保存到 trampoline_dump.log（依赖 gdb + 免密 sudo）
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
BPFTIME_BUILD="$SCRIPT_DIR/../bpftime/build"
AGENT_SO="$BPFTIME_BUILD/runtime/agent/libbpftime-agent.so"
SYSCALL_SO="$BPFTIME_BUILD/runtime/syscall-server/libbpftime-syscall-server.so"

VICTIM_BIN="$SCRIPT_DIR/bin/victim"
OBSERVER_BIN="$SCRIPT_DIR/bin/observer"

# ---------- 前置检查 ----------
check_file() {
    if [ ! -f "$1" ]; then
        echo "[run] ERROR: 找不到 $1"
        if [ "$2" = "agent" ]; then
            echo "       请先在 ../bpftime 下完成初始构建（见仓库根 README.md）。"
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

# ---------- 可选功能：trampoline 代码 dump ----------
# 用法：DUMP_TRAMPOLINE=1 ./run_test.sh [total_calls] [threads] [tolerance]
# 参考 bpftime/trampoline_analysis_final_bak.sh 的 gdb 分析流程。
#
# 必须放在测量阶段之后执行：dump 用的长驻 victim 会真实触发 observer
# 的 BPF 计数，若混在测量阶段会把 SAMPLE_HITS 撑爆导致误判 FAIL。
#
# 注意：bak 脚本里 trampoline+0xe/+0x24 的固定 thunk 偏移是旧版布局；
# 采样改造版在 thunk 跳转前多了 ~40 字节采样指令，因此这里改为从
# 反汇编文本动态解析跳转目标，兼容两种形式：
#   - 直接跳转   jmp 0x<addr>
#   - 远跳转     jmp *0x2(%rip) + ud2 + 8 字节目标指针

gdb_batch() {
    # gdb_batch <pid> <gdb-command>
    sudo gdb -batch -p "$1" -ex "$2" 2>&1
}

read_qword() {
    # read_qword <pid> <addr>：读目标进程 8 字节并输出
    gdb_batch "$1" "x/gx $2" | grep -E '^0x[0-9a-f]+:' | awk '{print $2}' || true
}

resolve_jump_target() {
    # resolve_jump_target <pid> <kind> <target>：far 跳转的 target 是指针
    # 槽位地址，需要再解一次引用；direct 跳转本身就是目标地址
    if [ "$2" = "far" ]; then
        read_qword "$1" "$3"
    else
        echo "$3"
    fi
}

dump_trampoline_code() {
    # dump_trampoline_code <victim-pid>：对已插桩的进程做 gdb 反汇编
    local pid="$1"

    echo "========================================"
    echo "Trampoline 插桩代码 dump (pid=$pid, 符号 target_function)"
    echo "========================================"
    echo

    echo "────────────────────────────────────────"
    echo "1. target_function 入口（插桩后）"
    echo "────────────────────────────────────────"
    local entry_info
    entry_info=$(gdb_batch "$pid" "x/i target_function" || true)
    echo "$entry_info"
    echo

    local trampoline slot
    trampoline=$(echo "$entry_info" | grep -oP 'jmpq?\s+\K0x[0-9a-f]+' | head -1 || true)
    if [ -z "$trampoline" ]; then
        # 入口跳转距离超出 ±2GB 时，Frida 改用 jmpq *0x2(%rip) + 8 字节
        # 指针；gdb 注释里的地址就是那个指针的槽位（jmpq? 兼容 jmp/jmpq）
        slot=$(echo "$entry_info" | grep -E 'jmpq?\s+\*0x2\(%rip\)' \
            | grep -oP '#\s+\K0x[0-9a-f]+' | head -1 || true)
        if [ -n "$slot" ]; then
            trampoline=$(read_qword "$pid" "$slot")
        fi
    fi

    if [ -z "$trampoline" ]; then
        echo "!! 无法从 target_function 入口提取 trampoline 地址（插桩可能未生效，"
        echo "   或该进程不在 agent LD_PRELOAD 下运行）"
        return 0
    fi
    echo "说明：函数开头 5 字节被覆写为 jmp，跳到 trampoline（on_enter_trampoline）"
    echo

    echo "────────────────────────────────────────"
    echo "2. Trampoline 代码（含采样快/慢路径）"
    echo "────────────────────────────────────────"
    echo "地址: $trampoline"
    echo
    local tramp_asm
    tramp_asm=$(gdb_batch "$pid" "disassemble /r $trampoline,+128" || true)
    echo "$tramp_asm"
    echo
    echo "阅读提示："
    echo "  - mov %fs:0x2d0 → and \$0x3f    : 按真实 TID 取采样桶 [0,63]"
    echo "  - cmp \$20 / jl sampling_skip   : 计数未满 20 走快路径（~95% 调用）"
    echo "  - 快路径跳到重定位后的原函数序言，完全绕过 enter_thunk"
    echo "  - 慢路径 reset 桶计数后 jmp 进 enter_thunk，触发 bpftime 回调"
    echo

    # 按地址顺序解析 trampoline 内的 jmp 指令。direct 跳转行尾可能带
    # <symbol+off> 注解（如 tail jump 回原函数），所以用 match() 提取
    # 而不是锚定行尾
    local jmp_list
    jmp_list=$(echo "$tramp_asm" | awk '
        /jmp[q]?[ \t]+\*0x2\(%rip\)/ && $NF ~ /^0x[0-9a-f]+$/ {
            print "far " $NF; next }
        {
            if (match($0, /jmp[q]?[ \t]+0x[0-9a-f]+/)) {
                s = substr($0, RSTART, RLENGTH)
                sub(/^jmp[q]?[ \t]+/, "", s)
                print "direct " s
            }
        }')
    local kinds=() tgts=()
    while read -r k t; do
        [ -n "$k" ] || continue
        kinds+=("$k")
        tgts+=("$t")
    done <<< "$jmp_list"

    echo "────────────────────────────────────────"
    echo "3. trampoline 内跳转目标解析"
    echo "────────────────────────────────────────"
    local labels=("慢路径 → Enter Thunk（触发 bpftime 监听器）" \
                  "快路径 sampling_skip → 重定位后的原函数序言" \
                  "Leave Thunk（函数返回时触发）" \
                  "tail jump → 跳回原函数被覆写点之后")
    local i=0 resolved
    while [ "$i" -lt "${#kinds[@]}" ] && [ "$i" -lt 4 ]; do
        resolved=$(resolve_jump_target "$pid" "${kinds[$i]}" "${tgts[$i]}")
        echo "  jmp[$i] (${kinds[$i]}): ${resolved:-<解析失败>}   # ${labels[$i]}"
        i=$((i + 1))
    done
    if [ "${#kinds[@]}" -eq 0 ]; then
        echo "  （未在 trampoline 前 128 字节解析到 jmp 指令，布局可能与预期不同）"
    fi
    echo

    if [ "${#kinds[@]}" -ge 1 ]; then
        local enter_thunk
        enter_thunk=$(resolve_jump_target "$pid" "${kinds[0]}" "${tgts[0]}")
        if [ -n "$enter_thunk" ]; then
            echo "────────────────────────────────────────"
            echo "4. Enter Thunk 代码（地址 $enter_thunk）"
            echo "────────────────────────────────────────"
            echo "Frida 生成的代理代码：保存 CPU 上下文 → 调用 bpftime 回调 →"
            echo "恢复上下文 → 跳回 trampoline 继续执行"
            echo
            gdb_batch "$pid" "disassemble /r $enter_thunk,+200" || true
        fi
    fi
}

run_trampoline_dump() {
    # 测量结束后执行：清理 shm → 重启 observer attach → 起长驻 victim → dump
    if ! command -v gdb >/dev/null 2>&1; then
        echo "[dump] WARN: 未安装 gdb，跳过 trampoline dump（sudo apt install gdb）"
        return 0
    fi
    # gdb attach 需要 root ptrace（yama ptrace_scope=1 时兄弟进程无法互 attach）。
    # sudo -v 先验证一次凭据：交互终端下输入一次密码即可，后续 sudo gdb 走缓存
    if ! sudo -v 2>/dev/null; then
        echo "[dump] WARN: sudo 验证失败（无法交互输密码？），跳过 trampoline dump"
        return 0
    fi

    # 清掉测量阶段残留的 bpftime 共享内存，避免 handler 冲突
    if [ -x "$BPFTIME_BUILD/tools/bpftimetool/bpftimetool" ]; then
        sudo "$BPFTIME_BUILD/tools/bpftimetool/bpftimetool" remove >/dev/null 2>&1 || true
    fi
    rm -f /dev/shm/bpftime* 2>/dev/null || true
    sleep 1

    echo "[dump] 重启 observer 完成 attach ..."
    LD_PRELOAD="$SYSCALL_SO" BPFTIME_VM_NAME=ubpf \
        "$OBSERVER_BIN" "$VICTIM_ABS" 1 \
        > observer_dump.stdout.log 2> observer_dump.stderr.log &
    DUMP_OBS_PID=$!

    # 关键顺序：必须等 observer 把 attach 写入 shm 后再启动 victim。
    # agent 只在启动时读一次 handler 表，不会感知后创建的 attach——
    # 两者同秒启动时 agent 初始化可能跑在 attach 落账之前，导致 victim
    # 完全不被插桩（runtime.log 里可见 "Attach successfully" 先于
    # "Created uprobe/uretprobe perf event handler"）。主流程同样靠
    # sleep 2 保证这一顺序。
    sleep 2

    # 长驻 victim：大循环计数让它活到 dump 结束（正常测量不受影响，
    # 它的调用只会计入上面这个 dump 专用 observer，从不读取）
    LD_PRELOAD="$AGENT_SO" BPFTIME_VM_NAME=ubpf \
        "$VICTIM_BIN" 2000000000 1 \
        > dump_victim.stdout.log 2> dump_victim.stderr.log &
    DUMP_VIC_PID=$!
    echo "[dump] dump observer pid=$DUMP_OBS_PID, dump victim pid=$DUMP_VIC_PID"

    if ! kill -0 "$DUMP_VIC_PID" 2>/dev/null; then
        echo "[dump] WARN: dump victim 已退出，插桩可能失败。dump_victim.stderr.log："
        tail -5 dump_victim.stderr.log 2>/dev/null || true
        kill -TERM "$DUMP_OBS_PID" 2>/dev/null || true
        wait "$DUMP_OBS_PID" 2>/dev/null || true
        return 0
    fi

    # 轮询探测插桩是否生效：target_function 入口被覆写为 jmp 才继续
    local probe="" trampoline="" try
    for try in $(seq 1 10); do
        probe=$(gdb_batch "$DUMP_VIC_PID" "x/i target_function" || true)
        trampoline=$(echo "$probe" | grep -oP 'jmpq?\s+\K0x[0-9a-f]+' | head -1 || true)
        [ -n "$trampoline" ] && break
        sleep 1
    done
    if [ -z "$trampoline" ]; then
        echo "[dump] WARN: 探测 ${try} 次后入口仍是原指令，插桩未生效。最后一次输出："
        echo "$probe"
        echo "       请检查 observer_dump.stderr.log 有无 'attached uprobe'，以及"
        echo "       ~/.bpftime/runtime.log 中 'Attach successfully' 与 'Created"
        echo "       uprobe ... perf event handler' 的先后顺序。"
        kill -TERM "$DUMP_VIC_PID" "$DUMP_OBS_PID" 2>/dev/null || true
        wait "$DUMP_VIC_PID" 2>/dev/null || true
        wait "$DUMP_OBS_PID" 2>/dev/null || true
        return 0
    fi
    echo "[dump] 插桩已生效（第 $try 次探测，jmp -> $trampoline）"

    dump_trampoline_code "$DUMP_VIC_PID" 2>&1 | tee trampoline_dump.log

    kill -TERM "$DUMP_VIC_PID" "$DUMP_OBS_PID" 2>/dev/null || true
    wait "$DUMP_VIC_PID" 2>/dev/null || true
    wait "$DUMP_OBS_PID" 2>/dev/null || true
    echo "[dump] 完成，输出已保存到 $SCRIPT_DIR/trampoline_dump.log"
    return 0
}

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
    echo "   - Frida 改造代码本身有 bug（先跑 ../tests/sampling_trampoline_test.c 排除，需 frida 构建环境）"
fi

# ---------- 可选：dump trampoline 代码 ----------
# 放在测量之后：dump victim 的调用会触发 observer 计数，提前执行会污染
# SAMPLE_HITS 判定。dump 失败只告警，不影响测试退出码。
if [ "${DUMP_TRAMPOLINE:-0}" = "1" ]; then
    echo
    echo "=== Trampoline 代码 dump（DUMP_TRAMPOLINE=1）==="
    run_trampoline_dump
fi

[ $PASS -eq 1 ] && exit 0 || exit 1
