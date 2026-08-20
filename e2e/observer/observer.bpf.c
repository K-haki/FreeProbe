/* observer.bpf.c — eBPF 观测程序，配合 bpftime 的 userspace uprobe 工作。
 *
 * 设计：
 *   - 每次 target_function 入口被触发（即 Frida trampoline 走到慢路径
 *     enter_thunk，bpftime agent 收到回调），就在 sample_counter map 里
 *     把 counter[0] 加 1。
 *   - 程序本身不做采样判断 —— 采样由 Frida trampoline 里的快/慢路径
 *     分发完成。eBPF 只在采样命中时被调用。
 *   - 因此 observer.c 端读到的 counter[0] 就是"实际触发完整 Frida /
 *     bpftime 慢路径"的次数；与 victim 侧的 OBSERVED_CALLS 比对，
 *     比值应该接近 GUM_SAMPLE_RATE 的倒数（默认 1/20 = 5%）。
 *
 * 实现注意：
 *   - 不用 __sync_fetch_and_add —— ubpf 后端不支持 64 位原子加
 *     （opcode 0xdb = BPF_ATOMIC | BPF_DW），会报 "unknown opcode 0xdb"。
 *     改成 read-modify-write，对本测试（单线程 victim）足够。
 *   - 不用 BPF_UPROBE 宏 —— 它会生成 CO-RE 重定位读取 pt_regs 字段，
 *     ubpf 对 CO-RE 的支持不完全。直接用 PT_REGS_PARM 宏更稳。
 */
#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* 单元素数组 map，counter[0] = 慢路径触发次数。 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} sample_counter SEC(".maps");

SEC("uprobe")
int count_target_function(struct pt_regs *ctx)
{
    u32 key = 0;
    u64 *cnt = bpf_map_lookup_elem(&sample_counter, &key);
    if (cnt) {
        /* read-modify-write（避免 ubpf 不支持的 64 位原子加指令） */
        u64 v = *cnt;
        v = v + 1;
        bpf_map_update_elem(&sample_counter, &key, &v, BPF_ANY);
    }
    return 0;
}
