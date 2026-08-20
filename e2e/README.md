# FreeProbe 端到端采样验证测试

验证改造后的 Frida trampoline 通过 bpftime userspace uprobe 路径执行 eBPF
观测程序时，**真的在做 FreeProbe 设计要求的 5% 采样**。

## 1. 这个测试在证明什么

FreeProbe 的核心设计：把采样判断前移到 Frida trampoline 入口。`GUM_SAMPLE_RATE`
次调用里只有 1 次走"完整插桩流程"（enter_thunk → bpftime agent → eBPF 程序），
其余 19/20 走快路径，**完全绕过** enter_thunk。

| 路径 | 走 enter_thunk 吗？ | 触发 eBPF 吗？ | 实测占比 |
|---|---|---|---|
| 慢路径（命中采样） | 是 | 是 | 1/20 = 5% |
| 快路径（未命中） | 否 | 否 | 19/20 = 95% |

测试通过的标准：

```
observer 触发次数 == victim 总调用 / 20  (±25% 容忍度)
```

如果采样没生效，observer 会收到 == victim 总调用（100%）；如果采样逻辑完全
坏掉，observer 会收到 0。

## 2. 目录结构

```
e2e/
├── README.md                       — 本文档
├── PROCESS.md                      — 过程性材料（遇到的问题 + 解决方案，历史路径仅供参考）
├── Makefile                        — 构建 victim + observer，复用 ../bpftime/third_party
├── deploy_frida_to_bpftime.sh      — 部署含采样逻辑的 libfrida-gum 到 bpftime
├── rebuild_bpftime.sh              — 重编 libbpftime-agent.so + libbpftime-syscall-server.so
├── run_test.sh                     — 端到端测试主控脚本
├── victim/
│   └── victim.c                    — 独立受害程序，含 target_function
├── observer/
│   ├── observer.bpf.c              — eBPF 计数器程序
│   └── observer.c                  — libbpf skeleton 加载器
├── bin/                            — 编译产物（gitignore 推荐）
│   ├── victim
│   └── observer
└── .output/                        — 中间产物（libbpf.a、bpftool、skel.h 等）
```

## 3. 一键运行

前置条件：
- `../bpftime/third_party/frida/` 下已有采样版 devkit（仓库自带，无需重新生成）
- `../bpftime/build/` 下已有一次构建（见下方第 2 步）

```sh
cd <本仓库>/e2e

# 1. 构建 victim + observer（首次约 30s，主要在编译 libbpf）
make

# 2. 首次构建 bpftime agent + syscall-server（本仓库已带 devkit 与全部子模块）
cmake -S ../bpftime -B ../bpftime/build -DBPFTIME_LLVM_JIT=OFF
cmake --build ../bpftime/build --target bpftime-agent bpftime-syscall-server

# 3. （可选）仅当修改了 frida-gum 采样代码后才需要：
#    在外部 frida 构建环境 ninja 出新 libfrida-gum-1.0.a，然后
#    FRIDA_ROOT=<frida目录> ./deploy_frida_to_bpftime.sh && ./rebuild_bpftime.sh

# 4. 跑测试
./run_test.sh
```

期望输出（最近一次实测）：
```
=== FreeProbe 端到端采样验证 ===
  victim 总调用       = 10000
  observer 触发次数   = 500
  期望触发 (~1/20)  = 500 (容忍 [375, 625])
  实测采样率          = 0.0500
  目标采样率          = 0.0500

  判定: PASS
```

### 参数

```sh
./run_test.sh [TOTAL_CALLS] [NUM_THREADS] [TOLERANCE]
# 默认值：10000 / 1 / 0.25
```

`TOLERANCE` 是 ±N% 容忍度（默认 ±25%），与 `../tests/sampling_trampoline_test.c`
保持一致。

### 多线程验证

```sh
./run_test.sh 40000 4
```

期望：40000 / 20 = 2000 ± 500。实测 1989（采样率 4.97%）。

多线程通过意味着 `fs:[0x2d0]` 拿到的真是 per-thread TID（否则 4 个线程撞同一
个采样桶，触发次数会偏离期望）。

## 4. 工作原理

### 4.1 进程拓扑

```
┌─────────────────────────┐         ┌─────────────────────────┐
│   observer (loader)     │         │   victim                │
│                         │         │                         │
│  LD_PRELOAD=            │         │  LD_PRELOAD=            │
│   libbpftime-           │         │   libbpftime-agent.so   │
│   syscall-server.so     │         │                         │
│                         │         │                         │
│  bpf(BPF_PROG_LOAD)  ──┼──shm──▶ │  读取 handler 列表      │
│  bpf(BPF_LINK_CREATE)   │         │  注册 Frida uprobe hook │
│  poll(BPF_MAP_LOOKUP)   │         │  调 target_function N 次│
│         ▲               │         │         │               │
│         │               │         │         ▼               │
│  read sample_counter[0] │         │  采样命中 → enter_thunk │
│         │               │         │   → 执行 eBPF 程序      │
│         │               │         │   → sample_counter[0]++ │
│         └─── 共享 BPF map ────────┤                         │
│                         │         │                         │
└─────────────────────────┘         └─────────────────────────┘
```

### 4.2 单次调用的完整轨迹（采样命中时）

```
victim 调 target_function(i, i+1)
    ↓
CPU 跳到 target_function 入口（已被覆写成 jmp on_enter_trampoline）
    ↓
on_enter_trampoline（Frida 改造代码）
    push ctx_ptr / rax / rcx / rdx
    rdx = fs:[0x2d0]                     ← 真 TID
    rdx &= 0x3f                          ← 桶号 0–63
    rcx = sampling_counters[rdx]
    rcx++
    cmp rcx, 20
    jl sampling_skip                     ← 未达阈值走快路径
    sampling_counters[rdx] = 0           ← 达阈值，清零
    jmp enter_thunk                      ← 慢路径
    ↓
enter_thunk
    保存所有寄存器
    调 _gum_function_context_begin_invocation
        ↓
    bpftime 的 Frida attach impl 拦截
        ↓
    eBPF 程序 count_target_function 运行
        ↓
    bpf_map_update_elem(sample_counter, 0, ++v)
        ↓
    返回，恢复寄存器，ret
```

**未命中采样**时（95% 的调用）走 `sampling_skip` 标签，直接 `jmp invoke_trampoline`
执行原函数，listener 和 eBPF 一次都不触发。

### 4.3 eBPF 程序的关键约束

```c
SEC("uprobe")
int count_target_function(struct pt_regs *ctx) {
    u32 key = 0;
    u64 *cnt = bpf_map_lookup_elem(&sample_counter, &key);
    if (cnt) {
        u64 v = *cnt;
        v = v + 1;
        bpf_map_update_elem(&sample_counter, &key, &v, BPF_ANY);
    }
    return 0;
}
```

- **不用 `BPF_UPROBE` 宏**：它会展开成 CO-RE 重定位读取 pt_regs，ubpf 后端
  对 CO-RE 支持不完全。直接用 `struct pt_regs *ctx` 参数更稳。
- **不用 `__sync_fetch_and_add`**：会生成 `BPF_ATOMIC | BPF_DW` 指令（opcode
  0xdb），ubpf 不支持。改用 read-modify-write。
- **不用 `bpf_printk`**：性能差且要解析 trace_pipe。改用 map 计数器，最干净。

详见 `PROCESS.md` 第 4 节。

## 5. 判定逻辑

```python
expected   = observed_calls / 20          # GUM_SAMPLE_RATE = 20
lower      = expected * (1 - 0.25)        # 容忍下界
upper      = expected * (1 + 0.25)        # 容忍上界
pass       = (lower <= sample_hits <= upper)
```

测试同时给出诊断：

| 实测结果 | 含义 |
|---|---|
| `sample_hits == 0` | observer 完全没被触发。uprobe 没装上 / agent 没启动 |
| `sample_hits == observed_calls` | 采样完全失效，每次都走慢路径。agent 没链到改造版 Frida |
| `sample_hits ≈ observed_calls / 20` | 采样生效（PASS） |

## 6. 与 `sampling_trampoline_test.c` 的关系

| 维度 | `sampling_trampoline_test.c` | 本测试（`e2e_bpftime_sampling`）|
|---|---|---|
| 验证层次 | Frida 单元层 | bpftime + Frida + eBPF 端到端 |
| Listener | C 写的 `GumInvocationListener`（直接在 victim 进程里） | eBPF 程序（通过 bpftime agent 间接触发） |
| 用到的 Frida | `libfrida-gum-1.0.a` 直接链接 | 经 `libbpftime-agent.so` → 链 `libfrida-gum.a` |
| 验证的调用路径 | trampoline → enter_thunk → listener 回调 | trampoline → enter_thunk → bpftime → eBPF |
| 通过意味着 | trampoline 改造对纯 Frida 应用有效 | trampoline 改造对 bpftime userspace uprobe 也有效 |

两个测试一起通过 = FreeProbe 设计从 Frida 改造到 bpftime 实测的整条链路打通。

## 7. 故障排查

### 7.1 `SAMPLE_HITS == 0`

observer 一次都没被触发。按顺序检查：

1. `tail ~/.bpftime/runtime.log | grep error` — 看有没有 VM 加载失败、
   handler 创建失败等错误。
2. `cat victim.stderr.log` — 看 `[victim] pid=...` 行是否出现，确认 victim
   真的在 agent 下跑。
3. `LD_PRELOAD=$AGENT_SO BPFTIME_VM_NAME=ubpf ./bin/victim 10 1` 直接跑
   victim，看是否报 symbol lookup error（agent.so GLib 链接问题）。

### 7.2 `SAMPLE_HITS == OBSERVED_CALLS`（采样没起作用）

agent 没链到改造版 Frida。检查：

```sh
strings ../bpftime/build/runtime/agent/libbpftime-agent.so | grep sampling_skip
```

应该有输出。如果没有：重跑 `./rebuild_bpftime.sh`（若改过采样代码，先以
`FRIDA_ROOT=<frida目录> ./deploy_frida_to_bpftime.sh` 重新部署 devkit）。

### 7.3 `unknown opcode 0xdb at PC N`

eBPF 程序用了 ubpf 不支持的字节码（多半是原子操作）。简化 BPF 程序，避免
`__sync_fetch_and_add`、`lock` 前缀等。

### 7.4 `undefined symbol: g_direct_hash`

agent.so 链了未带 `_frida_` 前缀的 libfrida-gum.a（直接用了
libfrida-gum-1.0.a 而不是 devkit）。重新跑 `deploy_frida_to_bpftime.sh`
让它用 `releng/devkit.py` 生成正确的 devkit。

## 8. 一句话结论

`run_test.sh` PASS = `OBSERVED_CALLS / 20 ≈ SAMPLE_HITS` = FreeProbe 采样
设计在 bpftime userspace uprobe 完整链路上真实生效。多线程 PASS 进一步
证明 per-thread 采样桶工作正常。
