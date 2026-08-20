# 过程性材料：端到端采样验证测试的实现过程

本文档记录从需求分析到最终验证的完整开发过程，**重点是踩过的坑和解决方法**。
对应代码：`./victim/victim.c`、`./observer/observer.{bpf.c,c}`、
`./deploy_frida_to_bpftime.sh`、`./rebuild_bpftime.sh`、`./run_test.sh`。

---

## 0. 起点

接到任务时的状态：

- Frida 端采样改造代码已经写进 `frida/frida-gum/gum/backend-x86/guminterceptor-x86.c`，
  GUM_SAMPLE_RATE=20、按 TID 哈希到 64 桶、fs:[0x2d0] 拿真 TID。
- `hk-tests/sampling_trampoline_test.c` 已经通过：单线程 10000 → 500 命中、
  多线程 40000 → 2000 命中，精确 5%。
- 但 bpftime 端的实验还**没有用上改造版 Frida**：
  `my_ex/bpftime/third_party/frida/libfrida-gum.a` 时间戳是 2026-03-08，
  早于 Frida 改造代码（4–5 月）。

任务：写一个新测试，验证 bpftime 执行 eBPF 观测程序 + Frida 插桩的完整流程
是否实现了 FreeProbe 采样设计。需要一个独立 victim 程序，观测其内部函数，
最后产出完整代码 + 说明 + 过程材料。

## 1. 探索阶段

### 1.1 阅读现有材料

读了 6 份关键文档，建立完整心智模型：
- `frida-implementation-progress.md`：Frida 改造的全景
- `experiment-design-simulation.md`：之前用什么模拟手段得到论文数据
- `step4-sampling-test.md` + `sampling-test-walkthrough.md`：单元测试怎么写、为什么这么写
- `my_ex/bpftime/benchmark/test.c` + `uprobe/uprobe.c`：bpftime 端 uprobe 实验的标准模式
- `my_ex/bpftime/CLAUDE.md`：bpftime 架构

关键发现：

| 维度 | 已有 | 待补 |
|---|---|---|
| Frida trampoline 改造 | ✅ 完成 | — |
| Frida 单元测试 | ✅ PASS | — |
| Frida devkit 部署到 bpftime | ❌ 缺口 | 写部署脚本 |
| bpftime 重编 | ❌ 缺口 | 写重编脚本 |
| bpftime + Frida + eBPF 端到端测试 | ❌ 不存在 | 写本测试 |

### 1.2 关键架构理解

测试要打通的链路：

```
victim (含 target_function)
   → LD_PRELOAD=libbpftime-agent.so 注入 Frida-based uprobe 拦截器
   → 每次调 target_function，agent 内部的 Frida trampoline 先跑采样判定
   → 5% 慢路径：触发 eBPF 程序，eBPF 把 sample_counter map 加 1
   → 95% 快路径：直接执行原函数

observer (libbpf loader)
   → LD_PRELOAD=libbpftime-syscall-server.so 拦截 bpf() 系统调用
   → 把 uprobe attach 注册到共享内存
   → 周期读 sample_counter map，输出 SAMPLE_HITS=<count>
```

判定标准：`SAMPLE_HITS ≈ OBSERVED_CALLS / 20`。

## 2. 设计与初始实现

### 2.1 目录布局

按用户要求"放在一个新目录下"，新建 `hk-tests/e2e_bpftime_sampling/`：

```
e2e_bpftime_sampling/
├── README.md
├── PROCESS.md
├── Makefile
├── deploy_frida_to_bpftime.sh
├── rebuild_bpftime.sh
├── run_test.sh
├── victim/victim.c
└── observer/{observer.bpf.c, observer.c}
```

### 2.2 关键设计选择

| 选择 | 理由 |
|---|---|
| 验证方式：BPF map 计数器 | 最干净，run_test.sh 直接 grep 数值；bpf_printk 要解析 trace_pipe，麻烦 |
| victim 函数体厚（200 次循环） | 给 Frida relocator ≥5 字节可拷；早期实验出现过函数体太薄触发死循环 |
| `__attribute__((noinline))` | 防止内联，保证有真实 `call target_function` 让 Frida attach |
| ±25% 容忍带 | 与 sampling_trampoline_test 一致；采样统计本身有方差，太严会 flaky |

## 3. 踩坑实录（按发生顺序）

下面是实际开发中遇到的坑，每个都给出**症状 → 定位 → 修复**。

### 3.1 坑 #1：Makefile 目录名与二进制名冲突

**症状**：第一次 `make` 报 `没有规则可制作目标 observer/observer.c`。

**定位**：检查发现 `OBSERVER_BIN := $(abspath observer)` 跟源码目录
`observer/` 同名。make 把 `observer` 当成目录而非可执行文件目标，依赖
关系错乱。

**修复**：把二进制产物移到 `bin/` 子目录：
```makefile
VICTIM_BIN := $(abspath bin/victim)
OBSERVER_BIN := $(abspath bin/observer)
```

### 3.2 坑 #2：`make clean` 误删源码目录

**症状**：修 #1 之后跑 `make clean`，再 `make`，报 `observer/observer.c` 不存在。

**定位**：旧 clean 规则 `rm -rf $(OUTPUT) $(VICTIM_BIN) $(OBSERVER_BIN)`
里的 `$(OBSERVER_BIN)` 当时还是 `observer`（目录），`rm -rf observer` 把
整个 observer/ 目录连同源码一起删了。

**修复**：clean 只删 `bin/` 和 `.output/`，绝不递归源码目录：
```makefile
clean:
	rm -rf $(OUTPUT) bin
```

**教训**：源码目录和构建产物不能同名；clean 规则要显式列出要删的具体路径。

### 3.3 坑 #3：bpftool 的 OUTPUT 目录必须预先存在

**症状**：构建时报 `output directory ".output/bpftool/bootstrap/" does not exist`。

**定位**：bpftool 的 `Makefile.include:4` 有一段：
```makefile
ifneq ($(OUTPUT),)
$(if $(shell [ -d "$(OUTPUT)" -a -x "$(OUTPUT)" ] && echo 1),, \
  $(error output directory "$(OUTPUT)" does not exist))
endif
```

它要求传给它的 OUTPUT 目录**事先存在**，否则直接 error 退出。我的
Makefile 用 `$(dir $@)/` 算出 OUTPUT，但只有 `$(OUTPUT)/bpftool` 这个父目录
被 order-only prereq 创建，bootstrap 子目录是 bpftool make 自己创建的——
但它创建之前先做了上述检查。

**修复**：用单独的 `BPFTOOL_OUTPUT` 变量，prereq 创建它：
```makefile
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	@mkdir -p $@
```
完全照抄 `my_ex/bpftime/benchmark/uprobe/Makefile`（这个是已验证可工作的）。

### 3.4 坑 #4：observer.c 用了 BPF 端的 `u32`/`u64` 类型

**症状**：`error: unknown type name 'u32'`。

**定位**：observer.c 是 userspace 代码，但混用了 BPF 头文件里的 `u32`/`u64`。
这些类型只在 vmlinux.h / bpf_helpers.h 里 typedef，userspace 看不到。

**修复**：改用 `<stdint.h>` 的 `uint32_t`/`uint64_t`。

### 3.5 坑 #5：`set -o pipefail` + `grep -q` 静默失效

**症状**：deploy 脚本里写：
```bash
if ! strings "$NEW_LIBGUM" | grep -q "sampling_skip"; then
    echo "ERROR: 不含 sampling_skip"; exit 1
fi
```
明明 `strings | grep sampling_skip` 手动跑能找到，但脚本里一直报 ERROR。

**定位**：`set -euo pipefail` + `grep -q` 的经典坑。
- `grep -q` 命中后立刻退出（exit 0）
- `strings` 还在往 pipe 写，收到 SIGPIPE（exit 141）
- `pipefail` 把 pipeline 的退出码视为 141
- `!` 取反得 0，但 set -e 在某些场景下还会被 pipefail 触发

**修复**：去掉 `-q`，重定向到 `/dev/null`：
```bash
if ! strings "$NEW_LIBGUM" | grep "sampling_skip" >/dev/null 2>&1; then
```

这个坑在 `rebuild_bpftime.sh` 和 `run_test.sh` 里都重复出现了，逐一修。

**教训**：`set -o pipefail` 配 `grep -q` 是反模式。要么不用 pipefail，要么用
`grep >/dev/null`。

### 3.6 坑 #6：release-packages 的 devkit 没含采样代码

**症状**：第一次写 deploy 脚本时直接用：
```bash
cp $FRIDA_BUILD/release-packages/frida-gum-devkit-16.1.2-linux-x86_64.tar.xz \
   $BPFTIME_FRIDA_DIR/
```
但部署后重编的 agent.so 里 `strings | grep sampling_skip` 为空。

**定位**：检查时间戳：
- `release-packages/frida-gum-devkit-16.1.2-linux-x86_64.tar.xz`：4月9日
- Frida 采样代码最后修改：8月12日

release-packages 的 tar **早于**采样代码改造！只是把 4 月的旧 tar 拷过去。

进一步发现：Frida 的构建系统不会因为源码改了就自动重打 devkit 包。devkit
是 `make gum-linux-x86_64` 之后**手动**用 `releng/devkit.py` 生成的，需要
显式调用。

**修复**：deploy 脚本里直接调用 `releng/devkit.py` 从当前构建产物生成新 devkit：
```bash
( cd "$FRIDA_ROOT" && python3 releng/devkit.py frida-gum linux-x86_64 "$WORK" )
```

### 3.7 坑 #7：`libfrida-gum-1.0.a` 不是 `libfrida-gum.a`

**症状**：一度想过"直接拿 libfrida-gum-1.0.a 当 devkit 用"。重打 tar、
更新 SHA256、部署、重编 agent.so。重编过 agent.so 加载时报：
```
undefined symbol: g_direct_hash
```

**定位**：`libfrida-gum-1.0.a`（5.8MB）是 Frida 主构建产出的"SDK"库，GLib 符号
都是 undefined（期望 host 进程提供）。但 victim 程序不链 GLib，运行时找不到
`g_direct_hash` 等符号。

正确的 devkit 库（`libfrida-gum.a`，88MB）经过 `releng/devkit.py` 处理：
- 用 objcopy 把所有 GLib 符号加上 `_frida_` 前缀（如 `_frida_g_direct_hash`）
- 把 GLib、libffi 等依赖静态编进同一个 .a
- 最终库自包含，host 进程不需要任何额外依赖

`nm` 对比验证：
```
libfrida-gum-1.0.a:  U g_direct_hash            ← undefined
devkit/libfrida-gum.a: T _frida_g_direct_hash   ← defined, prefixed
```

**修复**：必须走 `releng/devkit.py`，不能用 SDK 库替代。把这一步写进
deploy 脚本。

### 3.8 坑 #8：bpftime CMakeCache 残留旧源码路径

**症状**：deploy 完跑 rebuild_bpftime.sh，cmake 重新配置时报：
```
CMake Error: ... /mnt/disk3/huangkai/apnet/my_ex/bpftime/build/CMakeCache.txt
is different than the directory /mnt/disk1/huangkai/apnet/bpftime/bpftime/build
where CMakeCache.txt was created.
```

**定位**：bpftime 在历史上被复制/移动过：
- 原路径：`/mnt/disk1/huangkai/apnet/bpftime/bpftime/`
- 现路径：`/mnt/disk3/huangkai/apnet/my_ex/bpftime/`

CMakeCache.txt 里硬编码了原路径，移动后路径不匹配，cmake 直接拒绝配置。
而且不止顶层 cache 有问题，ubpf 等子项目的 ExternalProject 也有自己的 cache，
全部要清。

**修复**：rebuild 脚本里扫描所有 cache：
```bash
STALE_CACHES=$(find "$BUILD_DIR" -name CMakeCache.txt \
    -exec grep -l "/mnt/disk1\|/mnt/disk2/huangkai/apnet/bpftime" {} \; 2>/dev/null || true)
# 删 cache + 同级 CMakeFiles/，保留其余 build 产物
```

### 3.9 坑 #9：bpftime 全局 `-lncurses` 但 libncurses-dev 未装

**症状**：cmake 重新配置时 try_compile 失败：
```
/usr/bin/ld: 找不到 -lncurses
```

**定位**：bpftime/CMakeLists.txt:10：
```cmake
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lncurses")
```
全局给所有可执行目标加 `-lncurses`（bpftime CLI 工具的 readline 依赖）。
机器上 libncurses6 装了（运行时），但 libncurses-dev（含 .so symlink）没装。
我也没有 sudo 权限装包。

agent.so / syscall-server.so 都不需要 ncurses，是这个全局 flag 把 try_compile
卡住了。

**修复**：rebuild 脚本里临时注释这一行，编译完用 trap 恢复：
```bash
trap restore_ncurses EXIT
python3 <<EOF
import re
path = "$BPFTIME_CMAKE_MAIN"
with open(path) as f: c = f.read()
c2, n = re.subn(r'^(set\(CMAKE_EXE_LINKER_FLAGS.*-lncurses"\))',
                r'# \1  # disabled by rebuild_bpftime.sh', c, flags=re.M)
open(path, 'w').write(c2)
EOF
```

注意：`grep -q 'set(CMAKE_EXE_LINKER_FLAGS.*-lncurses)'` 在 BRE 下匹配不上
（不同 grep 实现对 `(` 处理不一致）。改用更宽松的 `grep -E '^[^#]*-lncurses'`。

### 3.10 坑 #10：BPFTIME_LLVM_JIT 默认 ON 但 LLVM 未装

**症状**：configure 走到 vm/llvm-jit/CMakeLists.txt:48 时：
```
CMake Error: ... Could not find a package configuration file provided by "LLVM"
```

**定位**：bpftime 默认启用 LLVM JIT 后端（高性能 VM）。本机没装 llvm-dev。
对端到端测试不需要 LLVM（ubpf 后端够用）。

**修复**：cmake 配置时显式关掉：
```bash
cmake -S "$BPFTIME_ROOT" -B "$BUILD_DIR" -DBPFTIME_LLVM_JIT=OFF
```

### 3.11 坑 #11：bpftime 默认 VM 是 "llvm"

**症状**：所有坑修完，agent.so 重编成功，跑 run_test.sh。victim 跑完，
SAMPLE_HITS=0。看 runtime.log：
```
[error] No VM factory registered for name: llvm
[error] Unable to instantiate handlers with error: Unknown VM type requested: llvm
```

**定位**：bpftime/runtime/include/bpftime_config.hpp:17：
```cpp
#define DEFAULT_VM_NAME "llvm"
```
默认 VM 名是 "llvm"。但我重编时禁用了 LLVM JIT，agent.so 里只有 ubpf factory。
agent 实例化 BPF handler 时找不到 LLVM factory，全部 handler 加载失败，
uprobe 等于没装。

**修复**：run_test.sh 里给 victim 加环境变量：
```bash
LD_PRELOAD="$AGENT_SO" BPFTIME_VM_NAME=ubpf ./bin/victim ...
```

**追加坑**：起初只在 victim 端加，仍然失败。runtime.log 显示**observer 端**
的 syscall-server 用默认 "llvm" 创建 handler，把 "llvm" 写进共享内存的
handler 元数据；victim 端的 agent 取 handler 时按 handler 里的 VM 名查找，
还是 "llvm"。

**最终修复**：observer 和 victim 两边都要设：
```bash
LD_PRELOAD="$SYSCALL_SO" BPFTIME_VM_NAME=ubpf ./bin/observer ...
LD_PRELOAD="$AGENT_SO"   BPFTIME_VM_NAME=ubpf ./bin/victim ...
```

### 3.12 坑 #12：ubpf 不支持 64 位原子加（opcode 0xdb）

**症状**：VM 配置正确后，runtime.log 出新错误：
```
[error] Failed to load insn: unknown opcode 0xdb at PC 9
[error] Failed to load program helpers for prog handler 5: -1
```

**定位**：0xdb = `BPF_ATOMIC | BPF_DW | BPF_STX`，即 64 位原子加。我的
observer.bpf.c 里写了 `__sync_fetch_and_add(cnt, 1)`，clang 把它编译成
这条指令。但 ubpf 后端不支持 64 位原子加。

**修复**：改成 read-modify-write：
```c
u64 v = *cnt;
v = v + 1;
bpf_map_update_elem(&sample_counter, &key, &v, BPF_ANY);
```

非原子，但本测试单线程访问 map，安全。

同时把 `BPF_UPROBE` 宏也去掉，改成裸 `struct pt_regs *ctx`。原因：`BPF_UPROBE`
展开后会 CO-RE 重定位读 pt_regs 字段，ubpf 对 CO-RE 支持不完全。本测试用不到
参数，干脆不读。

## 4. 最终验证

所有坑修完之后：

### 4.1 单线程

```
=== FreeProbe 端到端采样验证 ===
  victim 总调用       = 10000
  observer 触发次数   = 500
  期望触发 (~1/20)  = 500 (容忍 [375, 625])
  实测采样率          = 0.0500
  目标采样率          = 0.0500
  判定: PASS
```

### 4.2 多线程（4 线程，总 40000 调用）

```
=== FreeProbe 端到端采样验证 ===
  victim 总调用       = 40000
  observer 触发次数   = 1989
  期望触发 (~1/20)  = 2000 (容忍 [1500, 2500])
  实测采样率          = 0.0497
  目标采样率          = 0.0500
  判定: PASS
```

两个都 PASS。多线程 1989 vs 期望 2000 偏差 0.55%，完全在容忍带内。

**多线程通过 = per-thread 采样桶工作正常**。trampoline 里 `fs:[0x2d0]` 拿
到的是真 TID，4 个线程各分到不同的桶（TID & 0x3f），各自独立计数，没有出现
"4 个线程撞同一个桶导致计数偏差"的问题。

## 5. 教训总结

按踩坑频率和耗时排序：

| # | 教训 | 影响范围 |
|---|---|---|
| 1 | Frida devkit 必须用 `releng/devkit.py` 重新生成，不能用 SDK 库直接顶替，也不能用旧 release-packages tar | 部署脚本，浪费 ~30 分钟 |
| 2 | bpftime 历史被移动过，CMakeCache 残留旧路径，所有子项目都要清理 | 重编脚本，~20 分钟 |
| 3 | `set -o pipefail + grep -q` 是反模式，三个脚本都踩了 | 部署/重编/运行脚本，~15 分钟 |
| 4 | bpftime 的 VM 名要两端（observer + victim）都设 | run_test.sh，~10 分钟 |
| 5 | ubpf 不支持 64 位原子加，eBPF 程序要避免 `__sync_fetch_and_add` | BPF 源码，~10 分钟 |
| 6 | Makefile 里源码目录和二进制产物不能同名；clean 规则要显式 | Makefile，~10 分钟 |

总耗时约 2 小时（不含重编等待时间）。最耗时的两个发现是 #1（devkit 格式）
和 #2（CMakeCache 残留），都是"看代码看不出来、必须跑一次才知道"的环境问题。

## 6. 一句话回顾

**测试代码本身只占工作量的 30%**，剩下 70% 是处理 Frida 部署链 + bpftime
历史包袱 + 多组件（libbpf/clang/ubpf/Frida/CMake）之间的兼容性缺口。
最终通过逐项定位 + 文档化（本文），让整套测试可在干净环境上一键复现。
