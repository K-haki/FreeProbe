# FreeProbe

FreeProbe 采样 trampoline 的独立仓库：把 **bpftime → frida-gum → victim/observer**
整条链路的源码集中在一处，路径全部为仓库内相对引用，不依赖外部目录布局。

核心设计：把 1/20 采样判断前移到 Frida x86-64 trampoline 入口——95% 的被插桩
调用走快路径直接执行原函数（完全绕过 enter_thunk），仅 5% 进入慢路径触发
bpftime agent → eBPF 观测程序。详细原理见 `e2e/README.md` 与 `docs/`。

## 目录结构

```
freeprobe/
├── frida-gum/     Frida gum 16.1.2 源码快照（含采样改造，共 2 个文件被修改：
│                  gum/backend-x86/guminterceptor-x86.c 与 gum/guminterceptor-priv.h）
├── bpftime/       bpftime 源码快照（CMake 构建，改动仅 cmake/frida.cmake 的
│                  devkit SHA256 + benchmark；third_party/frida/ 内为采样版
│                  frida-gum devkit 与原版 frida-core devkit，cmake 走本地文件）
├── e2e/           端到端验证：victim + observer + run_test.sh + 构建部署脚本
├── tests/         单层测试源码（sampling_trampoline_test.c 需外部 frida 构建环境）
├── docs/          trampoline 机制分析与 devkit 生成笔记
└── patches/       与上游的 git diff 快照（frida-gum-sampling.patch、bpftime-local.patch）
```

## 快速开始

前置依赖：clang-16、gcc、libelf-dev、zlib、cmake、ninja、gdb（trampoline dump 用）。

```sh
# 1. 构建 victim + observer（约 30s）
cd e2e && make

# 2. 首次构建 bpftime（约 5–15 分钟，子模块与 devkit 均已在仓库内，
#    无需联网下载 frida devkit）
cmake -S ../bpftime -B ../bpftime/build -DBPFTIME_LLVM_JIT=OFF
cmake --build ../bpftime/build --target bpftime-agent bpftime-syscall-server -- -j$(nproc)

# 3. 端到端测试（期望采样率 0.05，±25% 容忍）
./run_test.sh                    # 默认 10000 次单线程
./run_test.sh 40000 4            # 多线程（验证 per-thread 采样桶）
DUMP_TRAMPOLINE=1 ./run_test.sh  # 测量后用 gdb dump trampoline/thunk 反汇编
                                    # （需 gdb + sudo；输出存 trampoline_dump.log）
```

## 修改采样代码后的重建

仓库自带预生成的采样版 devkit（`bpftime/third_party/frida/
frida-gum-devkit-16.1.2-linux-x86_64.tar.xz`），日常构建无需 frida 环境。
只有修改了 `frida-gum/gum/backend-x86/guminterceptor-x86.c` 等采样逻辑时才需要：

1. 在一个带构建产物的 frida checkout（本仓库未 vendor，体积太大）下 `ninja`
   出新的 `libfrida-gum-1.0.a`；
2. `cd e2e && FRIDA_ROOT=<frida目录> ./deploy_frida_to_bpftime.sh`
   —— 用 `releng/devkit.py` 重新生成带 `_frida_` 符号前缀的 devkit 并更新
   `cmake/frida.cmake` 的 SHA256（细节与坑见脚本头部注释）；
3. `./rebuild_bpftime.sh` 重编 agent + syscall-server，并自检
   `strings libbpftime-agent.so | grep sampling_skip`。

注意：frida-gum 源码快照仅作参考/修改载体——bpftime 实际链接的是 devkit tar
里的静态库，二者通过上述 deploy 流程同步。

## 验证链路

| 测试 | 位置 | 验证层次 |
|---|---|---|
| `run_test.sh` PASS | e2e/ | bpftime + Frida + eBPF 端到端，采样率 ≈ 1/20 |
| 多线程 PASS | e2e/ | `fs:[0x2d0]` 取到真 per-thread TID |
| trampoline dump | e2e/（DUMP_TRAMPOLINE=1） | gdb 反汇编插桩入口/trampoline/thunk |
| `sampling_trampoline_test.c` | tests/ | 纯 Frida 层（需外部 frida 构建环境） |

## 已知环境要点

- gdb attach 需要 `sudo`（yama ptrace_scope=1），交互终端输一次密码即可；
- bpftime agent 走 ubpf 后端（`BPFTIME_VM_NAME=ubpf`），eBPF 程序需避免
  CO-RE 与原子指令（见 `e2e/README.md` 第 4.3 节）；
- observer 必须先于 victim 完成 attach：agent 只在启动时读一次 handler 表
  （`e2e/run_test.sh` 的 dump 阶段对这一顺序有详细注释）。

## 上游与差异

- frida-gum 上游：frida/frida（16.1.2），差异见 `patches/frida-gum-sampling.patch`
- bpftime 上游：eunomia-bpf/bpftime，差异见 `patches/bpftime-local.patch`
- 历史过程记录（路径为旧布局，仅供参考）：`e2e/PROCESS.md`
