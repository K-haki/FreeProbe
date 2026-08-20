# Makefile — 构建 FreeProbe 端到端采样验证测试。
#
# 复用 ../bpftime/third_party 下已经编译好的 libbpf + bpftool + vmlinux.h，
# 避免在本目录里重新拉源码编译。如果重新部署 Frida 之后 bpftime agent 已经
# 重编，runtime SO 路径仍然指向 build/runtime/{agent,syscall-server}。

# ---------- 路径 ----------
BPFTIME_ROOT  := $(abspath $(CURDIR)/../bpftime)
LIBBPF_SRC    := $(BPFTIME_ROOT)/third_party/libbpf/src
BPFTOOL_SRC   := $(BPFTIME_ROOT)/third_party/bpftool/src
VMLINUX_DIR   := $(BPFTIME_ROOT)/third_party/vmlinux/x86
BPFTIME_BUILD := $(BPFTIME_ROOT)/build

# bpftime agent / syscall-server
AGENT_SO      := $(BPFTIME_BUILD)/runtime/agent/libbpftime-agent.so
SYSCALL_SO    := $(BPFTIME_BUILD)/runtime/syscall-server/libbpftime-syscall-server.so

# ---------- 工具链 ----------
CLANG     ?= clang-16
CC        ?= gcc
OUTPUT    := .output
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL   ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH      := x86

INCLUDES  := -I$(OUTPUT) \
             -I$(BPFTIME_ROOT)/third_party/libbpf/include \
             -I$(BPFTIME_ROOT)/third_party/libbpf/include/uapi \
             -I$(VMLINUX_DIR)
CFLAGS    := -g -O2 -Wall
LDLIBS    := -lelf -lz -lpthread

# Clang 的默认系统头搜索路径（编译 .bpf.c 时需要）
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# ---------- 目标 ----------
# 二进制输出到 bin/，避免与源码目录 victim/、observer/ 同名冲突
VICTIM_BIN := $(abspath bin/victim)
OBSERVER_BIN := $(abspath bin/observer)

.PHONY: all clean victim observer

all: victim observer

# ---------- victim ----------
victim: $(VICTIM_BIN)
$(VICTIM_BIN): victim/victim.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $< -lpthread

# ---------- observer (libbpf skeleton 工作流) ----------
observer: $(OBSERVER_BIN)
$(OBSERVER_BIN): observer/observer.c $(OUTPUT)/observer.skel.h $(LIBBPF_OBJ)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c observer/observer.c -o $(OUTPUT)/observer.o
	$(CC) $(CFLAGS) $(OUTPUT)/observer.o $(LIBBPF_OBJ) $(LDLIBS) -o $@

# 编译 BPF 程序
$(OUTPUT)/observer.bpf.o: observer/observer.bpf.c $(LIBBPF_OBJ) | $(OUTPUT) $(BPFTOOL)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
	         $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
	         -c $< -o $(OUTPUT)/observer.tmp.bpf.o
	$(BPFTOOL) gen object $@ $(OUTPUT)/observer.tmp.bpf.o

# 生成 skeleton 头文件
$(OUTPUT)/observer.skel.h: $(OUTPUT)/observer.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(BPFTOOL) gen skeleton $< > $@

# ---------- libbpf / bpftool (复用 ../bpftime 的源码) ----------
$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	@mkdir -p $@

$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
	        OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
	        INCLUDEDIR= LIBDIR= UAPIDIR= install

$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# ---------- clean ----------
# 注意：只删 bin/ 和 .output/，不递归删除 victim/、observer/ 源码目录
clean:
	rm -rf $(OUTPUT) bin

# 失败时删除目标，避免下次 make 看到半成品
.DELETE_ON_ERROR:
.SECONDARY:
