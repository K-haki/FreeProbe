// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// uprobe: 在函数入口处触发
SEC("uprobe/uprobe_add")
int BPF_UPROBE(uprobe_add, int a, int b)
{
    bpf_printk("uprobe_add(%d, %d) called\n", a, b);
    return 0;
}

// uretprobe: 在函数返回时触发
SEC("uretprobe/uprobe_add")
int BPF_URETPROBE(uretprobe_add, int ret)
{
    bpf_printk("uprobe_add returned %d\n", ret);
    return 0;
}
