// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Sartura */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "uprobe.skel.h"

// libbpf 日志回调函数
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

// 信号处理函数，用于优雅退出
static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct uprobe_bpf *skel;
    int err;
    const char *target_program_path;
    LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <target_program_path>\n", argv[0]);
        fprintf(stderr, "Example: %s ./target\n", argv[0]);
        return 1;
    }

    /* Extract target program path from command line argument */
    // 从命令行参数中解析目标程序的路径
    target_program_path = argv[1];

    /* Set up libbpf errors and debug info callback */
    // 设置libbpf错误和调试信息的回调函数
    libbpf_set_print(libbpf_print_fn);

    /* Open and load BPF application */
    // 打开和加载BPF程序
    skel = uprobe_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load and verify BPF application */
    // 加载和验证BPF程序
    err = uprobe_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* uprobe/uretprobe 需要指定要附加到的函数的相对偏移量。
     * 如果我们提供函数名，libbpf 将自动为我们查找偏移量。
     * 如果没有指定函数名，libbpf 将尝试使用函数偏移量。
     */

    /* Attach uprobe for uprobe_add function */
    uprobe_opts.func_name = "uprobe_add";  // 要附加的函数名称
    uprobe_opts.retprobe = false;          // 是否为retprobe
    skel->links.uprobe_add = bpf_program__attach_uprobe_opts(
                                skel->progs.uprobe_add,  /* 要附加的bpf程序 */
                                -1,                        /* all processes (所有进程) */
                                target_program_path,       /* 要探测的二进制程序的路径 */
                                0,                         /* 函数偏移量,因使用opts.func_name，所以设置为0 */
                                &uprobe_opts);             /* opts */

    if (!skel->links.uprobe_add) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe for uprobe_add: %d\n", err);
        goto cleanup;
    }

    /* Attach uretprobe for uprobe_add function */
    uprobe_opts.func_name = "uprobe_add";
    uprobe_opts.retprobe = true;           // 设置为true表示这是uretprobe
    skel->links.uretprobe_add = bpf_program__attach_uprobe_opts(
                                skel->progs.uretprobe_add,
                                -1,                        /* all processes */
                                target_program_path,       /* 要探测的二进制程序的路径 */
                                0,                         /* offset for function */
                                &uprobe_opts);             /* opts */

    if (!skel->links.uretprobe_add) {
        err = -errno;
        fprintf(stderr, "Failed to attach uretprobe for uprobe_add: %d\n", err);
        goto cleanup;
    }

    printf("Successfully attached uprobes to %s\n", target_program_path);
    printf("Monitoring functions: uprobe_add\n");
    printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` in another terminal to see output.\n");
    printf("Then run the target program: %s\n", target_program_path);
    printf("Press Ctrl+C to exit.\n");

    /* Set up signal handler for graceful exit */
    // 设置信号处理函数，用于优雅退出
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Keep the program running to monitor function calls */
    // 保持程序运行以监控函数调用
    while (!exiting) {
        printf(".");
        fflush(stdout);
        sleep(1);
    }

    printf("\nDetaching uprobes and exiting...\n");

cleanup:
    uprobe_bpf__destroy(skel);
    return -err;
}
