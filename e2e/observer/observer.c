/*
 * observer.c — libbpf skeleton 加载器，把 uprobe attach 到 victim 的
 * target_function 上，然后周期性读取 BPF map 计数器，最后输出
 * SAMPLE_HITS=<count>，供 run_test.sh 解析比对。
 *
 * 关键约定：
 *   argv[1] = victim 二进制绝对路径（必须包含符号 target_function）
 *   argv[2] = victim 期望被观测的总调用次数 N（仅用于日志）
 *
 * 工作模式：
 *   - 默认走 kernel uprobe（bpf_program__attach_uprobe_opts）。
 *   - 在 LD_PRELOAD=libbpftime-syscall-server.so 下运行时，syscall-server
 *     拦截 bpf() / perf_event_open() 等 syscall，把 attach 重定向到
 *     bpftime 的 userspace uprobe 实现（基于改造后的 Frida trampoline）。
 *   - 采样是否生效，由 victim 端链接的 libfrida-gum.a 决定 —— 因为是
 *     victim 进程内的 Frida 在做采样判定，observer 端无感。
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "observer.skel.h"

static volatile sig_atomic_t exiting = 0;
static void sig_handler(int sig) { (void)sig; exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level >= LIBBPF_WARN)
        return vfprintf(stderr, format, args);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr,
                "Usage: %s <victim_binary> <expected_observed_calls>\n"
                "Example: %s ./bin/victim 10000\n",
                argv[0], argv[0]);
        return 2;
    }

    const char *victim_path = argv[1];
    long expected = strtol(argv[2], NULL, 10);

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct observer_bpf *skel = observer_bpf__open();
    if (!skel) {
        fprintf(stderr, "[observer] failed to open skeleton: %s\n",
                strerror(errno));
        return 1;
    }

    if (observer_bpf__load(skel) != 0) {
        fprintf(stderr, "[observer] failed to load skeleton: %s\n",
                strerror(errno));
        observer_bpf__destroy(skel);
        return 1;
    }

    /* 显式指定 binary + func_name，让 libbpf 自己解析 offset。
     * pid=-1 表示所有进程；offset=0 + func_name 让 libbpf 自动符号化。 */
    LIBBPF_OPTS(bpf_uprobe_opts, opts);
    opts.func_name = "target_function";
    opts.retprobe = false;

    skel->links.count_target_function =
        bpf_program__attach_uprobe_opts(skel->progs.count_target_function,
                                        /*pid=*/-1,
                                        victim_path,
                                        /*offset=*/0,
                                        &opts);
    if (!skel->links.count_target_function) {
        fprintf(stderr, "[observer] failed to attach uprobe to %s: %s\n",
                victim_path, strerror(errno));
        observer_bpf__destroy(skel);
        return 1;
    }
    fprintf(stderr,
            "[observer] attached uprobe/target_function on %s, expected_hits=%ld\n",
            victim_path, expected);

    /* 等待 SIGTERM（run_test.sh 在 victim 退出后发）；同时每秒打印中间值
     * 方便人工观察。 */
    int map_fd = bpf_map__fd(skel->maps.sample_counter);
    uint32_t key = 0;
    uint64_t last = 0;
    while (!exiting) {
        uint64_t val = 0;
        if (bpf_map_lookup_elem(map_fd, &key, &val) == 0 && val != last) {
            fprintf(stderr, "[observer] sample_counter = %llu\n",
                    (unsigned long long)val);
            last = val;
        }
        sleep(1);
    }

    /* 读最终值并打印 SAMPLE_HITS=<n>。run_test.sh 抓这一行做判定。 */
    uint64_t final_val = 0;
    bpf_map_lookup_elem(map_fd, &key, &final_val);
    printf("SAMPLE_HITS=%llu\n", (unsigned long long)final_val);
    fflush(stdout);

    observer_bpf__destroy(skel);
    return 0;
}
