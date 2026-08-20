/*
 * victim.c — FreeProbe 端到端采样验证的独立受害程序。
 *
 * 关键设计：
 *   - target_function 必须用 noinline + asm volatile 防止被内联或 DCE，
 *     保证编译器生成真实的 `call target_function`，Frida 才有稳定的
 *     入口地址可以覆写成 jmp trampoline。
 *   - 函数体刻意写得厚（1300 次循环 + volatile 写），让 relocator 至少
 *     能拷到 5 字节序言（GUM_INTERCEPTOR_NEAR_REDIRECT_SIZE）。早期
 *     实验版本函数体只有 `return x;` 编出来才 5 字节，触发过死循环。
 *
 * 监控信号：
 *   - 程序运行结束后打印 OBSERVED_CALLS=<N>，run_test.sh 用这个值
 *     和 observer 端 BPF map 计数器对比，判断采样率是否符合预期。
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#define DEFAULT_TOTAL_CALLS 10000

/* 被观测的目标函数：参数和返回值都依赖输入，防止编译器聚合优化。
 * 函数体厚到足够给 Frida relocator 留 ≥5 字节。 */
__attribute__((noinline, optimize("O2")))
uint64_t target_function(uint32_t a, uint32_t b)
{
    asm volatile ("" ::: "memory");
    volatile uint32_t x = a;
    volatile uint32_t y = b;
    for (int i = 0; i < 200; i++) {
        x = (x * 31 + y) ^ (unsigned)i;
        y = (y * 17 + x) ^ (unsigned)(i + 1);
    }
    return (uint64_t)x + (uint64_t)y;
}

/* 单线程 worker：把 target_function 调 N 次。
 * 末尾的 asm volatile 防 dead code elimination。 */
static void *worker_single(void *arg)
{
    long total = (long)arg;
    volatile uint64_t sink = 0;
    for (long i = 0; i < total; i++) {
        sink += target_function((uint32_t)i, (uint32_t)(i + 1));
    }
    __asm__ volatile ("" :: "r"(sink) : "memory");
    return NULL;
}

/* 多线程 worker：每个线程独立计 N 次，用来验证 fs:[0x2d0] 拿到的是真
 * per-thread TID（如果拿到共享值，所有线程会撞同一个采样桶）。 */
typedef struct {
    long total_per_thread;
    int thread_id;
} worker_arg_t;

static void *worker_thread(void *arg)
{
    worker_arg_t *w = (worker_arg_t *)arg;
    volatile uint64_t sink = 0;
    for (long i = 0; i < w->total_per_thread; i++) {
        sink += target_function((uint32_t)w->thread_id,
                                (uint32_t)(w->thread_id + i + 1));
    }
    __asm__ volatile ("" :: "r"(sink) : "memory");
    return NULL;
}

int main(int argc, char **argv)
{
    long total_calls = DEFAULT_TOTAL_CALLS;
    int num_threads = 1;

    if (argc >= 2) {
        total_calls = strtol(argv[1], NULL, 10);
        if (total_calls <= 0) {
            fprintf(stderr, "total_calls must be positive, got %ld\n", total_calls);
            return 2;
        }
    }
    if (argc >= 3) {
        num_threads = atoi(argv[2]);
        if (num_threads < 1) num_threads = 1;
    }

    fprintf(stderr, "[victim] pid=%d  total_calls=%ld  threads=%d\n",
            (int)getpid(), total_calls, num_threads);

    if (num_threads == 1) {
        worker_single((void *)total_calls);
    } else {
        long per = total_calls / num_threads;
        pthread_t *threads = calloc(num_threads, sizeof(pthread_t));
        worker_arg_t *args = calloc(num_threads, sizeof(worker_arg_t));
        for (int i = 0; i < num_threads; i++) {
            args[i].thread_id = i + 1;
            args[i].total_per_thread = per;
            pthread_create(&threads[i], NULL, worker_thread, &args[i]);
        }
        for (int i = 0; i < num_threads; i++) {
            pthread_join(threads[i], NULL);
        }
        free(threads);
        free(args);
    }

    /* run_test.sh 抓这一行作为"应该被观测多少次"的 ground truth。
     * 命名 OBSERVED_CALLS 是因为：从 eBPF observer 的角度看，victim
     * 期望被观测这么多次；采样生效时实际观测值约等于 N/20。 */
    printf("OBSERVED_CALLS=%ld\n", total_calls);
    return 0;
}
