#include <stdio.h>
#include <unistd.h>
#include <time.h>

// 目标函数：将被 uprobe 跟踪的函数
// 使用 asm volatile 防止编译器内联优化
// __attribute__((noinline)) int uprobe_add(int a, int b)
// {
//     asm volatile ("");  // 防止编译器内联优化
//     return a + b;
// }
__attribute__((noinline)) unsigned int uprobe_add(unsigned int a, unsigned int b)
{
    volatile unsigned int x = a;
    volatile unsigned int y = b;
    
    for (int i = 0; i < 1300; i++) {
        // 无符号溢出是明确定义的行为（模 2^32）
        x = (x * 31 + y) ^ (unsigned)i;
        y = (y * 17 + x) ^ (unsigned)(i + 1);
    }
    
    return x + y;  // 自然回绕到 32-bit
}

// 获取当前时间（纳秒）
static inline long long get_nanos(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
    int result;
    int i;
    long long start, end, elapsed, average=0;

    printf("Target program started. PID: %d\n", getpid());
    printf("Each call will measure execution time in nanoseconds.\n");
    printf("=============================================================\n");

    // 多次调用 uprobe_add 函数，方便测试
    for (i = 1; i < 11; i++) {
        start= get_nanos();
        result = uprobe_add(i, i + 1);
        end = get_nanos();
        elapsed = end - start;
        average += elapsed;
        printf("Call: %2d, Result: %2d | Time: %6lld ns\n", i, result, elapsed);
        sleep(1);  // 每次调用间隔1秒
    }
    printf("Average Time = %6lld ns\n", average/10);

    printf("=============================================================\n");
    printf("Target program exiting.\n");
    return 0;
}
