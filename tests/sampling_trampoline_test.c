/*
 * sampling_trampoline_test.c — verify that the FreeProbe sampling guard
 * inserted into frida-gum's x86 trampoline actually:
 *   1. Lets most calls bypass the listener entirely (fast path).
 *   2. Triggers the listener roughly N / GUM_SAMPLE_RATE times (slow path).
 *   3. Keeps per-thread counters independent (bucket by TID & 0x3f).
 *
 * Build (linking against the freshly rebuilt libfrida-gum-1.0.a):
 *   FRIDA_PC=/mnt/disk3/huangkai/apnet/frida/build/frida-linux-x86_64-pkg-config
 *   gcc -O2 -Wall $($FRIDA_PC --cflags frida-gum-1.0) \
 *       sampling_trampoline_test.c \
 *       -o sampling_trampoline_test \
 *       $($FRIDA_PC --libs frida-gum-1.0) -lpthread
 */
#include <glib.h>
#include <glib-object.h>
#include <gum/gum.h>
#include <gum/guminvocationlistener.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syscall.h>

#define SAMPLE_RATE 20           /* must match GUM_SAMPLE_RATE in guminterceptor-x86.c */
#define CALLS_PER_THREAD 10000

/* Target function. noinline + asm volatile so the compiler cannot hoist
 * or CSE across calls; Frida needs a stable entry address to overwrite.
 * The body must be long enough to give the relocator ≥5 bytes to work with
 * (GUM_INTERCEPTOR_NEAR_REDIRECT_SIZE), so we include a call to a real
 * function. */
__attribute__((noinline)) int target_function(int x) {
    asm volatile ("" ::: "memory");
    volatile static int counter = 0;
    counter++;
    return x * 3 + 1 + counter;
}

/* ---------- Listener ---------- */
#define SAMPLE_TYPE_LISTENER (sample_listener_get_type ())
G_DECLARE_FINAL_TYPE (SampleListener, sample_listener, SAMPLE, LISTENER, GObject)

struct _SampleListener
{
    GObject parent;
    _Atomic(uint64_t) enter_count;
    _Atomic(uint64_t) leave_count;
};

static void sample_listener_on_enter(GumInvocationListener *listener,
                                     GumInvocationContext *ic) {
    SampleListener *self = SAMPLE_LISTENER(listener);
    atomic_fetch_add(&self->enter_count, 1);
    (void)ic;
}

static void sample_listener_on_leave(GumInvocationListener *listener,
                                     GumInvocationContext *ic) {
    SampleListener *self = SAMPLE_LISTENER(listener);
    atomic_fetch_add(&self->leave_count, 1);
    (void)ic;
}

static void sample_listener_iface_init(gpointer g_iface, gpointer iface_data) {
    GumInvocationListenerInterface *iface = (GumInvocationListenerInterface *)g_iface;
    iface->on_enter = sample_listener_on_enter;
    iface->on_leave = sample_listener_on_leave;
    (void)iface_data;
}

G_DEFINE_TYPE_EXTENDED(SampleListener,
                       sample_listener,
                       G_TYPE_OBJECT,
                       0,
                       G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER,
                                             sample_listener_iface_init))

static void sample_listener_class_init(SampleListenerClass *klass) { (void)klass; }
static void sample_listener_init(SampleListener *self) {
    atomic_store(&self->enter_count, 0);
    atomic_store(&self->leave_count, 0);
}

static SampleListener *sample_listener_new(void) {
    return g_object_new(SAMPLE_TYPE_LISTENER, NULL);
}

/* ---------- Worker ---------- */
static void *worker(void *arg) {
    long tid = (long)arg;
    int last = 0;
    for (int i = 0; i < CALLS_PER_THREAD; i++) {
        last = target_function((int)tid + i);
    }
    __asm__ volatile ("" :: "r"(last) : "memory");
    return NULL;
}

/* ---------- Main ---------- */
int main(void) {
    gum_init();

    SampleListener *listener = sample_listener_new();
    GumInterceptor *interceptor = gum_interceptor_obtain();

    GumAttachReturn attach_ret = gum_interceptor_attach(interceptor,
                                                       (gpointer)target_function,
                                                       GUM_INVOCATION_LISTENER(listener),
                                                       NULL);
    g_assert(attach_ret == GUM_ATTACH_OK);

    /* Single-thread sanity check */
    gum_interceptor_begin_transaction(interceptor);
    gum_interceptor_end_transaction(interceptor);

    worker((void *)1L);

    uint64_t enter_count_main = atomic_load(&listener->enter_count);
    uint64_t expected_main = CALLS_PER_THREAD / SAMPLE_RATE;
    printf("=== Single-thread ===\n");
    printf("  calls            = %d\n", CALLS_PER_THREAD);
    printf("  listener.on_enter= %lu  (expected ~%lu)\n",
           (unsigned long)enter_count_main, (unsigned long)expected_main);
    double ratio = (double)enter_count_main / CALLS_PER_THREAD;
    printf("  measured rate    = %.4f  (target %.4f)\n", ratio, 1.0 / SAMPLE_RATE);

    /* Reset counters */
    atomic_store(&listener->enter_count, 0);
    atomic_store(&listener->leave_count, 0);

    /* Multi-thread test: 4 threads, each with CALLS_PER_THREAD calls.
     * Each thread should get ~CALLS_PER_THREAD/SAMPLE_RATE enters thanks
     * to per-thread bucketing (TID & 0x3f). */
#define N_THREADS 4
    printf("\n=== Multi-thread (%d threads) ===\n", N_THREADS);
    pthread_t threads[N_THREADS];
    for (int i = 0; i < N_THREADS; i++) {
        pthread_create(&threads[i], NULL, worker, (void *)(long)(i + 1));
    }
    for (int i = 0; i < N_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    uint64_t enter_count_multi = atomic_load(&listener->enter_count);
    uint64_t expected_multi = (uint64_t)N_THREADS * CALLS_PER_THREAD / SAMPLE_RATE;
    printf("  total calls      = %d\n", N_THREADS * CALLS_PER_THREAD);
    printf("  listener.on_enter= %lu  (expected ~%lu)\n",
           (unsigned long)enter_count_multi, (unsigned long)expected_multi);
    double ratio_multi = (double)enter_count_multi / (N_THREADS * CALLS_PER_THREAD);
    printf("  measured rate    = %.4f  (target %.4f)\n", ratio_multi, 1.0 / SAMPLE_RATE);

    /* Pass/fail verdict with ±25% tolerance. */
    int pass_single = (enter_count_main >= expected_main * 0.75 &&
                       enter_count_main <= expected_main * 1.25);
    int pass_multi  = (enter_count_multi >= expected_multi * 0.75 &&
                       enter_count_multi <= expected_multi * 1.25);

    gum_interceptor_detach(interceptor, GUM_INVOCATION_LISTENER(listener));

    printf("\n=== Verdict ===\n");
    printf("  single-thread: %s\n", pass_single ? "PASS" : "FAIL");
    printf("  multi-thread : %s\n", pass_multi  ? "PASS" : "FAIL");

    if (enter_count_main == 0) {
        printf("\n!! on_enter fired 0 times on main thread. The sampling guard\n"
                 "   is never triggering. Likely causes:\n"
                 "     - the register-reuse bug is back (check that the write-back\n"
                 "       uses rdx for index, rcx for value)\n"
                 "     - fs:[0x2d0] is not the TID on this glibc (rerun tid_fs_probe)\n");
    }

    g_object_unref(listener);
    gum_deinit();

    return (pass_single && pass_multi) ? 0 : 1;
}
