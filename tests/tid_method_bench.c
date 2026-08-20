/*
 * tid_method_bench.c — compare three approaches to per-thread sampling counter
 *
 *   A. gettid() syscall     → bucket index into a shared counter array
 *   B. fs:[0x2d0] direct    → bucket index into a shared counter array
 *   C. pthread_getspecific() → per-thread counter pointer (no TID needed)
 *
 * Methods A and B match FreeProbe's "shared array + TID bucketing" trampoline
 * design (each thread hashes its TID to one of 64 buckets). Method C models
 * the alternative design where the counter itself lives in TLS, so no TID
 * lookup is needed at all — pthread_getspecific already gives per-thread
 * isolation.
 *
 * Build: gcc -O2 -Wall tid_method_bench.c -o tid_method_bench -lpthread
 * Run:   ./tid_method_bench
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <syscall.h>

#define SAMPLE_THRESHOLD  20
#define NUM_BUCKETS       64
#define ITERS_PER_TRIAL   (20 * 1000 * 1000)
#define NUM_TRIALS        5

/* ---------- Shared state for methods A & B ----------
 * volatile so the compiler can't hoist loads out of the loop. */
static volatile uint8_t g_counters[NUM_BUCKETS];

/* ---------- Per-thread counter for method C ---------- */
static pthread_key_t g_counter_key;
static void counter_dtor (void *p) { free (p); }

/* ---------- Timing helper ---------- */
static double now_ns (void)
{
  struct timespec ts;
  clock_gettime (CLOCK_MONOTONIC, &ts);
  return (double) ts.tv_sec * 1e9 + (double) ts.tv_nsec;
}

/* ---------- Method A: gettid() syscall ---------- */
static double run_method_A (int iters)
{
  double t0 = now_ns ();
  for (int i = 0; i < iters; i++)
  {
    pid_t tid = (pid_t) syscall (SYS_gettid);
    uint32_t bucket = (uint32_t) tid & 0x3f;
    uint8_t c = ++g_counters[bucket];
    if (c >= SAMPLE_THRESHOLD) g_counters[bucket] = 0;
  }
  return now_ns () - t0;
}

/* ---------- Method B: fs:[0x2d0] direct read ----------
 * Same shared counter array as A, but the TID is read from glibc's TCB
 * field instead of via syscall. */
static double run_method_B (int iters)
{
  double t0 = now_ns ();
  for (int i = 0; i < iters; i++)
  {
    uint32_t tid;
    __asm__ volatile ("movl %%fs:0x2d0, %0" : "=r"(tid));
    uint32_t bucket = tid & 0x3f;
    uint8_t c = ++g_counters[bucket];
    if (c >= SAMPLE_THRESHOLD) g_counters[bucket] = 0;
  }
  return now_ns () - t0;
}

/* ---------- Method C: pthread_getspecific ----------
 * One-time setup (alloc + setspecific) is OUTSIDE the timed loop.
 * Per-iteration cost is just: getspecific → increment → compare → reset.
 * No TID lookup needed because TLS already gives per-thread isolation. */
static double run_method_C (int iters)
{
  /* one-time TLS init for this thread */
  uint8_t * counter = pthread_getspecific (g_counter_key);
  if (!counter)
  {
    counter = calloc (1, 1);
    pthread_setspecific (g_counter_key, counter);
  }

  double t0 = now_ns ();
  for (int i = 0; i < iters; i++)
  {
    volatile uint8_t * c = pthread_getspecific (g_counter_key);
    if (++(*c) >= SAMPLE_THRESHOLD) *c = 0;
  }
  return now_ns () - t0;
}

/* ---------- Driver ---------- */
static void bench_method (const char * name, double (*fn)(int))
{
  /* warm up cache / branch predictor / TLS */
  fn (1000);

  /* reset state between methods so each starts at counter=0 */
  for (int i = 0; i < NUM_BUCKETS; i++) g_counters[i] = 0;
  uint8_t * tc = pthread_getspecific (g_counter_key);
  if (tc) *tc = 0;

  double trials[NUM_TRIALS];
  double sum = 0;
  double best = 1e18;
  for (int t = 0; t < NUM_TRIALS; t++)
  {
    trials[t] = fn (ITERS_PER_TRIAL);
    sum  += trials[t];
    if (trials[t] < best) best = trials[t];
  }
  double avg      = sum / NUM_TRIALS;
  double per_avg  = avg / ITERS_PER_TRIAL;
  double per_best = best / ITERS_PER_TRIAL;

  printf ("  %-26s avg=%7.2f ms  best=%7.2f ms  per-call avg=%5.2f ns  best=%5.2f ns\n",
          name, avg / 1e6, best / 1e6, per_avg, per_best);
}

int main (void)
{
  if (pthread_key_create (&g_counter_key, counter_dtor) != 0)
  {
    perror ("pthread_key_create");
    return 1;
  }

  printf ("=== Per-thread sampling counter: 3 methods ===\n");
  printf ("  iters per trial  : %d\n", ITERS_PER_TRIAL);
  printf ("  trials per method: %d\n", NUM_TRIALS);
  printf ("  sample threshold : every %d calls\n", SAMPLE_THRESHOLD);
  printf ("  bucket count (A,B): %d\n\n", NUM_BUCKETS);

  bench_method ("A. gettid() syscall",     run_method_A);
  bench_method ("B. fs:[0x2d0] direct",    run_method_B);
  bench_method ("C. pthread_getspecific",  run_method_C);

  printf ("\n  interpretation:\n");
  printf ("    A models a naive but portable trampoline;\n");
  printf ("    B is what FreeProbe's modified trampoline does;\n");
  printf ("    C is the alternative where the counter lives in TLS.\n");
  return 0;
}
