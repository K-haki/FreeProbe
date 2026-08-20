/*
 * tid_fs_probe.c — verify what `fs:[offset]` returns and locate the offset of
 * the real kernel TID inside the TLS area.
 *
 * Approach: each scan runs in a forked child. If the child segfaults, it just
 * dies; the parent reads what was printed before the fault and reports it.
 * This avoids the "longjmp causes uninitialized stack frame" issue that
 * sigsetjmp-based recovery hits under glibc Fortify.
 *
 * Build:  gcc -O2 -Wall tid_fs_probe.c -o tid_fs_probe -lpthread
 * Run:    ./tid_fs_probe
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>
#include <signal.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <asm/prctl.h>
#include <sys/prctl.h>

static void *get_fs_base(void) {
    void *fs = NULL;
    if (syscall(__NR_arch_prctl, ARCH_GET_FS, (unsigned long)&fs) != 0) {
        perror("arch_prctl ARCH_GET_FS");
        exit(1);
    }
    return fs;
}

/* Print TID, fs_base, fs:[0], and scan the first scan_len bytes for the TID.
 * Runs in a child process so a SIGSEGV only kills the child. */
static void scan_in_child(const char *tag) {
    pid_t child = fork();
    if (child == 0) {
        /* Child: do the scan, disable stdout buffering so we see output even on crash. */
        setvbuf(stdout, NULL, _IONBF, 0);

        pid_t tid = (pid_t)syscall(SYS_gettid);
        pid_t pid = (pid_t)syscall(SYS_getpid);
        void *fs_base = get_fs_base();

        printf("\n=== %s (pid=%d tid=%d) ===\n", tag, pid, tid);
        printf("  ARCH_GET_FS base   = %p\n", fs_base);

        uintptr_t fs0;
        __asm__ volatile ("movq %%fs:0, %0" : "=r"(fs0));
        printf("  fs:[0]             = 0x%016lx\n", fs0);
        printf("  fs_base == fs:[0]? = %s\n",
               fs_base == (void *)fs0 ? "YES (so fs:[0] is the TCB self-pointer)"
                                      : "no");
        printf("  fs:[0] == gettid()?= %s\n",
               (uintptr_t)tid == fs0 ? "YES"
                                     : "NO  ->  fs:[0] is NOT the real TID");

        printf("  Scanning first 0x1000 bytes of TLS area for TID (%d)...\n", tid);
        int hits = 0;
        unsigned char *base = (unsigned char *)fs_base;
        for (size_t off = 0; off < 0x1000; off += sizeof(int32_t)) {
            int32_t v;
            memcpy(&v, base + off, sizeof(v));   /* may SIGSEGV here */
            if (v == tid) {
                printf("    >>> fs:[0x%zx] = %d  (matches TID)\n", off, v);
                hits++;
            }
        }
        if (hits == 0) {
            printf("    (no 4-byte match for TID in scanned range)\n");
        }

        printf("  fs:[0] & 0x3f      = 0x%02lx\n", fs0 & 0x3f);
        printf("  tid    & 0x3f      = 0x%02x\n", ((uint32_t)tid) & 0x3f);

        _exit(0);
    }
    /* Parent: wait for child. */
    int status = 0;
    waitpid(child, &status, 0);
    if (WIFSIGNALED(status)) {
        printf("  [child died from signal %d (%s) during scan]\n",
               WTERMSIG(status), strsignal(WTERMSIG(status)));
    }
}

/* Forward decl — definition after main. */
static void validate_tid_offset_across_threads (void);

int main(void) {
    scan_in_child("main thread");

    /* Worker-thread scans must happen inside the thread, so spawn one and
     * fork from inside it. */
    pthread_t t1;
    pthread_create(&t1, NULL, (void *(*)(void *))scan_in_child, "worker-1");
    pthread_join(t1, NULL);

    /* Final sanity check: now that the scan above tells us the TID lives at
     * fs:[0x2d0], verify that simply reading that offset reproduces gettid()
     * in every one of N independent threads. */
    validate_tid_offset_across_threads ();
    return 0;
}

/* ====================== Final validation layer ======================
 *
 * Goal: confirm that the offset found by the scan (0x2d0 on this glibc)
 * really returns the kernel TID in *every* thread, not just by coincidence
 * in the threads we scanned above.
 *
 * Method: spawn N threads; in each thread, read 4 bytes from fs:[0x2d0] via
 * inline asm and compare against syscall(SYS_gettid). Atomically tally
 * matches / mismatches across threads.
 *
 * No fork needed here — reading a known-mapped 4-byte field can't fault.
 */
#define TID_OFFSET            0x2d0
#define N_VALIDATE_THREADS    8

static _Atomic int g_validate_pass = 0;
static _Atomic int g_validate_fail = 0;

static void *validate_tid_offset_thread (void *arg)
{
  long idx = (long) arg;
  pid_t real_tid = (pid_t) syscall (SYS_gettid);
  uint32_t fs_tid = 0;

  /* movl %fs:0x2d0, %eXX  — 4-byte read of the pid_t field. */
  __asm__ volatile ("movl %%fs:0x2d0, %0" : "=r"(fs_tid));

  int ok = ((pid_t) fs_tid == real_tid);
  if (ok)
    atomic_fetch_add (&g_validate_pass, 1);
  else
    atomic_fetch_add (&g_validate_fail, 1);

  printf ("  thread %ld: gettid()=%d  fs:[0x2d0]=%u  -> %s\n",
          idx, real_tid, fs_tid, ok ? "MATCH" : "*** MISMATCH ***");
  return NULL;
}

static void validate_tid_offset_across_threads (void)
{
  printf ("\n=== Validating fs:[0x%x] == gettid() across %d threads ===\n",
          TID_OFFSET, N_VALIDATE_THREADS);
  atomic_store (&g_validate_pass, 0);
  atomic_store (&g_validate_fail, 0);

  pthread_t threads[N_VALIDATE_THREADS];
  for (long i = 0; i < N_VALIDATE_THREADS; i++)
  {
    pthread_create (&threads[i], NULL,
                    validate_tid_offset_thread, (void *) i);
  }
  for (int i = 0; i < N_VALIDATE_THREADS; i++)
    pthread_join (threads[i], NULL);

  printf ("  Summary: %d/%d threads matched, %d mismatched\n",
          g_validate_pass, N_VALIDATE_THREADS, g_validate_fail);
  printf ("  Verdict: %s\n",
          g_validate_fail == 0
              ? "PASS — fs:[0x2d0] is the correct TID offset on this glibc"
              : "FAIL — offset 0x2d0 does NOT return the TID here");
}
