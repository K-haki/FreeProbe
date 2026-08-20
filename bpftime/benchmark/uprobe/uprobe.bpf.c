#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Sampling rate - trigger map write every N calls
#define SAMPLING_RATE 500

// Map to store sampled values
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} sample_map SEC(".maps");

// Per-CPU array to track call count
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} call_counter SEC(".maps");

#define DEFINE_MAP_OPERATIONS(map_name, map_type) \
struct { \
    __uint(type, map_type); \
    __uint(max_entries, 1024); \
    __type(key, u32); \
    __type(value, u64); \
} map_name SEC(".maps"); \
\
SEC("uprobe/benchmark/test:__bench_" #map_name "_update") \
int map_name##_update(struct pt_regs *ctx) \
{ \
    for (int i = 0; i < 1000; i++) { \
        u32 key = i; \
        u64 value = i; \
        bpf_map_update_elem(&map_name, &key, &value, BPF_ANY); \
    } \
    return 0; \
} \
\
SEC("uprobe/benchmark/test:__bench_" #map_name "_delete") \
int map_name##_delete(struct pt_regs *ctx) \
{ \
    for (int i = 0; i < 1000; i++) { \
        u32 key = i; \
        bpf_map_delete_elem(&map_name, &key); \
    } \
    return 0; \
} \
\
SEC("uprobe/benchmark/test:__bench_" #map_name "_lookup") \
int map_name##_lookup(struct pt_regs *ctx) \
{ \
    for (int i = 0; i < 1000; i++) { \
        u32 key = i; \
        bpf_map_lookup_elem(&map_name, &key); \
    } \
    return 0; \
}

// Define operations for an array map
DEFINE_MAP_OPERATIONS(array_map, BPF_MAP_TYPE_ARRAY)

// Define operations for a hash map
DEFINE_MAP_OPERATIONS(hash_map, BPF_MAP_TYPE_HASH)

// Define operations for a per-cpu array map
DEFINE_MAP_OPERATIONS(per_cpu_hash_map, BPF_MAP_TYPE_PERCPU_HASH)

// Define operations for a per-cpu hash map
DEFINE_MAP_OPERATIONS(per_cpu_array_map, BPF_MAP_TYPE_PERCPU_ARRAY)

SEC("uprobe/benchmark/test:__bench_write")
int BPF_UPROBE(__bench_write, char *a, int b, uint64_t c)
{
	char buffer[5] = "text";
    for (int i = 0; i < 1000; i++) {
	    bpf_probe_write_user(a, buffer, sizeof(buffer));
    }
	return b + c;
}

SEC("uprobe/benchmark/test:__bench_read")
int BPF_UPROBE(__bench_read, char *a, int b, uint64_t c)
{
	char buffer[5];
    int res;
    for (int i = 0; i < 1000; i++) {
	    bpf_probe_read_user(buffer, sizeof(buffer), a);
    }
	return b + c + res + buffer[1];
}

SEC("uprobe/benchmark/test:__bench_uprobe")
int BPF_UPROBE(__bench_uprobe_none, char *a, int b, uint64_t c)
{
    return b + c;
}

// SEC("uprobe/benchmark/test:__bench_uprobe")
// int BPF_UPROBE(__bench_uprobe, char *a, int b, uint64_t c)
// {
//     u32 key = 0;
//     u64 *count = bpf_map_lookup_elem(&call_counter, &key);
//     if (!count) {
//         // First call on this CPU, initialize counter
//         u64 init_val = 1;
//         bpf_map_update_elem(&call_counter, &key, &init_val, BPF_ANY);
//     } else {
//         __sync_add_and_fetch(count, 1);
//     }

//     // Re-fetch counter after potential initialization
//     count = bpf_map_lookup_elem(&call_counter, &key);
//     if (!count) {
//         return b + c;
//     }

//     // Check if we should sample this call
//     if ((*count % SAMPLING_RATE) == 0) {
//         // Sample triggered - aggregate b and c with existing map value
//         u32 map_key = (u32)(*count / SAMPLING_RATE);
//         u64 *old_value = bpf_map_lookup_elem(&sample_map, &map_key);

//         u64 new_b = (u64)b;
//         u64 new_c = c & 0xFFFFFFFF;
//         u64 aggregated_value;

//         if (old_value) {
//             // Existing value found - compute average
//             u64 old_b = (*old_value) >> 32;
//             u64 old_c = (*old_value) & 0xFFFFFFFF;
//             u64 avg_b = (old_b + new_b) / 2;
//             u64 avg_c = (old_c + new_c) / 2;
//             aggregated_value = (avg_b << 32) | (avg_c & 0xFFFFFFFF);
//         } else {
//             // No existing value - use current values
//             aggregated_value = (new_b << 32) | (new_c & 0xFFFFFFFF);
//         }

//         bpf_map_update_elem(&sample_map, &map_key, &aggregated_value, BPF_ANY);
//     }

//     return b + c;
// }

SEC("uretprobe/benchmark/test:__bench_uretprobe")
int BPF_URETPROBE(__bench_uretprobe, int ret)
{
	return ret;
}

SEC("uprobe/benchmark/test:__bench_uprobe_uretprobe")
int BPF_UPROBE(__bench_uprobe_uretprobe_1, char *a, int b, uint64_t c)
{
	return b;
}

SEC("uretprobe/benchmark/test:__bench_uprobe_uretprobe")
int BPF_URETPROBE(__benchmark_test_function_1_2, int ret)
{
	return ret;
}

char LICENSE[] SEC("license") = "GPL";
