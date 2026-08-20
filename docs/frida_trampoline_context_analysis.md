# Frida Trampoline 和 GumFunctionContext 深度分析

## 1. Trampoline 代码的创建位置和生成方式

### 创建位置

Trampoline 代码在 **`_gum_interceptor_backend_create_trampoline`** 函数中创建，这个函数在各个架构的后端实现中：

- **x86/x64**: `frida-gum/gum/backend-x86/guminterceptor-x86.c:167`
- **ARM64**: `frida-gum/gum/backend-arm64/guminterceptor-arm64.c:687`
- **ARM**: `frida-gum/gum/backend-arm/guminterceptor-arm.c`

### 生成流程

**X86/X64 架构的生成过程** (`guminterceptor-x86.c:167-225`):

```c
gboolean
_gum_interceptor_backend_create_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumX86Writer * cw = &self->writer;
  GumX86Relocator * rl = &self->relocator;
  GumX86FunctionContextData * data = GUM_FCDATA (ctx);
  GumAddress function_ctx_ptr;
  guint reloc_bytes;

  // 1. 准备 trampoline 内存空间
  if (!gum_interceptor_backend_prepare_trampoline (self, ctx))
    return FALSE;

  gum_x86_writer_reset (cw, ctx->trampoline_slice->data);

  if (ctx->type != GUM_INTERCEPTOR_TYPE_FAST)
  {
    // 2. 在 trampoline 开头写入 GumFunctionContext 指针
    function_ctx_ptr = GUM_ADDRESS (gum_x86_writer_cur (cw));
    gum_x86_writer_put_bytes (cw, (guint8 *) &ctx,
        sizeof (GumFunctionContext *));

    // 3. 生成 on_enter_trampoline
    ctx->on_enter_trampoline = gum_x86_writer_cur (cw);

    gum_x86_writer_put_push_near_ptr (cw, function_ctx_ptr);
    gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (self->enter_thunk->data));

    // 4. 生成 on_leave_trampoline
    ctx->on_leave_trampoline = gum_x86_writer_cur (cw);

    gum_x86_writer_put_push_near_ptr (cw, function_ctx_ptr);
    gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (self->leave_thunk->data));

    gum_x86_writer_flush (cw);
    g_assert (gum_x86_writer_offset (cw) <= ctx->trampoline_slice->size);
  }

  // 5. 生成 on_invoke_trampoline（原函数的重定位代码）
  ctx->on_invoke_trampoline = gum_x86_writer_cur (cw);
  gum_x86_relocator_reset (rl, (guint8 *) ctx->function_address, cw);

  do
  {
    reloc_bytes = gum_x86_relocator_read_one (rl, NULL);
    g_assert (reloc_bytes != 0);
  }
  while (reloc_bytes < data->redirect_code_size);
  gum_x86_relocator_write_all (rl);

  if (!gum_x86_relocator_eoi (rl))
  {
    gum_x86_writer_put_jmp_address (cw,
        GUM_ADDRESS (ctx->function_address) + reloc_bytes);
  }

  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) <= ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  gum_memcpy (ctx->overwritten_prologue, ctx->function_address, reloc_bytes);

  return TRUE;
}
```

## 2. Trampoline 代码之前的上下文指针

**是的，确实有一个指针指向 Frida 的上下文结构体！**

### 各架构的实现方式

**X86/X64** (`guminterceptor-x86.c:183-185`):
```c
// 在 trampoline 代码的开头直接写入 GumFunctionContext 指针
function_ctx_ptr = GUM_ADDRESS (gum_x86_writer_cur (cw));
gum_x86_writer_put_bytes (cw, (guint8 *) &ctx, sizeof (GumFunctionContext *));
```

**ARM64** (`guminterceptor-arm64.c:742-744, 749-751`):
```c
// 使用 LDR 指令将 GumFunctionContext 指针加载到 X17 寄存器
gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X17, GUM_ADDRESS (ctx));
gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X16,
    GUM_ADDRESS (gum_sign_code_pointer (self->enter_thunk)));
gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);
```

**ARM** (`guminterceptor-arm.c:262-264`):
```c
// 使用 LDR 指令将 GumFunctionContext 指针加载到 R6 寄存器
gum_arm_writer_put_ldr_reg_address (aw, ARM_REG_R6, GUM_ADDRESS (ctx));
gum_arm_writer_put_ldr_reg_address (aw, ARM_REG_PC,
    GUM_ADDRESS (self->enter_thunk_arm));
```

### GumFunctionContext 结构体内容

定义在 `frida-gum/gum/guminterceptor-priv.h:34-66`:

```c
struct _GumFunctionContext
{
  gpointer function_address;           // 目标函数地址
  gpointer grafted_hook;               // 接入的钩子
  gpointer import_target;              // 导入目标

  GumInterceptorType type;             // 拦截器类型
  guint8 destroyed;                    // 销毁标志
  guint8 activated;                    // 激活标志
  guint8 has_on_leave_listener;        // 是否有离开监听器

  GumCodeSlice * trampoline_slice;     // Trampoline 代码切片
  GumCodeDeflector * trampoline_deflector; // 代码重定向器
  volatile gint trampoline_usage_counter; // 使用计数器

  gpointer on_enter_trampoline;        // 进入 trampoline 地址
  guint8 overwritten_prologue[32];     // 被覆盖的原函数序言
  guint overwritten_prologue_len;      // 覆盖长度

  gpointer on_invoke_trampoline;       // 调用 trampoline 地址
  gpointer on_leave_trampoline;        // 离开 trampoline 地址

  volatile GPtrArray * listener_entries; // 监听器数组

  gpointer replacement_function;       // 替换函数
  gpointer replacement_data;           // 替换数据

  GumFunctionContextBackendData backend_data; // 后端特定数据
  GumInterceptor * interceptor;        // 拦截器实例
};
```

### 创建位置

GumFunctionContext 在 **`gum_function_context_new`** 函数中创建：

定义在 `frida-gum/gum/guminterceptor.c:1285-1299`:

```c
static GumFunctionContext *
gum_function_context_new (GumInterceptor * interceptor,
                          gpointer function_address,
                          GumInterceptorType type)
{
  GumFunctionContext * ctx;

  ctx = g_slice_new0 (GumFunctionContext);
  ctx->function_address = function_address;
  ctx->type = type;
  ctx->listener_entries =
      g_ptr_array_new_full (1, (GDestroyNotify) listener_entry_free);
  ctx->interceptor = interceptor;

  return ctx;
}
```

这个结构体在 `gum_interceptor_instrument()` 中被调用创建（`guminterceptor.c:876`），然后在创建 trampoline 时通过架构特定的方式嵌入到生成的代码中。

## 3. Trampoline 在 Thunk 中的使用方式

### X86/X64 架构的使用流程

#### 步骤1: 在 trampoline 代码开头嵌入 GumFunctionContext 指针

```c
// 源代码: frida-gum/gum/backend-x86/guminterceptor-x86.c:183-185
function_ctx_ptr = GUM_ADDRESS (gum_x86_writer_cur (cw));
gum_x86_writer_put_bytes (cw, (guint8 *) &ctx, sizeof (GumFunctionContext *));
```

生成的汇编代码 (32位):
```asm
trampoline_start:
  .long 0x12345678      ; 直接嵌入 4 字节指针
```

生成的汇编代码 (64位):
```asm
trampoline_start:
  .quad 0x000000012345678  ; 直接嵌入 8 字节指针
```

#### 步骤2: 生成 on_enter_trampoline

```c
// 源代码: frida-gum/gum/backend-x86/guminterceptor-x86.c:189-190
ctx->on_enter_trampoline = gum_x86_writer_cur (cw);
gum_x86_writer_put_push_near_ptr (cw, function_ctx_ptr);
gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (self->enter_thunk->data));
```

生成的汇编代码:
```asm
on_enter_trampoline:
  push dword [trampoline_start]  ; push ctx 指针到栈上
  jmp 0xABC00000                  ; 跳转到 enter_thunk
```

#### 步骤3: enter_thunk 的实现

```c
// 源代码: frida-gum/gum/backend-x86/guminterceptor-x86.c:321-342
static void
gum_emit_enter_thunk (GumX86Writer * cw)
{
  const gssize return_address_stack_displacement = 0;

  gum_emit_prolog (cw, return_address_stack_displacement);

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSI,
      GUM_X86_XBP, GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XDX,
      GUM_X86_XBP, GUM_FRAME_OFFSET_TOP);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XCX,
      GUM_X86_XBP, GUM_FRAME_OFFSET_NEXT_HOP);

  gum_x86_writer_put_call_address_with_aligned_arguments (cw, GUM_CALL_CAPI,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, GUM_X86_XBX,
      GUM_ARG_REGISTER, GUM_X86_XSI,
      GUM_ARG_REGISTER, GUM_X86_XDX,
      GUM_ARG_REGISTER, GUM_X86_XCX);

  gum_emit_epilog (cw);
}
```

生成的 enter_thunk 汇编代码:
```asm
enter_thunk:
  ; 设置栈帧 (保存寄存器状态)
  pushfd
  pushad
  ; ... (其他设置)

  ; 准备调用 _gum_function_context_begin_invocation 的参数
  ; 参数1 (ebx): GumFunctionContext* ctx - 已经在栈上 [ebp]
  mov ebx, [ebp]                 ; ebx = ctx

  ; 参数2 (esi): GumCpuContext* cpu_context
  lea esi, [ebp + offset_cpu_context]  ; esi = &cpu_context

  ; 参数3 (edx): gpointer* caller_ret_addr
  lea edx, [ebp + offset_top]           ; edx = &caller_ret_addr

  ; 参数4 (ecx): gpointer* next_hop
  lea ecx, [ebp + offset_next_hop]     ; ecx = &next_hop

  ; 调用 C 函数
  call _gum_function_context_begin_invocation

  ; 恢复寄存器并返回
  ; ...
  ret
```

#### 步骤4: 在 C 函数中访问结构体成员

```c
void _gum_function_context_begin_invocation(
    GumFunctionContext* ctx,     // 第一个参数 (ebx)
    GumCpuContext* cpu_context,  // 第二个参数 (esi)
    gpointer* caller_ret_addr,   // 第三个参数 (edx)
    gpointer* next_hop)          // 第四个参数 (ecx)
{
  // 访问结构体成员
  g_atomic_int_inc (&ctx->trampoline_usage_counter);  // 偏移 +48

  GumInterceptor* interceptor = ctx->interceptor;     // 偏移 +最后

  if (ctx->replacement_function != NULL) {             // 偏移 +last-8
    // ... 处理替换函数
  }

  // 设置返回地址
  *caller_ret_addr = ctx->on_leave_trampoline;         // 偏移 +56
  *next_hop = ctx->on_invoke_trampoline;               // 偏移 +54
}
```

### ARM64 架构的使用流程

#### 步骤1: 使用 LDR 指令加载结构体指针

```c
// 源代码: frida-gum/gum/backend-arm64/guminterceptor-arm64.c:742-752
gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X17, GUM_ADDRESS (ctx));
gum_arm64_writer_put_ldr_reg_address (aw, ARM64_REG_X16,
    GUM_ADDRESS (gum_sign_code_pointer (self->enter_thunk)));
gum_arm64_writer_put_br_reg (aw, ARM64_REG_X16);
```

生成的汇编代码:
```asm
on_enter_trampoline:
  ; 加载 GumFunctionContext 指针到 X17 寄存器
  ldr x17, #0x12345000     ; x17 = ctx (GumFunctionContext*)

  ; 加载 enter_thunk 地址到 X16 寄存器
  ldr x16, #0xABC00000     ; x16 = enter_thunk

  ; 跳转到 enter_thunk (ctx 在 x17 中传递)
  br x16                   ; 跳转
```

#### 步骤2: enter_thunk 设置参数并调用 C 函数

```asm
enter_thunk:
  ; ARM64 AAPCS64 调用约定
  ; x0-x7: 参数寄存器

  ; 参数1 (x0): GumFunctionContext* ctx
  mov x0, x17               ; x0 = ctx (从 x17 传递过来)

  ; 设置其他参数
  mov x1, sp                ; x1 = cpu_context (栈指针)
  add x2, sp, #offset       ; x2 = caller_ret_addr
  add x3, sp, #offset       ; x3 = next_hop

  ; 调用 C 函数
  bl _gum_function_context_begin_invocation

  ; 返回
  ret
```

#### 步骤3: 结构体成员访问的汇编表示

在 C 代码中访问: `ctx->trampoline_usage_counter++`

对应的汇编操作:
```asm
  ; 假设 ctx 在 x0 中
  ; trampoline_usage_counter 偏移 +48
  ldr w8, [x0, #48]           ; 加载当前值
  add w8, w8, #1              ; 加1
  str w8, [x0, #48]           ; 存储回去

  ; 或者使用原子操作 (实际使用)
  ; ldaddal w8, w9, [x0, #48] ; 原子加法指令
```

## 4. `trampoline_usage_counter` 的作用和使用分析

### 4.1 定义和类型

```c
// frida-gum/gum/guminterceptor-priv.h:48
volatile gint trampoline_usage_counter;
```

- **类型**: `volatile gint` - 使用原子操作确保线程安全
- **作用**: **跟踪当前有多少个线程正在执行特定函数的 trampoline 代码**

### 4.2 主要作用

**核心目的：确保 Hook 安全卸载**

这个计数器实现了**引用计数机制**，防止在函数调用仍在执行时销毁相关的 trampoline 代码，避免：
- 释放正在执行的代码内存
- 访问已释放的上下文结构
- 程序崩溃或内存损坏

### 4.3 使用位置和逻辑

#### 增加操作 (函数调用开始时)

**位置**: `frida-gum/gum/guminterceptor.c:1485`

```c
void
_gum_function_context_begin_invocation (GumFunctionContext * function_ctx,
                                        GumCpuContext * cpu_context,
                                        gpointer * caller_ret_addr,
                                        gpointer * next_hop)
{
  // ...

  // 函数调用开始时立即增加计数器
  g_atomic_int_inc (&function_ctx->trampoline_usage_counter);

  // ... 后续处理逻辑
}
```

#### 减少操作 (函数调用结束时)

有**4个位置**会减少计数器：

**位置1**: `guminterceptor.c:1622` - 不需要 leave trap 时
```c
if (!will_trap_on_leave)
{
  g_atomic_int_dec_and_test (&function_ctx->trampoline_usage_counter);
}
```

**位置2**: `guminterceptor.c:1628` - bypass 路径
```c
bypass:
  g_atomic_int_dec_and_test (&function_ctx->trampoline_usage_counter);
```

**位置3**: `guminterceptor.c:1708` - 正常结束调用时
```c
void
_gum_function_context_end_invocation (GumFunctionContext * function_ctx,
                                      GumCpuContext * cpu_context,
                                      gpointer * next_hop)
{
  // ... 处理 leave 监听器

  gum_invocation_stack_pop (interceptor_ctx->stack);
  gum_tls_key_set_value (gum_interceptor_guard_key, NULL);

  // 函数调用结束时减少计数器
  g_atomic_int_dec_and_test (&function_ctx->trampoline_usage_counter);
}
```

**位置4**: `guminterceptor.c:806` - 堆栈恢复时
```c
void
gum_interceptor_restore (GumInvocationState * state)
{
  GumInvocationStack * stack = gum_interceptor_get_current_stack ();

  for (i = old_depth; i != new_depth; i++)
  {
    GumInvocationStackEntry * entry = &g_array_index (stack, GumInvocationStackEntry, i);

    // 恢复堆栈时减少计数器
    g_atomic_int_dec_and_test (&entry->function_ctx->trampoline_usage_counter);
  }

  g_array_set_size (stack, old_depth);
}
```

#### 检查操作 (Hook 卸载时)

**位置**: `frida-gum/gum/guminterceptor.c:1186`

```c
// 在事务结束时检查是否可以安全销毁
while ((task = g_queue_pop_head (self->pending_destroy_tasks)) != NULL)
{
  if (task->ctx->trampoline_usage_counter == 0)
  {
    // 计数器为0，没有线程在执行，可以安全销毁
    GUM_INTERCEPTOR_UNLOCK (interceptor);
    task->notify (task->data);  // 执行销毁回调
    GUM_INTERCEPTOR_LOCK (interceptor);

    g_slice_free (GumDestroyTask, task);
  }
  else
  {
    // 计数器不为0，仍有线程在执行，延迟销毁
    interceptor->current_transaction.is_dirty = TRUE;
    g_queue_push_tail (interceptor->current_transaction.pending_destroy_tasks, task);
  }
}
```

### 4.4 工作流程图

```
函数调用开始
    ↓
_gum_function_context_begin_invocation()
    ↓
g_atomic_int_inc(&trampoline_usage_counter)  ← 计数器+1
    ↓
执行 hook 逻辑
    ↓
判断 will_trap_on_leave
    ↓
    ├── FALSE → 立即 g_atomic_int_dec_and_test()  ← 计数器-1
    │
    └── TRUE  → 继续执行，等待 _gum_function_context_end_invocation()
                      ↓
                 g_atomic_int_dec_and_test()  ← 计数器-1

用户尝试卸载 hook
    ↓
检查 trampoline_usage_counter == 0
    ↓
    ├── TRUE  → 立即销毁 hook 和 trampoline
    │
    └── FALSE → 延迟销毁，等待所有调用完成
```

### 4.5 关键特性

1. **原子操作**: 使用 `g_atomic_int_inc()` 和 `g_atomic_int_dec_and_test()` 确保多线程安全
2. **volatile 修饰符**: 防止编译器优化，确保每次都从内存读取最新值
3. **延迟销毁**: 如果计数器不为0，销毁任务会被重新排队，等待下次事务检查
4. **精确计数**: 每个函数调用都会精确地 +1 和 -1，确保计数准确

### 4.6 典型使用场景

**场景1: 单线程 hook**
```
计数器: 0 → 1 (调用开始) → 0 (调用结束) → 可以安全销毁
```

**场景2: 多线程并发 hook**
```
线程A: 计数器 0 → 1
线程B: 计数器 1 → 2
线程A: 计数器 2 → 1 (A结束)
线程B: 计数器 1 → 0 (B结束) → 现在可以安全销毁
```

**场景3: 尝试在调用期间卸载**
```
线程A: 计数器 0 → 1 (开始调用)
用户: 尝试卸载 hook，但计数器=1，延迟销毁
线程A: 计数器 1 → 0 (结束调用)
下次事务: 检查到计数器=0，执行销毁
```

## 5. GumFunctionContext 结构体完整类型定义

### 5.1 结构体定义

```c
struct _GumFunctionContext
{
  // 目标函数相关信息
  gpointer function_address;                    // void* - 目标函数的地址

  // Darwin/iOS 平台专用字段
  gpointer grafted_hook;                        // void* - 接入的钩子
  gpointer import_target;                       // void* - 导入目标

  // 拦截器类型和状态标志 (使用 GLib 类型)
  GumInterceptorType type;                      // guint8 - 拦截器类型枚举
  guint8 destroyed;                             // unsigned char - 销毁标志
  guint8 activated;                             // unsigned char - 激活标志
  guint8 has_on_leave_listener;                 // unsigned char - 是否有离开监听器

  // Trampoline 内存管理
  GumCodeSlice * trampoline_slice;              // 指向代码切片结构体
  GumCodeDeflector * trampoline_deflector;      // 指向代码重定向器结构体
  volatile gint trampoline_usage_counter;       // volatile int - 使用计数器

  // Trampoline 地址指针
  gpointer on_enter_trampoline;                 // void* - 进入时调用的 trampoline 地址
  guint8 overwritten_prologue[32];              // unsigned char[32] - 被覆盖的原函数序言字节
  guint overwritten_prologue_len;               // unsigned int - 覆盖的字节长度

  gpointer on_invoke_trampoline;                // void* - 调用原函数的 trampoline 地址
  gpointer on_leave_trampoline;                 // void* - 离开时调用的 trampoline 地址

  // 监听器管理
  volatile GPtrArray * listener_entries;        // 指针数组，存储监听器条目

  // 函数替换相关
  gpointer replacement_function;                // void* - 替换函数的地址
  gpointer replacement_data;                    // void* - 传递给替换函数的数据

  // 架构特定的后端数据
  GumFunctionContextBackendData backend_data;   // 联合体，存储架构特定数据

  GumInterceptor * interceptor;                 // 指向拦截器实例
};
```

### 5.2 相关类型定义

#### 枚举类型
```c
// 拦截器类型
enum _GumInterceptorType
{
  GUM_INTERCEPTOR_TYPE_DEFAULT = 0,  // 标准拦截器
  GUM_INTERCEPTOR_TYPE_FAST = 1      // 快速拦截器 (无监听器)
};
```

#### 后端数据联合体
```c
union _GumFunctionContextBackendData
{
  gchar storage[2 * GLIB_SIZEOF_VOID_P];  // 16 字节存储 (64位系统)
  gpointer p[2];                          // 2 个指针的数组
};
```

#### GLib 基础类型映射
```c
// GLib 基础类型
typedef unsigned int   guint;      // 通常是 4 字节
typedef int            gint;       // 通常是 4 字节
typedef unsigned char  guint8;     // 1 字节
typedef unsigned short guint16;    // 2 字节
typedef unsigned int   guint32;    // 4 字节
typedef unsigned long  guint64;    // 8 字节

// 指针大小相关
#define GLIB_SIZEOF_VOID_P sizeof(void*)  // 4 字节 (32位) 或 8 字节 (64位)

// 通用指针
typedef void* gpointer;
```

### 5.3 内存布局总结

#### 64位系统

| 字段 | 类型 | 大小 | 偏移 |
|------|------|------|------|
| function_address | `void*` | 8 | +0 |
| grafted_hook | `void*` | 8 | +8 |
| import_target | `void*` | 8 | +16 |
| type | `guint8` | 1 | +24 |
| destroyed | `guint8` | 1 | +25 |
| activated | `guint8` | 1 | +26 |
| has_on_leave_listener | `guint8` | 1 | +27 |
| [padding] | - | 4 | +28 |
| trampoline_slice | `GumCodeSlice*` | 8 | +32 |
| trampoline_deflector | `GumCodeDeflector*` | 8 | +40 |
| trampoline_usage_counter | `volatile int` | 4 | +48 |
| [padding] | - | 4 | +52 |
| on_enter_trampoline | `void*` | 8 | +56 |
| overwritten_prologue | `unsigned char[32]` | 32 | +64 |
| overwritten_prologue_len | `unsigned int` | 4 | +96 |
| [padding] | - | 4 | +100 |
| on_invoke_trampoline | `void*` | 8 | +104 |
| on_leave_trampoline | `void*` | 8 | +112 |
| listener_entries | `volatile GPtrArray*` | 8 | +120 |
| replacement_function | `void*` | 8 | +128 |
| replacement_data | `void*` | 8 | +136 |
| backend_data | `union[16]` | 16 | +144 |
| interceptor | `GumInterceptor*` | 8 | +160 |

**总计**: **168 字节** (64位系统)

#### 32位系统

| 字段 | 类型 | 大小 | 偏移 |
|------|------|------|------|
| function_address | `void*` | 4 | +0 |
| grafted_hook | `void*` | 4 | +4 |
| import_target | `void*` | 4 | +8 |
| type | `guint8` | 1 | +12 |
| destroyed | `guint8` | 1 | +13 |
| activated | `guint8` | 1 | +14 |
| has_on_leave_listener | `guint8` | 1 | +15 |
| trampoline_slice | `GumCodeSlice*` | 4 | +16 |
| trampoline_deflector | `GumCodeDeflector*` | 4 | +20 |
| trampoline_usage_counter | `volatile int` | 4 | +24 |
| on_enter_trampoline | `void*` | 4 | +28 |
| overwritten_prologue | `unsigned char[32]` | 32 | +32 |
| overwritten_prologue_len | `unsigned int` | 4 | +64 |
| on_invoke_trampoline | `void*` | 4 | +68 |
| on_leave_trampoline | `void*` | 4 | +72 |
| listener_entries | `volatile GPtrArray*` | 4 | +76 |
| replacement_function | `void*` | 4 | +80 |
| replacement_data | `void*` | 4 | +84 |
| backend_data | `union[8]` | 8 | +88 |
| interceptor | `GumInterceptor*` | 4 | +96 |

**总计**: **100 字节** (32位系统)

### 5.4 汇编访问示例

假设基址在 x0 寄存器中：

```asm
; 访问 function_address (偏移 0)
ldr x1, [x0, #0]            ; x1 = ctx->function_address

; 访问 trampoline_usage_counter (偏移 48)
ldr w1, [x0, #48]           ; w1 = ctx->trampoline_usage_counter

; 访问 on_enter_trampoline (偏移 56)
ldr x1, [x0, #56]           ; x1 = ctx->on_enter_trampoline

; 访问 replacement_function (偏移 128)
ldr x1, [x0, #128]          ; x1 = ctx->replacement_function

; 访问 interceptor (偏移 160)
ldr x1, [x0, #160]          ; x1 = ctx->interceptor
```

## 6. 总结

### Frida Trampoline 机制的核心特点

1. **架构自适应**: 针对不同架构（x86/x64/ARM/ARM64）使用不同的代码生成策略
2. **上下文嵌入**: 在 trampoline 代码开头直接嵌入 `GumFunctionContext` 指针
3. **统一接口**: 通过 thunk 机制统一调用 C 函数处理 hook 逻辑
4. **线程安全**: 使用原子操作和引用计数确保多线程环境下的安全性
5. **延迟销毁**: 通过 `trampoline_usage_counter` 实现安全的资源管理

### GumFunctionContext 的关键作用

- **状态管理**: 维护 hook 的生命周期状态
- **地址存储**: 保存各种 trampoline 的地址
- **原函数保护**: 保存被覆盖的原函数指令
- **监听器管理**: 管理 JavaScript 层的回调函数
- **引用计数**: 跟踪当前使用情况，确保安全卸载

这个设计体现了 Frida 在处理动态代码插桩时的严谨性和对并发情况的充分考虑。