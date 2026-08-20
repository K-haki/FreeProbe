# Frida Trampoline 代码生成详解

## 代码位置

**主要文件：** `/mnt/disk1/huangkai/apnet/frida/frida-gum/gum/backend-x86/guminterceptor-x86.c`

**关键函数：**
- `_gum_interceptor_backend_create_trampoline` (167-225行)
- `gum_emit_enter_thunk` (321-342行)
- `gum_emit_leave_thunk` (345-363行)
- `gum_emit_prolog` / `gum_emit_epilog` (366-419行)

---

## Trampoline 生成流程

### 1. 初始化阶段

```c
// 创建后端时生成全局的 enter_thunk 和 leave_thunk
_gum_interceptor_backend_create()
  → gum_interceptor_backend_create_thunks()
```

### 2. 为每个被拦截函数创建 Trampoline

```c
_gum_interceptor_backend_create_trampoline(function_ctx)
```

### 3. Trampoline 内存布局

```
+---------------------------+
| function_ctx_ptr          |  指向函数上下文的指针
+---------------------------+
| on_enter_trampoline:      |  入口trampoline
|   push function_ctx_ptr   |
|   jmp enter_thunk         |
+---------------------------+
| on_leave_trampoline:      |  退出trampoline
|   push function_ctx_ptr   |
|   jmp leave_thunk         |
+---------------------------+
| on_invoke_trampoline:     |  执行trampoline
|   [重定位的原始指令]       |
|   jmp 原函数剩余部分       |
+---------------------------+
```

---

## 核心代码详解

### Enter Thunk 生成

```c
static void gum_emit_enter_thunk(GumX86Writer * cw)
{
  // 1. 设置栈帧
  gum_emit_prolog(cw, 0);

  // 2. 设置参数
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_XSI,
      GUM_X86_XBP, GUM_FRAME_OFFSET_CPU_CONTEXT);  // 参数2: cpu_context
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_XDX,
      GUM_X86_XBP, GUM_FRAME_OFFSET_TOP);          // 参数3: caller_ret_addr
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_XCX,
      GUM_X86_XBP, GUM_FRAME_OFFSET_NEXT_HOP);     // 参数4: next_hop

  // 3. 调用核心函数
  gum_x86_writer_put_call_address_with_aligned_arguments(cw,
      GUM_ADDRESS(_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, GUM_X86_XBX,  // 参数1: function_ctx
      GUM_ARG_REGISTER, GUM_X86_XSI,  // 参数2: cpu_context
      GUM_ARG_REGISTER, GUM_X86_XDX,  // 参数3: caller_ret_addr
      GUM_ARG_REGISTER, GUM_X86_XCX);// 参数4: next_hop

  // 4. 恢复栈帧
  gum_emit_epilog(cw);
}
```

### Leave Thunk 生成

```c
static void gum_emit_leave_thunk(GumX86Writer * cw)
{
  const gssize next_hop_stack_displacement = -((gssize) sizeof (gpointer));

  gum_emit_prolog(cw, next_hop_stack_displacement);

  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_XSI,
      GUM_X86_XBP, GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_XDX,
      GUM_X86_XBP, GUM_FRAME_OFFSET_NEXT_HOP);

  gum_x86_writer_put_call_address_with_aligned_arguments(cw, GUM_CALL_CAPI,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, GUM_X86_XBX,
      GUM_ARG_REGISTER, GUM_X86_XSI,
      GUM_ARG_REGISTER, GUM_X86_XDX);

  gum_emit_epilog(cw);
}
```

### Prolog 栈帧设置

```c
static void gum_emit_prolog(GumX86Writer * cw, gssize stack_displacement)
{
  /*
   * 栈帧布局：
   * [next_hop]           <-- 调用前已push
   * [cpu_flags]          <-- pushfx
   * [cpu_context]        <-- pushax (所有通用寄存器)
   * [alignment_padding]
   * [extended_context]   <-- fxsave区域
   */

  gum_x86_writer_put_pushfx(cw);           // 保存标志寄存器
  gum_x86_writer_put_cld(cw);              // C ABI要求
  gum_x86_writer_put_pushax(cw);           // 保存所有通用寄存器
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_XSP,
      GUM_X86_XSP, -sizeof(gpointer));     // 为xip预留空间

  // 修正栈指针
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_XAX,
      GUM_X86_XSP, GUM_FRAME_OFFSET_TOP + stack_displacement);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(cw,
      GUM_X86_XSP, GUM_CPU_CONTEXT_OFFSET_XSP, GUM_X86_XAX);

  // 设置帧指针和对齐
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw, GUM_X86_XBX,
      GUM_X86_XSP, GUM_FRAME_OFFSET_NEXT_HOP);
  gum_x86_writer_put_mov_reg_reg(cw, GUM_X86_XBP, GUM_X86_XSP);
  gum_x86_writer_put_and_reg_u32(cw, GUM_X86_XSP, ~(16-1)); // 16字节对齐
  gum_x86_writer_put_sub_reg_imm(cw, GUM_X86_XSP, 512);     // 分配fxsave空间
  gum_x86_writer_put_bytes(cw, fxsave, sizeof(fxsave));    // 保存浮点寄存器
}
```

### Epilog 栈帧恢复

```c
static void gum_emit_epilog(GumX86Writer * cw)
{
  guint8 fxrstor[] = {
    0x0f, 0xae, 0x0c, 0x24 /* fxrstor [esp] */
  };

  gum_x86_writer_put_bytes(cw, fxrstor, sizeof(fxrstor)); // 恢复浮点寄存器
  gum_x86_writer_put_mov_reg_reg(cw, GUM_X86_XSP, GUM_X86_XBP); // 恢复栈指针
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_XSP,
      GUM_X86_XSP, sizeof(gpointer));          // 丢弃xip
  gum_x86_writer_put_popax(cw);                // 恢复通用寄存器
  gum_x86_writer_put_popfx(cw);                // 恢复标志寄存器
  gum_x86_writer_put_ret(cw);                  // 返回
}
```

---

## Trampoline 创建函数

```c
_gum_interceptor_backend_create_trampoline(GumFunctionContext * ctx)
{
  GumX86Writer * cw = &self->writer;
  GumX86Relocator * rl = &self->relocator;
  guint reloc_bytes;

  // 1. 准备trampoline内存
  if (!gum_interceptor_backend_prepare_trampoline(self, ctx))
    return FALSE;

  gum_x86_writer_reset(cw, ctx->trampoline_slice->data);

  if (ctx->type != GUM_INTERCEPTOR_TYPE_FAST)
  {
    // 2. 写入function_ctx指针
    function_ctx_ptr = GUM_ADDRESS(gum_x86_writer_cur(cw));
    gum_x86_writer_put_bytes(cw, (guint8 *) &ctx,
        sizeof(GumFunctionContext *));

    // 3. 生成on_enter_trampoline
    ctx->on_enter_trampoline = gum_x86_writer_cur(cw);
    gum_x86_writer_put_push_near_ptr(cw, function_ctx_ptr);
    gum_x86_writer_put_jmp_address(cw, GUM_ADDRESS(self->enter_thunk->data));

    // 4. 生成on_leave_trampoline
    ctx->on_leave_trampoline = gum_x86_writer_cur(cw);
    gum_x86_writer_put_push_near_ptr(cw, function_ctx_ptr);
    gum_x86_writer_put_jmp_address(cw, GUM_ADDRESS(self->leave_thunk->data));

    gum_x86_writer_flush(cw);
  }

  // 5. 生成on_invoke_trampoline（重定位原始指令）
  ctx->on_invoke_trampoline = gum_x86_writer_cur(cw);
  gum_x86_relocator_reset(rl, (guint8 *) ctx->function_address, cw);

  // 6. 读取足够的原始指令
  do
  {
    reloc_bytes = gum_x86_relocator_read_one(rl, NULL);
    g_assert(reloc_bytes != 0);
  }
  while (reloc_bytes < data->redirect_code_size);

  // 7. 写入重定位后的指令
  gum_x86_relocator_write_all(rl);

  // 8. 如果没有到达指令边界，跳回原函数
  if (!gum_x86_relocator_eoi(rl))
  {
    gum_x86_writer_put_jmp_address(cw,
        GUM_ADDRESS(ctx->function_address) + reloc_bytes);
  }

  gum_x86_writer_flush(cw);

  // 9. 保存被覆盖的原始指令
  ctx->overwritten_prologue_len = reloc_bytes;
  gum_memcpy(ctx->overwritten_prologue, ctx->function_address, reloc_bytes);

  return TRUE;
}
```

---

## 栈帧偏移量定义

```c
#define GUM_FRAME_OFFSET_CPU_CONTEXT 0
#define GUM_FRAME_OFFSET_CPU_FLAGS \
    (GUM_FRAME_OFFSET_CPU_CONTEXT + sizeof(GumCpuContext))
#define GUM_FRAME_OFFSET_NEXT_HOP \
    (GUM_FRAME_OFFSET_CPU_FLAGS + sizeof(gpointer))
#define GUM_FRAME_OFFSET_TOP \
    (GUM_FRAME_OFFSET_NEXT_HOP + sizeof(gpointer))
```

---

## Trampoline 激活过程

```c
_gum_interceptor_backend_activate_trampoline()
{
  GumX86Writer * cw = &self->writer;
  guint padding;

  gum_x86_writer_reset(cw, prologue);
  cw->pc = GPOINTER_TO_SIZE(ctx->function_address);

  if (ctx->type == GUM_INTERCEPTOR_TYPE_FAST)
  {
    // 快速模式：直接跳转到替换函数
    gum_x86_writer_put_jmp_address(cw,
        GUM_ADDRESS(ctx->replacement_function));
  }
  else
  {
    // 标准模式：跳转到on_enter_trampoline
    gum_x86_writer_put_jmp_address(cw,
        GUM_ADDRESS(ctx->on_enter_trampoline));
  }

  gum_x86_writer_flush(cw);

  // 填充剩余空间为NOP
  padding = ctx->overwritten_prologue_len - gum_x86_writer_offset(cw);
  gum_x86_writer_put_nop_padding(cw, padding);
  gum_x86_writer_flush(cw);
}
```

---

## 执行流程图

```
原函数调用
  ↓
[jmp on_enter_trampoline]  ← 原函数开头被覆盖为跳转指令
  ↓
push function_ctx_ptr
jmp enter_thunk
  ↓
enter_thunk:
  - pushfx (保存标志寄存器)
  - pushax (保存所有通用寄存器)
  - fxsave (保存浮点寄存器状态)
  - 设置调用栈帧
  ↓
调用 _gum_function_context_begin_invocation
  参数1: function_ctx (在ebx中)
  参数2: cpu_context (栈帧指针)
  参数3: caller_ret_addr (栈帧指针)
  参数4: next_hop (栈帧指针)
  ↓
根据 next_hop 跳转：
  - replacement_function (如果有替换函数)
  - on_invoke_trampoline (执行原始函数)
  ↓
on_invoke_trampoline:
  - 执行重定位的原始指令
  - jmp 原函数剩余部分
  ↓
原函数执行完成，返回到 on_leave_trampoline (如果设置了)
  ↓
leave_thunk:
  - 调用 _gum_function_context_end_invocation
  - 恢复所有寄存器状态
  - 跳转到原始返回地址
```

---

## 关键技术点

1. **动态代码生成**：使用 `GumX86Writer` 动态生成机器码
2. **指令重定位**：使用 `GumX86Relocator` 处理位置相关指令
3. **栈帧管理**：精心设计的栈帧布局，保存和恢复CPU状态
4. **上下文传递**：通过 function_ctx 指针传递拦截相关数据
5. **跳转优化**：使用相对跳转指令减少代码大小

这个设计实现了高效的函数拦截机制，通过动态生成机器码来接管函数执行流程，同时保证了原始函数的正确执行。
