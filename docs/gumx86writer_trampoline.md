# GumX86Writer 动态代码生成详解

## 目录
- [GumX86Writer 工作原理](#gumx86writer-工作原理)
- [在 Trampoline 中添加自定义代码](#在-trampoline-中添加自定义代码)
- [GumX86Writer 函数指令映射](#gumx86writer-函数指令映射)
- [实际应用示例](#实际应用示例)

---

## GumX86Writer 工作原理

### 核心概念

**GumX86Writer 是 Frida 提供的动态汇编代码生成器**，它允许你在运行时直接生成 x86/x64 机器码，而不需要汇编器或编译器。

### 核心结构

```c
struct _GumX86Writer
{
  volatile gint ref_count;
  gboolean flush_on_destroy;

  GumCpuType target_cpu;    // 目标CPU类型 (GUM_CPU_IA32/GUM_CPU_AMD64)
  GumAbiType target_abi;     // 目标ABI (System V/Microsoft)

  guint8 * base;             // 代码缓冲区基地址
  guint8 * code;             // 当前写入位置指针
  GumAddress pc;             // 当前程序计数器

  GumMetalHashTable * label_defs;   // 标签定义哈希表
  GumMetalArray label_refs;          // 标签引用数组
};
```

### 工作机制

```
高级API调用
    ↓
指令编码 (生成对应机器码字节)
    ↓
内存写入 (直接写入缓冲区)
    ↓
指针更新 (更新 code 和 pc 指针)
    ↓
代码生成完成
```

### 基础使用模式

```c
// 1. 初始化 Writer
GumX86Writer writer;
gum_x86_writer_init(&writer, code_buffer);

// 2. 设置目标CPU和ABI
gum_x86_writer_set_target_cpu(&writer, GUM_CPU_AMD64);
gum_x86_writer_set_target_abi(&writer, GUM_ABI_WINDOWS);

// 3. 生成汇编指令
gum_x86_writer_put_push_reg(&writer, GUM_X86_RAX);
gum_x86_writer_put_mov_reg_u32(&writer, GUM_X86_EAX, 0x12345678);

// 4. 刷新并完成
gum_x86_writer_flush(&writer);
```

---

## 具体实现原理

### 核心函数：`gum_x86_writer_commit`

```c
static void
gum_x86_writer_commit (GumX86Writer * self,
                       guint n)
{
  self->code += n;    // 移动写入位置指针
  self->pc += n;      // 更新程序计数器
}
```

### 基础字节写入

```c
void
gum_x86_writer_put_u8 (GumX86Writer * self,
                       guint8 value)
{
  *self->code = value;           // 直接写入字节到当前位置
  gum_x86_writer_commit (self, 1); // 更新指针
}

void
gum_x86_writer_put_bytes (GumX86Writer * self,
                          const guint8 * data,
                          guint n)
{
  gum_memcpy (self->code, data, n); // 批量写入字节
  gum_x86_writer_commit (self, n);   // 更新指针
}
```

### 复杂指令生成示例

#### 示例 1：生成 `push eax` 指令

```c
gum_x86_writer_put_push_reg(GumX86Writer * self, GumX86Reg reg)
{
  GumX86RegInfo ri;
  
  // 1. 获取寄存器信息 (索引、宽度等)
  gum_x86_writer_describe_cpu_reg(self, reg, &ri);
  
  // 2. 检查寄存器宽度
  if (ri.width != 32)
    return FALSE;
    
  // 3. 生成机器码: 0x50 + reg_index
  self->code[0] = 0x50 + ri.index;  // EAX索引=0 → 0x50
  
  // 4. 更新位置指针
  gum_x86_writer_commit(self, 1);
  
  return TRUE;
}
```

**生成结果：**
```
0x50  ; push eax 的机器码
```

#### 示例 2：生成 `jmp 0x12345678` 指令

```c
gum_x86_writer_put_jmp_address(GumX86Writer * self, GumAddress address)
{
  gint64 distance;
  
  // 1. 计算相对距离
  distance = (gssize)address - (gssize)(self->pc + 2);
  
  // 2. 选择最优编码
  if (GUM_IS_WITHIN_INT8_RANGE(distance))
  {
    // 短跳转: jmp rel8 (0xeb offset) - 2字节
    self->code[0] = 0xeb;
    *((gint8 *)(self->code + 1)) = distance;
    gum_x86_writer_commit(self, 2);
  }
  else
  {
    // 近跳转: jmp rel32 (0xe9 offset) - 5字节
    distance = (gssize)address - (gssize)(self->pc + 5);
    
    if (GUM_IS_WITHIN_INT32_RANGE(distance))
    {
      self->code[0] = 0xe9;
      *((gint32 *)(self->code + 1)) = GINT32_TO_LE((gint32)distance);
      gum_x86_writer_commit(self, 5);
    }
  }
  
  return TRUE;
}
```

**生成结果：**
```
0xe9              ; jmp rel32 操作码
0x73 0x22 0x33 0x12  ; 相对偏移量 (小端序)
```

#### 示例 3：生成 `pushax` (压入所有通用寄存器)

```c
gum_x86_writer_put_pushax(GumX86Writer * self)
{
  if (self->target_cpu == GUM_CPU_IA32)
  {
    // 32位模式: 0x60 是 pusha/pushax 的操作码
    gum_x86_writer_put_u8(self, 0x60);
  }
  else
  {
    // 64位模式: 逐个压入寄存器
    gum_x86_writer_put_push_reg(self, GUM_X86_RAX);
    gum_x86_writer_put_push_reg(self, GUM_X86_RCX);
    gum_x86_writer_put_push_reg(self, GUM_X86_RDX);
    gum_x86_writer_put_push_reg(self, GUM_X86_RBX);
    
    // 处理 RSP 和 R8-R15 (需要特殊处理)
    gum_x86_writer_put_lea_reg_reg_offset(self, GUM_X86_RAX,
        GUM_X86_RSP, 4 * 8);
    gum_x86_writer_put_push_reg(self, GUM_X86_RAX);
    gum_x86_writer_put_mov_reg_reg_offset_ptr(self, GUM_X86_RAX,
        GUM_X86_RSP, 4 * 8);

    gum_x86_writer_put_push_reg(self, GUM_X86_RBP);
    gum_x86_writer_put_push_reg(self, GUM_X86_RSI);
    gum_x86_writer_put_push_reg(self, GUM_X86_RDI);
    gum_x86_writer_put_push_reg(self, GUM_X86_R8);
    gum_x86_writer_put_push_reg(self, GUM_X86_R9);
    gum_x86_writer_put_push_reg(self, GUM_X86_R10);
    gum_x86_writer_put_push_reg(self, GUM_X86_R11);
    gum_x86_writer_put_push_reg(self, GUM_X86_R12);
    gum_x86_writer_put_push_reg(self, GUM_X86_R13);
    gum_x86_writer_put_push_reg(self, GUM_X86_R14);
    gum_x86_writer_put_push_reg(self, GUM_X86_R15);
  }
}
```

**生成结果：**
- **32位:** `0x60` - 单字节 pusha 指令
- **64位:** 一系列 push 指令组合

---

## 在 Trampoline 中添加自定义代码

### 确认答案

**是的，你可以直接使用 gum_x86_writer 函数在 trampoline 中加入自定义代码！**

这正是 Frida 的设计理念。在生成 trampoline 时，你可以在任何位置插入自定义的汇编代码。

### 修改 Trampoline 生成流程

```c
_gum_interceptor_backend_create_trampoline(GumFunctionContext * ctx)
{
  GumX86Writer * cw = &self->writer;
  
  // ... 标准的 trampoline 生成代码 ...
  
  // 在这里插入你的自定义代码！
  gum_x86_writer_put_push_reg(cw, GUM_X86_RAX);
  gum_x86_writer_put_mov_reg_u32(cw, GUM_X86_EAX, 0xDEADBEEF);
  gum_x86_writer_put_pop_reg(cw, GUM_X86_RAX);
  
  // ... 继续标准流程 ...
  
  gum_x86_writer_flush(cw);
}
```

### 实际应用场景

1. **日志记录**：在函数调用前后记录参数和返回值
2. **参数修改**：在函数执行前修改传入参数
3. **返回值篡改**：在函数返回前修改返回值
4. **性能监控**：插入时间测量代码
5. **调试辅助**：插入断点或调试信息

---

## GumX86Writer 函数指令映射

### 数据传输指令

#### MOV 指令系列
```c
// 寄存器到寄存器
gum_x86_writer_put_mov_reg_reg(writer, dst_reg, src_reg);
// 生成: mov dst_reg, src_reg

// 立即数到寄存器
gum_x86_writer_put_mov_reg_u32(writer, reg, imm32);
// 生成: mov reg, imm32

gum_x86_writer_put_mov_reg_u64(writer, reg, imm64);
// 生成: mov reg, imm64 (64位)

// 地址到寄存器
gum_x86_writer_put_mov_reg_address(writer, reg, address);
// 生成: mov reg, address

// 内存到寄存器
gum_x86_writer_put_mov_reg_reg_ptr(writer, dst_reg, src_reg);
// 生成: mov dst_reg, [src_reg]

gum_x86_writer_put_mov_reg_reg_offset_ptr(writer, dst_reg, src_reg, offset);
// 生成: mov dst_reg, [src_reg + offset]

gum_x86_writer_put_mov_reg_base_index_scale_offset_ptr(writer,
    dst_reg, base_reg, index_reg, scale, offset);
// 生成: mov dst_reg, [base_reg + index_reg*scale + offset]

// 寄存器到内存
gum_x86_writer_put_mov_reg_ptr_reg(writer, dst_reg, src_reg);
// 生成: mov [dst_reg], src_reg

gum_x86_writer_put_mov_reg_offset_ptr_reg(writer, dst_reg, offset, src_reg);
// 生成: mov [dst_reg + offset], src_reg

// 立即数到内存
gum_x86_writer_put_mov_reg_ptr_u32(writer, reg, imm32);
// 生成: mov [reg], imm32

gum_x86_writer_put_mov_reg_offset_ptr_u32(writer, reg, offset, imm32);
// 生成: mov [reg + offset], imm32

// 段寄存器访问
gum_x86_writer_put_mov_fs_u32_ptr_reg(writer, fs_offset, reg);
// 生成: mov reg, fs:[fs_offset]

gum_x86_writer_put_mov_reg_fs_u32_ptr(writer, reg, fs_offset);
// 生成: mov fs:[fs_offset], reg
```

#### LEA 指令
```c
gum_x86_writer_put_lea_reg_reg_offset(writer, dst_reg, src_reg, offset);
// 生成: lea dst_reg, [src_reg + offset]
```

#### XCHG 指令
```c
gum_x86_writer_put_xchg_reg_reg_ptr(writer, reg, mem_reg);
// 生成: xchg reg, [mem_reg]
```

### 栈操作指令

#### PUSH 指令系列
```c
// 压入寄存器
gum_x86_writer_put_push_reg(writer, reg);
// 生成: push reg

// 压入立即数
gum_x86_writer_put_push_u32(writer, imm32);
// 生成: push imm32

// 压入内存地址
gum_x86_writer_put_push_near_ptr(writer, address);
// 生成: push address

// 压入指针
gum_x86_writer_put_push_imm_ptr(writer, ptr);
// 生成: push ptr

// 压入所有通用寄存器
gum_x86_writer_put_pushax(writer);
// 生成: pusha (32位) 或一系列push (64位)

// 压入标志寄存器
gum_x86_writer_put_pushfx(writer);
// 生成: pushf
```

#### POP 指令系列
```c
// 弹出到寄存器
gum_x86_writer_put_pop_reg(writer, reg);
// 生成: pop reg

// 弹出所有通用寄存器
gum_x86_writer_put_popax(writer);
// 生成: popa (32位) 或一系列pop (64位)

// 弹出标志寄存器
gum_x86_writer_put_popfx(writer);
// 生成: popf
```

### 算术指令

#### ADD 指令系列
```c
gum_x86_writer_put_add_reg_imm(writer, reg, imm_value);
// 生成: add reg, imm_value

gum_x86_writer_put_add_reg_reg(writer, dst_reg, src_reg);
// 生成: add dst_reg, src_reg

gum_x86_writer_put_add_reg_near_ptr(writer, reg, address);
// 生成: add reg, [address]
```

#### SUB 指令系列
```c
gum_x86_writer_put_sub_reg_imm(writer, reg, imm_value);
// 生成: sub reg, imm_value

gum_x86_writer_put_sub_reg_reg(writer, dst_reg, src_reg);
// 生成: sub dst_reg, src_reg

gum_x86_writer_put_sub_reg_near_ptr(writer, reg, address);
// 生成: sub reg, [address]
```

#### INC/DEC 指令
```c
gum_x86_writer_put_inc_reg(writer, reg);
// 生成: inc reg

gum_x86_writer_put_dec_reg(writer, reg);
// 生成: dec reg

gum_x86_writer_put_inc_reg_ptr(writer, target, reg);
// 生成: inc [reg]

gum_x86_writer_put_dec_reg_ptr(writer, target, reg);
// 生成: dec [reg]
```

#### 逻辑运算指令
```c
gum_x86_writer_put_and_reg_reg(writer, dst_reg, src_reg);
// 生成: and dst_reg, src_reg

gum_x86_writer_put_and_reg_u32(writer, reg, imm32);
// 生成: and reg, imm32

gum_x86_writer_put_xor_reg_reg(writer, dst_reg, src_reg);
// 生成: xor dst_reg, src_reg

gum_x86_writer_put_shl_reg_u8(writer, reg, imm8);
// 生成: shl reg, imm8

gum_x86_writer_put_shr_reg_u8(writer, reg, imm8);
// 生成: shr reg, imm8
```

### 控制流指令

#### JMP 指令系列
```c
// 跳转到绝对地址
gum_x86_writer_put_jmp_address(writer, address);
// 生成: jmp address (自动选择最优编码)

// 跳转到寄存器
gum_x86_writer_put_jmp_reg(writer, reg);
// 生成: jmp reg

// 跳转到内存地址
gum_x86_writer_put_jmp_reg_ptr(writer, reg);
// 生成: jmp [reg]

gum_x86_writer_put_jmp_reg_offset_ptr(writer, reg, offset);
// 生成: jmp [reg + offset]

// 跳转到标签
gum_x86_writer_put_jmp_short_label(writer, label_id);
// 生成: jmp short label_id

gum_x86_writer_put_jmp_near_label(writer, label_id);
// 生成: jmp near label_id
```

#### CALL 指令系列
```c
// 调用绝对地址
gum_x86_writer_put_call_address(writer, address);
// 生成: call address

// 调用寄存器
gum_x86_writer_put_call_reg(writer, reg);
// 生成: call reg

// 调用内存地址
gum_x86_writer_put_call_reg_offset_ptr(writer, reg, offset);
// 生成: call [reg + offset]

// 调用函数（带参数）
gum_x86_writer_put_call_address_with_arguments(writer,
    convention, func_addr, num_args, ...);
// 生成: 参数设置 + call func_addr

gum_x86_writer_put_call_address_with_aligned_arguments(writer,
    convention, func_addr, num_args, ...);
// 生成: 对齐的参数设置 + call func_addr
```

#### RET 指令系列
```c
gum_x86_writer_put_ret(writer);
// 生成: ret

gum_x86_writer_put_ret_imm(writer, imm16);
// 生成: ret imm16
```

#### 条件跳转指令
```c
gum_x86_writer_put_jcc_short(writer, insn_id, target, hint);
// 生成: jcc short target

gum_x86_writer_put_jcc_near(writer, insn_id, target, hint);
// 生成: jcc near target

gum_x86_writer_put_jcc_short_label(writer, insn_id, label_id, hint);
// 生成: jcc short label_id

gum_x86_writer_put_jcc_near_label(writer, insn_id, label_id, hint);
// 生成: jcc near label_id
```

### 比较和测试指令

#### CMP 指令系列
```c
gum_x86_writer_put_cmp_reg_i32(writer, reg, imm32);
// 生成: cmp reg, imm32

gum_x86_writer_put_cmp_reg_reg(writer, reg_a, reg_b);
// 生成: cmp reg_a, reg_b

gum_x86_writer_put_cmp_reg_offset_ptr_reg(writer, reg_a, offset, reg_b);
// 生成: cmp [reg_a + offset], reg_b
```

#### TEST 指令系列
```c
gum_x86_writer_put_test_reg_reg(writer, reg_a, reg_b);
// 生成: test reg_a, reg_b

gum_x86_writer_put_test_reg_u32(writer, reg, imm32);
// 生成: test reg, imm32
```

### 标志位指令

```c
gum_x86_writer_put_clc(writer);     // 清除进位标志: clc
gum_x86_writer_put_stc(writer);     // 设置进位标志: stc
gum_x86_writer_put_cld(writer);     // 清除方向标志: cld
gum_x86_writer_put_std(writer);     // 设置方向标志: std
gum_x86_writer_put_sahf(writer);    // SAHF: 加载AH到标志寄存器
gum_x86_writer_put_lahf(writer);    // LAHF: 加载标志寄存器到AH
```

### 特殊指令

```c
gum_x86_writer_put_nop(writer);         // 空操作: nop
gum_x86_writer_put_breakpoint(writer);  // 断点: int3
gum_x86_writer_put_cpuid(writer);       // CPUID: cpuid
gum_x86_writer_put_rdtsc(writer);       // RDTSC: rdtsc
gum_x86_writer_put_pause(writer);       // PAUSE: pause
gum_x86_writer_put_lfence(writer);      // LFENCE: lfence

// 浮点寄存器保存/恢复
gum_x86_writer_put_fxsave_reg_ptr(writer, reg);
// 生成: fxsave [reg]

gum_x86_writer_put_fxrstor_reg_ptr(writer, reg);
// 生成: fxrstor [reg]
```

### 原子操作指令

```c
gum_x86_writer_put_lock_xadd_reg_ptr_reg(writer, dst_reg, src_reg);
// 生成: lock xadd [dst_reg], src_reg

gum_x86_writer_put_lock_cmpxchg_reg_ptr_reg(writer, dst_reg, src_reg);
// 生成: lock cmpxchg [dst_reg], src_reg

gum_x86_writer_put_lock_inc_imm32_ptr(writer, target);
// 生成: lock inc [target]

gum_x86_writer_put_lock_dec_imm32_ptr(writer, target);
// 生成: lock dec [target]
```

### 辅助函数

```c
// 标签操作
gum_x86_writer_put_label(writer, label_id);
// 定义标签位置

// 内存填充
gum_x86_writer_put_padding(writer, n);
// 用随机字节填充 n 字节

gum_x86_writer_put_nop_padding(writer, n);
// 用 NOP 指令填充 n 字节

// 原始字节写入
gum_x86_writer_put_u8(writer, value);
gum_x86_writer_put_s8(writer, value);
gum_x86_writer_put_bytes(writer, data, n);
```

### 寄存器枚举

```c
// 32位寄存器
GUM_X86_EAX, GUM_X86_ECX, GUM_X86_EDX, GUM_X86_EBX,
GUM_X86_ESP, GUM_X86_EBP, GUM_X86_ESI, GUM_X86_EDI,
GUM_X86_EIP

// 64位寄存器
GUM_X86_RAX, GUM_X86_RCX, GUM_X86_RDX, GUM_X86_RBX,
GUM_X86_RSP, GUM_X86_RBP, GUM_X86_RSI, GUM_X86_RDI,
GUM_X86_R8, GUM_X86_R9, GUM_X86_R10, GUM_X86_R11,
GUM_X86_R12, GUM_X86_R13, GUM_X86_R14, GUM_X86_R15,
GUM_X86_RIP

// 元寄存器 (自动适配位宽)
GUM_X86_XAX, GUM_X86_XCX, GUM_X86_XDX, GUM_X86_XBX,
GUM_X86_XSP, GUM_X86_XBP, GUM_X86_XSI, GUM_X86_XDI,
GUM_X86_XIP
```

---

## 实际应用示例

### 示例 1：在 Trampoline 中添加日志记录

```c
// 在函数入口处添加自定义代码
void add_custom_logging_to_trampoline(GumX86Writer * cw)
{
  // 保存所有寄存器
  gum_x86_writer_put_pushax(cw);
  gum_x86_writer_put_pushfx(cw);
  
  // 调用日志函数
  gum_x86_writer_put_lea_reg_reg_offset(cw, GUM_X86_XCX,
      GUM_X86_XSP, 8);  // 获取原始函数参数
  
  gum_x86_writer_put_call_address_with_arguments(cw,
      GUM_CALL_CAPI,
      GUM_ADDRESS(log_function_entry), 2,
      GUM_ARG_REGISTER, GUM_X86_XBX,      // function_ctx
      GUM_ARG_REGISTER, GUM_X86_XCX);     // parameter
  
  // 恢复寄存器
  gum_x86_writer_put_popfx(cw);
  gum_x86_writer_put_popax(cw);
}
```

### 示例 2：修改函数参数

```c
void modify_function_argument(GumX86Writer * cw)
{
  // 修改第一个参数 (假设在 ecx/rcx 中)
  gum_x86_writer_put_mov_reg_u32(cw, GUM_X86_ECX, 0x12345678);
  
  // 或者修改栈上的参数
  gum_x86_writer_put_mov_reg_u32(cw, GUM_X86_EAX, 0x12345678);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(cw, GUM_X86_XSP, 4, GUM_X86_EAX);
}
```

### 示例 3：插入性能监控代码

```c
void add_performance_monitoring(GumX86Writer * cw)
{
  // 读取时间戳计数器
  gum_x86_writer_put_push_reg(cw, GUM_X86_RAX);
  gum_x86_writer_put_push_reg(cw, GUM_X86_RDX);
  
  gum_x86_writer_put_rdtsc(cw);  // rdtsc 指令
  
  // 保存结果到指定位置
  gum_x86_writer_put_mov_reg_near_ptr(cw, GUM_X86_RAX, 
      GUM_ADDRESS(&start_time));
  gum_x86_writer_put_mov_reg_near_ptr(cw, GUM_X86_RDX,
      GUM_ADDRESS(&start_time + 4));
  
  gum_x86_writer_put_pop_reg(cw, GUM_X86_RDX);
  gum_x86_writer_put_pop_reg(cw, GUM_X86_RAX);
}
```

### 示例 4：条件分支和标签

```c
void add_conditional_logic(GumX86Writer * cw)
{
  gint skip_label = 0x1000;
  
  // 检查 eax 是否为 0
  gum_x86_writer_put_test_reg_u32(cw, GUM_X86_EAX, 0);
  
  // 如果为 0，跳转到 skip_label
  gum_x86_writer_put_jcc_short_label(cw, X86_INS_JZ, skip_label, GUM_BRANCH_HINT_NONE);
  
  // 非零情况的处理
  gum_x86_writer_put_mov_reg_u32(cw, GUM_X86_EAX, 1);
  
  // 定义标签
  gum_x86_writer_put_label(cw, skip_label);
  
  // 继续执行...
  gum_x86_writer_put_ret(cw);
}
```

### 示例 5：内存操作

```c
void add_memory_operations(GumX86Writer * cw)
{
  // 从内存读取数据到寄存器
  gum_x86_writer_put_mov_reg_reg_offset_ptr(cw,
      GUM_X86_EAX, GUM_X86_XBX, 0x10);  // mov eax, [ebx + 0x10]
  
  // 修改内存数据
  gum_x86_writer_put_mov_reg_u32(cw, GUM_X86_ECX, 0xDEADBEEF);
  gum_x86_writer_put_mov_reg_offset_ptr_reg(cw,
      GUM_X86_XBX, 0x10, GUM_X86_ECX);  // mov [ebx + 0x10], ecx
  
  // 原子操作
  gum_x86_writer_put_lock_inc_imm32_ptr(cw,
      GUM_ADDRESS(&global_counter));  // lock inc [global_counter]
}
```

---

## 关键设计特点

### 1. 分层设计
```
高级API (put_jmp_address)
    ↓
中级API (put_u8, put_bytes)
    ↓
底层写入 (*self->code = value)
    ↓
commit (更新指针)
```

### 2. 自动优化
- **跳转指令**：自动选择最短编码（短跳转/近跳转）
- **寄存器选择**：根据目标CPU自动选择最优指令
- **内存对齐**：自动处理对齐要求

### 3. 位置无关
- 使用相对寻址而非绝对地址
- 支持标签和符号引用
- 自动重定位

### 4. 跨平台支持
- 自动适配 32/64 位模式
- 支持不同调用约定
- 处理不同操作系统的差异

---

## 注意事项

1. **内存权限**：确保目标内存区域具有可执行权限
2. **缓冲区大小**：预留足够空间存放生成的代码
3. **调用约定**：注意不同平台的调用约定差异
4. **栈对齐**：在调用函数前保持栈对齐
5. **寄存器保护**：及时保存和恢复寄存器状态
6. **错误处理**：检查函数返回值，处理失败情况

---

## 总结

`GumX86Writer` 是一个强大而灵活的动态代码生成工具，它通过直接操作内存来生成机器码，提供了从高级抽象到低级字节写入的完整接口。在 Frida 的 trampoline 生成中，你可以使用这些函数在任何位置插入自定义代码，实现各种复杂的插桩和监控功能。

通过理解其工作原理和掌握可用的函数接口，你可以构建出功能强大且高效的动态二进制分析工具。
