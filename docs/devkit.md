# Frida 工具包打包指南

## 概述

本文档介绍如何将编译好的 Frida 组件打包成 tar.xz 格式的工具包。

## releng 目录说明

`/mnt/disk1/huangkai/apnet/frida/releng` 是 **release engineering** 目录，包含构建、打包和发布 Frida 的所有工具：

### 主要脚本
- `setup-env.sh` - 环境配置脚本
- `devkit.py` - 生成开发工具包
- `package-cirrus-ci-artifacts.sh` - 打包 CI 构建产物
- `pkgify.sh` - 包处理脚本

### 配置文件
- `frida.mk`, `frida.props` - 构建配置
- `deps.mk`, `deps.py` - 依赖管理
- `detect-*.sh` - 平台检测脚本

### 其他目录
- `meson/` - Meson 构建系统
- `crosstool-ng/` - 交叉编译工具链
- `devkit-assets/` - 开发工具包资源

## 使用 devkit.py 生成标准开发工具包

### 1. 创建输出目录

```bash
cd /mnt/disk1/huangkai/apnet/frida
mkdir -p build/release-packages
```

### 2. 生成 frida-gum 开发工具包

```bash
python3 releng/devkit.py frida-gum linux-x86_64 build/release-packages/frida-gum-devkit
```

### 3. 生成 frida-core 开发工具包（thin 版本）

```bash
python3 releng/devkit.py frida-core linux-x86_64 build/release-packages/frida-core-devkit -t
```

### 4. 将生成的工具包打包成 tar.xz

```bash
# 打包 frida-gum devkit
cd build/release-packages
tar -cJf frida-gum-devkit-16.1.2-linux-x86_64.tar.xz frida-gum-devkit/

# 打包 frida-core devkit (thin)
tar -cJf frida-core-devkit-16.1.2-linux-x86_64-thin.tar.xz frida-core-devkit/
```

### 5. 验证打包结果

```bash
# 查看生成的文件
ls -lh build/release-packages/*.tar.xz

# 查看包内容（不解压）
tar -tJf build/release-packages/frida-core-16.1.2-devkit-linux-x86_64-thin.tar.xz
```

## devkit.py 参数说明

```
usage: devkit.py [-h] [-t] kit host outdir

positional arguments:
  kit          工具包类型 (frida-gum, frida-gumjs, frida-core)
  host         目标平台 (linux-x86_64, linux-x86, android-arm64等)
  outdir       输出目录

options:
  -h, --help   显示帮助信息
  -t, --thin   生成不包含跨架构支持的 thin 版本
```

## 生成的工具包内容

### frida-gum-devkit 包含：
- `frida-gum.h` - 统一头文件
- `libfrida-gum.a` - 静态库
- `frida-gum-example.c` - 示例代码

### frida-core-devkit (thin) 包含：
- `frida-core.h` - 统一头文件
- `libfrida-core.a` - 静态库  
- `frida-core-example.c` - 示例代码
- `frida-core.gir` - GObject Introspection 文件

## 手动打包方法（备选方案）

如果不想使用 devkit.py，也可以手动打包编译产物：

### 1. 查看编译产物

```bash
# 查看 GUM 编译产物
ls -la build/frida-linux-x86_64/

# 查看 thin 版本 Core 编译产物  
ls -la build/frida_thin-linux-x86_64/
```

### 2. 手动打包 GUM 工具包

```bash
tar -cJf build/release-packages/frida-gum-16.1.2-linux-x86_64.tar.xz \
    -C build/frida-linux-x86_64 \
    bin/gum-graft \
    include/frida-1.0 \
    lib/libfrida-gum*.a \
    lib/libfrida-gumpp*.so \
    lib/pkgconfig/frida-gum*.pc \
    share/vala
```

### 3. 手动打包 thin 版本 Core 工具包

```bash
tar -cJf build/release-packages/frida-core-thin-16.1.2-linux-x86_64.tar.xz \
    -C build/frida_thin-linux-x86_64 \
    bin/frida-server \
    bin/frida-inject \
    bin/frida-portal \
    bin/gum-graft \
    include/frida-1.0 \
    lib/libfrida-*.a \
    lib/libfrida-gumpp*.so \
    lib/pkgconfig \
    lib/frida \
    share/vala
```

## 快速打包脚本

创建一个自动化脚本来执行所有打包步骤：

```bash
#!/bin/bash
cd /mnt/disk1/huangkai/apnet/frida
VERSION="16.1.2"
OUTPUT_DIR="build/release-packages"
mkdir -p "$OUTPUT_DIR"

echo "打包 Frida 工具包..."

# 使用 devkit.py 生成标准开发工具包
python3 releng/devkit.py frida-gum linux-x86_64 "$OUTPUT_DIR/frida-gum-devkit"
python3 releng/devkit.py frida-core linux-x86_64 "$OUTPUT_DIR/frida-core-devkit" -t

# 打包成 tar.xz
echo "正在打包 frida-gum devkit..."
tar -cJf "$OUTPUT_DIR/frida-gum-${VERSION}-devkit-linux-x86_64.tar.xz" -C "$OUTPUT_DIR" frida-gum-devkit/

echo "正在打包 frida-core devkit (thin)..."
tar -cJf "$OUTPUT_DIR/frida-core-${VERSION}-devkit-linux-x86_64-thin.tar.xz" -C "$OUTPUT_DIR" frida-core-devkit/

echo "打包完成！"
ls -lh "$OUTPUT_DIR"/*.tar.xz
```

## 注意事项

1. **使用 devkit.py 生成的是官方标准格式的开发工具包**，更适合分发和二次开发使用
2. **thin 版本** (`-t` 参数) 不包含跨架构支持，体积更小，适合单一平台使用
3. **版本号** 应根据实际编译版本调整，可通过 `build/frida-version.h` 或 `git describe` 获取
4. **平台参数** 常见的选项包括：
   - `linux-x86_64` - Linux 64位
   - `linux-x86` - Linux 32位
   - `linux-arm64` - Linux ARM64
   - `android-arm64` - Android ARM64
   - 等等

## 参考信息

- 当前编译版本：16.1.2
- 编译产物位置：`build/frida-linux-x86_64/` 和 `build/frida_thin-linux-x86_64/`
- 更多平台支持请参考 Makefile 中的目标平台定义
