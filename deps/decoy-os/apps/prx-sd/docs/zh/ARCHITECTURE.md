> 本文档为 [English](../ARCHITECTURE.md) 版本的中文翻译。

# 架构

PRX-SD 采用 Cargo 工作区结构，由多个模块化 crate 组成，每个 crate 负责一个特定的功能领域。

## 工作区布局

```
prx-sd/
├── crates/
│   ├── cli/           # "sd" 二进制程序 — 命令行界面
│   ├── core/          # 扫描引擎协调器
│   ├── signatures/    # 哈希数据库 (LMDB) + YARA-X 规则引擎
│   ├── parsers/       # 二进制格式解析器
│   ├── heuristic/     # 启发式评分 + ML 推理
│   ├── realtime/      # 文件系统监控 + 网络过滤
│   ├── quarantine/    # 加密隔离区
│   ├── remediation/   # 威胁响应处置
│   ├── sandbox/       # 进程隔离 + 行为分析
│   ├── plugins/       # WebAssembly 插件运行时
│   └── updater/       # 签名更新客户端
├── update-server/     # 签名分发服务器 (Axum)
├── gui/               # 桌面 GUI (Tauri 2 + Vue 3)
├── drivers/           # 操作系统内核驱动
│   └── windows-minifilter/  # Windows 文件系统微过滤驱动 (C)
├── signatures-db/     # 内嵌的最小签名集
├── packaging/         # 分发打包
├── tests/             # 集成测试
├── tools/             # 构建和实用脚本
├── install.sh         # 安装脚本
└── uninstall.sh       # 卸载脚本
```

## Crate 依赖关系图

```
cli
 ├── core
 │    ├── signatures
 │    │    └── (heed, yara-x, sha2, md5)
 │    ├── parsers
 │    │    └── (goblin)
 │    └── heuristic
 │         └── (tract-onnx [optional])
 ├── realtime
 │    ├── core
 │    └── (notify, nix [linux], adblock)
 ├── quarantine
 │    └── (aes-gcm, rand)
 ├── remediation
 │    ├── quarantine
 │    └── (nix [unix])
 ├── sandbox
 │    └── (nix [unix])
 ├── plugins
 │    └── (wasmtime, wasmtime-wasi)
 └── updater
      └── (ed25519-dalek, zstd, reqwest)
```

## 检测流水线

扫描引擎（`core`）协调一个多层检测流水线：

```
                    ┌──────────────┐
                    │  文件输入     │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  魔数识别     │  识别：PE、ELF、MachO、
                    │              │  PDF、ZIP、Office、未知
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐    │     ┌──────▼──────┐
       │   哈希匹配   │    │     │   YARA-X    │
       │   (LMDB)    │    │     │    规则      │
       │             │    │     │   (38K+)    │
       └──────┬──────┘    │     └──────┬──────┘
              │     ┌─────▼─────┐      │
              │     │  启发式    │      │
              │     │  分析     │      │
              │     └─────┬─────┘      │
              │           │            │
              │    ┌──────▼──────┐     │
              │    │  ML 推理    │     │
              │    │  (ONNX)    │     │
              │    └──────┬─────┘     │
              │           │            │
              │    ┌──────▼──────┐     │
              │    │ VirusTotal  │     │
              │    │  云端查询   │     │
              │    └──────┬─────┘     │
              │           │            │
              └───────────┼────────────┘
                          │
                   ┌──────▼──────┐
                   │   聚合判定   │
                   └─────────────┘
                   Clean / Suspicious / Malicious
```

### 各层详细说明

1. **哈希匹配** — 在 LMDB 数据库中进行 O(1) 查找，数据库包含来自 ClamAV、abuse.ch、VirusShare 和自定义黑名单的 SHA-256 及 MD5 哈希。

2. **YARA-X 规则** — 使用 YARA-X 引擎（Rust 原生的 YARA 实现）进行模式匹配。规则来源于内嵌的默认规则和外部签名仓库。

3. **启发式分析** — 基于文件类型的特定分析：
   - **PE:** 节熵值、可疑 API 导入（CreateRemoteThread、VirtualAllocEx）、加壳检测（UPX、Themida）、时间戳异常
   - **ELF:** 节熵值、LD_PRELOAD 引用、cron/systemd 持久化、SSH 后门特征
   - **MachO:** 节熵值、dylib 注入、LaunchAgent 持久化、Keychain 访问

4. **ML 推理**（可选，特性标志 `onnx`）— 通过 tract 执行 ONNX 模型评估：
   - PE：64 维特征向量（导入表哈希、节熵值、API 签名）
   - ELF：48 维特征向量（节熵值、符号表、动态库）

5. **VirusTotal 云端查询** — 本地未匹配文件的备用方案。查询 VirusTotal API（免费版：每天 500 次查询），结果缓存至 LMDB。

### 评分机制

- 评分 >= 60：**恶意（Malicious）**
- 评分 30-59：**可疑（Suspicious）**
- 评分 < 30：**安全（Clean）**

最终判定取所有检测层中的最高威胁等级。

## 实时防护

`realtime` crate 通过多个子系统提供持续防护：

| 子系统 | Linux | macOS | Windows |
|--------|-------|-------|---------|
| 文件监控 | fanotify + epoll | FSEvents (notify) | ReadDirectoryChangesW (notify) |
| 进程拦截 | FAN_OPEN_EXEC_PERM | - | Minifilter（计划中） |
| 内存扫描 | /proc/pid/mem | - | - |
| 勒索软件检测 | 写入+重命名模式监控 | 写入+重命名模式监控 | 写入+重命名模式监控 |
| 受保护目录 | ~/.ssh, /etc/shadow, /etc/systemd | ~/Library, /etc | Registry Run keys |
| DNS 过滤 | Adblock 引擎 + IOC 列表 | Adblock 引擎 + IOC 列表 | Adblock 引擎 + IOC 列表 |
| 行为监控 | /proc + audit (execve/connect/open) | - | - |

## 隔离区

文件使用 AES-256-GCM 认证加密进行隔离：

1. 生成随机 256 位密钥 + 96 位随机数（nonce）
2. 使用 AES-256-GCM 加密文件内容
3. 以 UUID 文件名存储加密文件
4. 保存 JSON 元数据（原始路径、哈希值、威胁名称、时间戳）
5. 恢复时先解密并验证完整性，然后再写回

## 修复流水线

当使用 `--remediate` 时：

```
威胁检测
  ├── 1. 终止进程     (Linux/macOS 上使用 SIGKILL，Windows 上使用 TerminateProcess)
  ├── 2. 隔离文件     (AES-256-GCM 加密保险库)
  └── 3. 清除持久化
        ├── Linux:   cron 任务、systemd 服务、LD_PRELOAD
        ├── macOS:   LaunchAgents、plist 条目、Keychain
        └── Windows: Run/RunOnce 注册表、计划任务、服务
```

处置动作可通过 `sd policy set` 配置。

## 签名数据库

### 内嵌签名（`signatures-db/`）

通过 `include_str!` 编译进 `sd` 二进制程序的最小签名集：
- EICAR 测试签名
- 核心 YARA 规则（勒索软件、木马、后门等）
- 已知恶意软件哈希（WannaCry、Emotet、NotPetya）

### 外部签名（[prx-sd-signatures](https://github.com/openprx/prx-sd-signatures)）

全面且频繁更新的威胁情报：
- 来自 9 个来源的 38,800+ 条 YARA 规则
- 来自 abuse.ch 源的哈希黑名单
- IOC 列表：585K+ 恶意 IP、域名、URL

### 存储方式

- **哈希：** LMDB（heed crate），O(1) 键值查找
- **YARA 规则：** 启动时由 YARA-X 加载并编译
- **IOC 列表：** 内存中的 HashSet，用于快速 IP/域名/URL 匹配

## 插件系统

PRX-SD 通过 Wasmtime 支持 WebAssembly 插件：

- 插件为 `.wasm` 文件，附带清单文件（`plugin.json`）
- 支持 WASI，可访问文件系统和环境变量
- 插件注册表用于发现和加载
- 向插件暴露宿主函数，提供扫描结果和配置访问

## 更新系统

`updater` crate 和 `update-server` 提供安全的更新流水线：

1. 客户端向更新服务器检查新的签名版本
2. 服务器响应版本信息和下载 URL
3. 客户端下载 zstd 压缩的签名包
4. 使用 Ed25519（ed25519-dalek）验证包签名
5. 提取签名并加载到 LMDB

## GUI 应用

基于 Tauri 2（Rust 后端）+ Vue 3（TypeScript 前端）构建：

- 系统托盘集成，带状态指示器
- 仪表板，显示威胁统计信息
- 拖拽式文件扫描
- 隔离区浏览器，支持恢复/删除
- 实时监控控制面板
- 设置和配置管理
- 多语言支持（10 种语言）

## 关键依赖

| 分类 | Crate | 版本 | 用途 |
|------|-------|------|------|
| 异步运行时 | tokio | 1.x | 异步运行时 |
| 并行计算 | rayon | - | 扫描线程池 |
| YARA | yara-x | 1.14 | 规则匹配引擎 |
| 数据库 | heed | - | LMDB 绑定 |
| 二进制解析 | goblin | 0.9 | PE/ELF/MachO 解析器 |
| 加密 | aes-gcm | - | 隔离区加密 |
| 加密 | ed25519-dalek | - | 更新验签 |
| 机器学习 | tract-onnx | - | ONNX 推理（可选） |
| WASM | wasmtime | 29 | 插件运行时 |
| DNS | adblock | 0.12 | Brave 广告拦截引擎 |
| CLI | clap | 4.x | 命令行参数解析 |
| HTTP | axum | 0.8 | 更新服务器 |
