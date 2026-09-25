> 本文档为 [English](../CLI.md) 版本的中文翻译。

# CLI 参考手册

PRX-SD 提供 `sd` 命令行工具，用于威胁检测和系统防护。

## 全局选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `--log-level <LEVEL>` | 日志详细程度：`trace`、`debug`、`info`、`warn`、`error` | `warn` |
| `--data-dir <PATH>` | 签名、隔离区、配置的数据目录 | `~/.prx-sd/` |

---

## 扫描

### `sd scan <PATH>`

扫描文件或目录中的威胁。

```bash
sd scan /path/to/file
sd scan /home --recursive
sd scan /tmp --auto-quarantine --remediate
sd scan /path --json
sd scan /path --report report.html
```

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `-r, --recursive <BOOL>` | 递归扫描子目录 | 对目录默认为 `true` |
| `--json` | 以 JSON 格式输出结果 | |
| `-t, --threads <NUM>` | 扫描线程数 | CPU 核心数 |
| `--auto-quarantine` | 自动隔离恶意文件 | |
| `--remediate` | 自动修复：终止进程、隔离文件、清除持久化机制 | |
| `-e, --exclude <PATTERN>` | 排除的 glob 模式（可重复使用） | |
| `--report <PATH>` | 导出结果为独立的 HTML 报告 | |

### `sd scan-memory`

扫描运行中进程的内存以检测威胁（仅限 Linux，需要 root 权限）。

```bash
sudo sd scan-memory
sudo sd scan-memory --pid 1234
sudo sd scan-memory --json
```

| 选项 | 说明 |
|------|------|
| `--pid <PID>` | 扫描特定进程（省略则扫描全部进程） |
| `--json` | 以 JSON 格式输出 |

### `sd scan-usb [DEVICE]`

扫描 USB/可移动设备。

```bash
sd scan-usb
sd scan-usb /dev/sdb1 --auto-quarantine
```

| 选项 | 说明 |
|------|------|
| `--auto-quarantine` | 自动隔离检测到的威胁 |

### `sd check-rootkit`

检查 rootkit 指标（仅限 Linux）。

```bash
sudo sd check-rootkit
sudo sd check-rootkit --json
```

检查项：隐藏进程、内核模块完整性、LD_PRELOAD 钩子、/proc 异常。

---

## 实时防护

### `sd monitor <PATHS...>`

实时文件系统监控。

```bash
sd monitor /home /tmp
sd monitor /home --block
sd monitor /home --daemon
```

| 选项 | 说明 |
|------|------|
| `--block` | 在文件被访问前拦截恶意文件（Linux 下需要 root 权限和 fanotify） |
| `--daemon` | 以后台守护进程运行 |

### `sd daemon [PATHS...]`

以后台守护进程运行，提供实时监控和自动更新。

```bash
sd daemon
sd daemon /home /tmp --update-hours 2
```

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `--update-hours <NUM>` | 签名更新检查间隔（小时） | `4` |

默认监控路径：`/home`、`/tmp`。

---

## 隔离区管理

### `sd quarantine <SUBCOMMAND>`

管理加密隔离区（AES-256-GCM）。

```bash
sd quarantine list
sd quarantine restore <ID>
sd quarantine restore <ID> --to /safe/path
sd quarantine delete <ID>
sd quarantine delete-all --yes
sd quarantine stats
```

| 子命令 | 说明 |
|--------|------|
| `list` | 列出所有被隔离的文件 |
| `restore <ID>` | 恢复隔离文件（使用 `--to <PATH>` 指定替代位置） |
| `delete <ID>` | 永久删除隔离文件 |
| `delete-all` | 删除所有隔离文件（使用 `--yes` 跳过确认） |
| `stats` | 显示隔离区统计信息 |

---

## 签名数据库

### `sd update`

检查并应用签名数据库更新。

```bash
sd update
sd update --check-only
sd update --force
sd update --server-url https://custom-server.example.com
```

| 选项 | 说明 |
|------|------|
| `--check-only` | 仅检查是否有可用更新 |
| `--force` | 即使已是最新版本也强制重新下载 |
| `--server-url <URL>` | 覆盖更新服务器 URL |

### `sd import <PATH>`

从黑名单文件导入哈希签名。

```bash
sd import /path/to/blocklist.txt
```

文件格式：每行一条记录，格式为 `hex_hash malware_name`。以 `#` 开头的行为注释。

```
# Example blocklist
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR.Test
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa Ransom.WannaCry
```

### `sd import-clamav <PATHS...>`

导入 ClamAV 签名数据库文件。

```bash
sd import-clamav main.cvd daily.cvd
sd import-clamav custom.hdb custom.hsb
```

支持格式：`.cvd`、`.cld`、`.hdb`、`.hsb`。

### `sd info`

显示引擎版本、签名数据库状态和系统信息。

```bash
sd info
```

显示内容：版本号、YARA 规则数量、哈希签名数量、隔离区统计、平台信息。

---

## 配置

### `sd config <SUBCOMMAND>`

管理引擎配置。

```bash
sd config show
sd config set scan.max_file_size 104857600
sd config set scan.follow_symlinks true
sd config reset
```

| 子命令 | 说明 |
|--------|------|
| `show` | 显示当前配置 |
| `set <KEY> <VALUE>` | 设置配置项（使用点分隔的路径） |
| `reset` | 重置为默认配置 |

值支持 JSON 类型：布尔值（`true`/`false`）、数字、`null`、数组、对象。

---

## 修复策略

### `sd policy <ACTION> [KEY] [VALUE]`

管理威胁修复策略。

```bash
sd policy show
sd policy set on_malicious "kill,quarantine,clean"
sd policy set on_suspicious "report,quarantine"
sd policy set kill_processes true
sd policy reset
```

| 操作 | 说明 |
|------|------|
| `show` | 显示当前策略 |
| `set <KEY> <VALUE>` | 设置策略字段 |
| `reset` | 重置为默认策略 |

**策略键：**

| 键 | 说明 | 可选值 |
|----|------|--------|
| `on_malicious` | 针对恶意威胁的处置动作 | 逗号分隔：`report`、`quarantine`、`block`、`kill`、`clean`、`delete`、`isolate`、`blocklist` |
| `on_suspicious` | 针对可疑威胁的处置动作 | 同上 |
| `kill_processes` | 终止关联进程 | `true` / `false` |
| `clean_persistence` | 清除持久化机制 | `true` / `false` |
| `network_isolation` | 隔离网络连接 | `true` / `false` |
| `audit_logging` | 将所有操作记录到审计日志 | `true` / `false` |

---

## 定时任务

### `sd schedule <SUBCOMMAND>`

管理定时扫描任务。使用平台原生调度器：systemd timers（Linux）、cron（Linux/macOS）、launchd（macOS）、Task Scheduler（Windows）。

```bash
sd schedule add /home --frequency daily
sd schedule add /tmp --frequency hourly
sd schedule status
sd schedule remove
```

| 子命令 | 说明 |
|--------|------|
| `add <PATH>` | 注册周期性定时扫描 |
| `remove` | 移除定时扫描任务 |
| `status` | 显示当前调度状态 |

**频率选项：** `hourly`、`4h`、`12h`、`daily`、`weekly`（默认：`weekly`）。

---

## 告警

### `sd webhook <SUBCOMMAND>`

管理 Webhook 告警端点。

```bash
sd webhook list
sd webhook add my-slack https://hooks.slack.com/services/... --format slack
sd webhook add my-discord https://discord.com/api/webhooks/... --format discord
sd webhook add custom https://example.com/alert --format generic
sd webhook remove my-slack
sd webhook test
```

| 子命令 | 说明 |
|--------|------|
| `list` | 列出已配置的 Webhook |
| `add <NAME> <URL>` | 添加 Webhook（`--format`：`slack`、`discord`、`generic`） |
| `remove <NAME>` | 按名称移除 Webhook |
| `test` | 向所有 Webhook 发送测试告警 |

### `sd email-alert <SUBCOMMAND>`

管理邮件告警配置。

```bash
sd email-alert configure
sd email-alert test
sd email-alert send "Trojan.Generic" "high" "/tmp/malware.exe"
```

| 子命令 | 说明 |
|--------|------|
| `configure` | 创建或查看 SMTP 邮件配置 |
| `test` | 发送测试告警邮件 |
| `send <NAME> <LEVEL> <PATH>` | 发送自定义告警邮件 |

---

## DNS 与网络过滤

### `sd adblock <SUBCOMMAND>`

管理广告拦截和恶意域名过滤。

```bash
sd adblock enable
sd adblock disable
sd adblock sync
sd adblock stats
sd adblock check https://suspicious-site.example.com
sd adblock log --count 100
sd adblock add custom-list https://example.com/blocklist.txt --category malware
sd adblock remove custom-list
```

| 子命令 | 说明 |
|--------|------|
| `enable` | 下载黑名单并安装 DNS 拦截（`/etc/hosts`） |
| `disable` | 移除 DNS 拦截条目 |
| `sync` | 强制重新下载所有过滤列表 |
| `stats` | 显示过滤统计信息 |
| `check <URL>` | 检查某个 URL/域名是否被拦截 |
| `log` | 显示最近被拦截的条目（`-c, --count <NUM>`，默认：50） |
| `add <NAME> <URL>` | 添加自定义过滤列表（`--category`：`ads`、`tracking`、`malware`、`social`） |
| `remove <NAME>` | 移除过滤列表 |

### `sd dns-proxy`

启动本地 DNS 代理，支持广告拦截、IOC 和自定义黑名单过滤。

```bash
sudo sd dns-proxy
sudo sd dns-proxy --listen 127.0.0.1:5353 --upstream 1.1.1.1:53
```

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `--listen <ADDR>` | 监听地址 | `127.0.0.1:53` |
| `--upstream <ADDR>` | 上游 DNS 服务器 | `8.8.8.8:53` |
| `--log-path <PATH>` | JSONL 查询日志路径 | `/tmp/prx-sd-dns.log` |

---

## 报告

### `sd report <OUTPUT>`

从 JSON 扫描结果生成独立的 HTML 报告。

```bash
sd scan /path --json | sd report report.html
sd report report.html --input results.json
```

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `--input <FILE>` | 输入 JSON 文件（`-` 表示标准输入） | `-`（标准输入） |

### `sd status`

显示守护进程状态，包括 PID、运行时间、签名版本和已拦截威胁数。

```bash
sd status
```

---

## 集成

### `sd install-integration`

安装文件管理器右键扫描集成。

```bash
sd install-integration
```

支持的文件管理器：
- **Linux:** Nautilus (GNOME Files)、Dolphin (KDE)、Nemo (Cinnamon)
- **macOS:** Finder Quick Action

### `sd self-update`

检查并从 GitHub Releases 应用二进制更新。

```bash
sd self-update
sd self-update --check-only
```

| 选项 | 说明 |
|------|------|
| `--check-only` | 仅检查是否有可用更新 |

---

## 使用示例

### 首次设置

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/openprx/prx-sd/main/install.sh | bash

# Import additional signatures
sd import my-custom-hashes.txt
sd import-clamav main.cvd daily.cvd

# Verify setup
sd info
```

### 日常防护

```bash
# Start daemon (monitors /home and /tmp, updates every 4h)
sd daemon

# Or manual scan
sd scan /home --recursive --auto-quarantine

# Check status
sd status
```

### 应急响应

```bash
# Scan with full remediation
sudo sd scan /tmp --auto-quarantine --remediate

# Check memory for in-memory threats
sudo sd scan-memory

# Check for rootkits
sudo sd check-rootkit

# Review quarantine
sd quarantine list
sd quarantine restore <ID> --to /safe/location
```

### 自动化

```bash
# Schedule weekly scan
sd schedule add /home --frequency weekly

# Set up alerts
sd webhook add slack https://hooks.slack.com/services/T.../B.../xxx --format slack
sd email-alert configure

# JSON output for scripts
sd scan /path --json | jq '.threats[] | .name'
```
