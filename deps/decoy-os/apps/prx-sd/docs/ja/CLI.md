> このドキュメントは [English](../CLI.md) 版の日本語訳です。

# CLI リファレンス

PRX-SD は脅威検出およびシステム保護のためのコマンドラインツール `sd` を提供します。

## グローバルオプション

| フラグ | 説明 | デフォルト |
|--------|------|------------|
| `--log-level <LEVEL>` | ログの詳細度: `trace`, `debug`, `info`, `warn`, `error` | `warn` |
| `--data-dir <PATH>` | シグネチャ、隔離、設定用のデータディレクトリ | `~/.prx-sd/` |

---

## スキャン

### `sd scan <PATH>`

ファイルまたはディレクトリの脅威をスキャンします。

```bash
sd scan /path/to/file
sd scan /home --recursive
sd scan /tmp --auto-quarantine --remediate
sd scan /path --json
sd scan /path --report report.html
```

| オプション | 説明 | デフォルト |
|------------|------|------------|
| `-r, --recursive <BOOL>` | サブディレクトリを再帰的にスキャン | ディレクトリの場合 `true` |
| `--json` | 結果を JSON 形式で出力 | |
| `-t, --threads <NUM>` | スキャナースレッド数 | CPU コア数 |
| `--auto-quarantine` | 悪意のあるファイルを自動的に隔離 | |
| `--remediate` | 自動修復: プロセス終了、隔離、永続化メカニズムの除去 | |
| `-e, --exclude <PATTERN>` | 除外する glob パターン（繰り返し指定可） | |
| `--report <PATH>` | 結果を自己完結型 HTML レポートとしてエクスポート | |

### `sd scan-memory`

実行中のプロセスメモリをスキャンして脅威を検出します（Linux のみ、root 権限が必要）。

```bash
sudo sd scan-memory
sudo sd scan-memory --pid 1234
sudo sd scan-memory --json
```

| オプション | 説明 |
|------------|------|
| `--pid <PID>` | 特定のプロセスをスキャン（省略時は全プロセスをスキャン） |
| `--json` | JSON 形式で出力 |

### `sd scan-usb [DEVICE]`

USB やリムーバブルデバイスをスキャンします。

```bash
sd scan-usb
sd scan-usb /dev/sdb1 --auto-quarantine
```

| オプション | 説明 |
|------------|------|
| `--auto-quarantine` | 検出された脅威を自動的に隔離 |

### `sd check-rootkit`

rootkit の兆候を確認します（Linux のみ）。

```bash
sudo sd check-rootkit
sudo sd check-rootkit --json
```

確認項目: 隠しプロセス、カーネルモジュールの整合性、LD_PRELOAD フック、/proc の異常。

---

## リアルタイム保護

### `sd monitor <PATHS...>`

ファイルシステムのリアルタイム監視を行います。

```bash
sd monitor /home /tmp
sd monitor /home --block
sd monitor /home --daemon
```

| オプション | 説明 |
|------------|------|
| `--block` | 悪意のあるファイルへのアクセスをブロック（root 権限 + Linux では fanotify が必要） |
| `--daemon` | バックグラウンドデーモンとして実行 |

### `sd daemon [PATHS...]`

リアルタイム監視と自動更新を行うバックグラウンドデーモンとして実行します。

```bash
sd daemon
sd daemon /home /tmp --update-hours 2
```

| オプション | 説明 | デフォルト |
|------------|------|------------|
| `--update-hours <NUM>` | シグネチャ更新チェックの間隔（時間単位） | `4` |

デフォルトの監視パス: `/home`, `/tmp`。

---

## 隔離管理

### `sd quarantine <SUBCOMMAND>`

暗号化された隔離ボールト（AES-256-GCM）を管理します。

```bash
sd quarantine list
sd quarantine restore <ID>
sd quarantine restore <ID> --to /safe/path
sd quarantine delete <ID>
sd quarantine delete-all --yes
sd quarantine stats
```

| サブコマンド | 説明 |
|--------------|------|
| `list` | 隔離されたファイルを一覧表示 |
| `restore <ID>` | 隔離されたファイルを復元（`--to <PATH>` で別の場所に復元可能） |
| `delete <ID>` | 隔離されたファイルを完全に削除 |
| `delete-all` | 隔離された全ファイルを削除（`--yes` で確認をスキップ） |
| `stats` | 隔離の統計情報を表示 |

---

## シグネチャデータベース

### `sd update`

シグネチャデータベースの更新を確認し、適用します。

```bash
sd update
sd update --check-only
sd update --force
sd update --server-url https://custom-server.example.com
```

| オプション | 説明 |
|------------|------|
| `--check-only` | 更新の有無のみを確認 |
| `--force` | 最新の場合でも強制的に再ダウンロード |
| `--server-url <URL>` | 更新サーバーの URL を上書き |

### `sd import <PATH>`

ブロックリストファイルからハッシュシグネチャをインポートします。

```bash
sd import /path/to/blocklist.txt
```

ファイル形式: 1 行に 1 エントリ、`hex_hash malware_name` の形式。`#` で始まる行はコメントです。

```
# Example blocklist
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR.Test
ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa Ransom.WannaCry
```

### `sd import-clamav <PATHS...>`

ClamAV シグネチャデータベースファイルをインポートします。

```bash
sd import-clamav main.cvd daily.cvd
sd import-clamav custom.hdb custom.hsb
```

対応形式: `.cvd`, `.cld`, `.hdb`, `.hsb`。

### `sd info`

エンジンバージョン、シグネチャデータベースの状態、システム情報を表示します。

```bash
sd info
```

表示内容: バージョン、YARA ルール数、ハッシュシグネチャ数、隔離の統計、プラットフォーム情報。

---

## 設定

### `sd config <SUBCOMMAND>`

エンジン設定を管理します。

```bash
sd config show
sd config set scan.max_file_size 104857600
sd config set scan.follow_symlinks true
sd config reset
```

| サブコマンド | 説明 |
|--------------|------|
| `show` | 現在の設定を表示 |
| `set <KEY> <VALUE>` | 設定キーを設定（ドット区切りのパス） |
| `reset` | デフォルト設定にリセット |

値は JSON 型をサポート: ブール値（`true`/`false`）、数値、`null`、配列、オブジェクト。

---

## 修復ポリシー

### `sd policy <ACTION> [KEY] [VALUE]`

脅威修復ポリシーを管理します。

```bash
sd policy show
sd policy set on_malicious "kill,quarantine,clean"
sd policy set on_suspicious "report,quarantine"
sd policy set kill_processes true
sd policy reset
```

| アクション | 説明 |
|------------|------|
| `show` | 現在のポリシーを表示 |
| `set <KEY> <VALUE>` | ポリシーフィールドを設定 |
| `reset` | デフォルトポリシーにリセット |

**ポリシーキー:**

| キー | 説明 | 値 |
|------|------|----|
| `on_malicious` | 悪意のある脅威に対するアクション | カンマ区切り: `report`, `quarantine`, `block`, `kill`, `clean`, `delete`, `isolate`, `blocklist` |
| `on_suspicious` | 不審な脅威に対するアクション | 同上 |
| `kill_processes` | 関連プロセスを終了 | `true` / `false` |
| `clean_persistence` | 永続化メカニズムを除去 | `true` / `false` |
| `network_isolation` | ネットワーク接続を隔離 | `true` / `false` |
| `audit_logging` | 全アクションを監査ログに記録 | `true` / `false` |

---

## スケジューリング

### `sd schedule <SUBCOMMAND>`

定期スキャンを管理します。プラットフォームネイティブのスケジューラを使用: systemd timers (Linux)、cron (Linux/macOS)、launchd (macOS)、Task Scheduler (Windows)。

```bash
sd schedule add /home --frequency daily
sd schedule add /tmp --frequency hourly
sd schedule status
sd schedule remove
```

| サブコマンド | 説明 |
|--------------|------|
| `add <PATH>` | 定期スキャンを登録 |
| `remove` | 定期スキャンを削除 |
| `status` | 現在のスケジュール状態を表示 |

**頻度:** `hourly`, `4h`, `12h`, `daily`, `weekly`（デフォルト: `weekly`）。

---

## アラート

### `sd webhook <SUBCOMMAND>`

Webhook アラートエンドポイントを管理します。

```bash
sd webhook list
sd webhook add my-slack https://hooks.slack.com/services/... --format slack
sd webhook add my-discord https://discord.com/api/webhooks/... --format discord
sd webhook add custom https://example.com/alert --format generic
sd webhook remove my-slack
sd webhook test
```

| サブコマンド | 説明 |
|--------------|------|
| `list` | 設定済みの Webhook を一覧表示 |
| `add <NAME> <URL>` | Webhook を追加（`--format`: `slack`, `discord`, `generic`） |
| `remove <NAME>` | 名前を指定して Webhook を削除 |
| `test` | 全 Webhook にテストアラートを送信 |

### `sd email-alert <SUBCOMMAND>`

メールアラート設定を管理します。

```bash
sd email-alert configure
sd email-alert test
sd email-alert send "Trojan.Generic" "high" "/tmp/malware.exe"
```

| サブコマンド | 説明 |
|--------------|------|
| `configure` | SMTP メール設定を作成または表示 |
| `test` | テストアラートメールを送信 |
| `send <NAME> <LEVEL> <PATH>` | カスタムアラートメールを送信 |

---

## DNS およびネットワークフィルタリング

### `sd adblock <SUBCOMMAND>`

広告ブロックおよびマルウェアドメインフィルタリングを管理します。

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

| サブコマンド | 説明 |
|--------------|------|
| `enable` | ブロックリストをダウンロードし DNS ブロッキングをインストール（`/etc/hosts`） |
| `disable` | DNS ブロッキングエントリを削除 |
| `sync` | 全フィルターリストを強制的に再ダウンロード |
| `stats` | フィルタリング統計情報を表示 |
| `check <URL>` | URL またはドメインがブロックされているか確認 |
| `log` | 最近のブロックエントリを表示（`-c, --count <NUM>`、デフォルト: 50） |
| `add <NAME> <URL>` | カスタムフィルターリストを追加（`--category`: `ads`, `tracking`, `malware`, `social`） |
| `remove <NAME>` | フィルターリストを削除 |

### `sd dns-proxy`

adblock、IOC、およびカスタムブロックリストフィルタリング機能を備えたローカル DNS プロキシを起動します。

```bash
sudo sd dns-proxy
sudo sd dns-proxy --listen 127.0.0.1:5353 --upstream 1.1.1.1:53
```

| オプション | 説明 | デフォルト |
|------------|------|------------|
| `--listen <ADDR>` | リッスンアドレス | `127.0.0.1:53` |
| `--upstream <ADDR>` | 上流 DNS サーバー | `8.8.8.8:53` |
| `--log-path <PATH>` | JSONL クエリログのパス | `/tmp/prx-sd-dns.log` |

---

## レポート

### `sd report <OUTPUT>`

JSON スキャン結果から自己完結型 HTML レポートを生成します。

```bash
sd scan /path --json | sd report report.html
sd report report.html --input results.json
```

| オプション | 説明 | デフォルト |
|------------|------|------------|
| `--input <FILE>` | 入力 JSON ファイル（標準入力は `-`） | `-`（標準入力） |

### `sd status`

PID、稼働時間、シグネチャバージョン、ブロックされた脅威数などのデーモンステータスを表示します。

```bash
sd status
```

---

## 統合機能

### `sd install-integration`

ファイルマネージャーの右クリックスキャン統合をインストールします。

```bash
sd install-integration
```

対応ファイルマネージャー:
- **Linux:** Nautilus (GNOME Files)、Dolphin (KDE)、Nemo (Cinnamon)
- **macOS:** Finder Quick Action

### `sd self-update`

GitHub Releases からバイナリの更新を確認し、適用します。

```bash
sd self-update
sd self-update --check-only
```

| オプション | 説明 |
|------------|------|
| `--check-only` | 更新の有無のみを確認 |

---

## 使用例

### 初回セットアップ

```bash
# インストール
curl -fsSL https://raw.githubusercontent.com/openprx/prx-sd/main/install.sh | bash

# 追加シグネチャのインポート
sd import my-custom-hashes.txt
sd import-clamav main.cvd daily.cvd

# セットアップの確認
sd info
```

### 日常の保護

```bash
# デーモンを起動（/home と /tmp を監視、4時間ごとに更新）
sd daemon

# または手動スキャン
sd scan /home --recursive --auto-quarantine

# ステータス確認
sd status
```

### インシデント対応

```bash
# 完全な修復を伴うスキャン
sudo sd scan /tmp --auto-quarantine --remediate

# メモリ内の脅威を確認
sudo sd scan-memory

# rootkit を確認
sudo sd check-rootkit

# 隔離の確認
sd quarantine list
sd quarantine restore <ID> --to /safe/location
```

### 自動化

```bash
# 週次スキャンをスケジュール
sd schedule add /home --frequency weekly

# アラートの設定
sd webhook add slack https://hooks.slack.com/services/T.../B.../xxx --format slack
sd email-alert configure

# スクリプト用 JSON 出力
sd scan /path --json | jq '.threats[] | .name'
```
