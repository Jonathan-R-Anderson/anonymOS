> このドキュメントは [English](../ARCHITECTURE.md) 版の日本語訳です。

# アーキテクチャ

PRX-SD はモジュール式のクレートで構成された Cargo ワークスペースであり、各クレートが特定のドメインを担当します。

## ワークスペースレイアウト

```
prx-sd/
├── crates/
│   ├── cli/           # "sd" バイナリ — コマンドラインインターフェース
│   ├── core/          # スキャンエンジンの統合制御
│   ├── signatures/    # ハッシュ DB (LMDB) + YARA-X ルールエンジン
│   ├── parsers/       # バイナリフォーマットパーサー
│   ├── heuristic/     # ヒューリスティックスコアリング + ML 推論
│   ├── realtime/      # ファイルシステム監視 + ネットワークフィルタリング
│   ├── quarantine/    # 暗号化された隔離ボールト
│   ├── remediation/   # 脅威対応アクション
│   ├── sandbox/       # プロセス分離 + 振る舞い分析
│   ├── plugins/       # WebAssembly プラグインランタイム
│   └── updater/       # シグネチャ更新クライアント
├── update-server/     # シグネチャ配信サーバー (Axum)
├── gui/               # デスクトップ GUI (Tauri 2 + Vue 3)
├── drivers/           # OS カーネルドライバー
│   └── windows-minifilter/  # Windows ファイルシステムミニフィルター (C)
├── signatures-db/     # 組み込み最小シグネチャ
├── packaging/         # 配布用パッケージング
├── tests/             # 統合テスト
├── tools/             # ビルドおよびユーティリティスクリプト
├── install.sh         # インストールスクリプト
└── uninstall.sh       # アンインストールスクリプト
```

## クレート依存関係グラフ

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

## 検出パイプライン

スキャンエンジン（`core`）は多層検出パイプラインを統合制御します:

```
                    ┌──────────────┐
                    │  ファイル入力  │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  マジックナンバー │  識別: PE, ELF, MachO,
                    │    検出       │  PDF, ZIP, Office, 不明
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐    │     ┌──────▼──────┐
       │   ハッシュ    │    │     │   YARA-X    │
       │   マッチング   │    │     │   ルール     │
       │   (LMDB)    │    │     │  (38K+)     │
       └──────┬──────┘    │     └──────┬──────┘
              │     ┌─────▼─────┐      │
              │     │ヒューリスティック│      │
              │     │   分析     │      │
              │     └─────┬─────┘      │
              │           │            │
              │    ┌──────▼──────┐     │
              │    │  ML 推論    │     │
              │    │  (ONNX)    │     │
              │    └──────┬─────┘     │
              │           │            │
              │    ┌──────▼──────┐     │
              │    │ VirusTotal  │     │
              │    │ クラウド照会  │     │
              │    └──────┬─────┘     │
              │           │            │
              └───────────┼────────────┘
                          │
                   ┌──────▼──────┐
                   │  結果の集約   │
                   │   最終判定   │
                   └─────────────┘
                   Clean / Suspicious / Malicious
```

### 各レイヤーの詳細

1. **ハッシュマッチング** -- ClamAV、abuse.ch、VirusShare、およびカスタムブロックリストから取得した SHA-256 と MD5 ハッシュを格納する LMDB データベースに対して O(1) ルックアップを行います。

2. **YARA-X ルール** -- YARA-X エンジン（Rust ネイティブの YARA 実装）を使用したパターンマッチング。組み込みデフォルトルールと外部シグネチャリポジトリからルールを読み込みます。

3. **ヒューリスティック分析** -- ファイル種別ごとの分析:
   - **PE:** セクションエントロピー、不審な API インポート（CreateRemoteThread, VirtualAllocEx）、パッカー検出（UPX, Themida）、タイムスタンプ異常
   - **ELF:** セクションエントロピー、LD_PRELOAD 参照、cron/systemd 永続化、SSH バックドアパターン
   - **MachO:** セクションエントロピー、dylib インジェクション、LaunchAgent 永続化、Keychain アクセス

4. **ML 推論**（任意、フィーチャーフラグ `onnx`）-- tract 経由の ONNX モデル評価:
   - PE: 64 次元特徴ベクトル（インポートテーブルハッシュ、セクションエントロピー、API シグネチャ）
   - ELF: 48 次元特徴ベクトル（セクションエントロピー、シンボルテーブル、動的ライブラリ）

5. **VirusTotal クラウド** -- ローカルでマッチしなかったファイルのフォールバック。VirusTotal API に照会します（無料枠: 1 日 500 クエリ）。結果は LMDB にキャッシュされます。

### スコアリング

- スコア >= 60: **Malicious**（悪意あり）
- スコア 30-59: **Suspicious**（不審）
- スコア < 30: **Clean**（安全）

最終判定は、全検出レイヤーの中で最も高い脅威レベルが採用されます。

## リアルタイム保護

`realtime` クレートは複数のサブシステムを通じて継続的な保護を提供します:

| サブシステム | Linux | macOS | Windows |
|--------------|-------|-------|---------|
| ファイル監視 | fanotify + epoll | FSEvents (notify) | ReadDirectoryChangesW (notify) |
| プロセスインターセプト | FAN_OPEN_EXEC_PERM | - | Minifilter（計画中） |
| メモリスキャン | /proc/pid/mem | - | - |
| ランサムウェア検出 | 書き込み + リネームパターン監視 | 書き込み + リネームパターン監視 | 書き込み + リネームパターン監視 |
| 保護ディレクトリ | ~/.ssh, /etc/shadow, /etc/systemd | ~/Library, /etc | Registry Run keys |
| DNS フィルタリング | Adblock エンジン + IOC リスト | Adblock エンジン + IOC リスト | Adblock エンジン + IOC リスト |
| 振る舞い監視 | /proc + audit (execve/connect/open) | - | - |

## 隔離ボールト

ファイルは AES-256-GCM 認証付き暗号化を使用して隔離されます:

1. ランダムな 256 ビット鍵 + 96 ビットナンスを生成
2. AES-256-GCM でファイル内容を暗号化
3. UUID をファイル名として暗号化されたファイルを保存
4. JSON メタデータ（元のパス、ハッシュ、脅威名、タイムスタンプ）を保存
5. 復元時は書き戻す前に復号化と整合性の検証を実施

## 修復パイプライン

`--remediate` 使用時:

```
脅威検出
  ├── 1. プロセス終了     (Linux/macOS では SIGKILL、Windows では TerminateProcess)
  ├── 2. ファイル隔離     (AES-256-GCM 暗号化ボールト)
  └── 3. 永続化メカニズムの除去
        ├── Linux:   cron ジョブ、systemd サービス、LD_PRELOAD
        ├── macOS:   LaunchAgents、plist エントリ、Keychain
        └── Windows: Run/RunOnce レジストリ、スケジュールタスク、サービス
```

アクションは `sd policy set` で設定できます。

## シグネチャデータベース

### 組み込みシグネチャ (`signatures-db/`)

`include_str!` を通じて `sd` バイナリにコンパイルされる最小シグネチャセット:
- EICAR テストシグネチャ
- コア YARA ルール（ランサムウェア、トロイの木馬、バックドアなど）
- 既知のマルウェアハッシュ（WannaCry, Emotet, NotPetya）

### 外部シグネチャ ([prx-sd-signatures](https://github.com/openprx/prx-sd-signatures))

包括的かつ頻繁に更新される脅威インテリジェンス:
- 9 つのソースから収集した 38,800 以上の YARA ルール
- abuse.ch フィードからのハッシュブロックリスト
- IOC リスト: 585K 以上の悪意ある IP、ドメイン、URL

### ストレージ

- **ハッシュ:** O(1) キーバリュールックアップのための LMDB（heed クレート）
- **YARA ルール:** 起動時に YARA-X によって読み込みおよびコンパイル
- **IOC リスト:** 高速な IP/ドメイン/URL マッチングのためのインメモリ HashSet

## プラグインシステム

PRX-SD は Wasmtime を通じて WebAssembly プラグインをサポートします:

- プラグインはマニフェスト（`plugin.json`）付きの `.wasm` ファイル
- ファイルシステムおよび環境アクセスのための WASI サポート
- プラグインの検出と読み込みのためのプラグインレジストリ
- スキャン結果と設定にアクセスするためのホスト関数をプラグインに公開

## 更新システム

`updater` クレートと `update-server` が安全な更新パイプラインを提供します:

1. クライアントが更新サーバーに新しいシグネチャバージョンを確認
2. サーバーがバージョン情報とダウンロード URL を応答
3. クライアントが zstd 圧縮されたシグネチャパッケージをダウンロード
4. Ed25519（ed25519-dalek）でパッケージ署名を検証
5. シグネチャを展開し LMDB に読み込み

## GUI アプリケーション

Tauri 2（Rust バックエンド）+ Vue 3（TypeScript フロントエンド）で構築:

- ステータスインジケーター付きシステムトレイ統合
- 脅威統計ダッシュボード
- ドラッグ & ドロップによるファイルスキャン
- 復元・削除が可能な隔離ブラウザー
- リアルタイム監視コントロール
- 設定およびコンフィグレーション
- 多言語サポート（10 言語）

## 主な依存関係

| カテゴリ | クレート | バージョン | 用途 |
|----------|----------|------------|------|
| 非同期 | tokio | 1.x | 非同期ランタイム |
| 並列処理 | rayon | - | スキャン用スレッドプール |
| YARA | yara-x | 1.14 | ルールマッチングエンジン |
| データベース | heed | - | LMDB バインディング |
| バイナリ解析 | goblin | 0.9 | PE/ELF/MachO パーサー |
| 暗号化 | aes-gcm | - | 隔離の暗号化 |
| 暗号化 | ed25519-dalek | - | 更新の検証 |
| ML | tract-onnx | - | ONNX 推論（任意） |
| WASM | wasmtime | 29 | プラグインランタイム |
| DNS | adblock | 0.12 | Brave adblock エンジン |
| CLI | clap | 4.x | 引数解析 |
| HTTP | axum | 0.8 | 更新サーバー |
