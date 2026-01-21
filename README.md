


# KaptainhooK

日本語 | [English](README.en.md)

Windows環境におけるプロセス実行制御・監視システム

## 概要

KaptainhooKは、Windows環境で危険なスクリプティングツール（PowerShell、cmd.exeなど）の実行を制御・監視する個人開発の学習用プロジェクトです。
IFEOの操作や悪用への対策の一例として、必要な対策や課題を可視化するために、こういう形にまとめました。
指定されたプロセスの起動を検知し、ポリシーに基づいて許可・通知・確認・拒否を行います。

あくまでも学習用プロジェクトなので、テスト環境で使用してください。

## IFEOとは

IFEO（Image File Execution Options）は、Windows が提供するデバッグ用のレジストリ機構です。特定の実行ファイルが起動されるとき、Windows が自動的に別のプログラム（デバッガ）を代わりに起動する仕組みがあります。

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<実行ファイル名>
```

ここに `Debugger` という値を設定すると、元の実行ファイルの代わりにそのデバッガが起動されます。

KaptainhooKはこの仕組みを利用して、対象exeの起動を「必ず一度こちらに通す」ことで、起動元の確認や警告表示を行います。

## 主な機能

### 反応（Log / Notify / Friction）

KaptainhooKの反応は3種類です：

- **Log**: ログ記録のみで許可
- **Notify**: 警告MessageBoxを表示して許可
- **Friction**: 確認UI（摩擦）を表示して許可

これとは別に、ポリシー条件（非対話セッション拒否、タイムアウト、Windows Hello失敗など）でブロックが発生します。

### 起動元カテゴリの自動分類

親/祖父プロセス名と引数のパターンでカテゴリを付けます：

**Mail（メール）と見なす例**

- 親/祖父が `outlook.exe` / `olk.exe` / `thunderbird.exe`
- 引数に `\Content.Outlook\` / `\INetCache\` / `mailto:` を含む

**Macro（マクロ）と見なす例**

- 親/祖父が `winword.exe` / `excel.exe` / `powerpnt.exe` / `visio.exe`
- 引数が `.docm` / `.xlsm` / `.pptm` / `.dotm` で終わる

**Relay（リレー）と見なす例**

- 親/祖父が `powershell.exe` / `pwsh.exe` / `cmd.exe` / `wscript.exe` / `cscript.exe` / `mshta.exe` / `rundll32.exe` / `regsvr32.exe` / `certutil.exe` / `bitsadmin.exe` / `wmic.exe` / `installutil.exe` / `msdt.exe` / `powershell_ise.exe` / `wt.exe` / `msiexec.exe` / `schtasks.exe`
- ターゲット自身がこれらのexeの場合もリレー扱い

複数のカテゴリが付いた場合、強い反応順（Friction > Notify > Log）で適用されます。

### プリセット（4種）

反応ルールはプリセットから選べます：

|プリセット    |Mail    |Macro   |Relay   |Always  |
|---------|--------|--------|--------|--------|
|`all_log`|Log     |Log     |Log     |Log     |
|`strong` |Friction|Friction|Friction|Friction|
|`medium` |Friction|Friction|Notify  |Friction|
|`weak`   |Notify  |Notify  |Log     |Notify  |

初期設定は `all_log` です。

### 実行場所の警告（Path Hint）

パスに以下が含まれると怪しい場所として警告します：

**不審な場所**

- `\users\public\`
- `\temp\`
- `\appdata\local\temp\`
- `\downloads\`
- `\desktop\`

**安全な場所（参考表示）**

- `\program files\`
- `\program files (x86)\`
- `\windows\system32\`
- `\windows\syswow64\`

### フリクション設定

Frictionモードの既定値：

|設定      |既定値    |範囲            |
|--------|-------|--------------|
|長押し要求   |有効     |-             |
|長押し時間   |1,500ms|500〜30,000ms  |
|マウス移動要求 |有効     |-             |
|移動距離    |80px   |10〜500px      |
|緊急バイパス  |有効     |-             |
|緊急バイパス時間|5,000ms|1,000〜10,000ms|

緊急バイパスは Ctrl + Shift + Alt を指定時間押し続けた場合に成立します。

### ポリシー設定

|設定         |既定値        |
|-----------|-----------|
|非対話セッションを許可|拒否（false）  |
|タイムアウト秒数   |60秒（0で無効）  |
|認証方式       |Friction UI|

### ナッジメッセージ

実行時に指定したメッセージを表示できます。デフォルトメッセージ：

> 不明な場合は IT 管理者に連絡してください。

### ログ（JSONL）

実行イベントはJSONL形式で記録します。5MBを超えるとローテート（リネーム）します。

- **ユーザーごと**: `C:\Users\<User>\AppData\Local\KaptainhooK\final\logs\guard.log.jsonl`
- **管理系**: `C:\ProgramData\KaptainhooK\final\logs\operation.log.jsonl`
- **ライフサイクル**: `C:\ProgramData\KaptainhooK\final\logs\kh-lifecycle.log`

ログ例（Frictionで許可されたケース）：

```json
{
  "timestamp": "2026-01-09T10:30:45.123Z",
  "normalized_target": "powershell.exe",
  "args": ["-encodedcommand", "…"],
  "username": "tanaka",
  "session": "Console",
  "reason": "reaction friction (origin: mail)",
  "action": "allowed",
  "reaction": "friction",
  "origin_categories": ["mail"],
  "allowed": true,
  "emergency": false,
  "nudge_message_id": "default-nudge",
  "exit_code": 0,
  "duration_ms": 3245,
  "enabled_targets": 14,
  "parent_pid": 1234,
  "parent_process": "outlook.exe",
  "parent_path": "C:\\Program Files\\Microsoft Office\\…",
  "grandparent_pid": 5678,
  "grandparent_process": "explorer.exe",
  "grandparent_path": "C:\\Windows\\explorer.exe"
}
```

### IFEO競合検出

既にIFEOに別のDebuggerが入っている場合、競合として検出します。既存デバッガの署名情報（Signed/Trust/Revocationなど）も表示します。

セットアップ時の選択肢：

- **尊重（スキップ）**: 既存設定を維持
- **引き継ぎ（上書き）**: KaptainhooKで上書き
- **隔離（Quarantine）**: 上書きし、バックアップに危険ラベルを付与

### バックアップとロールバック

バックアップは2系統あります：

- **ロールバック用**: `C:\ProgramData\KaptainhooK\final\backups\backups.json`
  - `kh-cli rollback` で使用
- **アンインストール用**: `HKLM\SOFTWARE\KaptainhooK\UninstallState\IfeoBackups`
  - バイナリ削除後もアンインストーラだけで復元可能

### サービス乗っ取り防止

KaptainhooKは「許可されたらサービスがIFEOを一瞬外す」ため、2段階のセーフティを実装：

1. **Allow-list**: `HKLM\SOFTWARE\KaptainhooK\Targets` でサービスが扱ってよいターゲット一覧を管理
1. **IPC検証**: Named Pipe（`\\.\pipe\KaptainhooKService`）で接続元を検証
- プロセスが `kh-guard.exe` であること
- パスが `C:\Program Files\KaptainhooK\bin\kh-guard.exe` と一致すること
- SHA256が `SOFTWARE\KaptainhooK\TrustedHashes` の `GuardHash` と一致すること

## 監視対象（デフォルト15種）

|# |ターゲット             |説明                   |既定    |
|--|------------------|---------------------|------|
|1 |powershell.exe    |Windows PowerShell   |有効    |
|2 |pwsh.exe          |PowerShell Core      |有効    |
|3 |cmd.exe           |コマンドプロンプト            |有効    |
|4 |wscript.exe       |Windows Script Host  |有効    |
|5 |cscript.exe       |コンソールスクリプトホスト        |有効    |
|6 |mshta.exe         |HTML Application Host|有効    |
|7 |rundll32.exe      |DLL実行ユーティリティ         |有効    |
|8 |regsvr32.exe      |COM登録ユーティリティ         |有効    |
|9 |certutil.exe      |証明書ユーティリティ           |有効    |
|10|bitsadmin.exe     |BITSファイル転送           |有効    |
|11|wmic.exe          |WMIコマンドライン           |有効    |
|12|installutil.exe   |.NETインストーラーツール       |有効    |
|13|msdt.exe          |Microsoft診断ツール       |有効    |
|14|powershell_ise.exe|PowerShell ISE       |有効    |
|15|wt.exe            |Windows Terminal     |**無効**|

これらはLOLBin（Living Off The Land Binaries）として悪用されるケースがあるため、標準ターゲットとしています。

## システム要件

- **OS**: Windows 11
- **権限**: 管理者権限が必要
- **Rust**: 1.85.0 以降（ビルド時）
- **C++ ビルド環境**: Visual Studio の「C++ デスクトップ開発」（MSVC + Windows SDK）

## インストール

### ZIPからビルドしてインストール

ZIPファイルを展開したフォルダでターミナルを起動し、下記でビルド。

```
cargo build --release
```

ビルド完了後、下記を実行するとpackageフォルダに実行ファイル一式とショートカットが作成されます。

```
./package.ps1
```

ショートカットを実行すると`bin/kh-setup.exe` が起動します。UACで管理者権限を与えて実行します。


### コマンドラインからインストール

```powershell
# 対話モード
kh-setup.exe --cli

# ドライラン（変更なし）
kh-setup.exe --cli --dry-run

# デフォルト設定で自動実行
kh-setup.exe --cli --defaults
```

### アンインストール

```powershell
# 設定 → アプリ → KaptainhooK からアンインストール
# または
kh-setup.exe --uninstall
# または
kh-uninstall.exe
```

### ソースからビルド

```bash
git clone https://github.com/burutofosu/KaptainhooK
cd KaptainhooK

# リリースビルド
cargo build --release

# 実行ファイルは target/release/ に生成されます
```

## 使用方法

### コマンドライン操作（kh-cli.exe）

```powershell
# インストール（ドライラン）
kh-cli.exe install --dry-run

# 状態確認
kh-cli.exe status

# 競合検出
kh-cli.exe conflicts

# ターゲット管理
kh-cli.exe targets list
kh-cli.exe targets enable powershell.exe
kh-cli.exe targets disable mshta.exe
kh-cli.exe targets remove wmic.exe

# クリーンアップ
kh-cli.exe cleanup
kh-cli.exe cleanup --scan

# ロールバック
kh-cli.exe rollback

# アンインストール（クリーンアップ用途）
kh-cli.exe uninstall
kh-cli.exe uninstall --remove-data  # データも削除

# タスク状態
kh-cli.exe task-info

# TrustedHashes更新
kh-cli.exe trusted-hashes refresh
```

完全アンインストールは `kh-uninstall.exe` または `kh-setup.exe --uninstall` を使用してください。

### 設定UI（kh-settings.exe）

WebView2ベースの設定UIで以下を変更できます：

- ターゲットの有効/無効
- 反応ルール（プリセット・個別設定）
- フリクション設定
- ポリシー（非対話セッション許可、タイムアウト秒、認証方式）
- ナッジメッセージ
- 言語（日本語/英語）
- 検索パス（ユーザー追加 search_paths）
- 背景画像（スキン）と不透明度

背景は設定画面にのみ適用されます。

### システムトレイ（kh-tray.exe）

常駐型のシステムトレイアプリケーション。設定UIの起動とサービス状態の確認ができます。

## 動作の仕組み

### インストール時

1. `C:\Program Files\KaptainhooK\bin\` にバイナリとassetsを配置
1. `C:\ProgramData\KaptainhooK\final\` 配下に config / logs / backups を作成
1. 競合検出と対応選択
1. `HKLM\SOFTWARE\KaptainhooK\Targets` と `TrustedHashes` を書き込み
1. 復元タスク `KaptainhooKRestore` を登録
1. アンインストール用にIFEO状態をバックアップ
1. サービス `KaptainhooKService` を登録して起動
1. IFEOを64bit/32bit両ビューに適用
1. `config.json` を保存
1. 「アプリと機能」に登録、スタートアップ登録、トレイ起動

### 実行時

1. ターゲット（例: `cmd.exe`）が実行される
1. Windows IFEOが `Debugger=kh-bootstrap.exe` を見つけて起動
1. `kh-bootstrap` が `kh-guard` を起動
1. `kh-guard` が config.json を読み込み、親/祖父情報を収集、カテゴリ判定
1. 反応とポリシーを評価、必要なら警告/確認UI
1. `guard.log.jsonl` に記録
1. 許可された場合、サービスへbypassを要求
1. サービスがIFEOを一時解除（TTL: `auto_restore_seconds` × 1000ms、既定2秒）
1. `kh-guard` が本物のexeを起動
1. サービスがIFEOを復元

## アーキテクチャ

ヘキサゴナルアーキテクチャとレイヤードアーキテクチャを組み合わせた設計：

```
Domain（最内層・stdのみ）
  ↓
Engine（Domainのみ）
  ↓
Application（Domain + Engine）
  ↓
Composition（合成ルート/DI）
  ↓
Infrastructure / UI（ポート実装）
  ↓
Apps（実行ファイル群）
```

## プロジェクト構成

```
KaptainhooK/
├── assets/                          # アイコン・背景画像
├── domain/kh-domain/                # ドメイン層
├── engine/kh-engine/                # エンジン層
├── application/kh-app/              # アプリケーション層
├── composition/kh-composition/      # 依存性注入・合成ルート
├── infrastructure/                  # インフラストラクチャアダプタ
│   ├── kh-adapter-registry/         # レジストリ操作
│   ├── kh-adapter-signature/        # デジタル署名検証
│   ├── kh-adapter-fs/               # ファイルシステム
│   ├── kh-adapter-task/             # タスクスケジューラ
│   ├── kh-adapter-clock/            # 時刻提供
│   ├── kh-adapter-service-ipc/      # プロセス間通信
│   ├── kh-adapter-paths/            # パス解決
│   ├── kh-adapter-guard/            # ガード関連
│   └── kh-adapter-uninstall-state/  # アンインストール状態
├── ui/                              # ユーザーインターフェース層
│   ├── kh-ui-common/                # 共通UI
│   └── kh-ui-guard/                 # ガードUI
├── shared/                          # 共有ユーティリティ
│   └── kh-log-utils/                # ログユーティリティ
├── apps/                            # 実行ファイル
│   ├── bootstrap/                   # IFEOエントリーポイント
│   ├── guard/                       # メインガード
│   ├── service/                     # Windowsサービス
│   ├── service-restart/             # サービス再起動
│   ├── restore/                     # 復元ツール
│   ├── setup/                       # セットアップウィザード
│   ├── cli/                         # コマンドラインツール
│   ├── settings/                    # 設定UI
│   ├── tray/                        # システムトレイ
│   └── uninstall/                   # アンインストーラ
└── scripts/                         # ビルド・テストスクリプト
    └── package.ps1                  # 配布パッケージ作成
     
```

## 外部依存

### コア（多くのクレートで共通）

- windows
- serde / serde_json
- clap
- sha2

### 設定UI（kh-settings）

- wry / tao（WebView2ホスト）

### セットアップ（kh-setup）

- embed-resource（ビルド時のリソース埋め込み）

## 設定ファイル

### パス

|種類      |パス                                                                    |
|--------|----------------------------------------------------------------------|
|データ     |`C:\ProgramData\KaptainhooK\final`                                    |
|バイナリ    |`C:\Program Files\KaptainhooK\bin`                                    |
|設定      |`C:\ProgramData\KaptainhooK\final\config\config.json`                 |
|ログ（ユーザー）|`C:\Users\<User>\AppData\Local\KaptainhooK\final\logs\guard.log.jsonl`|
|ログ（管理系） |`C:\ProgramData\KaptainhooK\final\logs\operation.log.jsonl`           |

### 設定項目

|項目                    |説明                                  |
|----------------------|------------------------------------|
|`targets`             |監視対象のターゲットリスト                       |
|`policy`              |非対話セッション許可、タイムアウト、認証方式              |
|`reaction`            |反応ルール（preset、default_rule、overrides）|
|`friction`            |ユーザー確認UIの設定                         |
|`nudge_messages`      |啓発メッセージ                             |
|`language`            |言語設定（ja / en）                       |
|`auto_restore_seconds`|自動復元タイムアウト（1-300秒、既定2秒）             |
|`search_paths`        |実行ファイル探索に追加するパス（ローカル絶対パスのみ）         |
|`background`          |背景設定（image、opacity: 0-100）          |

### 実行ファイルの解決順序

1. **絶対パスが渡された場合**: ローカルdrive-letter絶対パスのみ許可
- 許可: `C:\Windows\System32\cmd.exe`
- 不許可: UNC（`\\server\share\...`）、ドライブ文字なし
1. **それ以外**: パス区切りを含まない実行ファイル名に限り、安全な既定パス + `search_paths` から検索
1. **相対パス（区切りを含む）**: 不許可

## スコープ外

- IFEOを経由しない実行
- 監視対象外プロセス
- ConsentFix系（OAuthトークン窃取など）
- HKLM自体を改ざんされた場合
- bypassの短時間IFEO解除中の他プロセス起動

## 開発

### ビルド

```bash
# デバッグビルド
cargo build

# リリースビルド
cargo build --release

# 特定のバイナリをビルド
cargo build --release -p kh-guard
```

### 配布パッケージの作成

```powershell
scripts/package.ps1
```

### テスト

```bash
# すべてのテストを実行
cargo test

# 特定のパッケージをテスト
cargo test -p kh-domain
```

### 統合テスト（Windows / 管理者）

```powershell
scripts/run_integration_tests.ps1 -Profile debug
```

### リンター・フォーマット

```bash
cargo clippy
cargo fmt
```

## トラブルシューティング

### インストールが失敗する

- 管理者権限で実行しているか確認
- 既存のIFEO設定との競合を確認
- バックアップファイルを確認して復元を試行

### ターゲットが起動しない

- IFEOレジストリキーを確認
- `kh-bootstrap.exe` と `kh-guard.exe` のパスを確認
- ログファイルでエラーメッセージを確認

### ロールバックが必要な場合

```powershell
kh-restore.exe
# または
kh-cli.exe rollback
```

### レジストリを手動で削除する（最終手段）

> **注意**: 誤削除はシステムに影響します。必ずバックアップを取ってから実施してください。
> 可能なら `kh-restore` / `kh-cli` / `kh-uninstall` を先に試してください。

**手順**

1. 管理者権限でレジストリエディタ（regedit）を起動
1. IFEOのエントリを削除（`Debugger` が KaptainhooK の `kh-bootstrap.exe` を指しているサブキーのみ）
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
- 64bit OSの場合、32bit側も確認: `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
1. KaptainhooKの管理用キーを削除
- `HKEY_LOCAL_MACHINE\SOFTWARE\KaptainhooK\Targets`
- `HKEY_LOCAL_MACHINE\SOFTWARE\KaptainhooK\TrustedHashes`
- `HKEY_LOCAL_MACHINE\SOFTWARE\KaptainhooK\LeaseState`
- `HKEY_LOCAL_MACHINE\SOFTWARE\KaptainhooK\UninstallState`

**KaptainhooKと判断できる目安**: `Debugger` の値に以下が含まれている

```
C:\Program Files\KaptainhooK\bin\kh-bootstrap.exe
```

（`--ifeo-view=32/64` が付いていることがあります）

## セキュリティに関する注意事項

- このソフトウェアは管理者権限で動作します
- IFEOレジストリを変更するため、システムに影響を与える可能性があります
- あくまでも学習用プロジェクトです。必ずテスト環境で動作を確認してください
- 競合する他のセキュリティソフトウェアとの互換性を確認してください

## ライセンス

このプロジェクトは Apache License 2.0 の下でライセンスされています。詳細は [LICENSE](./LICENSE) ファイルを参照してください。

## バージョン

現在のバージョン: **0.95.0**
