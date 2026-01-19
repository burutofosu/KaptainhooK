# アーキテクチャ

日本語 | [English](ARCHITECTURE.en.md)

## 概要

KaptainhooKは、へキサゴナルアーキテクチャ（ポート&アダプタ）とレイヤードアーキテクチャを組み合わせた構成です。  
ドメインの判断ロジックを外部依存から分離し、Windows依存の実装は外側に配置しています。

## レイヤ構成（実際の構造）

```
Domain（stdのみ）
  ↓
Engine（Domainのみ）
  ↓
Application（Domain + Engine）
  ↓
Composition（DI/合成ルート）
  ↓
Infrastructure / UI（ポート実装）
  ↓
Apps（実行ファイル群）
```

## 各レイヤの責務（要点）

- **Domain (`domain/kh-domain`)**
  - ルールと値オブジェクト（Target/Policy/Reaction/Signature/PathHint 等）
  - ポート（IFEO/Config/Targets/Signature/Clock/Log/Task/IPC/Launcher などの抽象）
  - 純粋な判定ロジック（reaction/threat/ownership）

- **Engine (`engine/kh-engine`)**
  - IFEOのインストール/クリーンアップ/競合検出/バックアップ復元のワークフロー

- **Application (`application/kh-app`)**
  - ガード/管理のユースケースを統合し、各ポートを使って処理を組み立てる

- **Composition (`composition/kh-composition`)**
  - 依存性注入（DI）
  - サービス/ガード/復元タスクのランタイム配線

- **Infrastructure (`infrastructure/*`)**
  - レジストリ/署名検証/ファイル/タスク/IPC/パス解決などのWindows依存実装

- **UI (`ui/*`)**
  - ガードUI、共通メッセージ、i18n、WebView2設定UIの支援

- **Apps (`apps/*`)**
  - 実行ファイル群（bootstrap/guard/service/restore/setup/cli/settings/tray/uninstall）

## 主要フロー（短縮）

### インストール
1. `kh-setup` が Program Files / ProgramData に配置
1. 競合検出 → IFEO登録（32/64ビュー）
1. `KaptainhooKRestore` タスク登録
1. `KaptainhooKService` 登録・起動
1. `config.json` 保存、Targets/TrustedHashes をHKLMに書き込み

### 実行時（IFEO）
1. 対象exe起動 → IFEOで `kh-bootstrap` 起動
1. `kh-bootstrap` が同ディレクトリの `kh-guard` を起動（PATH非依存）
1. `kh-guard` が設定/親祖父情報を収集し反応判定
1. 許可時はサービスにbypass要求 → 一時的にIFEO解除
1. 実プロセス起動 → IFEO復元

### 復元/アンインストール
1. サービスTTL + 復元タスクでIFEO復旧を冗長化
1. アンインストール時はUninstallStateのバックアップから復元可能

## セキュリティ境界（要点）

- **IPC検証**: `\\.\pipe\KaptainhooKService` で接続元を guard実体（パス + ハッシュ）で検証
- **Owned/Foreign判定**: IFEOのDebuger値を Owned / Foreign / Disabled に分類し安全側に倒す
- **UNC拒否/パス正規化**: UNCや相対を拒否、ローカル絶対パスのみ許可
- **PATH非依存起動**: bootstrap → guard は同ディレクトリ固定

## このドキュメントの目的

- レイヤ分割と責務の境界を簡潔に示す
- 実装がどこにあるかを素早く把握できるようにする
- 詳細は README / ソースコードを参照
