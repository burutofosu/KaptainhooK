//! 多言語対応（i18n）モジュール
//!
//! 日本語/英語の切り替えをサポート。
//! 設定ファイルの言語設定に基づいてUIテキストを提供。

use kh_domain::error::{ServiceErrorCode, ServiceErrorMessageId};
use kh_domain::model::Language;

/// 翻訳テキストを取得するトレイト
pub trait Translations {
    // === ガードダイアログ ===
    fn guard_title(&self) -> &'static str;
    fn guard_process_confirmation(&self) -> &'static str;
    fn guard_hold_instruction(&self) -> &'static str;
    fn guard_move_instruction(&self) -> &'static str;
    fn guard_emergency_instruction(&self) -> &'static str;
    fn guard_allow(&self) -> &'static str;
    fn guard_cancel(&self) -> &'static str;
    fn guard_ok(&self) -> &'static str;
    fn guard_cli_target(&self) -> &'static str;
    fn guard_cli_args(&self) -> &'static str;
    fn guard_cli_path(&self) -> &'static str;
    fn guard_cli_user(&self) -> &'static str;
    fn guard_cli_message(&self) -> &'static str;
    fn guard_cli_simulating_hold(&self, ms: u64) -> String;
    fn guard_cli_hold_complete(&self) -> &'static str;
    fn guard_cli_allow_prompt(&self) -> &'static str;
    fn guard_cli_prompt(&self) -> &'static str;
    fn guard_hello_prompt(&self, target: &str) -> String;

    // === ガード通知/エラー ===
    fn guard_error_config_load_failed(&self) -> &'static str;
    fn guard_error_targets_unavailable(&self) -> &'static str;
    fn guard_error_target_not_found(&self) -> &'static str;
    fn guard_error_launch_failed(&self, detail: &str) -> String;
    fn guard_error_service_stopped(&self) -> &'static str;
    fn guard_info_service_restart(&self) -> &'static str;
    fn guard_error_service_comm_failed(&self, detail: &str) -> String;
    fn guard_warn_notify_unknown_origin(&self) -> &'static str;
    fn guard_warn_notify_origin(&self, categories: &str) -> String;
    fn guard_warn_suspicious_paths(&self, target: &str, related: &str, reasons: &str) -> String;
    fn guard_service_error_code(&self, code: ServiceErrorCode) -> String;
    fn guard_service_error_message_id(&self, id: ServiceErrorMessageId) -> String;

    // === セットアップウィザード ===
    fn setup_welcome(&self) -> &'static str;
    fn setup_admin_check(&self) -> &'static str;
    fn setup_target_selection(&self) -> &'static str;
    fn setup_conflict_check(&self) -> &'static str;
    fn setup_installing(&self) -> &'static str;
    fn setup_task_registration(&self) -> &'static str;
    fn setup_complete(&self) -> &'static str;
    fn setup_error(&self) -> &'static str;
    fn setup_title(&self) -> &'static str;

    fn setup_welcome_title(&self) -> &'static str;
    fn setup_welcome_desc(&self) -> &'static str;
    fn setup_step1(&self) -> &'static str;
    fn setup_step2(&self) -> &'static str;
    fn setup_step3(&self) -> &'static str;
    fn setup_step4(&self) -> &'static str;
    fn setup_step5(&self) -> &'static str;
    fn setup_start(&self) -> &'static str;
    fn setup_continue(&self) -> &'static str;
    fn setup_finish(&self) -> &'static str;
    fn setup_close(&self) -> &'static str;

    fn setup_admin_confirmed(&self) -> &'static str;
    fn setup_admin_required(&self) -> &'static str;
    fn setup_admin_restart(&self) -> &'static str;
    fn setup_retry_check(&self) -> &'static str;

    fn setup_select_targets(&self) -> &'static str;
    fn setup_targets_selected(&self, count: usize) -> String;
    fn setup_select_all(&self) -> &'static str;
    fn setup_deselect_all(&self) -> &'static str;

    fn setup_no_conflicts(&self) -> &'static str;
    fn setup_conflicts_detected(&self, count: usize) -> String;
    fn setup_conflict_handle(&self) -> &'static str;
    fn setup_conflict_abort(&self) -> &'static str;
    fn setup_conflict_skip(&self) -> &'static str;
    fn setup_conflict_overwrite(&self) -> &'static str;
    fn setup_conflict_quarantine(&self) -> &'static str;
    fn setup_conflict_abort_desc(&self) -> &'static str;
    fn setup_conflict_skip_desc(&self) -> &'static str;
    fn setup_conflict_overwrite_desc(&self) -> &'static str;
    fn setup_conflict_quarantine_desc(&self) -> &'static str;
    fn setup_conflict_signature(&self) -> &'static str;
    fn setup_conflict_path_hints(&self) -> &'static str;
    fn setup_cancel_setup(&self) -> &'static str;
    fn setup_continue_install(&self) -> &'static str;

    fn setup_installing_ifeo(&self) -> &'static str;
    fn setup_ifeo_success(&self) -> &'static str;
    fn setup_registering_task(&self) -> &'static str;
    fn setup_task_success(&self) -> &'static str;

    fn setup_complete_title(&self) -> &'static str;
    fn setup_complete_desc(&self) -> &'static str;
    fn setup_complete_behavior(&self) -> &'static str;
    fn setup_next_steps(&self) -> &'static str;
    fn setup_verify_cmd(&self) -> &'static str;
    fn setup_settings_cmd(&self) -> &'static str;

    fn setup_error_occurred(&self) -> &'static str;

    // === 設定 ===
    fn settings_title(&self) -> &'static str;
    fn settings_targets(&self) -> &'static str;
    fn settings_friction(&self) -> &'static str;
    fn settings_policy(&self) -> &'static str;
    fn settings_language(&self) -> &'static str;
    fn settings_save(&self) -> &'static str;
    fn settings_reset(&self) -> &'static str;
    fn settings_apply(&self) -> &'static str;

    fn settings_require_hold(&self) -> &'static str;
    fn settings_hold_duration(&self) -> &'static str;
    fn settings_require_movement(&self) -> &'static str;
    fn settings_movement_threshold(&self) -> &'static str;
    fn settings_emergency_bypass(&self) -> &'static str;
    fn settings_emergency_duration(&self) -> &'static str;

    fn settings_allow_non_interactive(&self) -> &'static str;
    fn settings_timeout(&self) -> &'static str;
    fn settings_search_paths_header(&self) -> &'static str;
    fn settings_search_paths_desc(&self) -> &'static str;
    fn settings_search_paths_empty(&self) -> &'static str;
    fn settings_search_paths_add_hint(&self) -> &'static str;
    fn settings_search_paths_add_help(&self) -> &'static str;

    fn settings_saved(&self) -> &'static str;
    fn settings_save_failed(&self) -> &'static str;

    fn settings_tab_messages(&self) -> &'static str;
    fn settings_tab_reactions(&self) -> &'static str;
    fn settings_tab_about(&self) -> &'static str;

    fn settings_header(&self) -> &'static str;
    fn settings_badge_unsaved(&self) -> &'static str;

    fn settings_status_validation_error(&self, detail: &str) -> String;
    fn settings_status_targets_required(&self) -> &'static str;
    fn settings_status_apply_failed(&self, detail: &str) -> String;
    fn settings_status_save_after_apply_failed(&self, detail: &str) -> String;
    fn settings_status_conflict_detected(&self) -> &'static str;
    fn settings_status_save_aborted(&self) -> &'static str;
    fn settings_status_save_cancelled(&self) -> &'static str;
    fn settings_status_apply_conflicts_failed(&self, detail: &str) -> String;
    fn settings_status_reset_success(&self) -> &'static str;
    fn settings_error_apply_targets_failed(&self, detail: &str) -> String;
    fn settings_error_opengl_required(&self, path: &str) -> String;

    fn settings_conflict_title(&self) -> &'static str;
    fn settings_conflict_intro(&self) -> &'static str;
    fn settings_conflict_instructions(&self) -> &'static str;
    fn settings_conflict_non_string_debugger(&self) -> &'static str;
    fn settings_conflict_signature_unsupported(&self) -> &'static str;

    fn settings_targets_header(&self) -> &'static str;
    fn settings_targets_desc(&self) -> &'static str;
    fn settings_targets_add_header(&self) -> &'static str;
    fn settings_targets_add_hint(&self) -> &'static str;
    fn settings_targets_add_help(&self) -> &'static str;
    fn settings_targets_enabled_count(&self, enabled: usize, total: usize) -> String;
    fn settings_targets_enable_all(&self) -> &'static str;
    fn settings_targets_common_header(&self) -> &'static str;
    fn settings_targets_common_desc(&self) -> &'static str;

    fn settings_messages_header(&self) -> &'static str;
    fn settings_messages_desc(&self) -> &'static str;
    fn settings_messages_empty(&self) -> &'static str;
    fn settings_messages_add_header(&self) -> &'static str;
    fn settings_messages_id_label(&self) -> &'static str;
    fn settings_messages_id_hint(&self) -> &'static str;
    fn settings_messages_text_label(&self) -> &'static str;
    fn settings_messages_text_hint(&self) -> &'static str;
    fn settings_messages_add_button(&self) -> &'static str;
    fn settings_messages_templates_header(&self) -> &'static str;
    fn settings_messages_templates_desc(&self) -> &'static str;
    fn settings_messages_count(&self, count: usize) -> String;

    fn settings_reactions_header(&self) -> &'static str;
    fn settings_reactions_desc(&self) -> &'static str;
    fn settings_reactions_presets_header(&self) -> &'static str;
    fn settings_reactions_preset_all_log(&self) -> &'static str;
    fn settings_reactions_preset_strong(&self) -> &'static str;
    fn settings_reactions_preset_medium(&self) -> &'static str;
    fn settings_reactions_preset_weak(&self) -> &'static str;
    fn settings_reactions_presets_note(&self) -> &'static str;
    fn settings_reactions_overrides_header(&self) -> &'static str;
    fn settings_reactions_kind_log(&self) -> &'static str;
    fn settings_reactions_kind_notify(&self) -> &'static str;
    fn settings_reactions_kind_friction(&self) -> &'static str;
    fn settings_reactions_forced_none(&self) -> &'static str;
    fn settings_reactions_forced_always(&self) -> &'static str;
    fn settings_reactions_forced_logging(&self) -> &'static str;
    fn settings_reactions_table_target(&self) -> &'static str;
    fn settings_reactions_table_forced(&self) -> &'static str;
    fn settings_reactions_table_mail(&self) -> &'static str;
    fn settings_reactions_table_macro(&self) -> &'static str;
    fn settings_reactions_table_relay(&self) -> &'static str;
    fn settings_reactions_table_always(&self) -> &'static str;
    fn settings_reactions_target_enabled(&self, name: &str) -> String;
    fn settings_reactions_target_disabled(&self, name: &str) -> String;
    fn settings_reactions_target_override(&self, name: &str) -> String;
    fn settings_reactions_forced_note(&self) -> &'static str;

    fn settings_friction_desc(&self) -> &'static str;
    fn settings_friction_hold_header(&self) -> &'static str;
    fn settings_friction_hold_label(&self) -> &'static str;
    fn settings_friction_hold_help(&self) -> &'static str;
    fn settings_friction_pointer_header(&self) -> &'static str;
    fn settings_friction_pointer_label(&self) -> &'static str;
    fn settings_friction_pointer_help(&self) -> &'static str;
    fn settings_friction_emergency_header(&self) -> &'static str;
    fn settings_friction_emergency_label(&self) -> &'static str;
    fn settings_friction_emergency_help(&self) -> &'static str;

    fn settings_policy_desc(&self) -> &'static str;
    fn settings_policy_non_interactive_header(&self) -> &'static str;
    fn settings_policy_non_interactive_label(&self) -> &'static str;
    fn settings_policy_non_interactive_help(&self) -> &'static str;
    fn settings_policy_timeout_header(&self) -> &'static str;
    fn settings_policy_timeout_help(&self) -> &'static str;
    fn settings_policy_auth_header(&self) -> &'static str;
    fn settings_policy_auth_friction_label(&self) -> &'static str;
    fn settings_policy_auth_hello_label(&self) -> &'static str;
    fn settings_policy_auth_help(&self) -> &'static str;

    fn settings_language_desc(&self) -> &'static str;
    fn settings_language_note(&self) -> &'static str;

    fn settings_about_header(&self) -> &'static str;
    fn settings_about_version_label(&self) -> &'static str;
    fn settings_about_description(&self) -> &'static str;
    fn settings_about_protected_desc(&self) -> &'static str;
    fn settings_about_paths_header(&self) -> &'static str;
    fn settings_about_data_dir_label(&self) -> &'static str;
    fn settings_about_config_file_label(&self) -> &'static str;
    fn settings_about_license_label(&self) -> &'static str;

    // === トレイ ===
    fn tray_tooltip(&self) -> &'static str;
    fn tray_settings(&self) -> &'static str;
    fn tray_status(&self) -> &'static str;
    fn tray_restart(&self) -> &'static str;
    fn tray_enable_all(&self) -> &'static str;
    fn tray_disable_all(&self) -> &'static str;
    fn tray_exit(&self) -> &'static str;

    fn tray_status_title(&self) -> &'static str;
    fn tray_restart_started(&self) -> &'static str;
    fn tray_restart_missing(&self) -> &'static str;
    fn tray_no_targets(&self) -> &'static str;
    fn tray_protected_targets(&self, count: usize) -> String;
    fn tray_use_settings(&self) -> &'static str;
    fn tray_unavailable(&self) -> &'static str;
    fn tray_error_detail(&self, detail: &str) -> String;
    fn tray_service_running(&self) -> &'static str;
    fn tray_service_stopped(&self) -> &'static str;
    fn tray_service_starting(&self) -> &'static str;
    fn tray_service_stopping(&self) -> &'static str;
    fn tray_service_not_installed(&self) -> &'static str;
    fn tray_service_unknown(&self) -> &'static str;

    // === 共通 ===
    fn common_enabled(&self) -> &'static str;
    fn common_disabled(&self) -> &'static str;
    fn common_yes(&self) -> &'static str;
    fn common_no(&self) -> &'static str;
    fn common_ms(&self) -> &'static str;
    fn common_seconds(&self) -> &'static str;
    fn common_px(&self) -> &'static str;
    fn common_add(&self) -> &'static str;
    fn common_remove(&self) -> &'static str;
    fn common_edit(&self) -> &'static str;
    fn common_cancel(&self) -> &'static str;
    fn common_note(&self) -> &'static str;
    fn common_view_64(&self) -> &'static str;
    fn common_view_32(&self) -> &'static str;
    fn common_signature_signed(&self, kind: &str) -> String;
    fn common_signature_trust(&self, trust: &str) -> String;
    fn common_signature_revocation(&self, revocation: &str) -> String;
    fn common_signature_subject(&self, subject: &str) -> String;
    fn common_signature_issuer(&self, issuer: &str) -> String;
    fn common_signature_unsigned(&self) -> &'static str;
    fn common_signature_error(&self, message: &str) -> String;
    fn common_signature_unsupported(&self, reason: &str) -> String;
    fn common_signature_notice_unsigned(&self) -> &'static str;
    fn common_signature_notice_untrusted(&self) -> &'static str;
    fn common_signature_notice_revoked(&self) -> &'static str;
    fn common_signature_notice_revocation_not_checked(&self) -> &'static str;
    fn common_signature_notice_revocation_check_failed(&self) -> &'static str;
    fn common_signature_notice_error(&self) -> &'static str;
    fn common_signature_notice_unsupported(&self) -> &'static str;
    fn common_path_hint_public_user_dir(&self) -> &'static str;
    fn common_path_hint_temp_dir(&self) -> &'static str;
    fn common_path_hint_user_temp_dir(&self) -> &'static str;
    fn common_path_hint_downloads_dir(&self) -> &'static str;
    fn common_path_hint_desktop_dir(&self) -> &'static str;
    fn common_path_hint_program_files_dir(&self) -> &'static str;
    fn common_path_hint_program_files_x86_dir(&self) -> &'static str;
    fn common_path_hint_system32_dir(&self) -> &'static str;
    fn common_path_hint_syswow64_dir(&self) -> &'static str;
    fn signature_kind_authenticode(&self) -> &'static str;
    fn signature_trust_trusted(&self) -> &'static str;
    fn signature_trust_untrusted(&self) -> &'static str;
    fn signature_trust_unknown(&self) -> &'static str;
    fn signature_revocation_good(&self) -> &'static str;
    fn signature_revocation_revoked(&self) -> &'static str;
    fn signature_revocation_not_checked(&self, reason: &str) -> String;
    fn signature_revocation_check_failed(&self, reason: &str) -> String;
}

/// 日本語翻訳
pub struct Japanese;

impl Translations for Japanese {
    fn guard_title(&self) -> &'static str { "KaptainhooK ガード" }
    fn guard_process_confirmation(&self) -> &'static str { "プロセス実行の確認" }
    fn guard_hold_instruction(&self) -> &'static str { "クリックまたはスペースを押し続ける" }
    fn guard_move_instruction(&self) -> &'static str { "マウスを移動" }
    fn guard_emergency_instruction(&self) -> &'static str { "緊急回避: Ctrl+Shift+Altを押し続ける" }
    fn guard_allow(&self) -> &'static str { "許可" }
    fn guard_cancel(&self) -> &'static str { "キャンセル" }
    fn guard_ok(&self) -> &'static str { "OK" }
    fn guard_cli_target(&self) -> &'static str { "対象" }
    fn guard_cli_args(&self) -> &'static str { "引数" }
    fn guard_cli_path(&self) -> &'static str { "パス" }
    fn guard_cli_user(&self) -> &'static str { "ユーザー" }
    fn guard_cli_message(&self) -> &'static str { "メッセージ" }
    fn guard_cli_simulating_hold(&self, ms: u64) -> String { format!("{}msのホールドをシミュレート中...", ms) }
    fn guard_cli_hold_complete(&self) -> &'static str { "ホールド完了。" }
    fn guard_cli_allow_prompt(&self) -> &'static str { "実行を許可しますか？(y/n)" }
    fn guard_cli_prompt(&self) -> &'static str { "> " }
    fn guard_hello_prompt(&self, target: &str) -> String {
        format!(
            "{}の実行を許可しますか？\nKaptainhooKの確認が必要です。",
            target
        )
    }

    fn guard_error_config_load_failed(&self) -> &'static str {
        "設定ファイルを読み取れません。再インストールまたは管理者に連絡してください。"
    }
    fn guard_error_targets_unavailable(&self) -> &'static str {
        "保護対象リストを読み取れません。再インストールまたは管理者に連絡してください。"
    }
    fn guard_error_target_not_found(&self) -> &'static str {
        "許可済みの検索パスに対象が見つかりません。設定で検索パスを追加してください。"
    }
    fn guard_error_launch_failed(&self, detail: &str) -> String {
        format!("起動に失敗しました: {}", detail)
    }
    fn guard_error_service_stopped(&self) -> &'static str {
        "サービスが停止しているため許可できません。"
    }
    fn guard_info_service_restart(&self) -> &'static str {
        "サービスの再起動を試みています。"
    }
    fn guard_error_service_comm_failed(&self, detail: &str) -> String {
        format!("サービスとの通信に失敗しました: {}", detail)
    }
    fn guard_warn_notify_unknown_origin(&self) -> &'static str {
        "警告: 起動元カテゴリを特定できませんが、通知のみで許可します。"
    }
    fn guard_warn_notify_origin(&self, categories: &str) -> String {
        format!("警告: 起動元カテゴリ({})。通知のみで許可します。", categories)
    }
    fn guard_warn_suspicious_paths(&self, target: &str, related: &str, reasons: &str) -> String {
        format!(
            "注意: 関連パスの場所が通常と異なる可能性があります。\n対象: {}\n関連: {}\n理由: {}",
            target, related, reasons
        )
    }
    fn guard_service_error_code(&self, code: ServiceErrorCode) -> String {
        match code {
            ServiceErrorCode::ProtocolVersionMismatch | ServiceErrorCode::ClientNotTrusted => {
                "インストールが破損/不整合の可能性があります。再インストールするか、バイナリ差し替え後は kh-cli trusted-hashes refresh を実行してください。"
                    .to_string()
            }
            ServiceErrorCode::TargetsUnavailable => {
                "保護対象リストを読み取れません。再インストールまたは管理者に連絡してください。"
                    .to_string()
            }
            ServiceErrorCode::TargetNotAllowed => {
                "この対象は保護対象に含まれていません（設定を確認してください）。".to_string()
            }
            ServiceErrorCode::Busy => {
                "他の管理操作が実行中です。少し待って再試行してください。".to_string()
            }
            ServiceErrorCode::ForeignDetected => {
                "他製品のIFEO Debuggerが検出されました。設定画面で競合を解決してください。"
                    .to_string()
            }
            ServiceErrorCode::InvalidLease | ServiceErrorCode::LeaseExpired => {
                "一時許可が期限切れ/無効です。もう一度試してください。".to_string()
            }
            ServiceErrorCode::InternalError => {
                "サービス内部エラーです。サービス再起動（kh-service-restart）を試してください。"
                    .to_string()
            }
            ServiceErrorCode::MessageTooLarge => {
                "サービスとの通信に失敗しました。".to_string()
            }
        }
    }
    fn guard_service_error_message_id(&self, id: ServiceErrorMessageId) -> String {
        match id {
            ServiceErrorMessageId::InvalidTargetName => {
                "対象名が無効です。設定を確認してください。".to_string()
            }
            ServiceErrorMessageId::FailedReadProtectedTargets => {
                "保護対象リストを読み取れません。再インストールまたは管理者に連絡してください。"
                    .to_string()
            }
            ServiceErrorMessageId::StateLockPoisoned => {
                "サービス内部状態のロックに失敗しました。サービス再起動を試してください。"
                    .to_string()
            }
            ServiceErrorMessageId::ForeignDetectedDuringRestore => {
                "復元中に他製品のIFEO Debuggerが検出されました。設定画面で競合を解決してください。"
                    .to_string()
            }
            ServiceErrorMessageId::FailedRestoreStaleLease => {
                "期限切れの復元に失敗しました。サービス再起動を試してください。".to_string()
            }
            ServiceErrorMessageId::FailedReadLeaseState => {
                "リース情報の読み取りに失敗しました。サービス再起動を試してください。"
                    .to_string()
            }
            ServiceErrorMessageId::FailedKickRestoreTask => {
                "復元タスクの起動に失敗しました。設定を確認してください。".to_string()
            }
            ServiceErrorMessageId::FailedAcquireIfeoMutex => {
                "IFEO操作のロック取得に失敗しました。少し待って再試行してください。"
                    .to_string()
            }
            ServiceErrorMessageId::ForeignDebuggerInView => {
                "他製品のIFEO Debuggerが検出されました。設定画面で競合を解決してください。"
                    .to_string()
            }
            ServiceErrorMessageId::IfeoEntryMissingInView => {
                "IFEO登録が片側欠損です。設定で削除するかアンインストールで修復してください。"
                    .to_string()
            }
            ServiceErrorMessageId::FailedWriteLeaseState => {
                "リース情報の書き込みに失敗しました。サービス再起動を試してください。"
                    .to_string()
            }
            ServiceErrorMessageId::FailedDisableIfeo => {
                "IFEOの一時解除に失敗しました。サービス再起動を試してください。"
                    .to_string()
            }
            ServiceErrorMessageId::FailedParseRequest => {
                "サービスの要求解析に失敗しました。再試行してください。".to_string()
            }
            ServiceErrorMessageId::MessageTooLarge => {
                "IPCメッセージが大きすぎます。".to_string()
            }
        }
    }

    fn setup_welcome(&self) -> &'static str { "ようこそ" }
    fn setup_admin_check(&self) -> &'static str { "管理者権限の確認" }
    fn setup_target_selection(&self) -> &'static str { "対象の選択" }
    fn setup_conflict_check(&self) -> &'static str { "競合の確認" }
    fn setup_installing(&self) -> &'static str { "インストール中" }
    fn setup_task_registration(&self) -> &'static str { "タスク登録" }
    fn setup_complete(&self) -> &'static str { "完了" }
    fn setup_error(&self) -> &'static str { "エラー" }
    fn setup_title(&self) -> &'static str { "KaptainhooK セットアップ" }

    fn setup_welcome_title(&self) -> &'static str { "KaptainhooK セットアップへようこそ" }
    fn setup_welcome_desc(&self) -> &'static str { "このウィザードでは以下の手順を実行します:" }
    fn setup_step1(&self) -> &'static str { "管理者権限の確認" }
    fn setup_step2(&self) -> &'static str { "保護対象の選択" }
    fn setup_step3(&self) -> &'static str { "競合の確認" }
    fn setup_step4(&self) -> &'static str { "IFEOエントリのインストール" }
    fn setup_step5(&self) -> &'static str { "スケジュールタスクの登録" }
    fn setup_start(&self) -> &'static str { "セットアップ開始" }
    fn setup_continue(&self) -> &'static str { "続行" }
    fn setup_finish(&self) -> &'static str { "完了" }
    fn setup_close(&self) -> &'static str { "閉じる" }

    fn setup_admin_confirmed(&self) -> &'static str { "管理者権限が確認されました。" }
    fn setup_admin_required(&self) -> &'static str { "管理者権限が必要です！" }
    fn setup_admin_restart(&self) -> &'static str { "このアプリケーションを管理者として再起動してください。" }
    fn setup_retry_check(&self) -> &'static str { "再確認" }

    fn setup_select_targets(&self) -> &'static str { "保護する実行ファイルを選択してください:" }
    fn setup_targets_selected(&self, count: usize) -> String { format!("{}個の対象を選択中", count) }
    fn setup_select_all(&self) -> &'static str { "すべて選択" }
    fn setup_deselect_all(&self) -> &'static str { "すべて解除" }

    fn setup_no_conflicts(&self) -> &'static str { "競合は検出されませんでした。" }
    fn setup_conflicts_detected(&self, count: usize) -> String { format!("{}件の競合が検出されました", count) }
    fn setup_conflict_handle(&self) -> &'static str { "競合ごとの処理方法を選択してください:" }
    fn setup_conflict_abort(&self) -> &'static str { "中止" }
    fn setup_conflict_skip(&self) -> &'static str { "尊重" }
    fn setup_conflict_overwrite(&self) -> &'static str { "引き継ぎ" }
    fn setup_conflict_quarantine(&self) -> &'static str { "隔離" }
    fn setup_conflict_abort_desc(&self) -> &'static str { "インストールを中止します。" }
    fn setup_conflict_skip_desc(&self) -> &'static str { "既存Debuggerを維持し、その対象は保護しません。" }
    fn setup_conflict_overwrite_desc(&self) -> &'static str { "既存エントリをバックアップして上書きします。" }
    fn setup_conflict_quarantine_desc(&self) -> &'static str { "不審とみなし隔離として上書きします（バックアップあり）。" }
    fn setup_conflict_signature(&self) -> &'static str { "署名" }
    fn setup_conflict_path_hints(&self) -> &'static str { "パスヒント" }
    fn setup_cancel_setup(&self) -> &'static str { "セットアップを中止" }
    fn setup_continue_install(&self) -> &'static str { "インストールを続行" }

    fn setup_installing_ifeo(&self) -> &'static str { "IFEOエントリをインストール中..." }
    fn setup_ifeo_success(&self) -> &'static str { "IFEOエントリのインストールが完了しました。" }
    fn setup_registering_task(&self) -> &'static str { "スケジュールタスクを登録中..." }
    fn setup_task_success(&self) -> &'static str { "スケジュールタスクの登録が完了しました。" }

    fn setup_complete_title(&self) -> &'static str { "セットアップ完了！" }
    fn setup_complete_desc(&self) -> &'static str { "KaptainhooKのインストールが正常に完了しました。" }
    fn setup_complete_behavior(&self) -> &'static str { "保護された実行ファイルは実行前に確認を求めるようになります。" }
    fn setup_next_steps(&self) -> &'static str { "次のステップ" }
    fn setup_verify_cmd(&self) -> &'static str { "'kh-cli status'でインストールを確認" }
    fn setup_settings_cmd(&self) -> &'static str { "'kh-settings'で設定を変更" }

    fn setup_error_occurred(&self) -> &'static str { "エラーが発生しました" }

    fn settings_title(&self) -> &'static str { "KaptainhooK 設定" }
    fn settings_targets(&self) -> &'static str { "保護対象" }
    fn settings_friction(&self) -> &'static str { "フリクション設定" }
    fn settings_policy(&self) -> &'static str { "ポリシー設定" }
    fn settings_language(&self) -> &'static str { "言語" }
    fn settings_save(&self) -> &'static str { "保存" }
    fn settings_reset(&self) -> &'static str { "リセット" }
    fn settings_apply(&self) -> &'static str { "適用" }

    fn settings_require_hold(&self) -> &'static str { "ホールド（長押し）を要求" }
    fn settings_hold_duration(&self) -> &'static str { "ホールド時間" }
    fn settings_require_movement(&self) -> &'static str { "マウス移動を要求" }
    fn settings_movement_threshold(&self) -> &'static str { "移動閾値" }
    fn settings_emergency_bypass(&self) -> &'static str { "緊急バイパス" }
    fn settings_emergency_duration(&self) -> &'static str { "緊急ホールド時間" }

    fn settings_allow_non_interactive(&self) -> &'static str { "非対話セッションを許可" }
    fn settings_timeout(&self) -> &'static str { "タイムアウト" }
    fn settings_search_paths_header(&self) -> &'static str { "検索パス" }
    fn settings_search_paths_desc(&self) -> &'static str { "安全な検索範囲にない実行ファイルは見つかりません。必要なら追加してください。" }
    fn settings_search_paths_empty(&self) -> &'static str { "追加された検索パスはありません。" }
    fn settings_search_paths_add_hint(&self) -> &'static str { "C:\\\\Program Files\\\\Example" }
    fn settings_search_paths_add_help(&self) -> &'static str { "絶対パスのみ追加できます。" }

    fn settings_saved(&self) -> &'static str { "設定を保存しました" }
    fn settings_save_failed(&self) -> &'static str { "設定の保存に失敗しました" }
    fn settings_tab_messages(&self) -> &'static str { "メッセージ" }
    fn settings_tab_reactions(&self) -> &'static str { "反応" }
    fn settings_tab_about(&self) -> &'static str { "情報" }
    fn settings_header(&self) -> &'static str { "設定" }
    fn settings_badge_unsaved(&self) -> &'static str { "未保存" }
    fn settings_status_validation_error(&self, detail: &str) -> String { format!("検証エラー: {}", detail) }
    fn settings_status_targets_required(&self) -> &'static str { "少なくとも1つの対象を有効にしてください。再有効化するかアンインストールしてください。" }
    fn settings_status_apply_failed(&self, detail: &str) -> String { format!("IFEO変更の適用に失敗しました: {}", detail) }
    fn settings_status_save_after_apply_failed(&self, detail: &str) -> String {
        format!("IFEO変更は適用されましたが、設定の保存に失敗しました: {}", detail)
    }
    fn settings_status_conflict_detected(&self) -> &'static str { "他製品のDebuggerを検出しました。競合を解決してから保存してください。" }
    fn settings_status_save_aborted(&self) -> &'static str { "競合処理により保存を中止しました。" }
    fn settings_status_save_cancelled(&self) -> &'static str { "保存をキャンセルしました。競合を解決して続行してください。" }
    fn settings_status_apply_conflicts_failed(&self, detail: &str) -> String { format!("競合の適用に失敗しました: {}", detail) }
    fn settings_status_reset_success(&self) -> &'static str { "保存済みの状態にリセットしました。" }
    fn settings_error_apply_targets_failed(&self, detail: &str) -> String {
        format!("設定の適用/保存に失敗しました:\n\n{}", detail)
    }
    fn settings_error_opengl_required(&self, path: &str) -> String {
        format!(
            "Settings GUIにはWebView2 Runtimeが必要です（この環境では利用できません）。\n\n\
設定を編集するには、設定ファイルを直接編集してください:\n{}",
            path
        )
    }
    fn settings_conflict_title(&self) -> &'static str { "他製品のDebuggerを検出" }
    fn settings_conflict_intro(&self) -> &'static str { "以下の対象で既存のDebuggerが見つかりました。" }
    fn settings_conflict_instructions(&self) -> &'static str { "対象ごとに処理方法を選択してください:" }
    fn settings_conflict_non_string_debugger(&self) -> &'static str { "<非文字列Debugger>" }
    fn settings_conflict_signature_unsupported(&self) -> &'static str { "未対応（非文字列Debugger）" }
    fn settings_targets_header(&self) -> &'static str { "保護対象" }
    fn settings_targets_desc(&self) -> &'static str { "保護する実行ファイルを選択してください。" }
    fn settings_targets_add_header(&self) -> &'static str { "新しい対象を追加" }
    fn settings_targets_add_hint(&self) -> &'static str { "例: mshta.exe" }
    fn settings_targets_add_help(&self) -> &'static str { ".exe で終わる実行ファイル名を入力してください。" }
    fn settings_targets_enabled_count(&self, enabled: usize, total: usize) -> String { format!("有効: {}/{}", enabled, total) }
    fn settings_targets_enable_all(&self) -> &'static str { "すべて有効化" }
    fn settings_targets_common_header(&self) -> &'static str { "よく使うLOLBins" }
    fn settings_targets_common_desc(&self) -> &'static str { "よく使う対象を追加:" }
    fn settings_messages_header(&self) -> &'static str { "ナッジメッセージ" }
    fn settings_messages_desc(&self) -> &'static str { "確認ダイアログに表示する警告メッセージを設定します。" }
    fn settings_messages_empty(&self) -> &'static str { "カスタムメッセージがありません。既定のメッセージが使用されます。" }
    fn settings_messages_add_header(&self) -> &'static str { "新しいメッセージを追加" }
    fn settings_messages_id_label(&self) -> &'static str { "ID:" }
    fn settings_messages_id_hint(&self) -> &'static str { "例: warn-01" }
    fn settings_messages_text_label(&self) -> &'static str { "本文:" }
    fn settings_messages_text_hint(&self) -> &'static str { "表示する警告文..." }
    fn settings_messages_add_button(&self) -> &'static str { "メッセージを追加" }
    fn settings_messages_templates_header(&self) -> &'static str { "メッセージテンプレート" }
    fn settings_messages_templates_desc(&self) -> &'static str { "よく使う警告文を追加:" }
    fn settings_messages_count(&self, count: usize) -> String { format!("{}件のメッセージが設定されています。先頭のメッセージがダイアログに表示されます。", count) }
    fn settings_reactions_header(&self) -> &'static str { "反応ルール" }
    fn settings_reactions_desc(&self) -> &'static str { "起動元カテゴリと対象ごとの設定で対応を決めます。" }
    fn settings_reactions_presets_header(&self) -> &'static str { "プリセット" }
    fn settings_reactions_preset_all_log(&self) -> &'static str { "ログのみ" }
    fn settings_reactions_preset_strong(&self) -> &'static str { "強: すべて確認" }
    fn settings_reactions_preset_medium(&self) -> &'static str { "中: メール/マクロ=確認・中継=通知" }
    fn settings_reactions_preset_weak(&self) -> &'static str { "弱: メール/マクロ=通知・中継=ログ" }
    fn settings_reactions_presets_note(&self) -> &'static str { "プリセットは既定ルールのみ更新。上書きは保持。" }
    fn settings_reactions_overrides_header(&self) -> &'static str { "対象ごとの上書き" }
    fn settings_reactions_kind_log(&self) -> &'static str { "ログ" }
    fn settings_reactions_kind_notify(&self) -> &'static str { "通知" }
    fn settings_reactions_kind_friction(&self) -> &'static str { "確認" }
    fn settings_reactions_forced_none(&self) -> &'static str { "起動元で決める" }
    fn settings_reactions_forced_always(&self) -> &'static str { "固定" }
    fn settings_reactions_forced_logging(&self) -> &'static str { "ログ固定" }
    fn settings_reactions_table_target(&self) -> &'static str { "対象" }
    fn settings_reactions_table_forced(&self) -> &'static str { "判定方法" }
    fn settings_reactions_table_mail(&self) -> &'static str { "メール" }
    fn settings_reactions_table_macro(&self) -> &'static str { "マクロ" }
    fn settings_reactions_table_relay(&self) -> &'static str { "中継" }
    fn settings_reactions_table_always(&self) -> &'static str { "固定" }
    fn settings_reactions_target_enabled(&self, name: &str) -> String { format!("{name}（有効）") }
    fn settings_reactions_target_disabled(&self, name: &str) -> String { format!("{name}（無効）") }
    fn settings_reactions_target_override(&self, name: &str) -> String { format!("{name}（上書き）") }
    fn settings_reactions_forced_note(&self) -> &'static str { "判定方法が固定の場合は「固定」の設定だけが使われます。" }
    fn settings_friction_desc(&self) -> &'static str { "確認ダイアログの挙動を設定します。" }
    fn settings_friction_hold_header(&self) -> &'static str { "ホールド確認" }
    fn settings_friction_hold_label(&self) -> &'static str { "ホールドで確認を必須にする" }
    fn settings_friction_hold_help(&self) -> &'static str { "クリック/スペースを保持する時間" }
    fn settings_friction_pointer_header(&self) -> &'static str { "ポインター移動" }
    fn settings_friction_pointer_label(&self) -> &'static str { "ポインター移動を必須にする" }
    fn settings_friction_pointer_help(&self) -> &'static str { "マウス移動の最小距離" }
    fn settings_friction_emergency_header(&self) -> &'static str { "緊急バイパス" }
    fn settings_friction_emergency_label(&self) -> &'static str { "緊急バイパスを許可" }
    fn settings_friction_emergency_help(&self) -> &'static str { "Ctrl+Shift+Altを押し続けてフリクションを回避します。" }
    fn settings_policy_desc(&self) -> &'static str { "各シナリオでの挙動を設定します。" }
    fn settings_policy_non_interactive_header(&self) -> &'static str { "非対話セッション" }
    fn settings_policy_non_interactive_label(&self) -> &'static str { "非対話セッションでの実行を許可" }
    fn settings_policy_non_interactive_help(&self) -> &'static str { "無効時はサービス/バッチからの実行をブロックします。" }
    fn settings_policy_timeout_header(&self) -> &'static str { "ダイアログタイムアウト" }
    fn settings_policy_timeout_help(&self) -> &'static str { "0は無期限です。指定時間後に自動で拒否します。" }
    fn settings_policy_auth_header(&self) -> &'static str { "認証方式" }
    fn settings_policy_auth_friction_label(&self) -> &'static str { "フリクション（ホールド＋ポインター移動）" }
    fn settings_policy_auth_hello_label(&self) -> &'static str { "Windows Hello" }
    fn settings_policy_auth_help(&self) -> &'static str { "実行確認の方法を選択します。" }
    fn settings_language_desc(&self) -> &'static str { "表示言語を選択" }
    fn settings_language_note(&self) -> &'static str { "注意: 言語変更は他の設定と一緒に保存されます。" }
    fn settings_about_header(&self) -> &'static str { "KaptainhooKについて" }
    fn settings_about_version_label(&self) -> &'static str { "バージョン" }
    fn settings_about_description(&self) -> &'static str { "KaptainhooKはIFEO（Image File Execution Options）を利用してLOLBinの実行を保護するWindows向けセキュリティツールです。" }
    fn settings_about_protected_desc(&self) -> &'static str { "PowerShell、cmd.exe、wscript、cscriptなど、よく悪用されるシステムツールが対象です。" }
    fn settings_about_paths_header(&self) -> &'static str { "設定パス" }
    fn settings_about_data_dir_label(&self) -> &'static str { "データディレクトリ:" }
    fn settings_about_config_file_label(&self) -> &'static str { "設定ファイル:" }
    fn settings_about_license_label(&self) -> &'static str { "ライセンス:" }

    fn tray_tooltip(&self) -> &'static str { "KaptainhooK - LOLBin保護" }
    fn tray_settings(&self) -> &'static str { "設定..." }
    fn tray_status(&self) -> &'static str { "サービス状態" }
    fn tray_restart(&self) -> &'static str { "サービス再起動" }
    fn tray_enable_all(&self) -> &'static str { "すべて有効化" }
    fn tray_disable_all(&self) -> &'static str { "すべて無効化" }
    fn tray_exit(&self) -> &'static str { "終了" }

    fn tray_status_title(&self) -> &'static str { "KaptainhooK サービス" }
    fn tray_restart_started(&self) -> &'static str { "サービスの再起動を開始しました。" }
    fn tray_restart_missing(&self) -> &'static str { "再起動ツールが見つかりません。" }
    fn tray_no_targets(&self) -> &'static str { "現在保護されている対象はありません。\n\n設定を実行して構成してください。" }
    fn tray_protected_targets(&self, count: usize) -> String { format!("保護中の対象 ({}):", count) }
    fn tray_use_settings(&self) -> &'static str { "対象の有効/無効を切り替えるには設定を使用してください。\n\nトレイメニューの「設定...」をクリックしてください。" }
    fn tray_unavailable(&self) -> &'static str { "システムトレイはWindowsでのみ利用できます。" }
    fn tray_error_detail(&self, detail: &str) -> String { format!("エラー: {}", detail) }
    fn tray_service_running(&self) -> &'static str { "サービスは動作中です。" }
    fn tray_service_stopped(&self) -> &'static str { "サービスが停止しています。" }
    fn tray_service_starting(&self) -> &'static str { "サービスを起動中です。" }
    fn tray_service_stopping(&self) -> &'static str { "サービスを停止中です。" }
    fn tray_service_not_installed(&self) -> &'static str { "サービスがインストールされていません。" }
    fn tray_service_unknown(&self) -> &'static str { "サービスの状態が不明です。" }

    fn common_enabled(&self) -> &'static str { "有効" }
    fn common_disabled(&self) -> &'static str { "無効" }
    fn common_yes(&self) -> &'static str { "はい" }
    fn common_no(&self) -> &'static str { "いいえ" }
    fn common_ms(&self) -> &'static str { "ミリ秒" }
    fn common_seconds(&self) -> &'static str { "秒" }
    fn common_px(&self) -> &'static str { "ピクセル" }
    fn common_add(&self) -> &'static str { "追加" }
    fn common_remove(&self) -> &'static str { "削除" }
    fn common_edit(&self) -> &'static str { "編集" }
    fn common_cancel(&self) -> &'static str { "キャンセル" }
    fn common_note(&self) -> &'static str { "注記" }
    fn common_view_64(&self) -> &'static str { "64ビット" }
    fn common_view_32(&self) -> &'static str { "32ビット" }
    fn common_signature_signed(&self, kind: &str) -> String { format!("署名あり ({})", kind) }
    fn common_signature_trust(&self, trust: &str) -> String { format!("信頼={}", trust) }
    fn common_signature_revocation(&self, revocation: &str) -> String { format!("失効={}", revocation) }
    fn common_signature_subject(&self, subject: &str) -> String { format!("サブジェクト={}", subject) }
    fn common_signature_issuer(&self, issuer: &str) -> String { format!("発行者={}", issuer) }
    fn common_signature_unsigned(&self) -> &'static str { "署名なし" }
    fn common_signature_error(&self, message: &str) -> String { format!("エラー ({})", message) }
    fn common_signature_unsupported(&self, reason: &str) -> String { format!("未対応 ({})", reason) }
    fn common_signature_notice_unsigned(&self) -> &'static str { "署名なし" }
    fn common_signature_notice_untrusted(&self) -> &'static str { "信頼されていない署名" }
    fn common_signature_notice_revoked(&self) -> &'static str { "失効済みの署名" }
    fn common_signature_notice_revocation_not_checked(&self) -> &'static str { "失効確認なし" }
    fn common_signature_notice_revocation_check_failed(&self) -> &'static str { "失効確認失敗" }
    fn common_signature_notice_error(&self) -> &'static str { "署名検証エラー" }
    fn common_signature_notice_unsupported(&self) -> &'static str { "署名検証未対応" }
    fn common_path_hint_public_user_dir(&self) -> &'static str { "公開ユーザー配下" }
    fn common_path_hint_temp_dir(&self) -> &'static str { "Temp 配下" }
    fn common_path_hint_user_temp_dir(&self) -> &'static str { "ユーザー Temp 配下" }
    fn common_path_hint_downloads_dir(&self) -> &'static str { "ダウンロード配下" }
    fn common_path_hint_desktop_dir(&self) -> &'static str { "デスクトップ配下" }
    fn common_path_hint_program_files_dir(&self) -> &'static str { "Program Files 配下" }
    fn common_path_hint_program_files_x86_dir(&self) -> &'static str { "Program Files (x86) 配下" }
    fn common_path_hint_system32_dir(&self) -> &'static str { "System32 配下" }
    fn common_path_hint_syswow64_dir(&self) -> &'static str { "SysWOW64 配下" }
    fn signature_kind_authenticode(&self) -> &'static str { "Authenticode" }
    fn signature_trust_trusted(&self) -> &'static str { "信頼済み" }
    fn signature_trust_untrusted(&self) -> &'static str { "未信頼" }
    fn signature_trust_unknown(&self) -> &'static str { "不明" }
    fn signature_revocation_good(&self) -> &'static str { "失効なし" }
    fn signature_revocation_revoked(&self) -> &'static str { "失効済み" }
    fn signature_revocation_not_checked(&self, reason: &str) -> String { format!("未検査 ({})", reason) }
    fn signature_revocation_check_failed(&self, reason: &str) -> String { format!("検査失敗 ({})", reason) }
}

/// 英語翻訳
pub struct English;

impl Translations for English {
    fn guard_title(&self) -> &'static str { "KaptainhooK Guard" }
    fn guard_process_confirmation(&self) -> &'static str { "Process Execution Confirmation" }
    fn guard_hold_instruction(&self) -> &'static str { "Hold click or space" }
    fn guard_move_instruction(&self) -> &'static str { "Move mouse" }
    fn guard_emergency_instruction(&self) -> &'static str { "Emergency: hold Ctrl+Shift+Alt" }
    fn guard_allow(&self) -> &'static str { "Allow" }
    fn guard_cancel(&self) -> &'static str { "Cancel" }
    fn guard_ok(&self) -> &'static str { "OK" }
    fn guard_cli_target(&self) -> &'static str { "Target" }
    fn guard_cli_args(&self) -> &'static str { "Args" }
    fn guard_cli_path(&self) -> &'static str { "Path" }
    fn guard_cli_user(&self) -> &'static str { "User" }
    fn guard_cli_message(&self) -> &'static str { "Message" }
    fn guard_cli_simulating_hold(&self, ms: u64) -> String { format!("Simulating {}ms hold...", ms) }
    fn guard_cli_hold_complete(&self) -> &'static str { "Hold complete." }
    fn guard_cli_allow_prompt(&self) -> &'static str { "Allow execution? (y/n)" }
    fn guard_cli_prompt(&self) -> &'static str { "> " }
    fn guard_hello_prompt(&self, target: &str) -> String {
        format!(
            "Allow execution of {}?\nKaptainhooK requires your confirmation.",
            target
        )
    }

    fn guard_error_config_load_failed(&self) -> &'static str {
        "Failed to read the config file. Reinstall or contact your administrator."
    }
    fn guard_error_targets_unavailable(&self) -> &'static str {
        "Failed to read the protected target list. Reinstall or contact your administrator."
    }
    fn guard_error_target_not_found(&self) -> &'static str {
        "Target not found in allowed search paths. Add it in settings."
    }
    fn guard_error_launch_failed(&self, detail: &str) -> String {
        format!("Launch failed: {}", detail)
    }
    fn guard_error_service_stopped(&self) -> &'static str {
        "Cannot allow because the service is stopped."
    }
    fn guard_info_service_restart(&self) -> &'static str {
        "Trying to restart the service."
    }
    fn guard_error_service_comm_failed(&self, detail: &str) -> String {
        format!("Failed to communicate with the service: {}", detail)
    }
    fn guard_warn_notify_unknown_origin(&self) -> &'static str {
        "Warning: origin category is unknown, but it will be allowed with notification."
    }
    fn guard_warn_notify_origin(&self, categories: &str) -> String {
        format!("Warning: origin category ({}) - allowed with notification.", categories)
    }
    fn guard_warn_suspicious_paths(&self, target: &str, related: &str, reasons: &str) -> String {
        format!(
            "Notice: related paths may be in unusual locations.\nTarget: {}\nRelated: {}\nReason: {}",
            target, related, reasons
        )
    }
    fn guard_service_error_code(&self, code: ServiceErrorCode) -> String {
        match code {
            ServiceErrorCode::ProtocolVersionMismatch | ServiceErrorCode::ClientNotTrusted => {
                "Install may be corrupted or inconsistent. Reinstall, or run kh-cli trusted-hashes refresh after replacing binaries."
                    .to_string()
            }
            ServiceErrorCode::TargetsUnavailable => {
                "Failed to read the protected target list. Reinstall or contact your administrator."
                    .to_string()
            }
            ServiceErrorCode::TargetNotAllowed => {
                "This target is not protected (check settings).".to_string()
            }
            ServiceErrorCode::Busy => {
                "Another admin operation is running. Please wait and retry.".to_string()
            }
            ServiceErrorCode::ForeignDetected => {
                "Another product's IFEO Debugger was detected. Resolve conflicts in settings."
                    .to_string()
            }
            ServiceErrorCode::InvalidLease | ServiceErrorCode::LeaseExpired => {
                "Temporary permission is expired or invalid. Try again.".to_string()
            }
            ServiceErrorCode::InternalError => {
                "Service internal error. Try restarting the service (kh-service-restart)."
                    .to_string()
            }
            ServiceErrorCode::MessageTooLarge => {
                "Failed to communicate with the service.".to_string()
            }
        }
    }
    fn guard_service_error_message_id(&self, id: ServiceErrorMessageId) -> String {
        match id {
            ServiceErrorMessageId::InvalidTargetName => {
                "Invalid target name. Check settings.".to_string()
            }
            ServiceErrorMessageId::FailedReadProtectedTargets => {
                "Failed to read the protected target list. Reinstall or contact your administrator."
                    .to_string()
            }
            ServiceErrorMessageId::StateLockPoisoned => {
                "Service state lock failed. Try restarting the service.".to_string()
            }
            ServiceErrorMessageId::ForeignDetectedDuringRestore => {
                "Another product's IFEO Debugger was detected during restore. Resolve conflicts in settings."
                    .to_string()
            }
            ServiceErrorMessageId::FailedRestoreStaleLease => {
                "Failed to restore an expired lease. Try restarting the service.".to_string()
            }
            ServiceErrorMessageId::FailedReadLeaseState => {
                "Failed to read lease state. Try restarting the service.".to_string()
            }
            ServiceErrorMessageId::FailedKickRestoreTask => {
                "Failed to trigger the restore task. Check the setup.".to_string()
            }
            ServiceErrorMessageId::FailedAcquireIfeoMutex => {
                "Failed to acquire IFEO lock. Wait and retry.".to_string()
            }
            ServiceErrorMessageId::ForeignDebuggerInView => {
                "Another product's IFEO Debugger was detected. Resolve conflicts in settings."
                    .to_string()
            }
            ServiceErrorMessageId::IfeoEntryMissingInView => {
                "IFEO entries are missing in one view. Remove via settings or repair by uninstalling."
                    .to_string()
            }
            ServiceErrorMessageId::FailedWriteLeaseState => {
                "Failed to write lease state. Try restarting the service.".to_string()
            }
            ServiceErrorMessageId::FailedDisableIfeo => {
                "Failed to disable IFEO temporarily. Try restarting the service.".to_string()
            }
            ServiceErrorMessageId::FailedParseRequest => {
                "Failed to parse service request. Please retry.".to_string()
            }
            ServiceErrorMessageId::MessageTooLarge => {
                "IPC message is too large.".to_string()
            }
        }
    }

    fn setup_welcome(&self) -> &'static str { "Welcome" }
    fn setup_admin_check(&self) -> &'static str { "Administrator Check" }
    fn setup_target_selection(&self) -> &'static str { "Target Selection" }
    fn setup_conflict_check(&self) -> &'static str { "Conflict Check" }
    fn setup_installing(&self) -> &'static str { "Installing" }
    fn setup_task_registration(&self) -> &'static str { "Task Registration" }
    fn setup_complete(&self) -> &'static str { "Complete" }
    fn setup_error(&self) -> &'static str { "Error" }
    fn setup_title(&self) -> &'static str { "KaptainhooK Setup" }

    fn setup_welcome_title(&self) -> &'static str { "Welcome to KaptainhooK Setup" }
    fn setup_welcome_desc(&self) -> &'static str { "This wizard will guide you through:" }
    fn setup_step1(&self) -> &'static str { "Check administrator privileges" }
    fn setup_step2(&self) -> &'static str { "Select targets to protect" }
    fn setup_step3(&self) -> &'static str { "Check for conflicts" }
    fn setup_step4(&self) -> &'static str { "Install IFEO entries" }
    fn setup_step5(&self) -> &'static str { "Register scheduled task" }
    fn setup_start(&self) -> &'static str { "Start Setup" }
    fn setup_continue(&self) -> &'static str { "Continue" }
    fn setup_finish(&self) -> &'static str { "Finish" }
    fn setup_close(&self) -> &'static str { "Close" }

    fn setup_admin_confirmed(&self) -> &'static str { "Administrator privileges confirmed." }
    fn setup_admin_required(&self) -> &'static str { "Administrator privileges required!" }
    fn setup_admin_restart(&self) -> &'static str { "Please restart this application as Administrator." }
    fn setup_retry_check(&self) -> &'static str { "Retry Check" }

    fn setup_select_targets(&self) -> &'static str { "Select which executables to protect:" }
    fn setup_targets_selected(&self, count: usize) -> String { format!("{} targets selected", count) }
    fn setup_select_all(&self) -> &'static str { "Select All" }
    fn setup_deselect_all(&self) -> &'static str { "Deselect All" }

    fn setup_no_conflicts(&self) -> &'static str { "No conflicts detected." }
    fn setup_conflicts_detected(&self, count: usize) -> String { format!("{} conflict(s) detected", count) }
    fn setup_conflict_handle(&self) -> &'static str { "Choose an action for each conflict:" }
    fn setup_conflict_abort(&self) -> &'static str { "Abort" }
    fn setup_conflict_skip(&self) -> &'static str { "Respect" }
    fn setup_conflict_overwrite(&self) -> &'static str { "Take over" }
    fn setup_conflict_quarantine(&self) -> &'static str { "Quarantine" }
    fn setup_conflict_abort_desc(&self) -> &'static str { "Installation will be cancelled." }
    fn setup_conflict_skip_desc(&self) -> &'static str { "Keep existing debuggers and do not protect those targets." }
    fn setup_conflict_overwrite_desc(&self) -> &'static str { "Back up existing entries and overwrite them." }
    fn setup_conflict_quarantine_desc(&self) -> &'static str { "Overwrite as quarantine (backed up)." }
    fn setup_conflict_signature(&self) -> &'static str { "Signature" }
    fn setup_conflict_path_hints(&self) -> &'static str { "Path hints" }
    fn setup_cancel_setup(&self) -> &'static str { "Cancel Setup" }
    fn setup_continue_install(&self) -> &'static str { "Continue to Installation" }

    fn setup_installing_ifeo(&self) -> &'static str { "Installing IFEO entries..." }
    fn setup_ifeo_success(&self) -> &'static str { "IFEO entries installed successfully." }
    fn setup_registering_task(&self) -> &'static str { "Registering scheduled task..." }
    fn setup_task_success(&self) -> &'static str { "Scheduled task registered successfully." }

    fn setup_complete_title(&self) -> &'static str { "Setup Complete!" }
    fn setup_complete_desc(&self) -> &'static str { "KaptainhooK has been successfully installed." }
    fn setup_complete_behavior(&self) -> &'static str { "Protected executables will now prompt for confirmation before running." }
    fn setup_next_steps(&self) -> &'static str { "Next steps" }
    fn setup_verify_cmd(&self) -> &'static str { "Use 'kh-cli status' to verify installation" }
    fn setup_settings_cmd(&self) -> &'static str { "Use 'kh-settings' to modify configuration" }

    fn setup_error_occurred(&self) -> &'static str { "An error occurred" }

    fn settings_title(&self) -> &'static str { "KaptainhooK Settings" }
    fn settings_targets(&self) -> &'static str { "Targets" }
    fn settings_friction(&self) -> &'static str { "Friction Settings" }
    fn settings_policy(&self) -> &'static str { "Policy Settings" }
    fn settings_language(&self) -> &'static str { "Language" }
    fn settings_save(&self) -> &'static str { "Save" }
    fn settings_reset(&self) -> &'static str { "Reset" }
    fn settings_apply(&self) -> &'static str { "Apply" }

    fn settings_require_hold(&self) -> &'static str { "Require Hold" }
    fn settings_hold_duration(&self) -> &'static str { "Hold Duration" }
    fn settings_require_movement(&self) -> &'static str { "Require Mouse Movement" }
    fn settings_movement_threshold(&self) -> &'static str { "Movement Threshold" }
    fn settings_emergency_bypass(&self) -> &'static str { "Emergency Bypass" }
    fn settings_emergency_duration(&self) -> &'static str { "Emergency Hold Duration" }

    fn settings_allow_non_interactive(&self) -> &'static str { "Allow Non-Interactive Sessions" }
    fn settings_timeout(&self) -> &'static str { "Timeout" }
    fn settings_search_paths_header(&self) -> &'static str { "Search Paths" }
    fn settings_search_paths_desc(&self) -> &'static str { "Executables outside the allowed safe paths are not found. Add paths if needed." }
    fn settings_search_paths_empty(&self) -> &'static str { "No additional search paths." }
    fn settings_search_paths_add_hint(&self) -> &'static str { "C:\\\\Program Files\\\\Example" }
    fn settings_search_paths_add_help(&self) -> &'static str { "Absolute paths only." }

    fn settings_saved(&self) -> &'static str { "Settings saved" }
    fn settings_save_failed(&self) -> &'static str { "Failed to save settings" }
    fn settings_tab_messages(&self) -> &'static str { "Messages" }
    fn settings_tab_reactions(&self) -> &'static str { "Reactions" }
    fn settings_tab_about(&self) -> &'static str { "About" }
    fn settings_header(&self) -> &'static str { "Settings" }
    fn settings_badge_unsaved(&self) -> &'static str { "Unsaved" }
    fn settings_status_validation_error(&self, detail: &str) -> String { format!("Validation error: {}", detail) }
    fn settings_status_targets_required(&self) -> &'static str { "At least one target must remain enabled. Re-enable a target or uninstall KaptainhooK." }
    fn settings_status_apply_failed(&self, detail: &str) -> String { format!("Failed to apply IFEO changes: {}", detail) }
    fn settings_status_save_after_apply_failed(&self, detail: &str) -> String {
        format!("IFEO changes were applied, but saving settings failed: {}", detail)
    }
    fn settings_status_conflict_detected(&self) -> &'static str { "Foreign debugger detected. Resolve conflicts before saving." }
    fn settings_status_save_aborted(&self) -> &'static str { "Save aborted due to conflict resolution." }
    fn settings_status_save_cancelled(&self) -> &'static str { "Save cancelled. Resolve conflicts to continue." }
    fn settings_status_apply_conflicts_failed(&self, detail: &str) -> String { format!("Failed to apply conflicts: {}", detail) }
    fn settings_status_reset_success(&self) -> &'static str { "Settings reset to last saved state." }
    fn settings_error_apply_targets_failed(&self, detail: &str) -> String {
        format!("Failed to apply/save settings:\n\n{}", detail)
    }
    fn settings_error_opengl_required(&self, path: &str) -> String {
        format!(
            "Settings GUI requires WebView2 Runtime (not available in this environment).\n\n\
To edit settings, manually edit the config file:\n{}",
            path
        )
    }
    fn settings_conflict_title(&self) -> &'static str { "Foreign Debugger Detected" }
    fn settings_conflict_intro(&self) -> &'static str { "Existing debugger entries were found for the targets below." }
    fn settings_conflict_instructions(&self) -> &'static str { "Choose how to proceed for each target:" }
    fn settings_conflict_non_string_debugger(&self) -> &'static str { "<non-string debugger>" }
    fn settings_conflict_signature_unsupported(&self) -> &'static str { "Unsupported (non-string debugger)" }
    fn settings_targets_header(&self) -> &'static str { "Protected Targets" }
    fn settings_targets_desc(&self) -> &'static str { "Select which executables to protect with KaptainhooK." }
    fn settings_targets_add_header(&self) -> &'static str { "Add New Target" }
    fn settings_targets_add_hint(&self) -> &'static str { "e.g., mshta.exe" }
    fn settings_targets_add_help(&self) -> &'static str { "Enter executable name ending with .exe" }
    fn settings_targets_enabled_count(&self, enabled: usize, total: usize) -> String { format!("{} of {} targets enabled", enabled, total) }
    fn settings_targets_enable_all(&self) -> &'static str { "Enable All" }
    fn settings_targets_common_header(&self) -> &'static str { "Common LOLBins" }
    fn settings_targets_common_desc(&self) -> &'static str { "Click to add common targets:" }
    fn settings_messages_header(&self) -> &'static str { "Nudge Messages" }
    fn settings_messages_desc(&self) -> &'static str { "Custom messages shown in the confirmation dialog to warn users." }
    fn settings_messages_empty(&self) -> &'static str { "No custom messages. Default message will be used." }
    fn settings_messages_add_header(&self) -> &'static str { "Add New Message" }
    fn settings_messages_id_label(&self) -> &'static str { "ID:" }
    fn settings_messages_id_hint(&self) -> &'static str { "e.g., warn-01" }
    fn settings_messages_text_label(&self) -> &'static str { "Text:" }
    fn settings_messages_text_hint(&self) -> &'static str { "Warning message to display..." }
    fn settings_messages_add_button(&self) -> &'static str { "Add Message" }
    fn settings_messages_templates_header(&self) -> &'static str { "Message Templates" }
    fn settings_messages_templates_desc(&self) -> &'static str { "Click to add common warning messages:" }
    fn settings_messages_count(&self, count: usize) -> String { format!("{} message(s) configured. First message will be shown in dialog.", count) }
    fn settings_reactions_header(&self) -> &'static str { "Reaction Rules" }
    fn settings_reactions_desc(&self) -> &'static str { "Configure actions by origin category and per-target settings." }
    fn settings_reactions_presets_header(&self) -> &'static str { "Presets" }
    fn settings_reactions_preset_all_log(&self) -> &'static str { "Log only" }
    fn settings_reactions_preset_strong(&self) -> &'static str { "Strong: always confirm" }
    fn settings_reactions_preset_medium(&self) -> &'static str { "Medium: Mail/Macro=confirm, Relay=notify" }
    fn settings_reactions_preset_weak(&self) -> &'static str { "Weak: Mail/Macro=notify, Relay=log" }
    fn settings_reactions_presets_note(&self) -> &'static str { "Presets update only the default rule. Overrides are kept." }
    fn settings_reactions_overrides_header(&self) -> &'static str { "Per-Target Overrides" }
    fn settings_reactions_kind_log(&self) -> &'static str { "Log" }
    fn settings_reactions_kind_notify(&self) -> &'static str { "Notify" }
    fn settings_reactions_kind_friction(&self) -> &'static str { "Confirm" }
    fn settings_reactions_forced_none(&self) -> &'static str { "By origin" }
    fn settings_reactions_forced_always(&self) -> &'static str { "Fixed" }
    fn settings_reactions_forced_logging(&self) -> &'static str { "Logging" }
    fn settings_reactions_table_target(&self) -> &'static str { "Target" }
    fn settings_reactions_table_forced(&self) -> &'static str { "Decision mode" }
    fn settings_reactions_table_mail(&self) -> &'static str { "Mail" }
    fn settings_reactions_table_macro(&self) -> &'static str { "Macro" }
    fn settings_reactions_table_relay(&self) -> &'static str { "Relay" }
    fn settings_reactions_table_always(&self) -> &'static str { "Fixed" }
    fn settings_reactions_target_enabled(&self, name: &str) -> String { format!("{name} (enabled)") }
    fn settings_reactions_target_disabled(&self, name: &str) -> String { format!("{name} (disabled)") }
    fn settings_reactions_target_override(&self, name: &str) -> String { format!("{name} (override)") }
    fn settings_reactions_forced_note(&self) -> &'static str { "Fixed uses only the Fixed setting." }
    fn settings_friction_desc(&self) -> &'static str { "Configure the confirmation dialog behavior." }
    fn settings_friction_hold_header(&self) -> &'static str { "Hold Confirmation" }
    fn settings_friction_hold_label(&self) -> &'static str { "Require hold to confirm" }
    fn settings_friction_hold_help(&self) -> &'static str { "How long the user must hold click/space to confirm" }
    fn settings_friction_pointer_header(&self) -> &'static str { "Pointer Movement" }
    fn settings_friction_pointer_label(&self) -> &'static str { "Require pointer movement" }
    fn settings_friction_pointer_help(&self) -> &'static str { "Minimum distance the mouse must move" }
    fn settings_friction_emergency_header(&self) -> &'static str { "Emergency Bypass" }
    fn settings_friction_emergency_label(&self) -> &'static str { "Allow emergency bypass" }
    fn settings_friction_emergency_help(&self) -> &'static str { "Hold Ctrl+Shift+Alt to bypass friction checks" }
    fn settings_policy_desc(&self) -> &'static str { "Configure how KaptainhooK handles different scenarios." }
    fn settings_policy_non_interactive_header(&self) -> &'static str { "Non-Interactive Sessions" }
    fn settings_policy_non_interactive_label(&self) -> &'static str { "Allow execution in non-interactive sessions" }
    fn settings_policy_non_interactive_help(&self) -> &'static str { "When disabled, LOLBin execution is blocked in service/batch contexts" }
    fn settings_policy_timeout_header(&self) -> &'static str { "Dialog Timeout" }
    fn settings_policy_timeout_help(&self) -> &'static str { "0 = no timeout. Dialog auto-denies after this time." }
    fn settings_policy_auth_header(&self) -> &'static str { "Authentication Mode" }
    fn settings_policy_auth_friction_label(&self) -> &'static str { "Friction (hold + pointer move)" }
    fn settings_policy_auth_hello_label(&self) -> &'static str { "Windows Hello" }
    fn settings_policy_auth_help(&self) -> &'static str { "Choose how users confirm protected execution." }
    fn settings_language_desc(&self) -> &'static str { "Select UI language" }
    fn settings_language_note(&self) -> &'static str { "Note: Language change will be saved with other settings." }
    fn settings_about_header(&self) -> &'static str { "About KaptainhooK" }
    fn settings_about_version_label(&self) -> &'static str { "Version" }
    fn settings_about_description(&self) -> &'static str { "KaptainhooK is a Windows security tool that uses IFEO (Image File Execution Options) to guard LOLBin (Living off the Land Binaries) execution." }
    fn settings_about_protected_desc(&self) -> &'static str { "Protected binaries include PowerShell, cmd.exe, wscript, cscript, and other commonly abused system tools." }
    fn settings_about_paths_header(&self) -> &'static str { "Configuration Paths" }
    fn settings_about_data_dir_label(&self) -> &'static str { "Data directory:" }
    fn settings_about_config_file_label(&self) -> &'static str { "Config file:" }
    fn settings_about_license_label(&self) -> &'static str { "License:" }

    fn tray_tooltip(&self) -> &'static str { "KaptainhooK - LOLBin Protection" }
    fn tray_settings(&self) -> &'static str { "Settings..." }
    fn tray_status(&self) -> &'static str { "Service Status" }
    fn tray_restart(&self) -> &'static str { "Restart Service" }
    fn tray_enable_all(&self) -> &'static str { "Enable All Targets" }
    fn tray_disable_all(&self) -> &'static str { "Disable All Targets" }
    fn tray_exit(&self) -> &'static str { "Exit" }

    fn tray_status_title(&self) -> &'static str { "KaptainhooK Service" }
    fn tray_restart_started(&self) -> &'static str { "Service restart requested." }
    fn tray_restart_missing(&self) -> &'static str { "Service restart tool not found." }
    fn tray_no_targets(&self) -> &'static str { "No targets currently protected.\n\nRun Settings to configure." }
    fn tray_protected_targets(&self, count: usize) -> String { format!("Protected targets ({}):", count) }
    fn tray_use_settings(&self) -> &'static str { "To enable/disable targets, please use Settings.\n\nClick 'Settings...' in the tray menu." }
    fn tray_unavailable(&self) -> &'static str { "System tray is only available on Windows." }
    fn tray_error_detail(&self, detail: &str) -> String { format!("Error: {}", detail) }
    fn tray_service_running(&self) -> &'static str { "Service is running." }
    fn tray_service_stopped(&self) -> &'static str { "Service is stopped." }
    fn tray_service_starting(&self) -> &'static str { "Service is starting." }
    fn tray_service_stopping(&self) -> &'static str { "Service is stopping." }
    fn tray_service_not_installed(&self) -> &'static str { "Service is not installed." }
    fn tray_service_unknown(&self) -> &'static str { "Service status is unknown." }

    fn common_enabled(&self) -> &'static str { "Enabled" }
    fn common_disabled(&self) -> &'static str { "Disabled" }
    fn common_yes(&self) -> &'static str { "Yes" }
    fn common_no(&self) -> &'static str { "No" }
    fn common_ms(&self) -> &'static str { "ms" }
    fn common_seconds(&self) -> &'static str { "sec" }
    fn common_px(&self) -> &'static str { "px" }
    fn common_add(&self) -> &'static str { "Add" }
    fn common_remove(&self) -> &'static str { "Remove" }
    fn common_edit(&self) -> &'static str { "Edit" }
    fn common_cancel(&self) -> &'static str { "Cancel" }
    fn common_note(&self) -> &'static str { "Note" }
    fn common_view_64(&self) -> &'static str { "64-bit" }
    fn common_view_32(&self) -> &'static str { "32-bit" }
    fn common_signature_signed(&self, kind: &str) -> String { format!("Signed ({})", kind) }
    fn common_signature_trust(&self, trust: &str) -> String { format!("trust={}", trust) }
    fn common_signature_revocation(&self, revocation: &str) -> String { format!("revocation={}", revocation) }
    fn common_signature_subject(&self, subject: &str) -> String { format!("subject={}", subject) }
    fn common_signature_issuer(&self, issuer: &str) -> String { format!("issuer={}", issuer) }
    fn common_signature_unsigned(&self) -> &'static str { "No signature" }
    fn common_signature_error(&self, message: &str) -> String { format!("Error ({})", message) }
    fn common_signature_unsupported(&self, reason: &str) -> String { format!("Unsupported ({})", reason) }
    fn common_signature_notice_unsigned(&self) -> &'static str { "Unsigned" }
    fn common_signature_notice_untrusted(&self) -> &'static str { "Untrusted signature" }
    fn common_signature_notice_revoked(&self) -> &'static str { "Revoked signature" }
    fn common_signature_notice_revocation_not_checked(&self) -> &'static str { "Revocation not checked" }
    fn common_signature_notice_revocation_check_failed(&self) -> &'static str { "Revocation check failed" }
    fn common_signature_notice_error(&self) -> &'static str { "Signature verification error" }
    fn common_signature_notice_unsupported(&self) -> &'static str { "Signature verification unsupported" }
    fn common_path_hint_public_user_dir(&self) -> &'static str { "Under Public user" }
    fn common_path_hint_temp_dir(&self) -> &'static str { "Under Temp" }
    fn common_path_hint_user_temp_dir(&self) -> &'static str { "Under user Temp" }
    fn common_path_hint_downloads_dir(&self) -> &'static str { "Under Downloads" }
    fn common_path_hint_desktop_dir(&self) -> &'static str { "Under Desktop" }
    fn common_path_hint_program_files_dir(&self) -> &'static str { "Under Program Files" }
    fn common_path_hint_program_files_x86_dir(&self) -> &'static str { "Under Program Files (x86)" }
    fn common_path_hint_system32_dir(&self) -> &'static str { "Under System32" }
    fn common_path_hint_syswow64_dir(&self) -> &'static str { "Under SysWOW64" }
    fn signature_kind_authenticode(&self) -> &'static str { "Authenticode" }
    fn signature_trust_trusted(&self) -> &'static str { "Trusted" }
    fn signature_trust_untrusted(&self) -> &'static str { "Untrusted" }
    fn signature_trust_unknown(&self) -> &'static str { "Unknown" }
    fn signature_revocation_good(&self) -> &'static str { "No revocation" }
    fn signature_revocation_revoked(&self) -> &'static str { "Revoked" }
    fn signature_revocation_not_checked(&self, reason: &str) -> String { format!("Not checked ({})", reason) }
    fn signature_revocation_check_failed(&self, reason: &str) -> String { format!("Check failed ({})", reason) }
}

/// 言語設定から翻訳インスタンスを取得
pub fn get_translations(lang: Language) -> &'static dyn Translations {
    match lang {
        Language::Japanese => &Japanese,
        Language::English => &English,
    }
}

/// グローバル翻訳コンテキスト（スレッドローカル）
use std::cell::RefCell;

thread_local! {
    static CURRENT_LANG: RefCell<Language> = RefCell::new(Language::default());
}

/// 現在の言語を設定
pub fn set_language(lang: Language) {
    CURRENT_LANG.with(|l| *l.borrow_mut() = lang);
}

/// 現在の言語を取得
pub fn current_language() -> Language {
    CURRENT_LANG.with(|l| *l.borrow())
}

/// 現在の言語に基づく翻訳を取得
pub fn t() -> &'static dyn Translations {
    get_translations(current_language())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_japanese() {
        let ja = Japanese;
        assert_eq!(ja.guard_allow(), "許可");
        assert_eq!(ja.guard_cancel(), "キャンセル");
    }

    #[test]
    fn test_english() {
        let en = English;
        assert_eq!(en.guard_allow(), "Allow");
        assert_eq!(en.guard_cancel(), "Cancel");
    }

    #[test]
    fn test_get_translations() {
        let ja = get_translations(Language::Japanese);
        assert_eq!(ja.guard_allow(), "許可");

        let en = get_translations(Language::English);
        assert_eq!(en.guard_allow(), "Allow");
    }

    #[test]
    fn test_thread_local() {
        set_language(Language::English);
        assert_eq!(t().guard_allow(), "Allow");

        set_language(Language::Japanese);
        assert_eq!(t().guard_allow(), "許可");
    }
}
