//! CLI smoke tests — verifies that every `sd` subcommand responds to
//! `--help` with exit code 0.  These tests are intentionally minimal:
//! they only exercise the argument-parsing layer, not any business logic.
//!
//! Run with:
//!   cargo test -p sd -- `commands_smoke`

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use assert_cmd::Command;

fn sd_cmd() -> Command {
    Command::cargo_bin("sd").unwrap()
}

// ── Top-level help / version ──────────────────────────────────────────────────

#[test]
fn help_top_level() {
    sd_cmd().arg("--help").assert().success();
}

#[test]
fn version_top_level() {
    sd_cmd().arg("--version").assert().success();
}

// ── macro_rules! bulk-generate --help smoke tests ────────────────────────────

/// Generate a test that calls `sd <args...> --help` and expects exit 0.
macro_rules! help_smoke_test {
    ($test_name:ident, $($args:expr),+) => {
        #[test]
        fn $test_name() {
            sd_cmd()
                .args([$($args),+, "--help"])
                .assert()
                .success();
        }
    };
}

// ── Top-level subcommands ─────────────────────────────────────────────────────

help_smoke_test!(help_scan, "scan");
help_smoke_test!(help_monitor, "monitor");
help_smoke_test!(help_quarantine, "quarantine");
help_smoke_test!(help_update, "update");
help_smoke_test!(help_config, "config");
help_smoke_test!(help_info, "info");
help_smoke_test!(help_import, "import");
help_smoke_test!(help_import_clamav, "import-clamav");
help_smoke_test!(help_schedule, "schedule");
help_smoke_test!(help_policy, "policy");
help_smoke_test!(help_daemon, "daemon");
help_smoke_test!(help_scan_usb, "scan-usb");
#[cfg(target_os = "linux")]
help_smoke_test!(help_scan_memory, "scan-memory");
#[cfg(target_os = "linux")]
help_smoke_test!(help_check_rootkit, "check-rootkit");
help_smoke_test!(help_webhook, "webhook");
help_smoke_test!(help_email_alert, "email-alert");
help_smoke_test!(help_report, "report");
help_smoke_test!(help_status, "status");
help_smoke_test!(help_self_update, "self-update");
help_smoke_test!(help_install_integration, "install-integration");
help_smoke_test!(help_adblock, "adblock");
help_smoke_test!(help_community, "community");
help_smoke_test!(help_runtime, "runtime");
help_smoke_test!(help_dns_proxy, "dns-proxy");

// ── Quarantine sub-subcommands ────────────────────────────────────────────────

help_smoke_test!(help_quarantine_list, "quarantine", "list");
help_smoke_test!(help_quarantine_restore, "quarantine", "restore");
help_smoke_test!(help_quarantine_delete, "quarantine", "delete");
help_smoke_test!(help_quarantine_delete_all, "quarantine", "delete-all");
help_smoke_test!(help_quarantine_stats, "quarantine", "stats");

// ── Config sub-subcommands ────────────────────────────────────────────────────

help_smoke_test!(help_config_show, "config", "show");
help_smoke_test!(help_config_set, "config", "set");
help_smoke_test!(help_config_reset, "config", "reset");

// ── Schedule sub-subcommands ──────────────────────────────────────────────────

help_smoke_test!(help_schedule_add, "schedule", "add");
help_smoke_test!(help_schedule_remove, "schedule", "remove");
help_smoke_test!(help_schedule_status, "schedule", "status");

// ── Webhook sub-subcommands ───────────────────────────────────────────────────

help_smoke_test!(help_webhook_list, "webhook", "list");
help_smoke_test!(help_webhook_add, "webhook", "add");
help_smoke_test!(help_webhook_remove, "webhook", "remove");
help_smoke_test!(help_webhook_test, "webhook", "test");

// ── Email-alert sub-subcommands ───────────────────────────────────────────────

help_smoke_test!(help_email_alert_configure, "email-alert", "configure");
help_smoke_test!(help_email_alert_test, "email-alert", "test");
help_smoke_test!(help_email_alert_send, "email-alert", "send");

// ── Adblock sub-subcommands ───────────────────────────────────────────────────

help_smoke_test!(help_adblock_enable, "adblock", "enable");
help_smoke_test!(help_adblock_disable, "adblock", "disable");
help_smoke_test!(help_adblock_sync, "adblock", "sync");
help_smoke_test!(help_adblock_stats, "adblock", "stats");
help_smoke_test!(help_adblock_check, "adblock", "check");
help_smoke_test!(help_adblock_log, "adblock", "log");
help_smoke_test!(help_adblock_add, "adblock", "add");
help_smoke_test!(help_adblock_remove, "adblock", "remove");

// ── Community sub-subcommands ─────────────────────────────────────────────────

help_smoke_test!(help_community_status, "community", "status");
help_smoke_test!(help_community_enroll, "community", "enroll");
help_smoke_test!(help_community_disable, "community", "disable");

// ── Runtime sub-subcommands ───────────────────────────────────────────────────

help_smoke_test!(help_runtime_status, "runtime", "status");
