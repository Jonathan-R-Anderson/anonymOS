// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod tray;

use std::path::PathBuf;

use commands::AppState;

fn main() {
    let data_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".prx-sd");

    // Ensure data directory exists (best-effort, commands will report errors
    // if critical directories are missing).
    let _ = std::fs::create_dir_all(&data_dir);

    if let Err(e) = tauri::Builder::default()
        .manage(AppState::new(data_dir))
        .invoke_handler(tauri::generate_handler![
            commands::scan_path,
            commands::scan_directory,
            commands::start_monitor,
            commands::stop_monitor,
            commands::get_quarantine_list,
            commands::restore_quarantine,
            commands::delete_quarantine,
            commands::get_config,
            commands::save_config,
            commands::get_engine_info,
            commands::update_signatures,
            commands::get_alert_history,
            commands::get_dashboard_stats,
            commands::get_adblock_stats,
            commands::adblock_enable,
            commands::adblock_disable,
            commands::adblock_sync,
            commands::adblock_check,
            commands::get_adblock_log,
        ])
        .setup(|app| {
            tray::setup_tray(app)?;
            Ok(())
        })
        .run(tauri::generate_context!())
    {
        eprintln!("Failed to run PRX-SD: {e}");
        std::process::exit(1);
    }
}
