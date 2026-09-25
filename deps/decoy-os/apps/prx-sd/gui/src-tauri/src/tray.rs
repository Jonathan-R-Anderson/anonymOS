use tauri::menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{App, Emitter, Manager};

/// Set up the system tray icon with a context menu.
///
/// Menu items:
/// - "Show Window"         — bring the main window to the foreground
/// - "Quick Scan /home"    — trigger a scan of /home via the main window
/// - "Status: Protected"   — informational (disabled)
/// - separator
/// - "Quit"                — exit the application
pub fn setup_tray(app: &App) -> Result<(), Box<dyn std::error::Error>> {
    let show_item = MenuItemBuilder::with_id("show_window", "Show Window").build(app)?;
    let scan_item =
        MenuItemBuilder::with_id("quick_scan", "Quick Scan /home").build(app)?;
    let status_item = MenuItemBuilder::with_id("status", "Status: Protected")
        .enabled(false)
        .build(app)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit_item = MenuItemBuilder::with_id("quit", "Quit").build(app)?;

    let menu = MenuBuilder::new(app)
        .items(&[&show_item, &scan_item, &status_item, &separator, &quit_item])
        .build()?;

    let _tray = TrayIconBuilder::with_id("main-tray")
        .menu(&menu)
        .tooltip("PRX-SD Antivirus")
        .on_menu_event(move |app_handle, event| {
            let id = event.id().as_ref();
            match id {
                "show_window" => {
                    if let Some(window) = app_handle.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "quick_scan" => {
                    // Bring window to front and emit an event that the frontend can
                    // listen to in order to start a scan of /home.
                    if let Some(window) = app_handle.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                        let _ = window.emit("tray-quick-scan", "/home");
                    }
                }
                "quit" => {
                    app_handle.exit(0);
                }
                // "status" is disabled, no action needed.
                _ => {}
            }
        })
        .build(app)?;

    Ok(())
}
