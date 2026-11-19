fn main() {
    // Only these commands may be called from the app's web view; by default
    // Tauri would allow every registered command.
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "live",
            "history",
            "export_history",
            "delete_history",
            "rules",
            "add_rule",
            "remove_rule",
            "set_blocking_paused",
            "get_settings",
            "set_settings",
            "alerts",
            "dismiss_alert",
            "set_list_updates",
            "check_lists_now",
        ]),
    ))
    .expect("failed to run the Tauri build script");
}
