fn main() {
    // Only these commands may be called from the app's web view; by default
    // Tauri would allow every registered command.
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(&["live", "history"])),
    )
    .expect("failed to run the Tauri build script");
}
