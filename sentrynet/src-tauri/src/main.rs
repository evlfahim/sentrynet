// Tauri v2 Rust entry point
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    sentrynet_lib::run();
}
