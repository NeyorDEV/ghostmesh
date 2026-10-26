#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::OpenOptions;
use std::io::Write;

fn main() {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("CRITICAL PANIC: {info}");
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open("ghostmesh-crash.log") {
            let _ = writeln!(f, "Panic: {info}");
        }
    }));

    ghostmesh_gui_lib::run();
}

