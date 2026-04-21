// Suppress the warnings
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(clippy::all)]
#![allow(unnecessary_transmutes)]

// Utilize the platform-specific bindings
#[cfg(not(target_os = "windows"))]
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/bindings.rs"));
#[cfg(target_os = "windows")]
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/bindings_windows.rs"));
