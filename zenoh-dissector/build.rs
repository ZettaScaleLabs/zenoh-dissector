use cargo_metadata::MetadataCommand;
use std::{env, ffi::CString, fs, path::Path};

fn main() {
    let metadata = MetadataCommand::new().exec().unwrap();
    let pkg = metadata.root_package().unwrap();

    // Get Wireshark version from workspace metadata
    let wireshark_version = metadata
        .workspace_metadata
        .get("wireshark_version")
        .and_then(|v| v.as_str())
        .expect("Wireshark version must be set in Cargo.toml under [workspace.metadata]");

    let ws_parts: Vec<_> = wireshark_version.split('.').collect();
    let ws_major: i32 = ws_parts[0].parse().expect("Invalid major version");
    let ws_minor: i32 = ws_parts.get(1).and_then(|v| v.parse().ok()).unwrap_or(0);

    // Generate Rust code for version symbols
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("version.rs");

    let version_str = pkg.version.to_string();

    // Use CString to create a proper null-terminated string
    let version_cstring = CString::new(version_str).unwrap();
    let version_bytes = version_cstring.as_bytes_with_nul();
    let len = version_bytes.len();

    // Convert bytes to c_char array format
    let version_array: String = version_bytes
        .iter()
        .map(|&b| b.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let code = format!(
        r#"
        #[no_mangle]
        #[used]
        pub static plugin_version: [std::ffi::c_char; {len}] = [{ver}];

        #[no_mangle]
        #[used]
        pub static plugin_want_major: std::ffi::c_int = {major};
        #[no_mangle]
        #[used]
        pub static plugin_want_minor: std::ffi::c_int = {minor};
        "#,
        len = len,
        ver = version_array,
        major = ws_major,
        minor = ws_minor,
    );

    fs::write(dest_path, code).unwrap();
}
