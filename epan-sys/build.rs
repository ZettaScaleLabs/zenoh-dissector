#[cfg(feature = "bindgen")]
extern crate bindgen;

use anyhow::Result;
use std::env;
use std::path::PathBuf;

const WIRESHARK_VERSION: &str = "4.2.3";
const WIRESHARK_SOURCE_DIR: &str = "wireshark";

fn main() -> Result<()> {
    // If we are in docs.rs, there is no need to actually link.
    if std::env::var("DOCS_RS").is_ok() {
        return Ok(());
    }

    // By default, we will just use a pre-generated bindings.rs file. If this feature is turned
    // on, we'll re-generate the bindings at build time.
    #[cfg(feature = "bindgen")]
    generate_bindings()?;

    link_wireshark()?;
    Ok(())
}

fn link_wireshark() -> Result<()> {
    // pkg-config will handle everything for us
    if pkg_config::probe_library("wireshark").is_ok() {
        return Ok(());
    }

    // Default wireshark libraray installed on macos
    #[cfg(target_os = "macos")]
    println!(
        "cargo:rustc-link-search=native={}",
        "/Applications/Wireshark.app/Contents/Frameworks"
    );

    // Specify the wireshark library directory by the environmental variable
    println!("cargo:rerun-if-env-changed=WIRESHARK_LIB_DIR");
    if let Ok(libws_dir) = env::var("WIRESHARK_LIB_DIR") {
        println!("cargo:rustc-link-search=native={}", libws_dir);
    } else {
        // We need to build the wireshark from source for the linking
        #[cfg(target_os = "windows")]
        {
            env::set_var("WIRESHARK_BASE_DIR", "C:\\Development");
            env::set_var("PLATFORM", "win64");

            // Download and build wireshark.lib
            download_wireshark()?;
            let dst = build_wireshark();
            // Default wireshark libraray installed on windows
            // println!( "cargo:rustc-link-search=native={}", "C:\\Program Files\\Wireshark");
            println!("cargo:rustc-link-search=native={}", dst.to_string_lossy());
        }
    }

    println!("cargo:rustc-link-lib=dylib=wireshark");

    Ok(())
}

#[cfg(feature = "bindgen")]
fn generate_bindings() -> Result<()> {
    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .generate_comments(false);

    match pkg_config::probe_library("wireshark") {
        Ok(libws) => {
            for path in libws.include_paths {
                builder = builder.clang_arg(format!("-I{}", path.to_string_lossy()));
            }
        }
        Err(_) => {
            download_wireshark()?;

            #[cfg(target_os = "windows")]
            {
                env::set_var("WIRESHARK_BASE_DIR", "C:\\Development");
                env::set_var("PLATFORM", "win64");
            }
            let dst = build_wireshark();

            let mut ws_headers_path = dst;
            ws_headers_path.push("include");
            ws_headers_path.push("wireshark");

            let glib = pkg_config::Config::new().probe("glib-2.0")?;
            for path in glib.include_paths {
                builder = builder.clang_arg(format!("-I{}", path.to_string_lossy()));
            }
            builder = builder.clang_arg(format!("-I{}", ws_headers_path.to_string_lossy()));
        }
    }

    let bindings = builder.generate()?;
    let out_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    bindings.write_to_file(out_path.join("bindings.rs"))?;

    Ok(())
}

#[cfg(any(feature = "bindgen", target_os = "windows"))]
fn download_wireshark() -> Result<()> {
    use tar::Archive;
    use xz2::read::XzDecoder;

    let url = format!("https://2.na.dl.wireshark.org/src/wireshark-{WIRESHARK_VERSION}.tar.xz");

    let response = reqwest::blocking::get(url)?;
    let bytes = response.bytes()?.to_vec();
    let readable = XzDecoder::new(bytes.as_slice());
    let mut archive = Archive::new(readable);
    archive.unpack(".")?;
    if std::path::Path::new(WIRESHARK_SOURCE_DIR).exists() {
        std::fs::remove_dir_all(WIRESHARK_SOURCE_DIR)?;
    }
    std::fs::rename(
        format!("wireshark-{WIRESHARK_VERSION}"),
        WIRESHARK_SOURCE_DIR,
    )?;
    Ok(())
}

fn build_wireshark() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        env::set_var("WIRESHARK_BASE_DIR", "C:\\Development");
        env::set_var("PLATFORM", "win64");
    }
    cmake::Config::new(WIRESHARK_SOURCE_DIR)
        .define("BUILD_androiddump", "OFF")
        .define("BUILD_capinfos", "OFF")
        .define("BUILD_captype", "OFF")
        .define("BUILD_ciscodump", "OFF")
        .define("BUILD_corbaidl2wrs", "OFF")
        .define("BUILD_dcerpcidl2wrs", "OFF")
        .define("BUILD_dftest", "OFF")
        .define("BUILD_dpauxmon", "OFF")
        .define("BUILD_dumpcap", "OFF")
        .define("BUILD_editcap", "OFF")
        .define("BUILD_etwdump", "OFF")
        .define("BUILD_logray", "OFF")
        .define("BUILD_mergecap", "OFF")
        .define("BUILD_randpkt", "OFF")
        .define("BUILD_randpktdump", "OFF")
        .define("BUILD_rawshark", "OFF")
        .define("BUILD_reordercap", "OFF")
        .define("BUILD_sshdump", "OFF")
        .define("BUILD_text2pcap", "OFF")
        .define("BUILD_tfshark", "OFF")
        .define("BUILD_tshark", "OFF")
        .define("BUILD_wifidump", "OFF")
        .define("BUILD_wireshark", "OFF")
        .define("BUILD_xxx2deb", "OFF")
        .define("ENABLE_KERBEROS", "OFF")
        .define("ENABLE_SBC", "OFF")
        .define("ENABLE_SPANDSP", "OFF")
        .define("ENABLE_BCG729", "OFF")
        .define("ENABLE_AMRNB", "OFF")
        .define("ENABLE_ILBC", "OFF")
        .define("ENABLE_LIBXML2", "OFF")
        .define("ENABLE_OPUS", "OFF")
        .define("ENABLE_SINSP", "OFF")
        .build()
}
