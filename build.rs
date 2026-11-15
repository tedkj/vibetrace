use std::collections::HashMap;
use std::path::PathBuf;

fn main() {
    let ui = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("ui");
    // Element debug info lets the UI tests find controls by accessible label; release builds skip it.
    let debug = std::env::var("PROFILE").as_deref() == Ok("debug");
    let config = slint_build::CompilerConfiguration::new()
        .with_library_paths(HashMap::from([("vibeware".to_string(), ui.join("vibeware").join("lib.slint"))]))
        .with_debug_info(debug);
    slint_build::compile_with_config(ui.join("all.slint"), config).unwrap();
    windows_resources();
}

/// Delay-loaded (the install check's network, signature and certificate DLLs).
const DELAYED: [&str; 3] = ["winhttp.dll", "wintrust.dll", "crypt32.dll"];

/// The exe's icon, version information and manifest.
fn windows_resources() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("assets");
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let mut n: Vec<u16> = version.split(['.', '-', '+']).take(3).map(|p| p.parse().unwrap_or(0)).collect();
    n.resize(4, 0);
    let numeric = format!("{},{},{},{}", n[0], n[1], n[2], n[3]);
    let path = |f: &str| dir.join(f).display().to_string().replace('\\', "\\\\");
    let rc = format!(
        r#"#pragma code_page(65001)
#include <winver.h>
1 ICON "{icon}"
1 24 "{manifest}"
1 VERSIONINFO
FILEVERSION {numeric}
PRODUCTVERSION {numeric}
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "CompanyName", "Ted K. Johansen"
      VALUE "FileDescription", "VibeTrace"
      VALUE "FileVersion", "{version}"
      VALUE "InternalName", "VibeTrace"
      VALUE "LegalCopyright", "Ted K. Johansen"
      VALUE "OriginalFilename", "VibeTrace.exe"
      VALUE "ProductName", "VibeTrace"
      VALUE "ProductVersion", "{version}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#,
        icon = path("app.ico"),
        manifest = path("app.manifest"),
    );
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("app.rc");
    std::fs::write(&out, rc).unwrap();
    println!("cargo:rerun-if-changed=assets");
    // DLL hardening (VibeLink LINK-1): the loader takes the exe's static imports from System32
    // only, never from the exe's own folder (a USB stick's, or the per-user install folder).
    // LOAD_LIBRARY_SEARCH_SYSTEM32; tests/pe.rs checks the load config carries it.
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg=/DEPENDENTLOADFLAG:0x800");
        // The DLLs only About's install check uses load when it first runs, not at every start:
        // after `main`'s SetDefaultDllDirectories, so from System32 only (tests/pe.rs checks
        // they are delay-loaded). The exe only; its unit-test build calls none of them, so the
        // linker's "nothing to delay-load" (LNK4199) is not a warning there.
        for dll in DELAYED {
            println!("cargo:rustc-link-arg-bins=/DELAYLOAD:{dll}");
        }
        println!("cargo:rustc-link-arg-bins=delayimp.lib");
        println!("cargo:rustc-link-arg-bins=/IGNORE:4199");
    }
    embed_resource::compile_for(&out, ["vibetrace"], embed_resource::NONE).manifest_required().unwrap();
}
