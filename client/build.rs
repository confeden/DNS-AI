//! Puts an icon and a version block *inside* `dns-ai.exe`.
//!
//! Until the program was installed rather than copied, neither mattered much: a tray icon is drawn
//! at runtime and nothing else ever looked at the file. An installed program is looked at
//! constantly and never while it is running — the Start-menu entry, the shortcut, the "Apps &
//! features" row and the Alt-Tab thumbnail all read the icon *resource* off the disk. Without one
//! they show the blank-page glyph Windows uses for "some executable".
//!
//! The version block earns its place at the UAC prompt. Windows takes the "Program name" line from
//! `FileDescription`; with no version resource it falls back to the file name, so the one dialog
//! that asks the user to trust us with administrator rights would say `dns-ai.exe` where it could
//! say what the program is.
//!
//! **Failure here is a warning, never an error.** The resource compiler comes with the Windows
//! SDK, which the MSVC toolchain already requires — but a build that produces a working binary
//! with a dull icon is a far better outcome than a build that refuses to produce one at all.

use std::path::PathBuf;

#[allow(dead_code)] // the runtime half of the module is not used here
mod mark {
    include!("src/mark.rs");
}

fn main() {
    println!("cargo:rerun-if-changed=src/mark.rs");
    println!("cargo:rerun-if-changed=build.rs");

    // Resources are a Windows concept. The crate is Windows-only in practice, but a `cargo check`
    // aimed elsewhere should not die in the build script.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let out_dir = match std::env::var_os("OUT_DIR") {
        Some(d) => PathBuf::from(d),
        None => {
            println!("cargo:warning=OUT_DIR is not set; the icon was not embedded");
            return;
        }
    };
    let ico_path = out_dir.join("dns-ai.ico");
    if let Err(e) = std::fs::write(&ico_path, mark::ico(&mark::ICO_SIZES)) {
        println!("cargo:warning=cannot write {}: {e}", ico_path.display());
        return;
    }

    let mut res = winresource::WindowsResource::new();
    res.set_icon(&ico_path.to_string_lossy());
    // Read by the UAC prompt, the task manager and the file's Properties page. Russian, because
    // every other user-facing string in this program is.
    res.set("FileDescription", "DNS-AI — защищённый DNS");
    res.set("ProductName", "DNS-AI");
    // The author, not the project: this is the line Windows shows as the publisher of an unsigned
    // file, and it has to be the same name the signing certificate carries (`CN=Brent`) or the two
    // places that answer "who made this" disagree.
    res.set("CompanyName", "Brent");
    res.set("LegalCopyright", "Brent · DNS-AI.RU");
    // Where a user goes when something is wrong. `Comments` is the only version-block field
    // Windows shows verbatim in a file's Properties, so both addresses live in it.
    res.set("Comments", "DNS-AI.RU · t.me/nova_txt");
    res.set("OriginalFilename", "dns-ai.exe");
    res.set("InternalName", "dns-ai");

    if let Err(e) = res.compile() {
        println!("cargo:warning=the icon and version block were not embedded: {e}");
    }
}
