#![forbid(unsafe_code)]
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Link the Kerberos libraries
    println!("cargo:rustc-link-lib=krb5");
    println!("cargo:rustc-link-lib=kadm5clnt");
    println!("cargo:rustc-link-lib=kadm5srv"); // optional but harmless

    // Let pkg-config find the headers/libs
    pkg_config::Config::new().probe("krb5").expect("krb5 pkg-config failed");
    pkg_config::Config::new().probe("kadm5clnt").ok(); // may not exist separately

    let bindings = bindgen::Builder::default()
    // Main admin header + base krb5 header
    .header("/usr/include/kadm5/admin.h")
    .header("/usr/include/krb5.h")
    // Keep bindings focused and small (helps compile time & error count)
    .allowlist_function("kadm5_.*")
    .allowlist_type("kadm5_.*")
    .allowlist_var("KADM5_.*")
    .allowlist_function("krb5_.*")
    .allowlist_type("krb5_.*")
    .allowlist_type("kadm5_config_params")
    .allowlist_var("KADM5_CONFIG_.*")
    // Common bindgen noise fixes
    .blocklist_type("_Float64x")
    .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
    .generate()
    .expect("Unable to generate bindgen bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings_file = out_path.join("bindings.rs");

    // Write initial bindings
    bindings
    .write_to_file(&bindings_file)
    .expect("Couldn't write initial bindings!");

    // === POST-PROCESS FIX: Add `unsafe` to extern blocks ===
    let content = fs::read_to_string(&bindings_file).expect("Failed to read bindings for post-process");
    let fixed_content = content.replace("extern \"C\" {", "unsafe extern \"C\" {");
    fs::write(&bindings_file, fixed_content).expect("Failed to write fixed bindings!");

    println!("cargo:rerun-if-changed=build.rs"); // Good practice
}
