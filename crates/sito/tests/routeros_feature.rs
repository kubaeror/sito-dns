//! Guards the RouterOS crate boundary.
//!
//! RouterOS is an optional integration: the default `sito` dependency graph
//! must not contain `sito-routeros`, and the `routeros` feature must add it.
//! The test shells out to `cargo tree` because the crate graph is a manifest
//! property and cannot be observed from a compiled test binary.

use std::process::Command;

fn cargo_tree(args: &[&str]) -> String {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(cargo)
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run cargo tree");
    assert!(
        output.status.success(),
        "cargo tree {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("cargo tree output is UTF-8")
}

#[test]
fn default_build_excludes_the_optional_routeros_crate() {
    let tree = cargo_tree(&["tree", "-p", "sito", "--locked", "--edges", "normal"]);
    assert!(
        !tree.contains("sito-routeros"),
        "the default `sito` build must not link sito-routeros:\n{tree}"
    );
}

#[test]
fn routeros_feature_enables_the_optional_crate() {
    let tree = cargo_tree(&[
        "tree",
        "-p",
        "sito",
        "--locked",
        "--edges",
        "normal",
        "--features",
        "routeros",
    ]);
    assert!(
        tree.contains("sito-routeros"),
        "`cargo build -p sito --features routeros` must link sito-routeros:\n{tree}"
    );
}

#[test]
fn routeros_dependency_is_optional() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        manifest.contains("sito-routeros = { workspace = true, optional = true }"),
        "sito-routeros must be an optional dependency"
    );
    assert!(
        !manifest.contains("default = [\"routeros\"]"),
        "routeros must never be part of the default feature set"
    );
}

/// The startup validator (also used by `check-config` and API writes) must
/// reject an enabled RouterOS integration in a build without the feature.
#[cfg(not(feature = "routeros"))]
#[test]
fn startup_rejects_enabled_routeros_without_the_feature() {
    let config = sito_core::config::Config::from_toml_str(
        "config_version = 1\n[upstream]\nservers = [\"1.1.1.1\"]\n[integrations.mikrotik]\nenabled = true\n",
    )
    .expect("parses");
    let err = sito::server::validate_typed_sections(&config)
        .expect_err("startup must fail closed instead of ignoring the knob");
    assert!(
        err.to_string().contains("routeros"),
        "startup error must name the missing feature: {err}"
    );
}
