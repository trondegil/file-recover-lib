//! The feature matrix in the README is a copy of what the code generates. If
//! a capability changes, `unearth info --features --markdown` changes and this
//! test points at the README until it is updated.

use unearth::recover;

#[test]
fn readme_feature_matrix_matches_the_code() {
    let readme =
        // Git may check the README out with CRLF endings on Windows.
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))
            .unwrap()
            .replace("\r\n", "\n");
    let start = readme
        .find("<!-- capability-matrix:start -->\n")
        .expect("README has the capability-matrix start marker");
    let end = readme
        .find("<!-- capability-matrix:end -->")
        .expect("README has the capability-matrix end marker");
    let in_readme = &readme[start + "<!-- capability-matrix:start -->\n".len()..end];
    assert_eq!(
        in_readme,
        recover::capability_markdown(),
        "README feature matrix is stale: paste the output of `unearth info --features --markdown` between the markers"
    );
}

#[test]
fn info_features_prints_the_same_table() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_unearth"))
        .args(["info", "--features", "--markdown"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        recover::capability_markdown()
    );
}
