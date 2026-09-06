//! The write barrier, end to end: whatever a deleted file's name says, the
//! recovered file lands inside the output directory, under a sanitised name,
//! with the right bytes, and nothing outside the output directory changes.
//! Covers the ext, FAT (long name), and HFS+ backends, the CLI, and MCP.

mod common;

use std::path::{Path, PathBuf};

use unearth::recover::{self, RecoverOptions};
use unearth::source::Source;

const PAYLOAD: &[u8] = b"the bytes that must come back, exactly once";

/// Every file under `dir`, recursively, without following symlinks (a symlink
/// is listed as itself, so a dangling one still counts).
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            let meta = std::fs::symlink_metadata(&p).unwrap();
            if meta.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Whether `p`, taken component by component under `root`, crosses a symlink.
fn crosses_symlink(root: &Path, p: &Path) -> bool {
    let rel = p.strip_prefix(root).unwrap();
    let mut cur = root.to_path_buf();
    for c in rel.components() {
        cur.push(c);
        if std::fs::symlink_metadata(&cur)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

struct Run {
    tmp: tempfile::TempDir,
    out: PathBuf,
    img: PathBuf,
    sentinel: PathBuf,
}

impl Run {
    fn new(image: &[u8]) -> Run {
        let tmp = tempfile::tempdir().unwrap();
        let img = tmp.path().join("disk.img");
        let sentinel = tmp.path().join("sentinel.txt");
        std::fs::write(&img, image).unwrap();
        std::fs::write(&sentinel, b"untouched").unwrap();
        let out = tmp.path().join("out");
        Run {
            tmp,
            out,
            img,
            sentinel,
        }
    }

    fn undelete(&self) -> recover::RecoverStats {
        let src = Source::open(&self.img).unwrap();
        let vols = recover::detect(&src).unwrap();
        assert_eq!(vols.len(), 1, "one volume");
        vols[0]
            .recover_deleted(&src, &self.out, &RecoverOptions::default())
            .unwrap()
    }

    /// Nothing outside `out` changed, and nothing new appeared anywhere else
    /// under the tempdir.
    fn assert_confined(&self) {
        assert_eq!(std::fs::read(&self.sentinel).unwrap(), b"untouched");
        let img_len = std::fs::metadata(&self.img).unwrap().len();
        for f in files_under(self.tmp.path()) {
            // Links the test planted are listed as themselves; what matters
            // is that nothing was written through them.
            if std::fs::symlink_metadata(&f)
                .unwrap()
                .file_type()
                .is_symlink()
            {
                continue;
            }
            assert!(
                f == self.img || f == self.sentinel || f.starts_with(&self.out),
                "file outside the output directory: {}",
                f.display()
            );
            assert!(
                !f.starts_with(&self.out) || !crosses_symlink(&self.out, &f),
                "written through a symlink: {}",
                f.display()
            );
        }
        assert_eq!(std::fs::metadata(&self.img).unwrap().len(), img_len);
    }

    /// Exactly one file was recovered, holding `payload`; returns its path.
    fn the_one_file(&self, payload: &[u8]) -> PathBuf {
        let files = files_under(&self.out);
        assert_eq!(files.len(), 1, "exactly one file recovered: {files:?}");
        assert_eq!(std::fs::read(&files[0]).unwrap(), payload);
        files[0].clone()
    }
}

fn file_name(p: &Path) -> String {
    p.file_name().unwrap().to_string_lossy().into_owned()
}

/// Names an ext dirent can carry. `.` and `..` are absent here on purpose:
/// every ext directory has those two entries as links, so the walker skips
/// them by name; they are exercised through the FAT long-name case instead.
const HOSTILE_NAMES: &[&str] = &[
    "../../escape.txt",
    "/abs.txt",
    "C:\\win.txt",
    "\\\\server\\share\\x.txt",
    "CON",
    "nul.txt",
    "a\u{0}b.txt",
    "trailing.",
    "spaced  ",
    "sub/dir/file.txt",
];

#[test]
fn hostile_ext_names_land_inside_the_output_directory() {
    let long = "n".repeat(255);
    let mut names: Vec<&str> = HOSTILE_NAMES.to_vec();
    names.push(&long);
    for name in names {
        let run = Run::new(&common::ext_volume(name, PAYLOAD));
        let stats = run.undelete();
        assert_eq!(stats.recovered, 1, "recovered count for {name:?}");
        run.assert_confined();
        let got = run.the_one_file(PAYLOAD);
        assert_eq!(
            file_name(&got),
            recover::sanitize_component(name),
            "name for {name:?}"
        );
        assert_eq!(
            got.parent().unwrap(),
            run.out,
            "{name:?} must be a direct child of the output directory"
        );
        if cfg!(windows) && (name == "CON" || name == "nul.txt") {
            assert!(file_name(&got).starts_with('_'), "{name:?} on Windows");
        }
    }
}

#[test]
fn hostile_fat_long_name_lands_inside_the_output_directory() {
    // A NUL in a long-name entry is the name terminator by the FAT spec, so
    // `a<NUL>b.txt` is the file `a`; the rest sanitise like any other name.
    let cases = [
        (
            "../../escape.txt",
            recover::sanitize_component("../../escape.txt"),
        ),
        ("..", recover::sanitize_component("..")),
        (".", recover::sanitize_component(".")),
        ("C:\\win.txt", recover::sanitize_component("C:\\win.txt")),
        ("a\u{0}b.txt", "a".to_string()),
    ];
    for (name, expect) in cases {
        let run = Run::new(&common::fat32_lfn_volume(name, PAYLOAD));
        let stats = run.undelete();
        assert_eq!(stats.recovered, 1, "recovered count for {name:?}");
        run.assert_confined();
        let got = run.the_one_file(PAYLOAD);
        assert_eq!(file_name(&got), expect, "name for {name:?}");
        assert_eq!(got.parent().unwrap(), run.out);
    }
}

#[test]
fn hostile_hfsplus_folder_name_lands_inside_the_output_directory() {
    for folder in ["../evil", "..", "/", "C:\\x", "a:b"] {
        let run = Run::new(&common::hfsplus_nested_volume(folder, "file.txt", PAYLOAD));
        let stats = run.undelete();
        assert_eq!(stats.recovered, 1, "recovered count for {folder:?}");
        run.assert_confined();
        let got = run.the_one_file(PAYLOAD);
        assert_eq!(file_name(&got), "file.txt");
        // HFS+ stores `/` as `:`, so the backend maps a colon to `_` first.
        let expect_dir = recover::sanitize_component(&folder.replace(':', "_"));
        assert_eq!(got.parent().unwrap(), run.out.join(expect_dir));
    }
}

#[test]
fn hostile_name_through_the_cli_lands_inside_the_output_directory() {
    let run = Run::new(&common::ext_volume("../../escape.txt", PAYLOAD));
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_unearth"))
        .args([
            "undelete",
            run.img.to_str().unwrap(),
            "-o",
            run.out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    run.assert_confined();
    let got = run.the_one_file(PAYLOAD);
    assert_eq!(file_name(&got), ".._.._escape.txt");
}

#[test]
fn hostile_name_through_mcp_lands_inside_the_output_directory() {
    use unearth::json;
    let run = Run::new(&common::ext_volume("../../escape.txt", PAYLOAD));
    let j = |p: &Path| p.display().to_string().replace('\\', "\\\\");
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"undelete","arguments":{{"source":"{}","output_dir":"{}"}}}}}}"#,
        j(&run.img),
        j(&run.out)
    );
    let resp = unearth::mcp::handle_request(&json::parse(&req).unwrap()).unwrap();
    let result = resp.get("result").unwrap();
    assert_eq!(result.get("isError").unwrap().as_bool(), Some(false));
    let text = result.get("content").unwrap().as_array().unwrap()[0]
        .get("text")
        .unwrap()
        .as_str()
        .unwrap();
    let body = json::parse(text).unwrap();
    assert_eq!(body.get("recovered").unwrap().as_u64(), Some(1));
    run.assert_confined();
    let got = run.the_one_file(PAYLOAD);
    assert_eq!(file_name(&got), ".._.._escape.txt");
}

// --- Task 2: symlinks in the output tree ----------------------------------

/// A symlink planted inside the output directory must not redirect a write
/// outside it: the file is either refused or created under a real directory.
#[cfg(unix)]
#[test]
fn a_symlinked_parent_inside_the_output_directory_is_not_followed() {
    let run = Run::new(&common::hfsplus_nested_volume("sub", "file.txt", PAYLOAD));
    let outside = run.tmp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(&run.out).unwrap();
    std::os::unix::fs::symlink(&outside, run.out.join("sub")).unwrap();

    let stats = run.undelete();
    assert!(
        files_under(&outside).is_empty(),
        "written through the symlinked parent: {:?}",
        files_under(&outside)
    );
    run.assert_confined();
    // Refused, or recovered under a real directory: never through the link.
    let files: Vec<PathBuf> = files_under(&run.out)
        .into_iter()
        .filter(|f| {
            !std::fs::symlink_metadata(f)
                .unwrap()
                .file_type()
                .is_symlink()
        })
        .collect();
    if stats.recovered == 1 {
        assert_eq!(files.len(), 1);
        assert_eq!(std::fs::read(&files[0]).unwrap(), PAYLOAD);
        assert!(!crosses_symlink(&run.out, &files[0]));
    } else {
        assert_eq!(stats.recovered, 0);
        assert_eq!(stats.skipped, 1, "the refusal is reported as a skip");
        assert!(files.is_empty(), "{files:?}");
    }
}

/// A symlink already sitting where the recovered file would go, dangling or
/// not, is left alone and not written through.
#[cfg(unix)]
#[test]
fn a_symlink_at_the_target_path_is_not_written_through() {
    for dangling in [false, true] {
        let run = Run::new(&common::ext_volume("report.txt", PAYLOAD));
        let target = run.tmp.path().join("link_target.txt");
        if !dangling {
            std::fs::write(&target, b"pre-existing").unwrap();
        }
        std::fs::create_dir_all(&run.out).unwrap();
        std::os::unix::fs::symlink(&target, run.out.join("report.txt")).unwrap();

        let stats = run.undelete();
        assert_eq!(stats.recovered, 1, "dangling={dangling}");
        if dangling {
            assert!(!target.exists(), "dangling link created its target");
        } else {
            assert_eq!(std::fs::read(&target).unwrap(), b"pre-existing");
        }
        // The payload went to a sibling name, not through the link.
        let real: Vec<PathBuf> = files_under(&run.out)
            .into_iter()
            .filter(|f| {
                !std::fs::symlink_metadata(f)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            })
            .collect();
        assert_eq!(real.len(), 1, "dangling={dangling}: {real:?}");
        assert_eq!(std::fs::read(&real[0]).unwrap(), PAYLOAD);
        assert_eq!(file_name(&real[0]), "report_1.txt");
        assert_eq!(std::fs::read(&run.sentinel).unwrap(), b"untouched");
    }
}

// --- Task 3: name collisions --------------------------------------------

fn both_payloads_present(out: &Path, a: &[u8], b: &[u8]) -> Vec<PathBuf> {
    let files = files_under(out);
    assert_eq!(files.len(), 2, "two files: {files:?}");
    let mut contents: Vec<Vec<u8>> = files.iter().map(|f| std::fs::read(f).unwrap()).collect();
    contents.sort();
    let mut want = vec![a.to_vec(), b.to_vec()];
    want.sort();
    assert_eq!(contents, want);
    files
}

#[test]
fn names_that_sanitise_to_one_string_both_survive() {
    let a = b"first file".as_slice();
    let b = b"second file".as_slice();
    let mut pairs = vec![("a/b", "a\\b")];
    if cfg!(windows) {
        pairs.push(("a:b.txt", "a?b.txt"));
    }
    for (n1, n2) in pairs {
        let run = Run::new(&common::ext_volume_multi(&[(n1, a), (n2, b)]));
        let stats = run.undelete();
        assert_eq!(stats.recovered, 2, "{n1:?} + {n2:?}");
        run.assert_confined();
        let files = both_payloads_present(&run.out, a, b);
        let names: Vec<String> = files.iter().map(|f| file_name(f)).collect();
        let base = recover::sanitize_component(n1);
        assert_eq!(base, recover::sanitize_component(n2));
        let stem = base.rsplit_once('.').map(|(s, _)| s).unwrap_or(&base);
        for n in &names {
            assert!(n == &base || n.starts_with(stem), "{n} from {base}");
        }
        assert_ne!(names[0], names[1]);
    }
}

#[test]
fn names_differing_only_by_unicode_normalisation_both_survive() {
    let a = b"precomposed".as_slice();
    let b = b"decomposed".as_slice();
    let nfc = "caf\u{e9}.txt";
    let nfd = "cafe\u{301}.txt";
    let run = Run::new(&common::ext_volume_multi(&[(nfc, a), (nfd, b)]));
    let stats = run.undelete();
    assert_eq!(stats.recovered, 2);
    run.assert_confined();
    // On a normalisation-insensitive filesystem the second gets a counter;
    // elsewhere the two names coexist. Either way both payloads are there.
    let files = both_payloads_present(&run.out, a, b);
    let names: Vec<String> = files.iter().map(|f| file_name(f)).collect();
    assert_ne!(names[0], names[1]);
}

#[test]
fn a_pre_existing_file_in_the_output_directory_is_not_overwritten() {
    let run = Run::new(&common::ext_volume("notes.txt", PAYLOAD));
    std::fs::create_dir_all(&run.out).unwrap();
    std::fs::write(run.out.join("notes.txt"), b"already here").unwrap();
    let stats = run.undelete();
    assert_eq!(stats.recovered, 1);
    run.assert_confined();
    assert_eq!(
        std::fs::read(run.out.join("notes.txt")).unwrap(),
        b"already here"
    );
    assert_eq!(std::fs::read(run.out.join("notes_1.txt")).unwrap(), PAYLOAD);
    assert_eq!(files_under(&run.out).len(), 2);
}
