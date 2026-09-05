//! Shared plumbing: the parsers read from a `Source`, which is a file, so each
//! input is written to a scratch file first. The file is reused across
//! iterations to keep the per-run cost to one write.

use std::io::{Seek, SeekFrom, Write};
use std::sync::Mutex;

use unearth::source::Source;

static SCRATCH: Mutex<Option<(tempfile::TempDir, std::path::PathBuf)>> = Mutex::new(None);

/// Write `data` to the scratch image and open it as a `Source`. An empty
/// input has no source to open, so it yields `None`.
pub fn source_of(data: &[u8]) -> Option<Source> {
    if data.is_empty() {
        return None;
    }
    let mut guard = SCRATCH.lock().unwrap();
    if guard.is_none() {
        let dir = tempfile::tempdir().expect("scratch dir");
        let path = dir.path().join("input.img");
        *guard = Some((dir, path));
    }
    let path = &guard.as_ref().unwrap().1;
    let mut f = std::fs::File::create(path).expect("scratch file");
    f.write_all(data).expect("write");
    f.seek(SeekFrom::Start(0)).ok();
    f.set_len(data.len() as u64).ok();
    drop(f);
    Source::open(path).ok()
}
