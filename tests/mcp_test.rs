//! End-to-end test of the MCP server: drive `mcp::serve` over in-memory buffers
//! with a real session (initialize, then tool calls that actually recover data).

mod common;

use std::io::Cursor;

use unearth::json::{self, Json};
use unearth::mcp;

/// A path as it must appear inside a JSON string literal: Windows paths carry
/// backslashes, which JSON reads as escapes.
fn j(p: &std::path::Path) -> String {
    p.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

/// Feed newline-delimited JSON-RPC requests through the server and return the
/// parsed responses (in order).
fn session(requests: &[&str]) -> Vec<Json> {
    let input = requests.join("\n");
    let mut output = Vec::new();
    mcp::serve(Cursor::new(input.into_bytes()), &mut output).unwrap();
    String::from_utf8(output)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| json::parse(l).unwrap())
        .collect()
}

/// Call one request through `handle_request` and return the parsed tool result
/// (the JSON inside `result.content[0].text`). Lets a test poll a background job.
fn call(req: &str) -> Json {
    let resp = mcp::handle_request(&json::parse(req).unwrap()).unwrap();
    tool_result(&resp)
}

/// Pull the parsed `result.content[0].text` JSON out of a tool-call response.
fn tool_result(resp: &Json) -> Json {
    let result = resp.get("result").unwrap();
    assert_eq!(
        result.get("isError").unwrap().as_bool(),
        Some(false),
        "tool reported an error: {resp}"
    );
    let text = result.get("content").unwrap().as_array().unwrap()[0]
        .get("text")
        .unwrap()
        .as_str()
        .unwrap();
    json::parse(text).unwrap()
}

#[test]
fn full_session_initializes_and_scans() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out = tmp.path().join("out");

    // An image with one planted JPEG.
    let jpeg = common::jpeg(&vec![0x41u8; 2000]);
    let mut data = vec![0u8; 600];
    data.extend_from_slice(&jpeg);
    std::fs::write(&img, &data).unwrap();

    // Handshake.
    let init = session(&[
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    ]);
    assert_eq!(init.len(), 1, "no reply to the notification");
    assert_eq!(
        init[0]
            .get("result")
            .unwrap()
            .get("serverInfo")
            .unwrap()
            .get("name")
            .unwrap()
            .as_str(),
        Some("unearth")
    );

    // `scan` starts a background job and returns a job_id.
    let scan_req = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"scan","arguments":{{"source":"{}","output_dir":"{}"}}}}}}"#,
        j(&img),
        j(&out)
    );
    let started = call(&scan_req);
    let job_id = started.get("job_id").unwrap().as_u64().unwrap();

    // Poll scan_status until the job is done, then read its result.
    let status_req = format!(
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"scan_status","arguments":{{"job_id":{job_id}}}}}}}"#
    );
    let mut status = call(&status_req);
    for _ in 0..2000 {
        if !status.get("running").unwrap().as_bool().unwrap() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
        status = call(&status_req);
    }
    assert_eq!(
        status.get("running").unwrap().as_bool(),
        Some(false),
        "job finished"
    );
    let scan = status.get("result").unwrap();

    assert_eq!(scan.get("files_recovered").unwrap().as_u64(), Some(1));
    assert_eq!(
        scan.get("per_type").unwrap().get("jpg").unwrap().as_u64(),
        Some(1)
    );
    // The JPEG was actually written to the output directory.
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1);

    // The per-file manifest is inline, with a digest matching the bytes on disk.
    let files = scan.get("files").unwrap().as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].get("type").unwrap().as_str(), Some("jpg"));
    let expected = unearth::hash::to_hex(&unearth::hash::digest(&jpeg));
    assert_eq!(
        files[0].get("sha256").unwrap().as_str(),
        Some(expected.as_str())
    );
    assert_eq!(scan.get("files_truncated").unwrap().as_bool(), Some(false));

    // Triage the output directory: one jpg file, no duplicates.
    let tr = format!(
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"triage","arguments":{{"dir":"{}"}}}}}}"#,
        j(&out)
    );
    let triage = tool_result(&session(&[&tr])[0]);
    assert_eq!(triage.get("total_files").unwrap().as_u64(), Some(1));
    assert_eq!(triage.get("duplicate_sets").unwrap().as_u64(), Some(0));
    assert_eq!(
        triage
            .get("by_type")
            .unwrap()
            .get("jpg")
            .unwrap()
            .get("count")
            .unwrap()
            .as_u64(),
        Some(1)
    );
}

#[test]
fn image_runs_as_a_background_job() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out = tmp.path().join("copy.img");

    let data: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&img, &data).unwrap();

    // `image` starts a background job and returns a job_id.
    let image_req = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"image","arguments":{{"source":"{}","output":"{}","sparse":false}}}}}}"#,
        j(&img),
        j(&out)
    );
    let started = call(&image_req);
    let job_id = started.get("job_id").unwrap().as_u64().unwrap();

    // Poll the shared job status API until done.
    let status_req = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"scan_status","arguments":{{"job_id":{job_id}}}}}}}"#
    );
    let mut status = call(&status_req);
    for _ in 0..2000 {
        if !status.get("running").unwrap().as_bool().unwrap() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
        status = call(&status_req);
    }
    assert_eq!(status.get("running").unwrap().as_bool(), Some(false));
    assert_eq!(status.get("kind").unwrap().as_str(), Some("image"));

    let result = status.get("result").unwrap();
    assert_eq!(result.get("bytes_total").unwrap().as_u64(), Some(50_000));
    assert_eq!(result.get("bad_region_count").unwrap().as_u64(), Some(0));
    // The image is a byte-for-byte copy of the source.
    assert_eq!(std::fs::read(&out).unwrap(), data);
}

#[test]
fn scan_status_and_cancel_reject_unknown_jobs() {
    let status = mcp::handle_request(
        &json::parse(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan_status","arguments":{"job_id":999999}}}"#,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        status
            .get("result")
            .unwrap()
            .get("isError")
            .unwrap()
            .as_bool(),
        Some(true)
    );

    let cancel = mcp::handle_request(
        &json::parse(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"scan_cancel","arguments":{"job_id":999999}}}"#,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        cancel
            .get("result")
            .unwrap()
            .get("isError")
            .unwrap()
            .as_bool(),
        Some(true)
    );
}

#[test]
fn list_volumes_and_undelete_tools() {
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("disk.img");
    let out = tmp.path().join("rec");
    std::fs::write(&img, common::ext_volume("notes.txt", b"hello mcp")).unwrap();

    let lv = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"list_volumes","arguments":{{"source":"{}","deleted":true}}}}}}"#,
        j(&img)
    );
    let und = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"undelete","arguments":{{"source":"{}","output_dir":"{}"}}}}}}"#,
        j(&img),
        j(&out)
    );
    let resps = session(&[&lv, &und]);

    let volumes = tool_result(&resps[0]);
    let vols = volumes.get("volumes").unwrap().as_array().unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(
        vols[0].get("filesystem").unwrap().as_str(),
        Some("ext2/3/4")
    );
    assert_eq!(vols[0].get("deleted").unwrap().as_u64(), Some(1));
    // ext exposes its allocation map, so free_bytes is a number (not null) and
    // cannot exceed the volume's size.
    let free = vols[0].get("free_bytes").unwrap().as_u64();
    assert!(free.is_some(), "ext should report numeric free_bytes");
    let size = vols[0].get("size").unwrap().as_u64().unwrap();
    assert!(free.unwrap() <= size, "free cannot exceed volume size");
    // A bare volume (no partition table) reports scheme "none" and no partitions.
    assert_eq!(
        volumes.get("partition_scheme").unwrap().as_str(),
        Some("none")
    );
    assert_eq!(
        volumes.get("partitions").unwrap().as_array().unwrap().len(),
        0
    );

    let undelete = tool_result(&resps[1]);
    assert_eq!(undelete.get("recovered").unwrap().as_u64(), Some(1));
    assert_eq!(std::fs::read(out.join("notes.txt")).unwrap(), b"hello mcp");

    // The recovered file is listed inline with its path and digest.
    let files = undelete.get("files").unwrap().as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].get("path").unwrap().as_str(), Some("notes.txt"));
    let expected = unearth::hash::to_hex(&unearth::hash::digest(b"hello mcp"));
    assert_eq!(
        files[0].get("sha256").unwrap().as_str(),
        Some(expected.as_str())
    );

    // The agent can read the recovered file's bytes back for inspection.
    let recovered_path = out.join("notes.txt");
    let rf = format!(
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{}"}}}}}}"#,
        j(&recovered_path)
    );
    let resps = session(&[&rf]);
    let read = tool_result(&resps[0]);
    assert_eq!(read.get("size").unwrap().as_u64(), Some(9)); // "hello mcp"
    assert_eq!(read.get("truncated").unwrap().as_bool(), Some(false));
    assert_eq!(read.get("encoding").unwrap().as_str(), Some("base64"));
    // "hello mcp" base64-encodes to "aGVsbG8gbWNw".
    assert_eq!(read.get("data").unwrap().as_str(), Some("aGVsbG8gbWNw"));
}

#[test]
fn list_volumes_scan_finds_a_lost_partition() {
    // An ext volume at 1 MiB with garbage (no partition table) before it:
    // ordinary detection finds nothing, but list_volumes with scan=true locates
    // it via the whole-source signature scan.
    const MIB: usize = 1024 * 1024;
    let ext = common::ext_volume("notes.txt", b"hello mcp");
    let mut img = vec![0xA5u8; MIB + ext.len()];
    img[MIB..MIB + ext.len()].copy_from_slice(&ext);
    img[510] = 0;
    img[511] = 0;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("nopart.img");
    std::fs::write(&path, &img).unwrap();

    // Without scan: nothing found.
    let plain = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"list_volumes","arguments":{{"source":"{}"}}}}}}"#,
        j(&path)
    );
    let scanned = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"list_volumes","arguments":{{"source":"{}","scan":true}}}}}}"#,
        j(&path)
    );
    let resps = session(&[&plain, &scanned]);

    let plain_vols = tool_result(&resps[0]);
    assert_eq!(
        plain_vols.get("volumes").unwrap().as_array().unwrap().len(),
        0
    );

    let scan_vols = tool_result(&resps[1]);
    let vols = scan_vols.get("volumes").unwrap().as_array().unwrap();
    assert_eq!(vols.len(), 1, "scan should find the orphaned ext volume");
    assert_eq!(
        vols[0].get("filesystem").unwrap().as_str(),
        Some("ext2/3/4")
    );
    assert_eq!(vols[0].get("offset").unwrap().as_u64(), Some(MIB as u64));
}

#[test]
fn list_volumes_reports_the_partition_table() {
    // An MBR with one Linux partition entry (no real filesystem inside).
    let mut disk = vec![0u8; 8192];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    let e = 446;
    disk[e + 4] = 0x83; // Linux
    disk[e + 8..e + 12].copy_from_slice(&2048u32.to_le_bytes());
    disk[e + 12..e + 16].copy_from_slice(&100u32.to_le_bytes());

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("mbr.img");
    std::fs::write(&path, &disk).unwrap();

    let lv = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"list_volumes","arguments":{{"source":"{}"}}}}}}"#,
        j(&path)
    );
    let result = tool_result(&session(&[&lv])[0]);
    assert_eq!(
        result.get("partition_scheme").unwrap().as_str(),
        Some("mbr")
    );
    let parts = result.get("partitions").unwrap().as_array().unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].get("type").unwrap().as_str(), Some("Linux"));
    assert_eq!(parts[0].get("start").unwrap().as_u64(), Some(2048 * 512));
}
