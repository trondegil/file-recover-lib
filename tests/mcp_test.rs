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

// --- Protocol edges ----------------------------------------------------------

fn num(j: &Json) -> Option<f64> {
    match j {
        Json::Num(v) => Some(*v),
        _ => None,
    }
}

fn error_code(resp: &Json) -> Option<f64> {
    num(resp.get("error")?.get("code")?)
}

/// Malformed input gets the JSON-RPC error it deserves and does not take the
/// session down: a later request on the same session is still answered.
#[test]
fn protocol_errors_are_coded_and_the_session_continues() {
    let ping = r#"{"jsonrpc":"2.0","id":99,"method":"ping"}"#;

    // Not JSON at all.
    let r = session(&["this is not json", ping]);
    assert_eq!(r.len(), 2);
    assert_eq!(error_code(&r[0]), Some(-32700.0), "{}", r[0]);
    assert_eq!(r[0].get("id"), Some(&Json::Null));
    assert!(r[1].get("result").is_some(), "{}", r[1]);

    // An object that is not a JSON-RPC 2.0 request.
    let r = session(&[r#"{"id":1,"method":"ping"}"#, ping]);
    assert_eq!(r.len(), 2);
    assert_eq!(error_code(&r[0]), Some(-32600.0), "{}", r[0]);
    let r = session(&[r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#, ping]);
    assert_eq!(error_code(&r[0]), Some(-32600.0), "{}", r[0]);
    let r = session(&[r#"{"jsonrpc":"2.0","id":1}"#, ping]);
    assert_eq!(error_code(&r[0]), Some(-32600.0), "no method: {}", r[0]);

    // A request without an id is a notification: no reply, session goes on.
    let r = session(&[r#"{"jsonrpc":"2.0","method":"ping"}"#, ping]);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].get("id").and_then(num), Some(99.0));

    // Params of the wrong shape, and a tool name that is not a string.
    let r = session(&[
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":5}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":7}}"#,
        ping,
    ]);
    assert_eq!(r.len(), 3);
    assert_eq!(error_code(&r[0]), Some(-32602.0), "{}", r[0]);
    assert_eq!(error_code(&r[1]), Some(-32602.0), "{}", r[1]);
    assert!(r[2].get("result").is_some());

    // An unknown tool is a protocol error (MCP: invalid params), an unknown
    // method is method-not-found.
    let r = session(&[
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"no/such/method"}"#,
        ping,
    ]);
    assert_eq!(error_code(&r[0]), Some(-32602.0), "{}", r[0]);
    assert!(r[0].to_string().contains("no_such_tool"));
    assert_eq!(error_code(&r[1]), Some(-32601.0), "{}", r[1]);
    assert!(r[2].get("result").is_some());

    // A tool argument of the wrong type is a tool error, reported in band as
    // the MCP tool contract wants, and names the argument.
    let r = session(&[
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"scan_status","arguments":{"job_id":"seven"}}}"#,
        ping,
    ]);
    let result = r[0].get("result").unwrap();
    assert_eq!(result.get("isError").unwrap().as_bool(), Some(true));
    assert!(r[0].to_string().contains("job_id"), "{}", r[0]);
    assert!(r[1].get("result").is_some());
}

fn poll_status(job_id: u64, until: impl Fn(&Json) -> bool, what: &str) -> Json {
    let req = format!(
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"scan_status","arguments":{{"job_id":{job_id}}}}}}}"#
    );
    for _ in 0..20_000 {
        let st = call(&req);
        if until(&st) {
            return st;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    panic!("{what}: status never satisfied the condition");
}

fn listing(dir: &std::path::Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Bytes with no long zero runs, so the carver cannot skip ahead and each
/// chunk takes real time, and no 0xFF, so nothing in the filler can start
/// or end a JPEG and swallow a planted one.
fn noisy(seed: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u64).wrapping_mul(7).wrapping_add(seed) % 251) as u8)
        .collect()
}

/// Cancel a scan that is really running: the job finishes with `cancelled`
/// set, repeated status calls agree, the output set does not change after
/// the finished report, and the checkpoint it left is accepted by a resume.
#[test]
fn a_running_scan_can_be_cancelled_and_then_resumed() {
    const MIB: usize = 1024 * 1024;
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("big.img");
    let out = tmp.path().join("out");
    let mut data = noisy(7, 64 * MIB);
    let jpegs: Vec<Vec<u8>> = (0..8u8)
        .map(|i| common::jpeg(&vec![0x20 + i; 3000]))
        .collect();
    for (i, j) in jpegs.iter().enumerate() {
        let at = i * 8 * MIB + 1000;
        data[at..at + j.len()].copy_from_slice(j);
    }
    std::fs::write(&img, &data).unwrap();

    let scan_req = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"scan","arguments":{{"source":"{}","output_dir":"{}","types":["jpg"]}}}}}}"#,
        j(&img),
        j(&out)
    );
    let job_id = call(&scan_req).get("job_id").unwrap().as_u64().unwrap();

    // Wait until the scan has demonstrably made progress, then cancel.
    poll_status(
        job_id,
        |st| st.get("bytes_scanned").unwrap().as_u64().unwrap_or(0) > 0,
        "progress",
    );
    let cancel_req = format!(
        r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"scan_cancel","arguments":{{"job_id":{job_id}}}}}}}"#
    );
    let c = call(&cancel_req);
    assert_eq!(c.get("cancel_requested").unwrap().as_bool(), Some(true));

    let finished = poll_status(
        job_id,
        |st| !st.get("running").unwrap().as_bool().unwrap(),
        "finish",
    );
    let result = finished.get("result").expect("a result, not an error");
    assert_eq!(result.get("cancelled").unwrap().as_bool(), Some(true));
    let scanned = finished.get("bytes_scanned").unwrap().as_u64().unwrap();
    assert!(
        scanned < data.len() as u64,
        "stopped before the end: {scanned}"
    );
    let files_after_finish = listing(&out);
    let recovered = result.get("files_recovered").unwrap().as_u64().unwrap();
    assert_eq!(files_after_finish.len() as u64, recovered);

    // Repeated status calls agree with each other and with the first report.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let again = poll_status(job_id, |_| true, "again");
    assert_eq!(again, finished);
    assert_eq!(listing(&out), files_after_finish, "output set stable");

    // The checkpoint (default: next to the output directory) resumes cleanly.
    let checkpoint = tmp.path().join("out.checkpoint");
    assert!(checkpoint.exists(), "a cancelled scan leaves a checkpoint");
    let resume_req = format!(
        r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"scan","arguments":{{"source":"{}","output_dir":"{}","types":["jpg"],"resume":true}}}}}}"#,
        j(&img),
        j(&out)
    );
    let job2 = call(&resume_req).get("job_id").unwrap().as_u64().unwrap();
    assert_ne!(job2, job_id);
    let done = poll_status(
        job2,
        |st| !st.get("running").unwrap().as_bool().unwrap(),
        "resume",
    );
    let r2 = done.get("result").unwrap();
    assert_eq!(r2.get("cancelled").unwrap().as_bool(), Some(false));
    assert_eq!(r2.get("files_recovered").unwrap().as_u64(), Some(8));
    assert_eq!(listing(&out).len(), 8);
    let mut got: Vec<Vec<u8>> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .collect();
    got.sort();
    let mut want = jpegs.clone();
    want.sort();
    assert_eq!(got, want, "every planted JPEG, once, byte for byte");
}

#[test]
fn two_scans_back_to_back_get_distinct_jobs_and_right_counts() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ids = Vec::new();
    for (k, count) in [1usize, 2].iter().enumerate() {
        let img = tmp.path().join(format!("disk{k}.img"));
        let out = tmp.path().join(format!("out{k}"));
        let mut data = vec![0u8; 512];
        for i in 0..*count {
            data.extend_from_slice(&common::jpeg(&vec![0x30 + i as u8; 1500]));
            data.extend_from_slice(&[0u8; 512]);
        }
        std::fs::write(&img, &data).unwrap();
        let req = format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"scan","arguments":{{"source":"{}","output_dir":"{}"}}}}}}"#,
            j(&img),
            j(&out)
        );
        let id = call(&req).get("job_id").unwrap().as_u64().unwrap();
        let st = poll_status(
            id,
            |st| !st.get("running").unwrap().as_bool().unwrap(),
            "scan",
        );
        assert_eq!(
            st.get("result")
                .unwrap()
                .get("files_recovered")
                .unwrap()
                .as_u64(),
            Some(*count as u64)
        );
        assert_eq!(listing(&out).len(), *count);
        ids.push(id);
    }
    assert_ne!(ids[0], ids[1]);
}
