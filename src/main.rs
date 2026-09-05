//! `unearth` command-line entry point.

mod cli;

use anyhow::Result;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};

use clap::CommandFactory;
use cli::{
    Cli, Command, CompletionsArgs, IdentifyArgs, ImageArgs, InfoArgs, RecoverArgs, ScanArgs,
    TriageArgs, UndeleteArgs, VerifyArgs,
};
use unearth::carver::{self, CarveOptions, ProgressSink};
use unearth::recover;
use unearth::signatures::{self, SIGNATURES};
use unearth::source::Source;

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::ListTypes => {
            list_types();
            Ok(())
        }
        Command::Scan(args) => scan(args),
        Command::Undelete(args) => undelete(args),
        Command::Recover(args) => recover_all(args),
        Command::Info(args) => info(args),
        Command::Image(args) => image(args),
        Command::Verify(args) => verify(args),
        Command::Triage(args) => triage(args),
        Command::Identify(args) => identify(args),
        Command::Mcp => {
            let stdin = std::io::stdin();
            let stdout = std::io::stdout();
            unearth::mcp::serve(stdin.lock(), stdout.lock())
        }
        Command::Completions(args) => {
            completions(args);
            Ok(())
        }
    }
}

/// Print a shell completion script for `unearth` to stdout.
fn completions(args: CompletionsArgs) {
    let mut cmd = Cli::command();
    clap_complete::generate(args.shell, &mut cmd, "unearth", &mut std::io::stdout());
}

fn verify(args: VerifyArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.manifest)
        .map_err(|e| anyhow::anyhow!("reading manifest {}: {e}", args.manifest.display()))?;
    let is_json = args
        .manifest
        .extension()
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let entries = unearth::manifest::parse(&text, is_json)?;

    let mut ok = 0u64;
    let mut mismatched = 0u64;
    let mut missing = 0u64;
    let mut no_digest = 0u64;

    for e in &entries {
        let expected = match &e.sha256 {
            Some(s) => s,
            None => {
                no_digest += 1;
                continue;
            }
        };
        let path = args.base.join(&e.path);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(_) => {
                missing += 1;
                println!("MISSING   {}", e.path);
                continue;
            }
        };
        let got = unearth::hash::to_hex(&unearth::hash::digest(&data));
        if got.eq_ignore_ascii_case(expected) {
            ok += 1;
        } else {
            mismatched += 1;
            println!("MISMATCH  {} (expected {expected}, got {got})", e.path);
        }
    }

    println!(
        "Verified {ok} OK, {mismatched} mismatched, {missing} missing, {no_digest} without a digest."
    );
    if mismatched > 0 || missing > 0 {
        anyhow::bail!("verification failed: {mismatched} mismatched, {missing} missing");
    }
    Ok(())
}

/// Count recoverable deleted files in a volume via a dry-run recovery; `None`
/// when the caller didn't ask, `Some(-1)` when the scan errored.
fn deleted_count(vol: &recover::Volume, source: &Source, requested: bool) -> Option<i64> {
    if !requested {
        return None;
    }
    let opts = recover::RecoverOptions {
        min_size: 0,
        max_size: None,
        modified_after: None,
        modified_before: None,
        names: Vec::new(),
        exclude_names: Vec::new(),
        dry_run: true,
    };
    Some(
        match vol.recover_deleted(source, std::path::Path::new("."), &opts) {
            Ok(stats) => stats.recovered as i64,
            Err(_) => -1,
        },
    )
}

fn triage(args: TriageArgs) -> Result<()> {
    use unearth::json::{obj, s, Json};

    let sum = unearth::triage::summarize(&args.dir, args.top)?;

    if args.json {
        let by_type = Json::Obj(
            sum.by_type
                .iter()
                .map(|(ext, st)| {
                    (
                        ext.clone(),
                        obj(vec![
                            ("count", Json::Num(st.count as f64)),
                            ("bytes", Json::Num(st.bytes as f64)),
                        ]),
                    )
                })
                .collect(),
        );
        let largest = sum
            .largest
            .iter()
            .map(|(p, sz)| {
                obj(vec![
                    ("path", s(p.as_str())),
                    ("size", Json::Num(*sz as f64)),
                ])
            })
            .collect();
        let by_category = Json::Obj(
            sum.by_category()
                .iter()
                .map(|(cat, st)| {
                    (
                        cat.to_string(),
                        obj(vec![
                            ("count", Json::Num(st.count as f64)),
                            ("bytes", Json::Num(st.bytes as f64)),
                        ]),
                    )
                })
                .collect(),
        );
        let mismatches = sum
            .mismatches
            .iter()
            .map(|m| {
                obj(vec![
                    ("path", s(m.path.as_str())),
                    ("claimed", s(m.claimed.as_str())),
                    ("detected", s(m.detected.as_str())),
                ])
            })
            .collect();
        let corrupt = sum
            .corrupt
            .iter()
            .map(|c| {
                obj(vec![
                    ("path", s(c.path.as_str())),
                    ("claimed", s(c.claimed.as_str())),
                ])
            })
            .collect();
        let out = obj(vec![
            ("dir", s(args.dir.display().to_string())),
            ("total_files", Json::Num(sum.total_files as f64)),
            ("total_bytes", Json::Num(sum.total_bytes as f64)),
            ("empty_files", Json::Num(sum.empty_files as f64)),
            ("duplicate_sets", Json::Num(sum.duplicate_sets as f64)),
            ("duplicate_bytes", Json::Num(sum.duplicate_bytes as f64)),
            ("by_category", by_category),
            ("by_type", by_type),
            ("largest", Json::Arr(largest)),
            ("mismatches", Json::Arr(mismatches)),
            ("corrupt", Json::Arr(corrupt)),
            (
                "oldest_mtime",
                sum.oldest_mtime.map_or(Json::Null, |t| Json::Num(t as f64)),
            ),
            (
                "newest_mtime",
                sum.newest_mtime.map_or(Json::Null, |t| Json::Num(t as f64)),
            ),
        ]);
        println!("{out}");
        return Ok(());
    }

    println!(
        "{} file(s), {} total.",
        sum.total_files,
        human_bytes(sum.total_bytes)
    );
    if sum.empty_files > 0 {
        println!("  {} empty file(s).", sum.empty_files);
    }
    if sum.duplicate_sets > 0 {
        println!(
            "  {} duplicate set(s), {} redundant.",
            sum.duplicate_sets,
            human_bytes(sum.duplicate_bytes)
        );
    }
    let by_category = sum.by_category();
    if !by_category.is_empty() {
        println!("\nBy category:");
        for (cat, st) in &by_category {
            println!("  {:<10} {:>5}  {}", cat, st.count, human_bytes(st.bytes));
        }
    }
    if !sum.by_type.is_empty() {
        println!("\nBy type:");
        for (ext, st) in &sum.by_type {
            let label = if ext.is_empty() { "(none)" } else { ext };
            println!("  {:<8} {:>5}  {}", label, st.count, human_bytes(st.bytes));
        }
    }
    if !sum.largest.is_empty() {
        println!("\nLargest:");
        for (path, size) in &sum.largest {
            println!("  {:>10}  {}", human_bytes(*size), path);
        }
    }
    if !sum.mismatches.is_empty() {
        println!("\nType mismatches (content \u{2260} extension):");
        for m in &sum.mismatches {
            println!("  {}: .{} but content is {}", m.path, m.claimed, m.detected);
        }
    }
    if !sum.corrupt.is_empty() {
        println!("\nCorrupt or truncated (content doesn't match a known extension):");
        for c in &sum.corrupt {
            println!("  {}: .{} header not found", c.path, c.claimed);
        }
    }
    if let (Some(oldest), Some(newest)) = (sum.oldest_mtime, sum.newest_mtime) {
        println!(
            "\nModified: {} .. {}",
            unearth::times::format_utc(oldest),
            unearth::times::format_utc(newest)
        );
    }
    Ok(())
}

fn identify(args: IdentifyArgs) -> Result<()> {
    use unearth::json::{obj, s, Json};

    // Read up to 64 KiB from the start of a file (what the signature table and
    // its validators need).
    fn read_head(path: &std::path::Path) -> Result<Vec<u8>> {
        use std::io::Read;
        let mut head = vec![0u8; 64 * 1024];
        let mut f = std::fs::File::open(path)
            .map_err(|e| anyhow::anyhow!("opening {}: {e}", path.display()))?;
        let mut read = 0usize;
        while read < head.len() {
            let nb = f.read(&mut head[read..])?;
            if nb == 0 {
                break;
            }
            read += nb;
        }
        head.truncate(read);
        Ok(head)
    }

    let one_json = |path: &std::path::Path| -> Result<Json> {
        let head = read_head(path)?;
        Ok(match unearth::identify::identify(&head) {
            Some(d) => obj(vec![
                ("file", s(path.display().to_string())),
                ("identified", Json::Bool(true)),
                ("type", s(d.ext)),
                ("name", s(d.name)),
                ("category", s(signatures::category_of(d.ext).as_str())),
                ("validated", Json::Bool(d.validated)),
            ]),
            None => obj(vec![
                ("file", s(path.display().to_string())),
                ("identified", Json::Bool(false)),
            ]),
        })
    };

    if args.json {
        // One file: a single object (back-compatible). Several: a JSON array.
        if let [path] = args.files.as_slice() {
            println!("{}", one_json(path)?);
        } else {
            let arr: Result<Vec<Json>> = args.files.iter().map(|p| one_json(p)).collect();
            println!("{}", Json::Arr(arr?));
        }
        return Ok(());
    }

    for path in &args.files {
        let head = read_head(path)?;
        match unearth::identify::identify(&head) {
            Some(d) => {
                let note = if d.validated {
                    "structurally validated"
                } else {
                    "by magic"
                };
                let category = signatures::category_of(d.ext).as_str();
                println!(
                    "{}: {} ({}, {category}, {note})",
                    path.display(),
                    d.name,
                    d.ext
                );
            }
            None => println!("{}: unknown", path.display()),
        }
    }
    Ok(())
}

fn info(args: InfoArgs) -> Result<()> {
    let source = Source::open(&args.source)?;
    let detected = recover::detect(&source);

    if args.json {
        let vols = detected.unwrap_or_default();
        let mut out = String::from("{\n");
        out.push_str(&format!(
            "  \"source\": \"{}\",\n",
            json_escape(&args.source.display().to_string())
        ));
        out.push_str(&format!("  \"source_bytes\": {},\n", source.size));
        let table = unearth::partition::read(&source);
        out.push_str(&format!(
            "  \"partition_scheme\": \"{}\",\n",
            partition_scheme_str(table.scheme)
        ));
        out.push_str(&format!("  \"gpt_from_backup\": {},\n", table.from_backup));
        let disk_guid = match &table.disk_guid {
            Some(g) => format!("\"{}\"", json_escape(g)),
            None => "null".to_string(),
        };
        out.push_str(&format!("  \"disk_guid\": {disk_guid},\n"));
        out.push_str("  \"partitions\": [");
        for (i, p) in table.partitions.iter().enumerate() {
            let name = match &p.name {
                Some(n) => format!("\"{}\"", json_escape(n)),
                None => "null".to_string(),
            };
            let uuid = match &p.uuid {
                Some(u) => format!("\"{}\"", json_escape(u)),
                None => "null".to_string(),
            };
            let attributes = p
                .attributes
                .iter()
                .map(|a| format!("\"{a}\""))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "{}\n    {{\"type\": \"{}\", \"name\": {}, \"uuid\": {}, \"start\": {}, \"size\": {}, \"attributes\": [{}]}}",
                if i == 0 { "" } else { "," },
                json_escape(&p.kind),
                name,
                uuid,
                p.start,
                p.size,
                attributes,
            ));
        }
        out.push_str(if table.partitions.is_empty() {
            "],\n"
        } else {
            "\n  ],\n"
        });
        if vols.is_empty() {
            out.push_str("  \"volumes\": []\n");
        } else {
            out.push_str("  \"volumes\": [\n");
            for (i, vol) in vols.iter().enumerate() {
                let deleted = match deleted_count(vol, &source, args.deleted) {
                    Some(n) => n.to_string(),
                    None => "null".to_string(),
                };
                let comma = if i + 1 < vols.len() { "," } else { "" };
                let volumes = vol
                    .contained_volumes()
                    .iter()
                    .map(|n| format!("\"{}\"", json_escape(n)))
                    .collect::<Vec<_>>()
                    .join(", ");
                let label = match vol.volume_label() {
                    Some(l) => format!("\"{}\"", json_escape(&l)),
                    None => "null".to_string(),
                };
                let version = match vol.fs_version() {
                    Some(v) => format!("\"{}\"", json_escape(v)),
                    None => "null".to_string(),
                };
                let uuid = match vol.volume_uuid() {
                    Some(u) => format!("\"{}\"", json_escape(&u)),
                    None => "null".to_string(),
                };
                let last_mounted = match vol.last_mounted() {
                    Some(p) => format!("\"{}\"", json_escape(&p)),
                    None => "null".to_string(),
                };
                let boot = match vol.boot_info() {
                    Some(b) => format!("\"{}\"", json_escape(&b)),
                    None => "null".to_string(),
                };
                let clean = match vol.is_clean() {
                    Some(b) => b.to_string(),
                    None => "null".to_string(),
                };
                let free = match free_bytes(vol, &source) {
                    Some(n) => n.to_string(),
                    None => "null".to_string(),
                };
                let alloc_unit = match vol.alloc_unit() {
                    Some(n) => n.to_string(),
                    None => "null".to_string(),
                };
                let (inodes_used, inodes_total) = match vol.inode_usage() {
                    Some((u, t)) => (u.to_string(), t.to_string()),
                    None => ("null".to_string(), "null".to_string()),
                };
                let created_time = match vol.created_time() {
                    Some(n) => n.to_string(),
                    None => "null".to_string(),
                };
                let written_time = match vol.written_time() {
                    Some(n) => n.to_string(),
                    None => "null".to_string(),
                };
                out.push_str(&format!(
                    "    {{\"index\": {}, \"filesystem\": \"{}\", \"version\": {}, \"offset\": {}, \"size\": {}, \"alloc_unit_bytes\": {}, \"inodes_used\": {}, \"inodes_total\": {}, \"free_bytes\": {}, \"deleted\": {}, \"label\": {}, \"uuid\": {}, \"last_mounted\": {}, \"boot\": {}, \"clean\": {}, \"created_time\": {}, \"written_time\": {}, \"contained_volumes\": [{}]}}{}\n",
                    i,
                    json_escape(&vol.fs_label()),
                    version,
                    vol.offset(),
                    vol.size(),
                    alloc_unit,
                    inodes_used,
                    inodes_total,
                    free,
                    deleted,
                    label,
                    uuid,
                    last_mounted,
                    boot,
                    clean,
                    created_time,
                    written_time,
                    volumes,
                    comma
                ));
            }
            out.push_str("  ]\n");
        }
        if args.scan {
            let scanned =
                recover::scan_lost_volumes(&source, args.scan_step, |_| {}).unwrap_or_default();
            out.push_str(",\n  \"scan\": [\n");
            for (i, v) in scanned.iter().enumerate() {
                let comma = if i + 1 < scanned.len() { "," } else { "" };
                out.push_str(&format!(
                    "    {{\"filesystem\": \"{}\", \"offset\": {}, \"size\": {}}}{}\n",
                    json_escape(&v.fs_label()),
                    v.offset(),
                    v.size(),
                    comma
                ));
            }
            out.push_str("  ]\n");
        }
        out.push_str("}\n");
        print!("{out}");
        return Ok(());
    }

    println!(
        "Source: {} ({})",
        args.source.display(),
        human_bytes(source.size)
    );

    let table = unearth::partition::read(&source);
    if !table.partitions.is_empty() {
        let from_backup = if table.from_backup {
            " (recovered from backup header; primary GPT is missing or corrupt)"
        } else {
            ""
        };
        println!(
            "\nPartition table: {}{}",
            partition_scheme_str(table.scheme).to_uppercase(),
            from_backup
        );
        if let Some(g) = &table.disk_guid {
            println!("  disk GUID: {g}");
        }
        for (i, p) in table.partitions.iter().enumerate() {
            let name = p
                .name
                .as_deref()
                .map(|n| format!(" \"{n}\""))
                .unwrap_or_default();
            println!(
                "  {:<3} {:<22} {:>12} {}{}",
                i,
                p.kind,
                p.start,
                human_bytes(p.size),
                name
            );
            if let Some(u) = &p.uuid {
                println!("      uuid: {u}");
            }
            if !p.attributes.is_empty() {
                println!("      flags: {}", p.attributes.join(", "));
            }
        }
    }

    let volumes = match detected {
        Ok(v) => v,
        Err(e) => {
            println!("No supported volumes detected: {e}");
            // A deep signature scan is exactly what helps when the partition
            // table is gone, so fall through to it rather than returning.
            if !args.scan {
                return Ok(());
            }
            Vec::new()
        }
    };

    if !volumes.is_empty() {
        println!("\nDetected {} volume(s):\n", volumes.len());
        println!(
            "  {:<3} {:<10} {:<14} {:<10} DELETED",
            "#", "FS", "OFFSET", "SIZE"
        );
        println!(
            "  {:<3} {:<10} {:<14} {:<10} -------",
            "-", "--", "------", "----"
        );
    }
    for (i, vol) in volumes.iter().enumerate() {
        let deleted = match deleted_count(vol, &source, args.deleted) {
            None => "-".to_string(),
            Some(-1) => "?".to_string(),
            Some(n) => n.to_string(),
        };
        println!(
            "  {:<3} {:<10} {:<14} {:<10} {}",
            i,
            vol.fs_label(),
            vol.offset(),
            human_bytes(vol.size()),
            deleted
        );
        if let Some(version) = vol.fs_version() {
            println!("      version: {version}");
        }
        if let Some(label) = vol.volume_label() {
            println!("      label: {label}");
        }
        if let Some(uuid) = vol.volume_uuid() {
            println!("      uuid: {uuid}");
        }
        if let Some(path) = vol.last_mounted() {
            println!("      last mounted: {path}");
        }
        if let Some(boot) = vol.boot_info() {
            println!("      boot: {boot}");
        }
        if vol.is_clean() == Some(false) {
            println!("      state: dirty (not cleanly unmounted)");
        }
        if let Some(unit) = vol.alloc_unit() {
            println!("      alloc unit: {}", human_bytes(unit));
        }
        if let Some((used, total)) = vol.inode_usage() {
            println!("      inodes: {used} used / {total}");
        }
        if let Some(t) = vol.created_time() {
            println!("      created: {}", unearth::times::format_utc(t));
        }
        if let Some(t) = vol.written_time() {
            println!("      last written: {}", unearth::times::format_utc(t));
        }
        if let Some(free) = free_bytes(vol, &source) {
            let pct = if vol.size() > 0 {
                free as f64 / vol.size() as f64 * 100.0
            } else {
                0.0
            };
            println!("      free:  {} ({pct:.1}% unallocated)", human_bytes(free));
        }
        let contained = vol.contained_volumes();
        if !contained.is_empty() {
            println!("      volumes: {}", contained.join(", "));
        }
    }
    if !volumes.is_empty() && !args.deleted {
        println!("\nRun with --deleted to count recoverable deleted files per volume.");
    }

    if args.scan {
        eprintln!("\nScanning the whole source for filesystem signatures...");
        let bar = ProgressBar::new(source.size);
        bar.set_style(
            ProgressStyle::with_template("  scanning {bar:40} {bytes}/{total_bytes}")
                .unwrap_or_else(|_| ProgressStyle::default_bar()),
        );
        let scanned =
            recover::scan_lost_volumes(&source, args.scan_step, |off| bar.set_position(off))?;
        bar.finish_and_clear();

        println!(
            "\nSignature scan ({}-aligned) — {} volume(s) found:\n",
            human_bytes(args.scan_step),
            scanned.len()
        );
        println!("  {:<3} {:<10} {:<16} SIZE", "#", "FS", "OFFSET");
        println!("  {:<3} {:<10} {:<16} ----", "-", "--", "------");
        for (i, v) in scanned.iter().enumerate() {
            println!(
                "  {:<3} {:<10} {:<16} {}",
                i,
                v.fs_label(),
                v.offset(),
                human_bytes(v.size())
            );
        }
        if !scanned.is_empty() {
            println!(
                "\nTarget a lost volume with `undelete --offset <OFFSET>` or `scan --start <OFFSET>`."
            );
        }
    }
    Ok(())
}

/// Drop from `active` every signature whose type is named (directly or via a
/// category) in `exclude`. An unknown exclude value is an error.
fn apply_exclude(
    active: &mut Vec<&'static signatures::Signature>,
    exclude: &[String],
) -> Result<()> {
    if exclude.is_empty() {
        return Ok(());
    }
    let dropped = signatures::select(exclude)?;
    let drop_exts: std::collections::HashSet<&str> = dropped.iter().map(|s| s.ext).collect();
    active.retain(|s| !drop_exts.contains(s.ext));
    Ok(())
}

fn list_types() {
    use unearth::signatures::{category_of, Category};

    // (category, display heading) in presentation order.
    let groups = [
        (Category::Image, "IMAGE"),
        (Category::Audio, "AUDIO"),
        (Category::Video, "VIDEO"),
        (Category::Document, "DOCUMENT"),
        (Category::Archive, "ARCHIVE"),
        (Category::Executable, "EXECUTABLE"),
        (Category::Font, "FONT"),
        (Category::System, "SYSTEM"),
        (
            Category::Volume,
            "VOLUME (filesystem images; not in the default set, ask with --type volume)",
        ),
        (Category::Other, "OTHER"),
    ];

    // Count distinct extensions across all signatures.
    let mut all_exts: Vec<&str> = SIGNATURES.iter().map(|s| s.ext).collect();
    all_exts.sort_unstable();
    all_exts.dedup();
    println!("Recoverable file types ({}), by category:", all_exts.len());

    for (cat, heading) in groups {
        // Distinct extensions in this category, in signature order, with the
        // first signature's description.
        let mut rows: Vec<(&str, &str)> = Vec::new();
        for sig in SIGNATURES {
            if category_of(sig.ext) == cat && !rows.iter().any(|(e, _)| *e == sig.ext) {
                rows.push((sig.ext, sig.name));
            }
        }
        if rows.is_empty() {
            continue;
        }
        println!("\n{heading}");
        for (ext, name) in rows {
            println!("  {ext:<6}  {name}");
        }
    }

    println!("\nSelect one type with --type <EXT>, or a whole category with --type <CATEGORY>");
    println!("(categories: image, audio, video, document, archive, executable, font, system).");
}

/// Lowercase name of a partitioning scheme for output.
fn partition_scheme_str(scheme: unearth::partition::Scheme) -> &'static str {
    use unearth::partition::Scheme;
    match scheme {
        Scheme::Gpt => "gpt",
        Scheme::Mbr => "mbr",
        Scheme::Apm => "apm",
        Scheme::Bsd => "bsd",
        Scheme::None => "none",
    }
}

/// Pick the detected volume at index `n` (as listed by `info`), erroring with a
/// clear message if the index is out of range.
fn select_volume(source: &Source, n: usize) -> Result<recover::Volume> {
    let volumes = recover::detect(source)?;
    let count = volumes.len();
    volumes.into_iter().nth(n).ok_or_else(|| {
        anyhow::anyhow!(
            "--volume {n} is out of range: {count} volume(s) detected (indexes 0..{count})"
        )
    })
}

/// The free (unallocated) byte ranges across every detected volume, or `None`
/// when no volume is found or any one cannot report its free-space map (in
/// which case the caller carves the whole source).
fn free_space_regions(source: &Source) -> Option<Vec<(u64, u64)>> {
    let volumes = recover::detect(source).ok()?;
    if volumes.is_empty() {
        return None;
    }
    let mut regions = Vec::new();
    for v in &volumes {
        regions.extend(v.free_extents(source)?);
    }
    Some(regions)
}

/// Total free (unallocated) bytes in a single volume, or `None` when the
/// backend cannot report it (from the allocation map, or the superblock counts
/// for XFS / Btrfs).
fn free_bytes(vol: &recover::Volume, source: &Source) -> Option<u64> {
    vol.free_space(source)
}

/// Accumulate one region's carve stats into a running total.
fn merge_carve_stats(into: &mut carver::CarveStats, from: carver::CarveStats) {
    into.files_recovered += from.files_recovered;
    into.bytes_recovered += from.bytes_recovered;
    into.rejected += from.rejected;
    into.duplicates += from.duplicates;
    into.skipped_large += from.skipped_large;
    for (k, v) in from.per_type {
        *into.per_type.entry(k).or_insert(0) += v;
    }
    into.files.extend(from.files);
}

fn scan(args: ScanArgs) -> Result<()> {
    let started = std::time::Instant::now();
    if args.unallocated && args.resume {
        anyhow::bail!("--unallocated cannot be combined with --resume");
    }
    let mut active = signatures::select(&args.types)?;
    apply_exclude(&mut active, &args.exclude)?;

    let source = Source::open(&args.source)?;
    eprintln!(
        "Source: {} ({})",
        args.source.display(),
        human_bytes(source.size)
    );
    let type_list: Vec<&str> = active.iter().map(|s| s.ext).collect();
    eprintln!("Recovering: {}", type_list.join(", "));
    eprintln!("Output:     {}", args.output.display());

    // A checkpoint file enables resume; default it next to the output directory
    // when --resume is requested without an explicit --checkpoint.
    let checkpoint = args.checkpoint.clone().or_else(|| {
        if args.resume {
            let mut p = args.output.clone().into_os_string();
            p.push(".checkpoint");
            Some(p.into())
        } else {
            None
        }
    });

    let opts = CarveOptions {
        output_dir: args.output,
        start: args.start,
        end: args.end,
        min_size: args.min_size,
        max_size: args.max_size,
        max_files: args.max_files,
        allow_nested: args.allow_nested,
        validate: !args.no_validate,
        dedup: args.dedup,
        progress: !args.quiet,
        checkpoint: checkpoint.clone(),
        resume: args.resume,
        organize: args.organize,
        dry_run: args.dry_run,
        align: args.align,
    };

    let progress: Box<dyn ProgressSink> = if opts.progress {
        Box::new(Bar::new())
    } else {
        Box::new(carver::NoProgress)
    };

    // With --unallocated, carve only the detected volumes' free space; fall back
    // to the whole source when no free-space map is available.
    let carve_regions: Option<Vec<(u64, u64)>> = if args.unallocated {
        match free_space_regions(&source) {
            Some(r) => Some(r),
            None => {
                eprintln!(
                    "--unallocated: free-space map unavailable for the detected filesystem(s); \
                     carving the whole source instead."
                );
                None
            }
        }
    } else {
        None
    };

    let stats = match carve_regions {
        Some(regions) => {
            eprintln!("Carving {} unallocated region(s).", regions.len());
            let mut merged = carver::CarveStats::default();
            let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
            for (rstart, rlen) in regions {
                if opts.max_files.is_some_and(|m| merged.files_recovered >= m) {
                    break;
                }
                let remaining = opts.max_files.map(|m| m - merged.files_recovered);
                let ropts = CarveOptions {
                    output_dir: opts.output_dir.clone(),
                    start: rstart,
                    end: Some(rstart + rlen),
                    min_size: opts.min_size,
                    max_size: opts.max_size,
                    max_files: remaining,
                    allow_nested: opts.allow_nested,
                    validate: opts.validate,
                    dedup: opts.dedup,
                    progress: false,
                    checkpoint: None,
                    resume: false,
                    organize: opts.organize,
                    dry_run: opts.dry_run,
                    align: opts.align,
                };
                let cs = carver::carve_seeded(
                    &source,
                    &active,
                    &ropts,
                    &carver::NoProgress,
                    seen.clone(),
                )?;
                // Thread dedup digests across regions so --dedup is global.
                if opts.dedup {
                    for f in &cs.files {
                        seen.insert(f.sha256);
                    }
                }
                merge_carve_stats(&mut merged, cs);
            }
            merged
        }
        None => carver::carve(&source, &active, &opts, progress.as_ref())?,
    };

    eprintln!();
    if args.dry_run {
        println!(
            "Dry run: would recover {} file(s), {} (nothing written).",
            stats.files_recovered,
            human_bytes(stats.bytes_recovered)
        );
    } else {
        println!(
            "Done. Recovered {} file(s), {}.",
            stats.files_recovered,
            human_bytes(stats.bytes_recovered)
        );
    }
    if !stats.per_type.is_empty() {
        for (ext, count) in &stats.per_type {
            println!("  {:<6} {}", ext, count);
        }
    }
    if stats.rejected > 0 {
        println!(
            "Rejected {} candidate(s) that failed validation (use --no-validate to keep them).",
            stats.rejected
        );
    }
    if let Some(report_path) = &args.report {
        write_carve_report(report_path, &stats.files)?;
        eprintln!("Report written to {}", report_path.display());
    }
    if stats.duplicates > 0 {
        println!(
            "Skipped {} duplicate(s) with identical content.",
            stats.duplicates
        );
    }
    if stats.skipped_large > 0 {
        println!(
            "Skipped {} file(s) larger than the --max-size cap.",
            stats.skipped_large
        );
    }
    if let Some(summary_path) = &args.summary {
        let per_type: Vec<(String, u64)> = stats
            .per_type
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect();
        let fields = [
            ("command", Sv::S("scan".into())),
            ("source", Sv::S(args.source.display().to_string())),
            ("source_bytes", Sv::N(source.size)),
            ("output", Sv::S(opts.output_dir.display().to_string())),
            ("types", Sv::S(type_list.join(","))),
            ("validate", Sv::B(!args.no_validate)),
            ("dedup", Sv::B(args.dedup)),
            ("allow_nested", Sv::B(args.allow_nested)),
            ("unallocated", Sv::B(args.unallocated)),
            ("min_size", Sv::N(args.min_size)),
            ("files_recovered", Sv::N(stats.files_recovered)),
            ("bytes_recovered", Sv::N(stats.bytes_recovered)),
            ("rejected", Sv::N(stats.rejected)),
            ("duplicates", Sv::N(stats.duplicates)),
            ("skipped_large", Sv::N(stats.skipped_large)),
            ("per_type", Sv::Map(per_type)),
            ("elapsed_ms", Sv::N(started.elapsed().as_millis() as u64)),
            ("timestamp_unix", Sv::N(unix_now())),
        ];
        write_summary(summary_path, &fields)?;
        eprintln!("Summary written to {}", summary_path.display());
    }
    Ok(())
}

fn undelete(args: UndeleteArgs) -> Result<()> {
    let started = std::time::Instant::now();
    let source = Source::open(&args.source)?;
    eprintln!(
        "Source: {} ({})",
        args.source.display(),
        human_bytes(source.size)
    );

    let volumes = if args.scan {
        eprintln!("Scanning the whole source for volumes (this may take a while)...");
        recover::scan_lost_volumes(&source, args.scan_step, |_| {})?
    } else if let Some(off) = args.offset {
        vec![recover::parse_at(&source, off)?]
    } else if let Some(n) = args.volume {
        vec![select_volume(&source, n)?]
    } else {
        recover::detect(&source)?
    };
    eprintln!("Found {} volume(s).", volumes.len());

    let opts = recover::RecoverOptions {
        min_size: args.min_size,
        max_size: args.max_size,
        modified_after: args.modified_after,
        modified_before: args.modified_before,
        names: args.names.clone(),
        exclude_names: args.exclude_names.clone(),
        dry_run: args.dry_run,
    };
    if args.dry_run {
        eprintln!("Dry run: no files will be written.");
    } else {
        std::fs::create_dir_all(&args.output)
            .map_err(|e| anyhow::anyhow!("creating output dir {}: {e}", args.output.display()))?;
    }

    let mut total_recovered = 0u64;
    let mut total_bytes = 0u64;
    let mut total_skipped = 0u64;
    // Report rows: (filesystem, volume offset, relative path, size, recovered,
    // sha256-hex). The digest is empty for skipped files and dry runs.
    let mut report_rows: Vec<(String, u64, String, u64, bool, String)> = Vec::new();

    for (i, vol) in volumes.iter().enumerate() {
        // Keep each volume's output separate to avoid path collisions.
        let out = if volumes.len() > 1 {
            args.output.join(format!("volume_{i}"))
        } else {
            args.output.clone()
        };
        eprintln!(
            "Volume {i}: {} at offset {} -> {}",
            vol.fs_label(),
            vol.offset(),
            out.display()
        );
        let stats = vol.recover_deleted(&source, &out, &opts)?;
        total_recovered += stats.recovered;
        total_bytes += stats.bytes_recovered;
        total_skipped += stats.skipped;

        let label = vol.fs_label();
        let offset = vol.offset();
        for f in &stats.files {
            let sha = f
                .sha256
                .map(|d| unearth::hash::to_hex(&d))
                .unwrap_or_default();
            report_rows.push((
                label.clone(),
                offset,
                f.path.to_string_lossy().into_owned(),
                f.size,
                f.recovered,
                sha,
            ));
        }
    }

    if let Some(report_path) = &args.report {
        write_report(report_path, &report_rows)?;
        eprintln!("Report written to {}", report_path.display());
    }

    eprintln!();
    let verb = if args.dry_run {
        "Would recover"
    } else {
        "Recovered"
    };
    println!(
        "Done. {verb} {} deleted file(s), {} ({} skipped as unrecoverable).",
        total_recovered,
        human_bytes(total_bytes),
        total_skipped
    );

    if let Some(summary_path) = &args.summary {
        let fields = [
            ("command", Sv::S("undelete".into())),
            ("source", Sv::S(args.source.display().to_string())),
            ("source_bytes", Sv::N(source.size)),
            ("output", Sv::S(args.output.display().to_string())),
            ("volumes", Sv::N(volumes.len() as u64)),
            ("dry_run", Sv::B(args.dry_run)),
            ("min_size", Sv::N(args.min_size)),
            ("recovered", Sv::N(total_recovered)),
            ("bytes_recovered", Sv::N(total_bytes)),
            ("skipped", Sv::N(total_skipped)),
            ("elapsed_ms", Sv::N(started.elapsed().as_millis() as u64)),
            ("timestamp_unix", Sv::N(unix_now())),
        ];
        write_summary(summary_path, &fields)?;
        eprintln!("Summary written to {}", summary_path.display());
    }
    Ok(())
}

/// One-pass recovery: filesystem-aware undelete into `named/`, then carving
/// into `carved/` (content-deduplicated against the undelete results).
fn recover_all(args: RecoverArgs) -> Result<()> {
    use std::collections::HashSet;

    let started = std::time::Instant::now();
    let source = Source::open(&args.source)?;
    eprintln!(
        "Source: {} ({})",
        args.source.display(),
        human_bytes(source.size)
    );

    // Pass 1: filesystem-aware undelete (restores names and paths).
    let named_dir = args.output.join("named");
    let volumes = if args.scan {
        eprintln!("Scanning the whole source for volumes (this may take a while)...");
        recover::scan_lost_volumes(&source, args.scan_step, |_| {})?
    } else if let Some(off) = args.offset {
        vec![recover::parse_at(&source, off)?]
    } else if let Some(n) = args.volume {
        vec![select_volume(&source, n)?]
    } else {
        recover::detect(&source).unwrap_or_default()
    };
    if volumes.is_empty() {
        eprintln!("No supported filesystem detected; carving only.");
    }
    let ropts = recover::RecoverOptions {
        min_size: args.min_size,
        max_size: args.max_size,
        modified_after: args.modified_after,
        modified_before: args.modified_before,
        names: args.names.clone(),
        exclude_names: args.exclude_names.clone(),
        dry_run: args.dry_run,
    };
    let multi = volumes.len() > 1;
    let mut named_recovered = 0u64;
    let mut named_bytes = 0u64;
    // Digests of everything undelete restored, so carving skips that content.
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    // Combined manifest rows: (kind, path-relative-to-output, size, sha256-hex).
    let mut report_rows: Vec<(&str, String, u64, String)> = Vec::new();
    for (i, vol) in volumes.iter().enumerate() {
        let out = if multi {
            named_dir.join(format!("volume_{i}"))
        } else {
            named_dir.clone()
        };
        eprintln!(
            "Undelete: {} at offset {} -> {}",
            vol.fs_label(),
            vol.offset(),
            out.display()
        );
        let st = vol.recover_deleted(&source, &out, &ropts)?;
        named_recovered += st.recovered;
        named_bytes += st.bytes_recovered;
        for f in &st.files {
            if let Some(d) = f.sha256 {
                seen.insert(d);
            }
            let rel = if multi {
                format!("named/volume_{i}/{}", f.path.to_string_lossy())
            } else {
                format!("named/{}", f.path.to_string_lossy())
            };
            let sha = f
                .sha256
                .map(|d| unearth::hash::to_hex(&d))
                .unwrap_or_default();
            report_rows.push(("named", rel, f.size, sha));
        }
    }

    // With --unallocated, carve only each volume's free space (so live files
    // aren't re-found). Available only when every volume can report its free
    // map; otherwise fall back to carving the whole source.
    let carve_regions: Option<Vec<(u64, u64)>> = if args.unallocated {
        let mut regions = Vec::new();
        let mut supported = !volumes.is_empty();
        for v in &volumes {
            match v.free_extents(&source) {
                Some(r) => regions.extend(r),
                None => {
                    supported = false;
                    break;
                }
            }
        }
        if supported {
            Some(regions)
        } else {
            eprintln!(
                "--unallocated: free-space map unavailable for the detected filesystem(s); \
                 carving the whole source instead."
            );
            None
        }
    } else {
        None
    };

    // Pass 2: carving for whatever the metadata could not restore.
    let mut active = signatures::select(&args.types)?;
    apply_exclude(&mut active, &args.exclude)?;
    let carved_dir = args.output.join("carved");
    let mk_opts = |start: u64, end: Option<u64>, progress: bool| CarveOptions {
        output_dir: carved_dir.clone(),
        start,
        end,
        min_size: args.min_size,
        max_size: args.max_size,
        max_files: None,
        allow_nested: false,
        validate: true,
        dedup: true,
        progress,
        checkpoint: None,
        resume: false,
        organize: args.organize,
        dry_run: args.dry_run,
        align: args.align,
    };
    let (mut carved_files, mut carved_bytes, mut carved_dups) = (0u64, 0u64, 0u64);
    let push_carved = |files: &[carver::CarvedFile],
                       rows: &mut Vec<(&str, String, u64, String)>| {
        for f in files {
            rows.push((
                "carved",
                format!("carved/{}", f.name),
                f.size,
                unearth::hash::to_hex(&f.sha256),
            ));
        }
    };
    match carve_regions {
        Some(regions) => {
            eprintln!(
                "Carve:    {} unallocated region(s) into {}",
                regions.len(),
                carved_dir.display()
            );
            for (rstart, rlen) in regions {
                let opts = mk_opts(rstart, Some(rstart + rlen), false);
                let cs = carver::carve_seeded(
                    &source,
                    &active,
                    &opts,
                    &carver::NoProgress,
                    seen.clone(),
                )?;
                carved_files += cs.files_recovered;
                carved_bytes += cs.bytes_recovered;
                carved_dups += cs.duplicates;
                push_carved(&cs.files, &mut report_rows);
            }
        }
        None => {
            eprintln!("Carve:    into {}", carved_dir.display());
            let opts = mk_opts(0, None, !args.quiet);
            let progress: Box<dyn ProgressSink> = if opts.progress {
                Box::new(Bar::new())
            } else {
                Box::new(carver::NoProgress)
            };
            let cs = carver::carve_seeded(&source, &active, &opts, progress.as_ref(), seen)?;
            carved_files += cs.files_recovered;
            carved_bytes += cs.bytes_recovered;
            carved_dups += cs.duplicates;
            push_carved(&cs.files, &mut report_rows);
        }
    }

    eprintln!();
    if args.dry_run {
        println!(
            "Dry run (nothing written). Undelete would recover {} named file(s), {}.",
            named_recovered,
            human_bytes(named_bytes)
        );
        println!(
            "Carving would recover {} additional file(s), {} ({} duplicate(s) skipped).",
            carved_files,
            human_bytes(carved_bytes),
            carved_dups
        );
    } else {
        println!(
            "Done. Undelete recovered {} named file(s), {}.",
            named_recovered,
            human_bytes(named_bytes)
        );
        println!(
            "Carving recovered {} additional file(s), {} ({} duplicate(s) of already-recovered content skipped).",
            carved_files,
            human_bytes(carved_bytes),
            carved_dups
        );
    }

    if let Some(report_path) = &args.report {
        write_recover_report(report_path, &report_rows)?;
        eprintln!("Report written to {}", report_path.display());
    }
    if let Some(summary_path) = &args.summary {
        let fields = [
            ("command", Sv::S("recover".into())),
            ("source", Sv::S(args.source.display().to_string())),
            ("source_bytes", Sv::N(source.size)),
            ("output", Sv::S(args.output.display().to_string())),
            ("named_recovered", Sv::N(named_recovered)),
            ("named_bytes", Sv::N(named_bytes)),
            ("unallocated_only", Sv::B(args.unallocated)),
            ("carved_recovered", Sv::N(carved_files)),
            ("carved_bytes", Sv::N(carved_bytes)),
            ("carved_duplicates", Sv::N(carved_dups)),
            ("elapsed_ms", Sv::N(started.elapsed().as_millis() as u64)),
            ("timestamp_unix", Sv::N(unix_now())),
        ];
        write_summary(summary_path, &fields)?;
        eprintln!("Summary written to {}", summary_path.display());
    }
    Ok(())
}

/// Write the combined `recover` manifest as CSV, or JSON when the path ends in
/// `.json`. Each row records whether a file came from the undelete pass
/// (`named`) or carving (`carved`), its path relative to the output directory,
/// its size, and its SHA-256 — so `verify --base <OUTPUT>` can re-check it.
fn write_recover_report(
    path: &std::path::Path,
    rows: &[(&str, String, u64, String)],
) -> Result<()> {
    let is_json = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let mut out = String::new();
    if is_json {
        out.push_str("[\n");
        for (i, (kind, p, size, sha)) in rows.iter().enumerate() {
            let comma = if i + 1 < rows.len() { "," } else { "" };
            out.push_str(&format!(
                "  {{\"kind\": \"{}\", \"path\": \"{}\", \"size\": {}, \"sha256\": \"{}\"}}{}\n",
                kind,
                json_escape(p),
                size,
                sha,
                comma
            ));
        }
        out.push_str("]\n");
    } else {
        out.push_str("kind,path,size,sha256\n");
        for (kind, p, size, sha) in rows {
            out.push_str(&format!("{},{},{},{}\n", kind, csv_escape(p), size, sha));
        }
    }
    std::fs::write(path, out)
        .map_err(|e| anyhow::anyhow!("writing report {}: {e}", path.display()))?;
    Ok(())
}

fn image(args: ImageArgs) -> Result<()> {
    use unearth::image::{self, ImageOptions};

    let started = std::time::Instant::now();
    let source = Source::open(&args.source)?;
    eprintln!(
        "Source: {} ({})",
        args.source.display(),
        human_bytes(source.size)
    );
    eprintln!("Image:  {}", args.output.display());

    // A map file enables resume; default it next to the image when --resume is
    // requested without an explicit --map.
    let map = args.map.clone().or_else(|| {
        if args.resume {
            let mut p = args.output.clone().into_os_string();
            p.push(".map");
            Some(p.into())
        } else {
            None
        }
    });

    let opts = ImageOptions {
        output: args.output.clone(),
        start: args.start,
        end: args.end,
        sparse: !args.no_sparse,
        sector_size: args.sector_size,
        map,
        resume: args.resume,
        retries: args.retry_bad,
    };

    let progress: Box<dyn ProgressSink> = if args.quiet {
        Box::new(carver::NoProgress)
    } else {
        Box::new(Bar::new())
    };

    let stats = image::image(&source, &opts, progress.as_ref())?;

    eprintln!();
    if stats.cancelled {
        println!("Cancelled.");
    }
    println!(
        "Done. Imaged {} ({} copied, {} sparse).",
        human_bytes(stats.bytes_total),
        human_bytes(stats.bytes_copied),
        human_bytes(stats.bytes_sparse),
    );
    if stats.retry_passes > 0 {
        println!(
            "Retried unreadable regions {} pass(es), salvaging {}.",
            stats.retry_passes,
            human_bytes(stats.bytes_recovered_retry)
        );
    }
    if !stats.bad_regions.is_empty() {
        println!(
            "WARNING: {} unreadable region(s), {} zero-filled:",
            stats.bad_regions.len(),
            human_bytes(stats.bytes_zeroed)
        );
        for r in stats.bad_regions.iter().take(20) {
            println!("  offset {} length {}", r.offset, human_bytes(r.len));
        }
        if stats.bad_regions.len() > 20 {
            println!("  ... and {} more", stats.bad_regions.len() - 20);
        }
    }

    // Optional chain-of-custody digest of the written image.
    let image_hash = if args.hash {
        eprintln!("Hashing image...");
        let h = hash_file(&args.output)?;
        println!("SHA-256: {h}");
        Some(h)
    } else {
        None
    };

    if let Some(summary_path) = &args.summary {
        let fields = [
            ("command", Sv::S("image".into())),
            ("sha256", Sv::S(image_hash.clone().unwrap_or_default())),
            ("source", Sv::S(args.source.display().to_string())),
            ("source_bytes", Sv::N(source.size)),
            ("output", Sv::S(args.output.display().to_string())),
            ("sparse", Sv::B(!args.no_sparse)),
            ("sector_size", Sv::N(args.sector_size)),
            ("resume", Sv::B(args.resume)),
            ("retry_bad", Sv::N(args.retry_bad as u64)),
            ("bytes_total", Sv::N(stats.bytes_total)),
            ("bytes_copied", Sv::N(stats.bytes_copied)),
            ("bytes_sparse", Sv::N(stats.bytes_sparse)),
            ("bytes_zeroed", Sv::N(stats.bytes_zeroed)),
            ("retry_passes", Sv::N(stats.retry_passes as u64)),
            ("bytes_recovered_retry", Sv::N(stats.bytes_recovered_retry)),
            ("bad_regions", Sv::N(stats.bad_regions.len() as u64)),
            ("cancelled", Sv::B(stats.cancelled)),
            ("elapsed_ms", Sv::N(started.elapsed().as_millis() as u64)),
            ("timestamp_unix", Sv::N(unix_now())),
        ];
        write_summary(summary_path, &fields)?;
        eprintln!("Summary written to {}", summary_path.display());
    }

    if !stats.bad_regions.is_empty() {
        anyhow::bail!(
            "{} unreadable region(s) were zero-filled",
            stats.bad_regions.len()
        );
    }
    Ok(())
}

/// Stream a file through SHA-256 and return the lowercase hex digest.
fn hash_file(path: &std::path::Path) -> Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("opening {}: {e}", path.display()))?;
    let mut hasher = unearth::hash::Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(unearth::hash::to_hex(&hasher.finalize()))
}

/// Seconds since the Unix epoch (0 if the clock is before it).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A value in a run summary.
enum Sv {
    S(String),
    N(u64),
    B(bool),
    /// A nested object of string -> number (e.g. the per-type breakdown).
    Map(Vec<(String, u64)>),
}

/// Write a run summary as JSON (when the path ends in `.json`) or plain text.
fn write_summary(path: &std::path::Path, fields: &[(&str, Sv)]) -> Result<()> {
    let is_json = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let mut out = String::new();
    if is_json {
        out.push_str("{\n");
        for (i, (k, v)) in fields.iter().enumerate() {
            let comma = if i + 1 < fields.len() { "," } else { "" };
            match v {
                Sv::S(s) => out.push_str(&format!("  \"{k}\": \"{}\"{comma}\n", json_escape(s))),
                Sv::N(n) => out.push_str(&format!("  \"{k}\": {n}{comma}\n")),
                Sv::B(b) => out.push_str(&format!("  \"{k}\": {b}{comma}\n")),
                Sv::Map(m) => {
                    if m.is_empty() {
                        out.push_str(&format!("  \"{k}\": {{}}{comma}\n"));
                    } else {
                        out.push_str(&format!("  \"{k}\": {{\n"));
                        for (j, (sk, sn)) in m.iter().enumerate() {
                            let c2 = if j + 1 < m.len() { "," } else { "" };
                            out.push_str(&format!("    \"{}\": {sn}{c2}\n", json_escape(sk)));
                        }
                        out.push_str(&format!("  }}{comma}\n"));
                    }
                }
            }
        }
        out.push_str("}\n");
    } else {
        for (k, v) in fields {
            match v {
                Sv::S(s) => out.push_str(&format!("{k}: {s}\n")),
                Sv::N(n) => out.push_str(&format!("{k}: {n}\n")),
                Sv::B(b) => out.push_str(&format!("{k}: {b}\n")),
                Sv::Map(m) => {
                    out.push_str(&format!("{k}:\n"));
                    for (sk, sn) in m {
                        out.push_str(&format!("  {sk}: {sn}\n"));
                    }
                }
            }
        }
    }
    std::fs::write(path, out)
        .map_err(|e| anyhow::anyhow!("writing summary {}: {e}", path.display()))?;
    Ok(())
}

/// Write a recovery report as CSV, or JSON when the path ends in `.json`. The
/// `sha256` column is a forensic manifest: a verifiable digest of each
/// recovered file's contents (empty for skipped files and dry runs).
fn write_report(
    path: &std::path::Path,
    rows: &[(String, u64, String, u64, bool, String)],
) -> Result<()> {
    let is_json = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let mut out = String::new();
    if is_json {
        out.push_str("[\n");
        for (i, (fs, off, p, size, rec, sha)) in rows.iter().enumerate() {
            let comma = if i + 1 < rows.len() { "," } else { "" };
            out.push_str(&format!(
                "  {{\"filesystem\": \"{}\", \"volume_offset\": {}, \"path\": \"{}\", \"size\": {}, \"recovered\": {}, \"sha256\": \"{}\"}}{}\n",
                json_escape(fs),
                off,
                json_escape(p),
                size,
                rec,
                sha,
                comma
            ));
        }
        out.push_str("]\n");
    } else {
        out.push_str("filesystem,volume_offset,path,size,recovered,sha256\n");
        for (fs, off, p, size, rec, sha) in rows {
            out.push_str(&format!(
                "{},{},{},{},{},{}\n",
                fs,
                off,
                csv_escape(p),
                size,
                rec,
                sha
            ));
        }
    }
    std::fs::write(path, out)
        .map_err(|e| anyhow::anyhow!("writing report {}: {e}", path.display()))?;
    Ok(())
}

/// Write a carve manifest as CSV, or JSON when the path ends in `.json`. Each
/// row records the output filename, type, source offset, size, and the SHA-256
/// of the carved bytes — so the report is a verifiable record of the run.
fn write_carve_report(path: &std::path::Path, files: &[carver::CarvedFile]) -> Result<()> {
    let is_json = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let mut out = String::new();
    if is_json {
        out.push_str("[\n");
        for (i, f) in files.iter().enumerate() {
            let comma = if i + 1 < files.len() { "," } else { "" };
            out.push_str(&format!(
                "  {{\"name\": \"{}\", \"type\": \"{}\", \"offset\": {}, \"size\": {}, \"sha256\": \"{}\"}}{}\n",
                json_escape(&f.name),
                f.ext,
                f.offset,
                f.size,
                unearth::hash::to_hex(&f.sha256),
                comma
            ));
        }
        out.push_str("]\n");
    } else {
        out.push_str("name,type,offset,size,sha256\n");
        for f in files {
            out.push_str(&format!(
                "{},{},{},{},{}\n",
                csv_escape(&f.name),
                f.ext,
                f.offset,
                f.size,
                unearth::hash::to_hex(&f.sha256)
            ));
        }
    }
    std::fs::write(path, out)
        .map_err(|e| anyhow::anyhow!("writing report {}: {e}", path.display()))?;
    Ok(())
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// indicatif-backed progress sink.
struct Bar {
    inner: ProgressBar,
}

impl Bar {
    fn new() -> Self {
        Bar {
            inner: ProgressBar::hidden(),
        }
    }
}

impl ProgressSink for Bar {
    fn begin(&self, total: u64) {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner} [{elapsed_precise}] [{bar:40}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta})",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        // Replace the hidden bar with a live one.
        self.inner.set_length(total);
        self.inner.set_style(pb.style());
        self.inner
            .set_draw_target(indicatif::ProgressDrawTarget::stderr());
    }
    fn update(&self, scanned: u64) {
        self.inner.set_position(scanned);
    }
    fn finish(&self, scanned: u64) {
        self.inner.set_position(scanned);
        self.inner.finish_and_clear();
    }
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} {}", UNITS[0])
    } else {
        format!("{v:.2} {}", UNITS[u])
    }
}
