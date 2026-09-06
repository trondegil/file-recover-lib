//! Verify ext4 journal (jbd2) recovery: a deleted file whose **live** inode has
//! its extent tree zeroed is recovered from an older copy of the inode-table
//! block preserved in the journal.

use unearth::ext4;
use unearth::recover::RecoverOptions;
use unearth::source::Source;

const BS: usize = 1024;
const INODE_SIZE: usize = 128;
const INODES_PER_GROUP: u32 = 32;
const TOTAL_BLOCKS: usize = 64;

const ITAB: usize = 5; // inode table starts at block 5 (blocks 5..9)
const ROOT_DIR: usize = 9;
const JOURNAL_START: usize = 16; // journal occupies blocks 16..24
const DATA_BLOCK: usize = 30; // the deleted file's data
const INODE_TABLE_BLOCK_OF_11: u64 = 6; // fs block holding inode 11

fn inode_offset(ino: u32) -> usize {
    ITAB * BS + (ino as usize - 1) * INODE_SIZE
}

/// Build a 128-byte inode. With `block = Some((start, len))` it gets a single
/// extent mapping `len` blocks from `start`; with `None` the block map is left
/// zeroed (as after deletion).
fn inode(
    mode: u16,
    links: u16,
    dtime: u32,
    size: u32,
    block: Option<(u32, u16)>,
) -> [u8; INODE_SIZE] {
    let mut n = [0u8; INODE_SIZE];
    n[0..2].copy_from_slice(&mode.to_le_bytes());
    n[4..8].copy_from_slice(&size.to_le_bytes());
    n[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());
    n[0x1A..0x1C].copy_from_slice(&links.to_le_bytes());
    n[0x20..0x24].copy_from_slice(&0x0008_0000u32.to_le_bytes()); // EXTENTS_FL
    if let Some((start, len)) = block {
        let ib = 0x28;
        n[ib..ib + 2].copy_from_slice(&0xF30Au16.to_le_bytes());
        n[ib + 2..ib + 4].copy_from_slice(&1u16.to_le_bytes()); // entries
        n[ib + 4..ib + 6].copy_from_slice(&4u16.to_le_bytes()); // max
        n[ib + 16..ib + 18].copy_from_slice(&len.to_le_bytes()); // extent length
        n[ib + 20..ib + 24].copy_from_slice(&start.to_le_bytes()); // start lo
    }
    n
}

fn put_inode(img: &mut [u8], ino: u32, bytes: &[u8; INODE_SIZE]) {
    let o = inode_offset(ino);
    img[o..o + INODE_SIZE].copy_from_slice(bytes);
}

fn wd(img: &mut [u8], block: usize, off: usize, ino: u32, rec_len: u16, name: &str, ft: u8) {
    let p = block * BS + off;
    img[p..p + 4].copy_from_slice(&ino.to_le_bytes());
    img[p + 4..p + 6].copy_from_slice(&rec_len.to_le_bytes());
    img[p + 6] = name.len() as u8;
    img[p + 7] = ft;
    img[p + 8..p + 8 + name.len()].copy_from_slice(name.as_bytes());
}

fn be32(img: &mut [u8], at: usize, v: u32) {
    img[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

#[test]
fn recovers_via_journal_when_live_inode_zeroed() {
    let mut img = vec![0u8; TOTAL_BLOCKS * BS];

    // Superblock.
    let sb = 1024;
    img[sb..sb + 4].copy_from_slice(&32u32.to_le_bytes()); // inodes_count
    img[sb + 4..sb + 8].copy_from_slice(&(TOTAL_BLOCKS as u32).to_le_bytes());
    img[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes()); // first_data_block
    img[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes()); // blocks_per_group
    img[sb + 0x28..sb + 0x2C].copy_from_slice(&INODES_PER_GROUP.to_le_bytes());
    img[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes()); // magic
    img[sb + 0x58..sb + 0x5A].copy_from_slice(&(INODE_SIZE as u16).to_le_bytes());
    img[sb + 0x60..sb + 0x64].copy_from_slice(&0x0002u32.to_le_bytes()); // FILETYPE
    img[sb + 0xE0..sb + 0xE4].copy_from_slice(&8u32.to_le_bytes()); // s_journal_inum

    // Group descriptor: inode table at block 5.
    img[2 * BS + 8..2 * BS + 12].copy_from_slice(&(ITAB as u32).to_le_bytes());

    let payload: Vec<u8> = (0..500u32).map(|i| (i % 251) as u8).collect();

    // Inodes (live table):
    // - root dir, live.
    put_inode(
        &mut img,
        2,
        &inode(0x41ED, 3, 0, BS as u32, Some((ROOT_DIR as u32, 1))),
    );
    // - journal (inode 8), live, mapping the 8 journal blocks.
    put_inode(
        &mut img,
        8,
        &inode(
            0x8180,
            1,
            0,
            (8 * BS) as u32,
            Some((JOURNAL_START as u32, 8)),
        ),
    );
    // - inode 11: DELETED with a zeroed block map (unrecoverable from the live
    //   inode alone).
    put_inode(
        &mut img,
        11,
        &inode(0x81A4, 0, 12345, payload.len() as u32, None),
    );

    // The file's data.
    img[DATA_BLOCK * BS..DATA_BLOCK * BS + payload.len()].copy_from_slice(&payload);

    // Root directory: ".", "..", and a stale entry for the deleted file.
    wd(&mut img, ROOT_DIR, 0, 2, 12, ".", 2);
    wd(&mut img, ROOT_DIR, 12, 2, (BS - 12) as u16, "..", 2);
    wd(&mut img, ROOT_DIR, 28, 11, 24, "secret.txt", 1);

    // --- Journal contents ---
    // Block 0 of the journal: jbd2 superblock.
    let js = JOURNAL_START * BS;
    be32(&mut img, js, 0xC03B_3998); // h_magic
    be32(&mut img, js + 4, 4); // h_blocktype = v2 superblock
    be32(&mut img, js + 0x0C, BS as u32); // s_blocksize
    be32(&mut img, js + 0x10, 8); // s_maxlen
    be32(&mut img, js + 0x14, 1); // s_first
    be32(&mut img, js + 0x28, 0); // s_feature_incompat (simplest tag format)

    // Block 1 of the journal: descriptor naming fs block 6 (inode-table block of
    // inode 11).
    let jd = (JOURNAL_START + 1) * BS;
    be32(&mut img, jd, 0xC03B_3998); // h_magic
    be32(&mut img, jd + 4, 1); // h_blocktype = descriptor
    be32(&mut img, jd + 8, 1); // h_sequence
    be32(&mut img, jd + 12, INODE_TABLE_BLOCK_OF_11 as u32); // tag t_blocknr
    img[jd + 16] = 0x00; // t_checksum (BE u16)
    img[jd + 17] = 0x00;
    img[jd + 18] = 0x00; // t_flags (BE u16) = LAST_TAG (0x0008)
    img[jd + 19] = 0x08;
    // A 16-byte UUID follows (left zeroed).

    // Block 2 of the journal: an older copy of fs block 6, where inode 11 still
    // has an intact extent map. Within block 6, inode 11 sits at offset 256.
    let jdata = (JOURNAL_START + 2) * BS;
    let good = inode(
        0x81A4,
        1,
        0,
        payload.len() as u32,
        Some((DATA_BLOCK as u32, 1)),
    );
    img[jdata + 256..jdata + 256 + INODE_SIZE].copy_from_slice(&good);

    // Run recovery.
    let tmp = tempfile::tempdir().unwrap();
    let img_path = tmp.path().join("disk.img");
    std::fs::write(&img_path, &img).unwrap();
    let out_dir = tmp.path().join("out");

    let source = Source::open(&img_path).unwrap();
    let vol = ext4::Volume::parse(&source, 0).unwrap();

    // Sanity: the live inode really is unrecoverable on its own.
    let live_only = vol
        .recover_deleted(
            &source,
            &tmp.path().join("none"),
            &RecoverOptions {
                min_size: 0,
                max_size: None,
                modified_after: None,
                modified_before: None,
                names: Vec::new(),
                exclude_names: Vec::new(),
                dry_run: true,
            },
        )
        .unwrap();
    // (Dry run still counts it because journal recovery supplies the inode.)
    assert_eq!(live_only.recovered, 1);

    let stats = vol
        .recover_deleted(&source, &out_dir, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 1, "should recover via the journal");
    assert_eq!(
        std::fs::read(out_dir.join("secret.txt")).unwrap(),
        payload,
        "journal-recovered contents must match"
    );
}

// --- Which journaled copy wins -------------------------------------------

/// One jbd2 transaction holding a copy of the inode-table block that carries
/// inode 11.
struct Txn {
    seq: u32,
    /// The inode 11 bytes in this transaction's copy of fs block 6.
    inode: [u8; INODE_SIZE],
    /// Whether the transaction has a commit block.
    commit: bool,
}

const JOURNAL_BLOCKS: usize = 12;
const DATA_A: usize = 30;
const DATA_B: usize = 32;

/// Like [`inode`], with a change time, which is what copy selection keys on.
fn inode_at(ctime: u32, block: u32, size: u32) -> [u8; INODE_SIZE] {
    let mut n = inode(0x81A4, 1, 0, size, Some((block, 1)));
    n[0x0C..0x10].copy_from_slice(&ctime.to_le_bytes());
    n
}

/// A volume whose deleted inode 11 has a zeroed live block map, with the
/// given transactions in the journal in order, and optionally a final revoke
/// record for the inode-table block. Data block A holds `a`, B holds `b`.
fn journal_volume(txns: &[Txn], revoke_after: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut img = vec![0u8; TOTAL_BLOCKS * BS];
    let sb = 1024;
    img[sb..sb + 4].copy_from_slice(&32u32.to_le_bytes());
    img[sb + 4..sb + 8].copy_from_slice(&(TOTAL_BLOCKS as u32).to_le_bytes());
    img[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
    img[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    img[sb + 0x28..sb + 0x2C].copy_from_slice(&INODES_PER_GROUP.to_le_bytes());
    img[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    img[sb + 0x58..sb + 0x5A].copy_from_slice(&(INODE_SIZE as u16).to_le_bytes());
    img[sb + 0x60..sb + 0x64].copy_from_slice(&0x0002u32.to_le_bytes());
    img[sb + 0xE0..sb + 0xE4].copy_from_slice(&8u32.to_le_bytes());
    img[2 * BS + 8..2 * BS + 12].copy_from_slice(&(ITAB as u32).to_le_bytes());

    put_inode(
        &mut img,
        2,
        &inode(0x41ED, 3, 0, BS as u32, Some((ROOT_DIR as u32, 1))),
    );
    put_inode(
        &mut img,
        8,
        &inode(
            0x8180,
            1,
            0,
            (JOURNAL_BLOCKS * BS) as u32,
            Some((JOURNAL_START as u32, JOURNAL_BLOCKS as u16)),
        ),
    );
    put_inode(&mut img, 11, &inode(0x81A4, 0, 12345, a.len() as u32, None));
    img[DATA_A * BS..DATA_A * BS + a.len()].copy_from_slice(a);
    img[DATA_B * BS..DATA_B * BS + b.len()].copy_from_slice(b);
    wd(&mut img, ROOT_DIR, 0, 2, 12, ".", 2);
    wd(&mut img, ROOT_DIR, 12, 2, (BS - 12) as u16, "..", 2);
    wd(&mut img, ROOT_DIR, 28, 11, 24, "secret.txt", 1);

    // Journal superblock.
    let js = JOURNAL_START * BS;
    be32(&mut img, js, 0xC03B_3998);
    be32(&mut img, js + 4, 4);
    be32(&mut img, js + 0x0C, BS as u32);
    be32(&mut img, js + 0x10, JOURNAL_BLOCKS as u32);
    be32(&mut img, js + 0x14, 1);
    be32(&mut img, js + 0x28, 0);

    let mut ji = 1usize;
    for t in txns {
        // Descriptor naming fs block 6 with one LAST_TAG tag.
        let jd = (JOURNAL_START + ji) * BS;
        be32(&mut img, jd, 0xC03B_3998);
        be32(&mut img, jd + 4, 1);
        be32(&mut img, jd + 8, t.seq);
        be32(&mut img, jd + 12, INODE_TABLE_BLOCK_OF_11 as u32);
        img[jd + 18] = 0x00;
        img[jd + 19] = 0x08;
        // The data block: a copy of fs block 6 with inode 11 at offset 256.
        let jdata = (JOURNAL_START + ji + 1) * BS;
        img[jdata + 256..jdata + 256 + INODE_SIZE].copy_from_slice(&t.inode);
        ji += 2;
        if t.commit {
            let jc = (JOURNAL_START + ji) * BS;
            be32(&mut img, jc, 0xC03B_3998);
            be32(&mut img, jc + 4, 2); // commit block
            be32(&mut img, jc + 8, t.seq);
            ji += 1;
        }
    }
    if revoke_after {
        let jr = (JOURNAL_START + ji) * BS;
        be32(&mut img, jr, 0xC03B_3998);
        be32(&mut img, jr + 4, 5); // revoke block
        be32(
            &mut img,
            jr + 8,
            txns.last().map(|t| t.seq.wrapping_add(1)).unwrap_or(1),
        );
        be32(&mut img, jr + 12, 20); // r_count: 16-byte header + one 4-byte entry
        be32(&mut img, jr + 16, INODE_TABLE_BLOCK_OF_11 as u32);
        ji += 1;
    }
    assert!(ji <= JOURNAL_BLOCKS, "journal too small for the fixture");
    img
}

fn recovered_bytes(img: &[u8]) -> Vec<u8> {
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("disk.img");
    std::fs::write(&p, img).unwrap();
    let src = Source::open(&p).unwrap();
    let vol = ext4::Volume::parse(&src, 0).unwrap();
    let out = tmp.path().join("out");
    let stats = vol
        .recover_deleted(&src, &out, &RecoverOptions::default())
        .unwrap();
    assert_eq!(stats.recovered, 1);
    std::fs::read(out.join("secret.txt")).unwrap()
}

const A: &[u8] = b"older copy: extent A, the file before its last write";
const B: &[u8] = b"newer copy: extent B, the file as it was finally";

/// Two committed copies: the newer one (by ctime) wins.
#[test]
fn the_newest_committed_copy_wins() {
    let img = journal_volume(
        &[
            Txn {
                seq: 1,
                inode: inode_at(1000, DATA_A as u32, A.len() as u32),
                commit: true,
            },
            Txn {
                seq: 2,
                inode: inode_at(2000, DATA_B as u32, B.len() as u32),
                commit: true,
            },
        ],
        false,
        A,
        B,
    );
    assert_eq!(recovered_bytes(&img), B);
}

/// The newer copy earlier in the journal still wins: change time decides,
/// not position.
#[test]
fn change_time_outranks_journal_position() {
    let img = journal_volume(
        &[
            Txn {
                seq: 1,
                inode: inode_at(2000, DATA_B as u32, B.len() as u32),
                commit: true,
            },
            Txn {
                seq: 2,
                inode: inode_at(1000, DATA_A as u32, A.len() as u32),
                commit: true,
            },
        ],
        false,
        A,
        B,
    );
    assert_eq!(recovered_bytes(&img), B);
}

/// Sequence numbers wrap at 2^32; the wrap must not upset selection.
#[test]
fn wrapped_sequence_numbers_still_pick_the_newest_copy() {
    let img = journal_volume(
        &[
            Txn {
                seq: u32::MAX,
                inode: inode_at(1000, DATA_A as u32, A.len() as u32),
                commit: true,
            },
            Txn {
                seq: 0,
                inode: inode_at(2000, DATA_B as u32, B.len() as u32),
                commit: true,
            },
        ],
        false,
        A,
        B,
    );
    assert_eq!(recovered_bytes(&img), B);
}

/// The current policy, pinned: a newer copy in a transaction that never
/// committed is used all the same. For undelete this is arguably right (an
/// uncommitted copy is often the pre-deletion state), so this test documents
/// the behaviour rather than endorsing it; changing it is the owner's call.
#[test]
fn an_uncommitted_newer_copy_is_used_today() {
    let img = journal_volume(
        &[
            Txn {
                seq: 1,
                inode: inode_at(1000, DATA_A as u32, A.len() as u32),
                commit: true,
            },
            Txn {
                seq: 2,
                inode: inode_at(2000, DATA_B as u32, B.len() as u32),
                commit: false,
            },
        ],
        false,
        A,
        B,
    );
    assert_eq!(recovered_bytes(&img), B);
}

/// The current policy, pinned: a later revoke record for the inode-table
/// block does not withdraw the newer copy. Same caveat as above.
#[test]
fn a_later_revoke_record_does_not_withdraw_the_copy_today() {
    let img = journal_volume(
        &[
            Txn {
                seq: 1,
                inode: inode_at(1000, DATA_A as u32, A.len() as u32),
                commit: true,
            },
            Txn {
                seq: 2,
                inode: inode_at(2000, DATA_B as u32, B.len() as u32),
                commit: true,
            },
        ],
        true,
        A,
        B,
    );
    assert_eq!(recovered_bytes(&img), B);
}
