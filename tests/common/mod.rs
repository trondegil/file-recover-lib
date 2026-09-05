//! Shared image builders for integration tests.
//!
//! These hand-craft minimal but valid on-disk structures so tests don't depend
//! on `mkfs`/`mtools` being installed.

#![allow(dead_code)] // each test binary uses a different subset

/// A minimal JPEG (header + payload + `FF D9` footer) for carving tests.
pub fn jpeg(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
    v.extend_from_slice(payload);
    v.extend_from_slice(&[0xFF, 0xD9]);
    v
}

// --- ext4 ---------------------------------------------------------------

const EXT_BS: usize = 1024;
const EXT_ISIZE: usize = 128;
const EXT_ITAB: usize = 5;
const EXT_ROOT_DIR: usize = 9;
const EXT_DATA: usize = 11;
const EXT_BLOCKS: usize = 32;

fn ext_inode(v: &mut [u8], ino: u32, mode: u16, links: u16, dtime: u32, size: u32, block: u32) {
    let o = EXT_ITAB * EXT_BS + (ino as usize - 1) * EXT_ISIZE;
    v[o..o + 2].copy_from_slice(&mode.to_le_bytes());
    v[o + 4..o + 8].copy_from_slice(&size.to_le_bytes());
    v[o + 0x14..o + 0x18].copy_from_slice(&dtime.to_le_bytes());
    v[o + 0x1A..o + 0x1C].copy_from_slice(&links.to_le_bytes());
    v[o + 0x20..o + 0x24].copy_from_slice(&0x0008_0000u32.to_le_bytes()); // EXTENTS_FL
    let ib = o + 0x28;
    v[ib..ib + 2].copy_from_slice(&0xF30Au16.to_le_bytes());
    v[ib + 2..ib + 4].copy_from_slice(&1u16.to_le_bytes());
    v[ib + 4..ib + 6].copy_from_slice(&4u16.to_le_bytes());
    v[ib + 16..ib + 18].copy_from_slice(&1u16.to_le_bytes());
    v[ib + 20..ib + 24].copy_from_slice(&block.to_le_bytes());
}

fn ext_dirent(v: &mut [u8], block: usize, off: usize, ino: u32, rec_len: u16, name: &str, ft: u8) {
    let p = block * EXT_BS + off;
    v[p..p + 4].copy_from_slice(&ino.to_le_bytes());
    v[p + 4..p + 6].copy_from_slice(&rec_len.to_le_bytes());
    v[p + 6] = name.len() as u8;
    v[p + 7] = ft;
    v[p + 8..p + 8 + name.len()].copy_from_slice(name.as_bytes());
}

/// A bare ext4 volume (no partition table) with one deleted regular file named
/// `name` holding `payload`, reachable as a stale entry in the root directory.
pub fn ext_volume(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; EXT_BLOCKS * EXT_BS];
    let sb = 1024;
    v[sb..sb + 4].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 4..sb + 8].copy_from_slice(&(EXT_BLOCKS as u32).to_le_bytes());
    v[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
    v[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    v[sb + 0x28..sb + 0x2C].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    v[sb + 0x58..sb + 0x5A].copy_from_slice(&(EXT_ISIZE as u16).to_le_bytes());
    v[sb + 0x60..sb + 0x64].copy_from_slice(&0x0002u32.to_le_bytes());
    v[2 * EXT_BS + 8..2 * EXT_BS + 12].copy_from_slice(&(EXT_ITAB as u32).to_le_bytes());

    ext_inode(&mut v, 2, 0x41ED, 3, 0, EXT_BS as u32, EXT_ROOT_DIR as u32);
    ext_inode(
        &mut v,
        11,
        0x81A4,
        0,
        12345,
        payload.len() as u32,
        EXT_DATA as u32,
    );
    v[EXT_DATA * EXT_BS..EXT_DATA * EXT_BS + payload.len()].copy_from_slice(payload);

    ext_dirent(&mut v, EXT_ROOT_DIR, 0, 2, 12, ".", 2);
    ext_dirent(&mut v, EXT_ROOT_DIR, 12, 2, (EXT_BS - 12) as u16, "..", 2);
    ext_dirent(&mut v, EXT_ROOT_DIR, 28, 11, 24, name, 1);
    v
}

// --- HFS+ ---------------------------------------------------------------

const HFS_BS: usize = 512;
const HFS_ALLOC_BLOCK: usize = 6; // allocation file (volume bitmap), 1 block
const HFS_CATALOG_BLOCK: usize = 8; // catalog file starts here (2 nodes)
const HFS_NODE_SIZE: usize = 512;
const HFS_DATA_BLOCK: usize = 12; // file data starts here

fn put_be16(v: &mut [u8], o: usize, x: u16) {
    v[o..o + 2].copy_from_slice(&x.to_be_bytes());
}
fn put_be32(v: &mut [u8], o: usize, x: u32) {
    v[o..o + 4].copy_from_slice(&x.to_be_bytes());
}
fn put_be64(v: &mut [u8], o: usize, x: u64) {
    v[o..o + 8].copy_from_slice(&x.to_be_bytes());
}

/// A bare HFS+ volume (no partition table) with one deleted regular file named
/// `name` holding `payload`, left as a stale record in a catalog leaf node's
/// free space — the situation this backend recovers from.
pub fn hfsplus_volume(name: &str, payload: &[u8]) -> Vec<u8> {
    let name16: Vec<u16> = name.encode_utf16().collect();
    let name_len = name16.len();
    let block_count = payload.len().div_ceil(HFS_BS).max(1);
    let total_blocks = HFS_DATA_BLOCK + block_count + 2;
    let mut v = vec![0u8; total_blocks * HFS_BS];

    // Volume header at offset 1024.
    let vh = 1024;
    put_be16(&mut v, vh, 0x482B); // "H+"
    put_be16(&mut v, vh + 2, 4); // version
                                 // createDate (0x10) / modifyDate (0x14): seconds since the HFS epoch (1904);
                                 // these decode to Unix 1_600_000_000 and 1_700_000_000.
    put_be32(&mut v, vh + 0x10, 1_600_000_000 + 2_082_844_800);
    put_be32(&mut v, vh + 0x14, 1_700_000_000 + 2_082_844_800);
    put_be32(&mut v, vh + 40, HFS_BS as u32); // allocation block size
    put_be32(&mut v, vh + 44, total_blocks as u32);
    // Catalog file fork: logicalSize, totalBlocks, then first extent.
    put_be64(&mut v, vh + 272, (2 * HFS_NODE_SIZE) as u64); // two nodes
    put_be32(&mut v, vh + 284, 2);
    put_be32(&mut v, vh + 288, HFS_CATALOG_BLOCK as u32); // extent start block
    put_be32(&mut v, vh + 292, 2); // extent block count
                                   // Allocation file fork (the volume bitmap): one block at HFS_ALLOC_BLOCK.
    put_be64(&mut v, vh + 112, HFS_BS as u64); // logicalSize
    put_be32(&mut v, vh + 124, 1); // totalBlocks
    put_be32(&mut v, vh + 128, HFS_ALLOC_BLOCK as u32); // extent start block
    put_be32(&mut v, vh + 132, 1); // extent block count

    // Allocation bitmap (MSB-first: bit 7 of byte 0 is block 0). Mark the
    // structural blocks allocated and leave the rest free; the data blocks are
    // marked allocated too so a deleted file's blocks read as still-in-use.
    let bmp = HFS_ALLOC_BLOCK * HFS_BS;
    let mut set_alloc = |block: usize| {
        v[bmp + block / 8] |= 0x80 >> (block % 8);
    };
    set_alloc(2); // volume header block
    set_alloc(HFS_ALLOC_BLOCK);
    set_alloc(HFS_CATALOG_BLOCK);
    set_alloc(HFS_CATALOG_BLOCK + 1);
    for b in 0..block_count {
        set_alloc(HFS_DATA_BLOCK + b);
    }

    // Catalog node 0 (header node): the parser only needs the node size.
    let n0 = HFS_CATALOG_BLOCK * HFS_BS;
    v[n0 + 8] = 1; // kind = header node
    put_be16(&mut v, n0 + 32, HFS_NODE_SIZE as u16); // BTHeaderRec.nodeSize

    // Catalog node 1 (leaf node) with no live records; the deleted file record
    // sits in its free space, starting right after the node descriptor.
    let n1 = n0 + HFS_NODE_SIZE;
    v[n1 + 8] = 0xFF; // kind = leaf node (-1)
    put_be16(&mut v, n1 + 10, 0); // numRecords = 0
    put_be16(&mut v, n1 + HFS_NODE_SIZE - 2, 14); // offset[0] -> free space at 14

    // The stale file record at node offset 14.
    let key = n1 + 14;
    let key_len = 6 + 2 * name_len;
    put_be16(&mut v, key, key_len as u16);
    put_be32(&mut v, key + 2, 2); // parentID = root folder
    put_be16(&mut v, key + 6, name_len as u16);
    for (i, &u) in name16.iter().enumerate() {
        put_be16(&mut v, key + 8 + i * 2, u);
    }
    let rec = key + 2 + key_len; // record data follows the key
    put_be16(&mut v, rec, 0x0002); // recordType = file
    put_be32(&mut v, rec + 8, 16); // fileID (CNID)
    put_be32(&mut v, rec + 16, 2_082_844_800 + 1_000_000); // contentModDate
    put_be64(&mut v, rec + 88, payload.len() as u64); // data fork logical size
    put_be32(&mut v, rec + 104, HFS_DATA_BLOCK as u32); // extent start block
    put_be32(&mut v, rec + 108, block_count as u32); // extent block count

    // File data.
    let data_off = HFS_DATA_BLOCK * HFS_BS;
    v[data_off..data_off + payload.len()].copy_from_slice(payload);
    v
}

/// A bare HFS+ volume with one deleted file whose data fork is fragmented into
/// two non-contiguous extents: the first (a full block) is recorded inline in
/// the catalog record, the second (the tail) only in the **extents-overflow**
/// B-tree. Recovering it requires following the overflow tree. `payload` must be
/// longer than one block (512 B) and at most two blocks so the tail fits one.
pub fn hfsplus_fragmented_volume(name: &str, payload: &[u8]) -> Vec<u8> {
    assert!(
        (HFS_BS + 1..=2 * HFS_BS).contains(&payload.len()),
        "fragmented payload must span exactly two blocks"
    );
    let name16: Vec<u16> = name.encode_utf16().collect();
    let name_len = name16.len();

    // Block layout: header @2, catalog @8-9, overflow @10-11, data parts @14,16.
    const CATALOG_BLOCK: usize = 8;
    const OVERFLOW_BLOCK: usize = 10;
    const PART1_BLOCK: usize = 14;
    const PART2_BLOCK: usize = 16; // non-contiguous with PART1
    let total_blocks = 18;
    let mut v = vec![0u8; total_blocks * HFS_BS];

    // Volume header at offset 1024.
    let vh = 1024;
    put_be16(&mut v, vh, 0x482B); // "H+"
    put_be16(&mut v, vh + 2, 4); // version
    put_be32(&mut v, vh + 40, HFS_BS as u32);
    put_be32(&mut v, vh + 44, total_blocks as u32);
    // Catalog fork: two nodes at CATALOG_BLOCK.
    put_be64(&mut v, vh + 272, (2 * HFS_NODE_SIZE) as u64);
    put_be32(&mut v, vh + 284, 2);
    put_be32(&mut v, vh + 288, CATALOG_BLOCK as u32);
    put_be32(&mut v, vh + 292, 2);
    // Extents-overflow fork at offset 192: two nodes at OVERFLOW_BLOCK.
    put_be64(&mut v, vh + 192, (2 * HFS_NODE_SIZE) as u64);
    put_be32(&mut v, vh + 204, 2); // totalBlocks
    put_be32(&mut v, vh + 208, OVERFLOW_BLOCK as u32); // extent start
    put_be32(&mut v, vh + 212, 2); // extent count

    // Catalog node 0 (header): only the node size matters.
    let cn0 = CATALOG_BLOCK * HFS_BS;
    v[cn0 + 8] = 1; // header node
    put_be16(&mut v, cn0 + 32, HFS_NODE_SIZE as u16);
    // Catalog node 1 (leaf): the deleted record sits in free space.
    let cn1 = cn0 + HFS_NODE_SIZE;
    v[cn1 + 8] = 0xFF; // leaf node
    put_be16(&mut v, cn1 + 10, 0); // numRecords = 0
    put_be16(&mut v, cn1 + HFS_NODE_SIZE - 2, 14); // free space starts at 14

    let key = cn1 + 14;
    let key_len = 6 + 2 * name_len;
    put_be16(&mut v, key, key_len as u16);
    put_be32(&mut v, key + 2, 2); // parentID = root
    put_be16(&mut v, key + 6, name_len as u16);
    for (i, &u) in name16.iter().enumerate() {
        put_be16(&mut v, key + 8 + i * 2, u);
    }
    let rec = key + 2 + key_len;
    put_be16(&mut v, rec, 0x0002); // file record
    put_be32(&mut v, rec + 8, 16); // fileID
    put_be32(&mut v, rec + 16, 2_082_844_800 + 1_000_000);
    put_be64(&mut v, rec + 88, payload.len() as u64); // logical size
    put_be32(&mut v, rec + 104, PART1_BLOCK as u32); // inline extent: first block
    put_be32(&mut v, rec + 108, 1);

    // Extents-overflow node 0 (header) + node 1 (leaf) with one live record
    // mapping fork offset block 1 (after the inline extent) to PART2_BLOCK.
    let on0 = OVERFLOW_BLOCK * HFS_BS;
    v[on0 + 8] = 1; // header node
    put_be16(&mut v, on0 + 32, HFS_NODE_SIZE as u16);
    let on1 = on0 + HFS_NODE_SIZE;
    v[on1 + 8] = 0xFF; // leaf node
    put_be16(&mut v, on1 + 10, 1); // numRecords = 1
    put_be16(&mut v, on1 + HFS_NODE_SIZE - 2, 14); // offset[0] -> record at 14
    let er = on1 + 14;
    put_be16(&mut v, er, 10); // HFSPlusExtentKey length
    v[er + 2] = 0; // forkType = data
    put_be32(&mut v, er + 4, 16); // fileID
    put_be32(&mut v, er + 8, 1); // startBlock = 1 (after the inline block)
    put_be32(&mut v, er + 12, PART2_BLOCK as u32); // extent start
    put_be32(&mut v, er + 16, 1); // extent count

    // File data: first full block, then the tail in the non-contiguous block.
    let p1 = PART1_BLOCK * HFS_BS;
    v[p1..p1 + HFS_BS].copy_from_slice(&payload[..HFS_BS]);
    let tail = &payload[HFS_BS..];
    let p2 = PART2_BLOCK * HFS_BS;
    v[p2..p2 + tail.len()].copy_from_slice(tail);
    v
}

/// A bare HFS+ volume with one **live folder** (named `folder`, CNID 100) in the
/// root and one **deleted file** (`name`, holding `payload`) inside it, left as a
/// stale record in the catalog leaf node's free space. Exercises folder-path
/// reconstruction: the file should be recovered under `folder/name`. `payload`
/// must fit one block.
pub fn hfsplus_nested_volume(folder: &str, name: &str, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= HFS_BS, "nested payload must fit one block");
    const FOLDER_ID: u32 = 100;
    let fname16: Vec<u16> = folder.encode_utf16().collect();
    let name16: Vec<u16> = name.encode_utf16().collect();
    let total_blocks = HFS_DATA_BLOCK + 1 + 2;
    let mut v = vec![0u8; total_blocks * HFS_BS];

    // Volume header.
    let vh = 1024;
    put_be16(&mut v, vh, 0x482B);
    put_be16(&mut v, vh + 2, 4);
    put_be32(&mut v, vh + 40, HFS_BS as u32);
    put_be32(&mut v, vh + 44, total_blocks as u32);
    put_be64(&mut v, vh + 272, (2 * HFS_NODE_SIZE) as u64);
    put_be32(&mut v, vh + 284, 2);
    put_be32(&mut v, vh + 288, HFS_CATALOG_BLOCK as u32);
    put_be32(&mut v, vh + 292, 2);

    // Catalog node 0 (header).
    let n0 = HFS_CATALOG_BLOCK * HFS_BS;
    v[n0 + 8] = 1;
    put_be16(&mut v, n0 + 32, HFS_NODE_SIZE as u16);

    // Catalog node 1 (leaf): one live folder record, then the deleted file
    // record in the free space below it.
    let n1 = n0 + HFS_NODE_SIZE;
    v[n1 + 8] = 0xFF; // leaf node
    put_be16(&mut v, n1 + 10, 1); // numRecords = 1 (the folder)
    put_be16(&mut v, n1 + HFS_NODE_SIZE - 2, 14); // offset[0] -> folder record

    // Live folder record at node offset 14.
    let fkey = n1 + 14;
    let fkey_len = 6 + 2 * fname16.len();
    put_be16(&mut v, fkey, fkey_len as u16);
    put_be32(&mut v, fkey + 2, 2); // parentID = root
    put_be16(&mut v, fkey + 6, fname16.len() as u16);
    for (i, &u) in fname16.iter().enumerate() {
        put_be16(&mut v, fkey + 8 + i * 2, u);
    }
    let frec = fkey + 2 + fkey_len;
    put_be16(&mut v, frec, 0x0001); // recordType = folder
    put_be32(&mut v, frec + 8, FOLDER_ID); // folderID (CNID)
    let folder_rec_len = 88; // HFSPlusCatalogFolder
    let free_start = (frec + folder_rec_len) - n1;
    put_be16(&mut v, n1 + HFS_NODE_SIZE - 4, free_start as u16); // offset[1] -> free space

    // Deleted file record at the start of the free space.
    let key = n1 + free_start;
    let key_len = 6 + 2 * name16.len();
    put_be16(&mut v, key, key_len as u16);
    put_be32(&mut v, key + 2, FOLDER_ID); // parentID = the folder
    put_be16(&mut v, key + 6, name16.len() as u16);
    for (i, &u) in name16.iter().enumerate() {
        put_be16(&mut v, key + 8 + i * 2, u);
    }
    let rec = key + 2 + key_len;
    put_be16(&mut v, rec, 0x0002); // recordType = file
    put_be32(&mut v, rec + 8, 16); // fileID
    put_be32(&mut v, rec + 16, 2_082_844_800 + 1_000_000);
    put_be64(&mut v, rec + 88, payload.len() as u64);
    put_be32(&mut v, rec + 104, HFS_DATA_BLOCK as u32);
    put_be32(&mut v, rec + 108, 1);

    // File data.
    let data_off = HFS_DATA_BLOCK * HFS_BS;
    v[data_off..data_off + payload.len()].copy_from_slice(payload);
    v
}

// --- FAT32 --------------------------------------------------------------

/// A bare FAT32 volume with a cluster-chained root directory containing one
/// deleted file (8.3 short entry). Large enough (>= 65525 clusters) to be
/// classified as FAT32.
pub fn fat32_volume(name8: &[u8; 8], ext3: &[u8; 3], payload: &[u8]) -> Vec<u8> {
    const BPS: usize = 512;
    const RESERVED: usize = 32;
    const FAT_SECTORS: usize = 512;
    const DATA_CLUSTERS: usize = 65530; // > 65524 => FAT32
    const TOTAL: usize = RESERVED + FAT_SECTORS + DATA_CLUSTERS;
    let first_data = RESERVED + FAT_SECTORS; // spc = 1
    let root_cluster = 2usize;
    let file_cluster = 3usize;

    let mut v = vec![0u8; TOTAL * BPS];
    v[0] = 0xEB;
    v[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    v[13] = 1; // sectors per cluster
    v[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    v[16] = 1; // num FATs
    v[17..19].copy_from_slice(&0u16.to_le_bytes()); // root entry count (0 for FAT32)
    v[22..24].copy_from_slice(&0u16.to_le_bytes()); // FAT size 16
    v[32..36].copy_from_slice(&(TOTAL as u32).to_le_bytes()); // total sectors 32
    v[36..40].copy_from_slice(&(FAT_SECTORS as u32).to_le_bytes()); // FAT size 32
    v[44..48].copy_from_slice(&(root_cluster as u32).to_le_bytes()); // root cluster
    v[510] = 0x55;
    v[511] = 0xAA;

    // FAT: mark the root directory cluster as end-of-chain.
    let fat_base = RESERVED * BPS;
    v[fat_base + root_cluster * 4..fat_base + root_cluster * 4 + 4]
        .copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());

    // File data.
    let data_off = (first_data + (file_cluster - 2)) * BPS;
    v[data_off..data_off + payload.len()].copy_from_slice(payload);

    // Deleted short directory entry in the root cluster.
    let root_off = (first_data + (root_cluster - 2)) * BPS;
    let e = root_off;
    v[e..e + 8].copy_from_slice(name8);
    v[e + 8..e + 11].copy_from_slice(ext3);
    v[e] = 0xE5; // deletion marker
    v[e + 20..e + 22].copy_from_slice(&0u16.to_le_bytes()); // cluster high
    v[e + 26..e + 28].copy_from_slice(&(file_cluster as u16).to_le_bytes()); // cluster low
    v[e + 28..e + 32].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    v
}

// --- GPT wrapper --------------------------------------------------------

/// Wrap a volume image in a GPT disk using the given logical `sector_size`
/// (512 or 4096), placing the volume at `part_lba`.
pub fn gpt_disk(volume: &[u8], sector_size: usize, part_lba: usize) -> Vec<u8> {
    let part_off = part_lba * sector_size;
    let mut disk = vec![0u8; part_off + volume.len()];
    // Protective MBR signature.
    disk[510] = 0x55;
    disk[511] = 0xAA;
    // GPT header at LBA 1.
    let h = sector_size;
    disk[h..h + 8].copy_from_slice(b"EFI PART");
    disk[h + 72..h + 80].copy_from_slice(&2u64.to_le_bytes()); // entry array LBA
    disk[h + 80..h + 84].copy_from_slice(&4u32.to_le_bytes()); // entry count
    disk[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes()); // entry size
                                                                 // One partition entry at LBA 2.
    let e = 2 * sector_size;
    disk[e..e + 16].copy_from_slice(&[0x11; 16]); // non-zero type GUID
    disk[e + 32..e + 40].copy_from_slice(&(part_lba as u64).to_le_bytes());
    disk[part_off..part_off + volume.len()].copy_from_slice(volume);
    disk
}

/// A **journaled** HFS+ volume whose live catalog leaf holds nothing for the
/// deleted file: the stale record was scrubbed from the node's free space, as
/// macOS does. An older copy of the leaf node, from before the deletion and
/// with the record still live, sits in the journal buffer. This is the
/// situation a real Mac-formatted disk presents.
pub fn hfsplus_journaled_volume(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut v = hfsplus_volume(name, payload);
    let vh = 1024;
    let n1 = HFS_CATALOG_BLOCK * HFS_BS + HFS_NODE_SIZE;

    // Older copy of the leaf node with the record live: kind leaf, height 1,
    // one record at 14, free space after it.
    let mut node = v[n1..n1 + HFS_NODE_SIZE].to_vec();
    let key_len = 6 + 2 * name.encode_utf16().count();
    let rec_end = 14 + 2 + key_len + 248; // key + HFSPlusCatalogFile
    node[9] = 1; // height
    put_be16(&mut node, 10, 1); // numRecords
    put_be16(&mut node, HFS_NODE_SIZE - 2, 14); // offset[0]
    put_be16(&mut node, HFS_NODE_SIZE - 4, rec_end as u16); // offset[1] = free space

    // Journal info block at block 3, journal buffer at blocks 4..6 (1024 bytes);
    // the node copy is the buffer's second 512-byte half.
    const JIB_BLOCK: usize = 3;
    const JOURNAL_BLOCK: usize = 4;
    put_be32(&mut v, vh + 4, 1 << 13); // kHFSVolumeJournaledBit
    put_be32(&mut v, vh + 12, JIB_BLOCK as u32);
    let jib = JIB_BLOCK * HFS_BS;
    put_be32(&mut v, jib, 1); // kJIJournalInFSMask
    put_be64(&mut v, jib + 36, (JOURNAL_BLOCK * HFS_BS) as u64);
    put_be64(&mut v, jib + 44, (2 * HFS_BS) as u64);
    let jn = JOURNAL_BLOCK * HFS_BS + HFS_BS;
    v[jn..jn + HFS_NODE_SIZE].copy_from_slice(&node);

    // Scrub the live leaf's free space so only the journal knows the file.
    for b in &mut v[n1 + 14..n1 + HFS_NODE_SIZE - 2] {
        *b = 0;
    }
    v
}

/// A bare FAT32 volume where a whole folder was removed: the root holds a
/// **deleted** directory entry for `dir8`, whose cluster still starts with the
/// `.`/`..` entries and holds a deleted entry for the file `name8.ext3`.
pub fn fat32_deleted_dir_volume(
    dir8: &[u8; 8],
    name8: &[u8; 8],
    ext3: &[u8; 3],
    payload: &[u8],
) -> Vec<u8> {
    fat32_deleted_dir_volume_impl(dir8, name8, ext3, payload, true)
}

/// As [`fat32_deleted_dir_volume`], but the file entry inside the deleted
/// folder still looks live: Windows frees a folder's cluster without writing
/// back the deletion markers of the files it just removed from it.
pub fn fat32_windows_deleted_dir_volume(
    dir8: &[u8; 8],
    name8: &[u8; 8],
    ext3: &[u8; 3],
    payload: &[u8],
) -> Vec<u8> {
    fat32_deleted_dir_volume_impl(dir8, name8, ext3, payload, false)
}

fn fat32_deleted_dir_volume_impl(
    dir8: &[u8; 8],
    name8: &[u8; 8],
    ext3: &[u8; 3],
    payload: &[u8],
    mark_child_deleted: bool,
) -> Vec<u8> {
    const BPS: usize = 512;
    const RESERVED: usize = 32;
    const FAT_SECTORS: usize = 512;
    const DATA_CLUSTERS: usize = 65530;
    const TOTAL: usize = RESERVED + FAT_SECTORS + DATA_CLUSTERS;
    let first_data = RESERVED + FAT_SECTORS;
    let root_cluster = 2usize;
    let dir_cluster = 3usize;
    let file_cluster = 4usize;

    let mut v = vec![0u8; TOTAL * BPS];
    v[0] = 0xEB;
    v[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    v[13] = 1;
    v[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    v[16] = 1;
    v[32..36].copy_from_slice(&(TOTAL as u32).to_le_bytes());
    v[36..40].copy_from_slice(&(FAT_SECTORS as u32).to_le_bytes());
    v[44..48].copy_from_slice(&(root_cluster as u32).to_le_bytes());
    v[510] = 0x55;
    v[511] = 0xAA;
    let fat_base = RESERVED * BPS;
    v[fat_base + root_cluster * 4..fat_base + root_cluster * 4 + 4]
        .copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    // Clusters 3 and 4 are free in the FAT: the folder and file were deleted.

    let cluster_off = |c: usize| (first_data + (c - 2)) * BPS;
    let put_entry =
        |v: &mut [u8], at: usize, n8: &[u8; 8], e3: &[u8; 3], attr: u8, cl: usize, size: u32| {
            v[at..at + 8].copy_from_slice(n8);
            v[at + 8..at + 11].copy_from_slice(e3);
            v[at + 11] = attr;
            v[at + 26..at + 28].copy_from_slice(&(cl as u16).to_le_bytes());
            v[at + 28..at + 32].copy_from_slice(&size.to_le_bytes());
        };

    // Root: one deleted directory entry.
    let root = cluster_off(root_cluster);
    put_entry(&mut v, root, dir8, b"   ", 0x10, dir_cluster, 0);
    v[root] = 0xE5;

    // The folder's cluster: ".", "..", then the deleted file.
    let dir = cluster_off(dir_cluster);
    put_entry(&mut v, dir, b".       ", b"   ", 0x10, dir_cluster, 0);
    put_entry(&mut v, dir + 32, b"..      ", b"   ", 0x10, 0, 0);
    put_entry(
        &mut v,
        dir + 64,
        name8,
        ext3,
        0x20,
        file_cluster,
        payload.len() as u32,
    );
    if mark_child_deleted {
        v[dir + 64] = 0xE5;
    }

    let data = cluster_off(file_cluster);
    v[data..data + payload.len()].copy_from_slice(payload);
    v
}

/// A FAT32 volume with more than 65,536 clusters holding one deleted file
/// whose data sits at cluster 65,540 — but whose entry, as Windows leaves it,
/// records only the low 16 bits (cluster 4). Cluster 4 itself is allocated to
/// something else, so the FAT alone points at the right place.
pub fn fat32_highword_volume(name8: &[u8; 8], ext3: &[u8; 3], payload: &[u8]) -> Vec<u8> {
    const BPS: usize = 512;
    const RESERVED: usize = 32;
    const FAT_SECTORS: usize = 520;
    const DATA_CLUSTERS: usize = 66000;
    const TOTAL: usize = RESERVED + FAT_SECTORS + DATA_CLUSTERS;
    let first_data = RESERVED + FAT_SECTORS;
    let root_cluster = 2usize;
    let real_cluster = 65_540usize;

    let mut v = vec![0u8; TOTAL * BPS];
    v[0] = 0xEB;
    v[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    v[13] = 1;
    v[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    v[16] = 1;
    v[32..36].copy_from_slice(&(TOTAL as u32).to_le_bytes());
    v[36..40].copy_from_slice(&(FAT_SECTORS as u32).to_le_bytes());
    v[44..48].copy_from_slice(&(root_cluster as u32).to_le_bytes());
    v[510] = 0x55;
    v[511] = 0xAA;
    let fat_base = RESERVED * BPS;
    let eoc = 0x0FFF_FFFFu32.to_le_bytes();
    v[fat_base + root_cluster * 4..fat_base + root_cluster * 4 + 4].copy_from_slice(&eoc);
    // The low-half cluster is in use by a live file, so it is not a candidate.
    v[fat_base + 4 * 4..fat_base + 4 * 4 + 4].copy_from_slice(&eoc);

    let cluster_off = |c: usize| (first_data + (c - 2)) * BPS;
    let data = cluster_off(real_cluster);
    v[data..data + payload.len()].copy_from_slice(payload);

    let e = cluster_off(root_cluster);
    v[e..e + 8].copy_from_slice(name8);
    v[e + 8..e + 11].copy_from_slice(ext3);
    v[e] = 0xE5;
    v[e + 11] = 0x20;
    v[e + 20..e + 22].copy_from_slice(&0u16.to_le_bytes()); // high half zeroed
    v[e + 26..e + 28].copy_from_slice(&((real_cluster & 0xFFFF) as u16).to_le_bytes());
    v[e + 28..e + 32].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    v
}
