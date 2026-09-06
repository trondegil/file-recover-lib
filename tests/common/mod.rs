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
/// (512 or 4096), placing the volume at `part_lba`. The primary header sits
/// at LBA 1 with its entry array at LBA 2; a backup header sits at the last
/// LBA with its own copy of the entry array in the sector before it, as a
/// real GPT disk carries, so a wiped primary can be tested.
pub fn gpt_disk(volume: &[u8], sector_size: usize, part_lba: usize) -> Vec<u8> {
    let part_off = part_lba * sector_size;
    // The volume, rounded up to whole sectors, then the backup entry array
    // sector and the backup header sector.
    let body_sectors = part_lba + volume.len().div_ceil(sector_size);
    let total_sectors = body_sectors + 2;
    let backup_entries_lba = body_sectors;
    let backup_hdr_lba = body_sectors + 1;
    let mut disk = vec![0u8; total_sectors * sector_size];
    // Protective MBR signature.
    disk[510] = 0x55;
    disk[511] = 0xAA;
    let write_header = |disk: &mut [u8], lba: usize, entries_lba: usize, alternate: usize| {
        let h = lba * sector_size;
        disk[h..h + 8].copy_from_slice(b"EFI PART");
        disk[h + 24..h + 32].copy_from_slice(&(lba as u64).to_le_bytes()); // current LBA
        disk[h + 32..h + 40].copy_from_slice(&(alternate as u64).to_le_bytes()); // backup LBA
        disk[h + 72..h + 80].copy_from_slice(&(entries_lba as u64).to_le_bytes()); // entry array LBA
        disk[h + 80..h + 84].copy_from_slice(&4u32.to_le_bytes()); // entry count
        disk[h + 84..h + 88].copy_from_slice(&128u32.to_le_bytes()); // entry size
    };
    let write_entry = |disk: &mut [u8], lba: usize| {
        let e = lba * sector_size;
        disk[e..e + 16].copy_from_slice(&[0x11; 16]); // non-zero type GUID
        disk[e + 32..e + 40].copy_from_slice(&(part_lba as u64).to_le_bytes());
        disk[e + 40..e + 48].copy_from_slice(&((body_sectors - 1) as u64).to_le_bytes());
    };
    write_header(&mut disk, 1, 2, backup_hdr_lba);
    write_entry(&mut disk, 2);
    write_header(&mut disk, backup_hdr_lba, backup_entries_lba, 1);
    write_entry(&mut disk, backup_entries_lba);
    disk[part_off..part_off + volume.len()].copy_from_slice(volume);
    disk
}

// --- Detect-only filesystems -------------------------------------------

/// A minimal Btrfs volume: just enough of the primary superblock (at 64 KiB)
/// for detection, with a label and total size.
pub fn btrfs_volume(label: &str, total_bytes: u64) -> Vec<u8> {
    const SB_OFFSET: usize = 0x1_0000;
    let mut v = vec![0u8; SB_OFFSET + 4096];
    let sb = SB_OFFSET;
    v[sb + 64..sb + 72].copy_from_slice(b"_BHRfS_M");
    v[sb + 112..sb + 120].copy_from_slice(&total_bytes.to_le_bytes());
    v[sb + 144..sb + 148].copy_from_slice(&4096u32.to_le_bytes()); // sectorsize
    v[sb + 148..sb + 152].copy_from_slice(&16384u32.to_le_bytes()); // nodesize
    let lb = label.as_bytes();
    v[sb + 299..sb + 299 + lb.len()].copy_from_slice(lb);
    v
}

/// A minimal ISO 9660 image: a Primary Volume Descriptor at sector 16 with a
/// volume size (block count × block size) and a volume label. No directory
/// tree, so there are no files to extract.
pub fn iso_image(blocks: u32, label: &str) -> Vec<u8> {
    const VDS_OFFSET: usize = 16 * 2048;
    const VD_SIZE: usize = 2048;
    let mut v = vec![0u8; VDS_OFFSET + 4 * VD_SIZE];
    let off = VDS_OFFSET;
    v[off] = 1; // Primary Volume Descriptor
    v[off + 1..off + 6].copy_from_slice(b"CD001");
    v[off + 6] = 1;
    v[off + 40..off + 40 + label.len()].copy_from_slice(label.as_bytes());
    v[off + 80..off + 84].copy_from_slice(&blocks.to_le_bytes());
    v[off + 128..off + 130].copy_from_slice(&2048u16.to_le_bytes());
    // Volume creation date/time at offset 813: 2021-01-01 12:00:00, GMT.
    v[off + 813..off + 829].copy_from_slice(b"2021010112000000");
    v
}

/// A minimal UDF image: a reserved area followed by a BEA01 / NSR03 / TEA01
/// Volume Recognition Sequence at sector 16.
pub fn udf_image() -> Vec<u8> {
    const VRS_OFFSET: usize = 16 * 2048;
    const VSD_SIZE: usize = 2048;
    let mut v = vec![0u8; VRS_OFFSET + 8 * VSD_SIZE];
    let put = |v: &mut [u8], index: usize, id: &[u8; 5]| {
        let off = VRS_OFFSET + index * VSD_SIZE;
        v[off + 1..off + 6].copy_from_slice(id);
    };
    put(&mut v, 0, b"BEA01");
    put(&mut v, 1, b"NSR03");
    put(&mut v, 2, b"TEA01");
    v
}

/// A 1 MiB LUKS container header of the given version (1 or 2).
pub fn luks_image(version: u16) -> Vec<u8> {
    let mut v = vec![0u8; 1 << 20];
    v[0..6].copy_from_slice(b"LUKS\xba\xbe");
    v[6..8].copy_from_slice(&version.to_be_bytes());
    v
}

/// A 1 MiB BitLocker volume: its boot sector carries the `-FVE-FS-` OEM ID.
pub fn bitlocker_image() -> Vec<u8> {
    let mut v = vec![0u8; 1 << 20];
    v[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]); // boot-sector jump
    v[3..11].copy_from_slice(b"-FVE-FS-"); // BitLocker OEM ID
    v[510] = 0x55;
    v[511] = 0xAA;
    v
}

/// A minimal XFS volume: the superblock's magic, block size, block count,
/// and label, in `blocks` blocks of `block_size` bytes.
pub fn xfs_volume(label: &str, block_size: u32, blocks: u64) -> Vec<u8> {
    let mut v = vec![0u8; (block_size as usize) * (blocks as usize)];
    v[0..4].copy_from_slice(b"XFSB");
    v[4..8].copy_from_slice(&block_size.to_be_bytes());
    v[8..16].copy_from_slice(&blocks.to_be_bytes());
    let lb = label.as_bytes();
    assert!(lb.len() <= 12);
    v[0x6C..0x6C + lb.len()].copy_from_slice(lb);
    v
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

/// A bare FAT32 volume holding one deleted file whose data is not contiguous:
/// it occupies `data_clusters` in order, and every cluster between them is
/// allocated to a live file in the FAT (a chain of end-of-chain marks). The
/// deleted file's own chain is cleared, as a FAT driver leaves it. With
/// `wrap`, the file starts in the last cluster and continues from the first
/// free one, the way a next-fit allocator lays out a file written into the
/// last free stretch.
pub fn fat32_fragmented_volume(
    name8: &[u8; 8],
    ext3: &[u8; 3],
    payload: &[u8],
    wrap: bool,
) -> Vec<u8> {
    const BPS: usize = 512;
    const RESERVED: usize = 32;
    const FAT_SECTORS: usize = 512;
    const DATA_CLUSTERS: usize = 65530;
    const TOTAL: usize = RESERVED + FAT_SECTORS + DATA_CLUSTERS;
    let first_data = RESERVED + FAT_SECTORS;
    let root_cluster = 2usize;
    let last_cluster = DATA_CLUSTERS + 1;

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
    let mut allocate = |c: usize| v[fat_base + c * 4..fat_base + c * 4 + 4].copy_from_slice(&eoc);
    allocate(root_cluster);

    // Data clusters, in file order, and the live clusters that sit between them.
    let (data_clusters, live): (Vec<usize>, Vec<usize>) = if wrap {
        (vec![last_cluster, 3, 4, 6], vec![5])
    } else {
        (vec![3, 5, 6, 9], vec![4, 7, 8])
    };
    for &c in &live {
        allocate(c);
    }
    let cluster_off = |c: usize| (first_data + (c - 2)) * BPS;
    for (i, chunk) in payload.chunks(BPS).enumerate() {
        let off = cluster_off(data_clusters[i]);
        v[off..off + chunk.len()].copy_from_slice(chunk);
    }
    for &c in &live {
        let off = cluster_off(c);
        v[off..off + BPS].fill(0xEE);
    }

    let e = cluster_off(root_cluster);
    v[e..e + 8].copy_from_slice(name8);
    v[e + 8..e + 11].copy_from_slice(ext3);
    v[e] = 0xE5;
    v[e + 11] = 0x20;
    let start = data_clusters[0] as u32;
    v[e + 20..e + 22].copy_from_slice(&((start >> 16) as u16).to_le_bytes());
    v[e + 26..e + 28].copy_from_slice(&((start & 0xFFFF) as u16).to_le_bytes());
    v[e + 28..e + 32].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    v
}

/// A bare FAT32 volume with a deleted JPEG split around a *free* decoy
/// cluster: the file's first cluster, then a free cluster holding bytes that
/// cannot be JPEG scan data (`FF 7A`), then the JPEG's real continuation.
/// Only JPEG structure, not the allocation map, tells the decoy apart.
pub fn fat32_jpeg_decoy_volume(jpeg: &[u8]) -> Vec<u8> {
    const BPS: usize = 512;
    const RESERVED: usize = 32;
    const FAT_SECTORS: usize = 512;
    const DATA_CLUSTERS: usize = 65530;
    const TOTAL: usize = RESERVED + FAT_SECTORS + DATA_CLUSTERS;
    let first_data = RESERVED + FAT_SECTORS;
    let root_cluster = 2usize;
    assert!(jpeg.len() > BPS && jpeg.len() <= 3 * BPS);

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

    let cluster_off = |c: usize| (first_data + (c - 2)) * BPS;
    // Cluster 3: JPEG start. Cluster 4: free decoy. Clusters 5, 6: the rest.
    let mut chunks = jpeg.chunks(BPS);
    let c3 = chunks.next().unwrap();
    v[cluster_off(3)..cluster_off(3) + c3.len()].copy_from_slice(c3);
    let decoy = cluster_off(4);
    for i in 0..BPS / 2 {
        v[decoy + 2 * i] = 0xFF;
        v[decoy + 2 * i + 1] = 0x7A;
    }
    for (k, chunk) in chunks.enumerate() {
        let off = cluster_off(5 + k);
        v[off..off + chunk.len()].copy_from_slice(chunk);
    }

    let e = cluster_off(root_cluster);
    v[e..e + 11].copy_from_slice(b"PHOTO   JPG");
    v[e] = 0xE5;
    v[e + 11] = 0x20;
    v[e + 26..e + 28].copy_from_slice(&3u16.to_le_bytes());
    v[e + 28..e + 32].copy_from_slice(&(jpeg.len() as u32).to_le_bytes());
    v
}

/// Like [`ext_volume`], but with several deleted files: entry `i` is inode
/// `11 + i` with its data in block `11 + i`, reachable as a stale root
/// dirent. Each payload must fit one 1 KiB block; at most 16 entries.
pub fn ext_volume_multi(entries: &[(&str, &[u8])]) -> Vec<u8> {
    assert!(entries.len() <= 16, "at most 16 entries fit the fixture");
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
    ext_dirent(&mut v, EXT_ROOT_DIR, 0, 2, 12, ".", 2);
    ext_dirent(&mut v, EXT_ROOT_DIR, 12, 2, (EXT_BS - 12) as u16, "..", 2);

    let mut off = 28;
    for (i, (name, payload)) in entries.iter().enumerate() {
        assert!(payload.len() <= EXT_BS, "payload must fit one block");
        assert!(name.len() <= 255, "name must fit a dirent");
        let ino = 11 + i as u32;
        let block = EXT_DATA + i;
        assert!(block < EXT_BLOCKS);
        ext_inode(
            &mut v,
            ino,
            0x81A4,
            0,
            12345,
            payload.len() as u32,
            block as u32,
        );
        v[block * EXT_BS..block * EXT_BS + payload.len()].copy_from_slice(payload);
        let rec_len = (8 + name.len() + 7) & !7;
        assert!(
            off + 8 + name.len() <= EXT_BS,
            "root dirents overflow the block"
        );
        ext_dirent(&mut v, EXT_ROOT_DIR, off, ino, rec_len as u16, name, 1);
        off += rec_len;
    }
    v
}

/// A FAT32 volume (as [`fat32_volume`]) whose deleted file carries a long
/// name: the deleted LFN entries precede a deleted `LONGNA~1.TXT` short entry,
/// so the recovered name is `long_name`, whatever characters it holds.
pub fn fat32_lfn_volume(long_name: &str, payload: &[u8]) -> Vec<u8> {
    const BPS: usize = 512;
    const RESERVED: usize = 32;
    const FAT_SECTORS: usize = 512;
    let root_off = (RESERVED + FAT_SECTORS) * BPS; // root cluster 2 is the first data cluster
    let mut v = fat32_volume(b"LONGNA~1", b"TXT", payload);
    let mut short = [0u8; 32];
    short.copy_from_slice(&v[root_off..root_off + 32]);
    v[root_off..root_off + 32].fill(0);

    let mut units: Vec<u16> = long_name.encode_utf16().collect();
    units.push(0);
    let chunks: Vec<&[u16]> = units.chunks(13).collect();
    assert!(chunks.len() <= 20, "long name too long for one LFN chain");
    // Physical order is highest sequence first; every slot is marked deleted.
    for (slot, chunk) in chunks.iter().rev().enumerate() {
        let e = root_off + slot * 32;
        v[e] = 0xE5;
        v[e + 11] = 0x0F;
        let mut padded = chunk.to_vec();
        while padded.len() < 13 {
            padded.push(0xFFFF);
        }
        let ranges = [1usize..11, 14..26, 28..32];
        let mut k = 0;
        for r in ranges {
            for pair in v[e + r.start..e + r.end].chunks_exact_mut(2) {
                pair.copy_from_slice(&padded[k].to_le_bytes());
                k += 1;
            }
        }
    }
    let e = root_off + chunks.len() * 32;
    v[e..e + 32].copy_from_slice(&short);
    v
}

/// A 64-block ext2-style volume (no extents flag) with one deleted file whose
/// data is mapped by the twelve direct pointers and one single-indirect
/// block. Data blocks sit on every other block from 12, the indirect block
/// at `EXT_INDIRECT_BLOCK`, and the blocks it points at after it, so a
/// truncation just before the indirect block cuts the map, not the data.
/// `payload` must be longer than 12 KiB and at most 24 KiB.
pub const EXT_INDIRECT_BLOCK: usize = 36;
pub fn ext_indirect_volume(name: &str, payload: &[u8]) -> Vec<u8> {
    const BLOCKS: usize = 64;
    assert!(
        (12 * EXT_BS + 1..=24 * EXT_BS).contains(&payload.len()),
        "payload must need the indirect block"
    );
    let mut v = vec![0u8; BLOCKS * EXT_BS];
    let sb = 1024;
    v[sb..sb + 4].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 4..sb + 8].copy_from_slice(&(BLOCKS as u32).to_le_bytes());
    v[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes());
    v[sb + 0x20..sb + 0x24].copy_from_slice(&8192u32.to_le_bytes());
    v[sb + 0x28..sb + 0x2C].copy_from_slice(&32u32.to_le_bytes());
    v[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    v[sb + 0x58..sb + 0x5A].copy_from_slice(&(EXT_ISIZE as u16).to_le_bytes());
    v[sb + 0x60..sb + 0x64].copy_from_slice(&0x0002u32.to_le_bytes());
    v[2 * EXT_BS + 8..2 * EXT_BS + 12].copy_from_slice(&(EXT_ITAB as u32).to_le_bytes());

    ext_inode(&mut v, 2, 0x41ED, 3, 0, EXT_BS as u32, EXT_ROOT_DIR as u32);
    ext_dirent(&mut v, EXT_ROOT_DIR, 0, 2, 12, ".", 2);
    ext_dirent(&mut v, EXT_ROOT_DIR, 12, 2, (EXT_BS - 12) as u16, "..", 2);
    ext_dirent(&mut v, EXT_ROOT_DIR, 28, 11, 24, name, 1);

    // Inode 11: deleted, no extents flag, classic block map.
    let o = EXT_ITAB * EXT_BS + 10 * EXT_ISIZE;
    v[o..o + 2].copy_from_slice(&0x81A4u16.to_le_bytes());
    v[o + 4..o + 8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    v[o + 0x14..o + 0x18].copy_from_slice(&12345u32.to_le_bytes());
    v[o + 0x1A..o + 0x1C].copy_from_slice(&0u16.to_le_bytes());
    let ib = o + 0x28;
    let n_blocks = payload.len().div_ceil(EXT_BS);
    let data_block = |i: usize| -> usize {
        if i < 12 {
            12 + 2 * i
        } else {
            EXT_INDIRECT_BLOCK + 2 + 2 * (i - 12)
        }
    };
    for i in 0..12.min(n_blocks) {
        v[ib + 4 * i..ib + 4 * i + 4].copy_from_slice(&(data_block(i) as u32).to_le_bytes());
    }
    v[ib + 48..ib + 52].copy_from_slice(&(EXT_INDIRECT_BLOCK as u32).to_le_bytes());
    let ind = EXT_INDIRECT_BLOCK * EXT_BS;
    for i in 12..n_blocks {
        let k = i - 12;
        v[ind + 4 * k..ind + 4 * k + 4].copy_from_slice(&(data_block(i) as u32).to_le_bytes());
    }
    for (i, chunk) in payload.chunks(EXT_BS).enumerate() {
        let b = data_block(i) * EXT_BS;
        assert!(b + chunk.len() <= v.len());
        v[b..b + chunk.len()].copy_from_slice(chunk);
    }
    v
}

// --- FAT12 / FAT16 ---------------------------------------------------------

/// A bare FAT12 volume: 100 data clusters of 512 bytes (well under 4085),
/// one FAT sector, a 16-entry root directory region, and one deleted 8.3
/// file at cluster 3 holding `payload`. FAT entries are 12-bit packed.
pub fn fat12_volume(name8: &[u8; 8], ext3: &[u8; 3], payload: &[u8]) -> Vec<u8> {
    fat_small_volume(name8, ext3, payload, 100, 1, 12)
}

/// A bare FAT16 volume: 8192 data clusters of 512 bytes (between 4085 and
/// 65525), 32 FAT sectors, a 16-entry root directory region, and one
/// deleted 8.3 file at cluster 3 holding `payload`.
pub fn fat16_volume(name8: &[u8; 8], ext3: &[u8; 3], payload: &[u8]) -> Vec<u8> {
    fat_small_volume(name8, ext3, payload, 8192, 32, 16)
}

fn fat_small_volume(
    name8: &[u8; 8],
    ext3: &[u8; 3],
    payload: &[u8],
    data_clusters: usize,
    fat_sectors: usize,
    bits: u32,
) -> Vec<u8> {
    const BPS: usize = 512;
    const RESERVED: usize = 1;
    const ROOT_ENTRIES: usize = 16; // one sector
    let root_sector = RESERVED + fat_sectors;
    let first_data = root_sector + 1;
    let total = first_data + data_clusters;
    let file_cluster = 3usize;
    assert!(payload.len() <= (data_clusters - 2) * BPS);

    let mut v = vec![0u8; total * BPS];
    v[0] = 0xEB;
    v[1] = 0x3C;
    v[2] = 0x90;
    v[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    v[13] = 1; // sectors per cluster
    v[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    v[16] = 1; // one FAT
    v[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    if total < 65536 {
        v[19..21].copy_from_slice(&(total as u16).to_le_bytes());
    } else {
        v[32..36].copy_from_slice(&(total as u32).to_le_bytes());
    }
    v[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
    v[0x27..0x2B].copy_from_slice(&0x1234_5678u32.to_le_bytes()); // serial
    v[510] = 0x55;
    v[511] = 0xAA;

    // FAT: media byte entries 0 and 1, root region is not in the FAT; the
    // deleted file's chain is cleared, as a driver leaves it.
    let fat = RESERVED * BPS;
    let set = |v: &mut [u8], cluster: usize, value: u32| match bits {
        12 => {
            let i = cluster * 3 / 2;
            let cur = u16::from_le_bytes([v[fat + i], v[fat + i + 1]]);
            let new = if cluster & 1 == 0 {
                (cur & 0xF000) | (value as u16 & 0x0FFF)
            } else {
                (cur & 0x000F) | ((value as u16 & 0x0FFF) << 4)
            };
            v[fat + i..fat + i + 2].copy_from_slice(&new.to_le_bytes());
        }
        _ => v[fat + cluster * 2..fat + cluster * 2 + 2]
            .copy_from_slice(&(value as u16).to_le_bytes()),
    };
    set(&mut v, 0, 0xFF8);
    set(&mut v, 1, 0xFFF);

    let data = (first_data + (file_cluster - 2)) * BPS;
    v[data..data + payload.len()].copy_from_slice(payload);

    let e = root_sector * BPS;
    v[e..e + 8].copy_from_slice(name8);
    v[e + 8..e + 11].copy_from_slice(ext3);
    v[e] = 0xE5;
    v[e + 11] = 0x20;
    v[e + 26..e + 28].copy_from_slice(&(file_cluster as u16).to_le_bytes());
    v[e + 28..e + 32].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    v
}

/// A bare HFS+ volume of 40 blocks whose deleted file has one inline extent
/// (block 14, one block) and whose remaining extents live in the
/// extents-overflow B-tree as `records`: each is `(startBlock key, extents)`
/// and is written into the leaf in the order given. Every block from 14 up
/// is filled with its own index, so the bytes a recovery produces name the
/// blocks it read. `logical_size` is the file's recorded size.
pub const HFS_OVERFLOW_TOTAL_BLOCKS: usize = 40;
pub fn hfsplus_overflow_volume(
    name: &str,
    logical_size: u64,
    records: &[(u32, Vec<(u32, u32)>)],
) -> Vec<u8> {
    let name16: Vec<u16> = name.encode_utf16().collect();
    let name_len = name16.len();
    const CATALOG_BLOCK: usize = 8;
    const OVERFLOW_BLOCK: usize = 10;
    const INLINE_BLOCK: usize = 14;
    let total_blocks = HFS_OVERFLOW_TOTAL_BLOCKS;
    let mut v = vec![0u8; total_blocks * HFS_BS];
    for b in INLINE_BLOCK..total_blocks {
        v[b * HFS_BS..(b + 1) * HFS_BS].fill(b as u8);
    }

    let vh = 1024;
    put_be16(&mut v, vh, 0x482B);
    put_be16(&mut v, vh + 2, 4);
    put_be32(&mut v, vh + 40, HFS_BS as u32);
    put_be32(&mut v, vh + 44, total_blocks as u32);
    put_be64(&mut v, vh + 272, (2 * HFS_NODE_SIZE) as u64);
    put_be32(&mut v, vh + 284, 2);
    put_be32(&mut v, vh + 288, CATALOG_BLOCK as u32);
    put_be32(&mut v, vh + 292, 2);
    put_be64(&mut v, vh + 192, (2 * HFS_NODE_SIZE) as u64);
    put_be32(&mut v, vh + 204, 2);
    put_be32(&mut v, vh + 208, OVERFLOW_BLOCK as u32);
    put_be32(&mut v, vh + 212, 2);

    let cn0 = CATALOG_BLOCK * HFS_BS;
    v[cn0 + 8] = 1;
    put_be16(&mut v, cn0 + 32, HFS_NODE_SIZE as u16);
    let cn1 = cn0 + HFS_NODE_SIZE;
    v[cn1 + 8] = 0xFF;
    put_be16(&mut v, cn1 + 10, 0);
    put_be16(&mut v, cn1 + HFS_NODE_SIZE - 2, 14);
    let key = cn1 + 14;
    let key_len = 6 + 2 * name_len;
    put_be16(&mut v, key, key_len as u16);
    put_be32(&mut v, key + 2, 2);
    put_be16(&mut v, key + 6, name_len as u16);
    for (i, &u) in name16.iter().enumerate() {
        put_be16(&mut v, key + 8 + i * 2, u);
    }
    let rec = key + 2 + key_len;
    put_be16(&mut v, rec, 0x0002);
    put_be32(&mut v, rec + 8, 16);
    put_be32(&mut v, rec + 16, 2_082_844_800 + 1_000_000);
    put_be64(&mut v, rec + 88, logical_size);
    put_be32(&mut v, rec + 104, INLINE_BLOCK as u32);
    put_be32(&mut v, rec + 108, 1);

    let on0 = OVERFLOW_BLOCK * HFS_BS;
    v[on0 + 8] = 1;
    put_be16(&mut v, on0 + 32, HFS_NODE_SIZE as u16);
    let on1 = on0 + HFS_NODE_SIZE;
    v[on1 + 8] = 0xFF;
    put_be16(&mut v, on1 + 10, records.len() as u16);
    let mut off = 14usize;
    for (i, (start_block, extents)) in records.iter().enumerate() {
        assert!(extents.len() <= 8);
        put_be16(&mut v, on1 + HFS_NODE_SIZE - 2 * (i + 1), off as u16);
        let er = on1 + off;
        put_be16(&mut v, er, 10);
        v[er + 2] = 0; // data fork
        put_be32(&mut v, er + 4, 16); // fileID
        put_be32(&mut v, er + 8, *start_block);
        for (k, &(start, count)) in extents.iter().enumerate() {
            put_be32(&mut v, er + 12 + k * 8, start);
            put_be32(&mut v, er + 16 + k * 8, count);
        }
        off += 12 + 64;
    }
    assert!(off + 2 * (records.len() + 1) <= HFS_NODE_SIZE);
    v
}
