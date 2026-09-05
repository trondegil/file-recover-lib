//! A streaming check of JPEG structure, used to tell whether a candidate
//! cluster can belong to a JPEG being reassembled from free space.
//!
//! A deleted file's cluster chain is gone; the allocation map says which
//! clusters are *not* ours, but among the free ones a neighbour deleted after
//! the file looks exactly like the file's own continuation. JPEG's structure
//! settles many of those cases: in the entropy-coded data after an SOS marker,
//! an `FF` byte may only be followed by `00` (a stuffed byte), `D0`–`D7`
//! (restart markers), `D9` (end of image), `FF` (fill), or one of the few
//! markers that may legally start another segment (DHT, DQT, SOS, DNL, DRI,
//! COM, APPn). Anything else means the bytes are not this JPEG's. Data with
//! no `FF` bytes at all (zeros, text) passes, so this is a filter, not proof.
//!
//! The scanner is a small state machine that survives cluster boundaries:
//! segment headers and their lengths are parsed so a marker split across two
//! clusters is still seen. `accept` returns the state after a chunk, or `None`
//! if the chunk cannot be part of the stream.

/// Where the scanner is in the JPEG structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Reading marker segments before (or between) scans.
    Segments,
    /// Skipping the payload of a segment whose length is known.
    SkipPayload,
    /// Inside entropy-coded data after an SOS marker.
    Scan,
    /// Past the EOI marker: anything may follow (padding, appended data).
    Done,
}

/// Streaming JPEG structure check. `Clone` so a candidate chunk can be tried
/// without committing to it.
#[derive(Clone, Debug)]
pub struct JpegScan {
    stage: Stage,
    /// Bytes of segment payload still to skip.
    skip: u64,
    /// The last byte was `FF` (marker prefix), carried across chunks.
    after_ff: bool,
    /// Partial segment header: the marker byte seen, waiting for its length.
    marker: Option<u8>,
    /// First byte of the two-byte length, when split across chunks.
    len_hi: Option<u8>,
    /// After the current payload skip, enter the scan (the payload was an
    /// SOS header).
    scan_after_skip: bool,
    /// Bytes consumed so far.
    pub consumed: u64,
}

impl Default for JpegScan {
    fn default() -> Self {
        Self::new()
    }
}

impl JpegScan {
    /// A scanner positioned at the start of a file (expects `FF D8`).
    pub fn new() -> Self {
        JpegScan {
            stage: Stage::Segments,
            skip: 0,
            after_ff: false,
            marker: None,
            len_hi: None,
            scan_after_skip: false,
            consumed: 0,
        }
    }

    /// Whether the data so far ends in a complete image (EOI seen).
    pub fn finished(&self) -> bool {
        self.stage == Stage::Done
    }

    /// Feed `chunk`; `Some(next state)` if it is consistent with a JPEG at
    /// this point in the stream, `None` if it cannot be.
    pub fn accept(&self, chunk: &[u8]) -> Option<JpegScan> {
        let mut s = self.clone();
        let mut i = 0;
        while i < chunk.len() {
            match s.stage {
                Stage::Done => break,
                Stage::SkipPayload => {
                    let take = (s.skip as usize).min(chunk.len() - i);
                    s.skip -= take as u64;
                    i += take;
                    if s.skip == 0 {
                        s.stage = if s.scan_after_skip {
                            Stage::Scan
                        } else {
                            Stage::Segments
                        };
                        s.scan_after_skip = false;
                    }
                    continue;
                }
                Stage::Segments => {
                    let b = chunk[i];
                    i += 1;
                    if let Some(m) = s.marker {
                        // Reading the big-endian length that follows the marker.
                        match s.len_hi {
                            None => s.len_hi = Some(b),
                            Some(hi) => {
                                let len = u16::from_be_bytes([hi, b]) as u64;
                                if len < 2 {
                                    return None;
                                }
                                s.marker = None;
                                s.len_hi = None;
                                s.skip = len - 2;
                                // SOS: skip its header, then entropy-coded data.
                                s.scan_after_skip = m == 0xDA;
                                s.stage = if s.skip > 0 {
                                    Stage::SkipPayload
                                } else if m == 0xDA {
                                    Stage::Scan
                                } else {
                                    Stage::Segments
                                };
                            }
                        }
                        continue;
                    }
                    if s.after_ff {
                        s.after_ff = false;
                        match b {
                            0xFF => s.after_ff = true,      // fill byte
                            0xD8 | 0x01 | 0xD0..=0xD7 => {} // standalone markers
                            0xD9 => s.stage = Stage::Done,
                            0xC0..=0xFE => s.marker = Some(b),
                            _ => return None,
                        }
                    } else if b == 0xFF {
                        s.after_ff = true;
                    } else {
                        // Between segments only markers are legal.
                        return None;
                    }
                }
                Stage::Scan => {
                    let b = chunk[i];
                    i += 1;
                    if s.after_ff {
                        s.after_ff = false;
                        match b {
                            0x00 | 0xD0..=0xD7 | 0xFF => {
                                if b == 0xFF {
                                    s.after_ff = true;
                                }
                            }
                            0xD9 => s.stage = Stage::Done,
                            // A new segment inside a (progressive) scan: DHT,
                            // DQT, DRI, DNL, SOS, COM, APPn.
                            0xC4 | 0xDB | 0xDD | 0xDC | 0xDA | 0xFE | 0xE0..=0xEF => {
                                s.stage = Stage::Segments;
                                s.marker = Some(b);
                            }
                            _ => return None,
                        }
                    } else if b == 0xFF {
                        s.after_ff = true;
                    }
                }
            }
        }
        s.consumed += chunk.len() as u64;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_jpeg(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00]; // SOI, APP0(len 4)
        v.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x03, 0x01]); // SOS with a 1-byte header body
        v.extend_from_slice(payload);
        v.extend_from_slice(&[0xFF, 0xD9]);
        v
    }

    #[test]
    fn accepts_a_whole_jpeg_in_one_go_and_in_pieces() {
        let jpeg = minimal_jpeg(&[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56]);
        let s = JpegScan::new().accept(&jpeg).expect("valid");
        assert!(s.finished());
        // Every split point must work, including inside the FF pairs.
        for cut in 1..jpeg.len() {
            let s1 = JpegScan::new()
                .accept(&jpeg[..cut])
                .unwrap_or_else(|| panic!("cut {cut}"));
            let s2 = s1
                .accept(&jpeg[cut..])
                .unwrap_or_else(|| panic!("cut {cut} tail"));
            assert!(s2.finished(), "cut {cut}");
        }
    }

    #[test]
    fn rejects_foreign_bytes_in_the_scan() {
        let jpeg = minimal_jpeg(&[0x12, 0x34]);
        let head = JpegScan::new().accept(&jpeg[..jpeg.len() - 2]).unwrap();
        // An FF followed by a byte that is not a legal marker in scan data.
        assert!(head.accept(&[0xFF, 0x7A]).is_none());
        assert!(head.accept(&[0xFF, 0xC0]).is_none()); // SOF cannot follow a scan
                                                       // Legal continuations.
        assert!(head.accept(&[0xFF, 0x00]).is_some());
        assert!(head.accept(&[0xFF, 0xD3]).is_some());
        assert!(head.accept(&[0xFF, 0xC4, 0x00, 0x02]).is_some()); // DHT between scans
                                                                   // Zeros carry no evidence either way.
        assert!(head.accept(&[0u8; 512]).is_some());
    }

    #[test]
    fn rejects_garbage_between_segments() {
        let mut s = JpegScan::new();
        s = s.accept(&[0xFF, 0xD8]).unwrap();
        assert!(
            s.accept(&[0x41, 0x42]).is_none(),
            "text where a marker is due"
        );
        assert!(
            s.accept(&[0xFF, 0x00]).is_none(),
            "FF 00 is not a marker here"
        );
        let s = s.accept(&[0xFF, 0xDB, 0x00, 0x05, 1, 2, 3]).unwrap();
        assert!(
            s.accept(&[0xFF, 0xDA, 0x00, 0x01]).is_none(),
            "length below 2"
        );
    }
}
