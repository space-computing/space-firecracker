// Copyright 2026 Spacebox authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The bytes of the stream of checkpoints (version 2; all integers big-endian; a page is 4096
//! bytes):
//!
//! ```text
//! a page record:      u64 offset | u32 pages | u32 kind   kind 0: data, the pages follow
//!                                                          kind 1: zeros, no bytes follow
//!                     `pages` 0 ends a list of records (16 zero bytes)
//! a new stream:       "SBFH" | u32 version | u32 R | R x (u64 guest_addr | u64 size | u64 offset)
//!                     the full copy: page records and the end record
//!                     frame 0, frame 1, ...
//! frame N:            "SBCK" or "SBCH" | u64 N | u64 pages_len | u64 state_len | u64 gpu_len
//!                     | page records and the end record | the state (Firecracker's state file)
//!                     | the GPU device's large state (gpu_len 0: the guest has no GPU device)
//!                     | "SBCE"
//! the GPU's state:    u64 S | S bytes: its structure (S 0: the same as in the frame before)
//!                     | u32 B | B × (u64 id | u64 L | L bytes: a blob; L 2^64-1: no bytes,
//!                     the blob of this id in the frame before, or earlier in this frame)
//! the answer:         u64 N
//! a continued stream: "SBCC" | u64 N, or "SBCI" | u64 N | 16 bytes, answered with u64 N;
//!                     then frame N + 1 and on
//! ```
//!
//! The offset of a page record is the offset in the memory file: each region of guest memory
//! lies there at its offset, in the order of the regions (`GET /space/memory`). `SBCH` says that
//! the output of the guest is held under a lease for this checkpoint. Frame 0 closes the full
//! copy: it has the pages that changed while the full copy was sent.
//!
//! The GPU device's large state is its side file in two parts (`GpuSideState::split`): the
//! structure, and the blobs in their order. A blob is sent once on a connection: the frames
//! after it name it by its id while the state still holds it (the sender knows a blob by its
//! allocation, which the device never changes). The first frame on a connection sends all its
//! blobs. The receiving place writes the side file from the newest whole frame at its seal.

use std::collections::HashMap;
use std::sync::Arc;

use crate::devices::virtio::gpu::SideParts;
use gpu_journal::Blob;

/// The version of the stream.
pub const VERSION: u32 = 2;
/// A new stream.
pub const HEADER: &[u8; 4] = b"SBFH";
/// A frame.
pub const FRAME: &[u8; 4] = b"SBCK";
/// A frame whose output is held under a lease.
pub const FRAME_HELD: &[u8; 4] = b"SBCH";
/// The end of a frame.
pub const FRAME_END: &[u8; 4] = b"SBCE";
/// A continued stream.
pub const CONTINUE: &[u8; 4] = b"SBCC";
/// A continued stream that names the identity of its place.
pub const CONTINUE_ID: &[u8; 4] = b"SBCI";
/// The length of an identity.
pub const ID_LEN: usize = 16;
/// The size of a page.
pub const PAGE: usize = 4096;
/// The kind of a record whose pages follow it.
pub const KIND_DATA: u32 = 0;
/// The kind of a record of zeros.
pub const KIND_ZERO: u32 = 1;
/// The most pages of one record.
pub const MAX_RECORD_PAGES: u64 = u32::MAX as u64;

/// One region of guest memory, as the header names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionDesc {
    /// Its guest physical address.
    pub guest_addr: u64,
    /// Its size.
    pub size: u64,
    /// Its offset in the memory file.
    pub offset: u64,
}

/// The head of a page record.
pub fn record_head(out: &mut Vec<u8>, offset: u64, pages: u32, kind: u32) {
    out.extend_from_slice(&offset.to_be_bytes());
    out.extend_from_slice(&pages.to_be_bytes());
    out.extend_from_slice(&kind.to_be_bytes());
}

/// The end record of a list.
pub fn end_record(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0u8; 16]);
}

/// The head of a new stream.
pub fn header(regions: &[RegionDesc]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + 24 * regions.len());
    out.extend_from_slice(HEADER);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&u32::try_from(regions.len()).unwrap().to_be_bytes());
    for r in regions {
        out.extend_from_slice(&r.guest_addr.to_be_bytes());
        out.extend_from_slice(&r.size.to_be_bytes());
        out.extend_from_slice(&r.offset.to_be_bytes());
    }
    out
}

/// The head of frame `n`.
pub fn frame_head(n: u64, held: bool, pages_len: u64, state_len: u64, gpu_len: u64) -> [u8; 36] {
    let mut out = [0u8; 36];
    out[..4].copy_from_slice(if held { FRAME_HELD } else { FRAME });
    out[4..12].copy_from_slice(&n.to_be_bytes());
    out[12..20].copy_from_slice(&pages_len.to_be_bytes());
    out[20..28].copy_from_slice(&state_len.to_be_bytes());
    out[28..36].copy_from_slice(&gpu_len.to_be_bytes());
    out
}

/// The length of a blob that the receiving place has from the frame before.
pub const BLOB_KNOWN: u64 = u64::MAX;

/// A piece of the GPU's part of a frame: bytes of the stream, or a blob's bytes.
#[derive(Debug)]
pub enum GpuPiece {
    /// Bytes of the stream: the structure, the heads of the blobs.
    Bytes(Vec<u8>),
    /// The bytes of a blob.
    Blob(Blob),
}

impl GpuPiece {
    /// The bytes that go on the stream.
    pub fn bytes(&self) -> &[u8] {
        match self {
            GpuPiece::Bytes(b) => b,
            GpuPiece::Blob(b) => b,
        }
    }
}

/// What the receiving place has of the GPU's state on this connection: the structure of the
/// frame before and its blobs (the blobs are kept, so that their allocations stay theirs).
#[derive(Debug, Default)]
pub struct GpuKnown {
    next_id: u64,
    skeleton: Option<Vec<u8>>,
    blobs: HashMap<usize, (u64, Blob)>,
}

/// The GPU's part of a frame for `parts`, in pieces; `known` becomes what the receiving place
/// has after it.
pub fn gpu_section(parts: SideParts, known: &mut GpuKnown) -> Vec<GpuPiece> {
    let mut out = Vec::new();
    let mut head = Vec::with_capacity(16 + parts.skeleton.len() + 16 * parts.blobs.len());
    let same = known.skeleton.as_deref() == Some(&parts.skeleton[..]);
    if same {
        head.extend_from_slice(&0u64.to_be_bytes());
    } else {
        head.extend_from_slice(&(parts.skeleton.len() as u64).to_be_bytes());
        head.extend_from_slice(&parts.skeleton);
    }
    head.extend_from_slice(&u32::try_from(parts.blobs.len()).unwrap().to_be_bytes());
    let mut now: HashMap<usize, (u64, Blob)> = HashMap::with_capacity(parts.blobs.len());
    for b in parts.blobs {
        let key = Arc::as_ptr(&b) as usize;
        if let Some((id, _)) = now.get(&key).or_else(|| known.blobs.get(&key)) {
            let id = *id;
            head.extend_from_slice(&id.to_be_bytes());
            head.extend_from_slice(&BLOB_KNOWN.to_be_bytes());
            now.entry(key).or_insert((id, b));
        } else {
            known.next_id += 1;
            let id = known.next_id;
            head.extend_from_slice(&id.to_be_bytes());
            head.extend_from_slice(&(b.len() as u64).to_be_bytes());
            out.push(GpuPiece::Bytes(std::mem::take(&mut head)));
            out.push(GpuPiece::Blob(b.clone()));
            now.insert(key, (id, b));
        }
    }
    if !head.is_empty() {
        out.push(GpuPiece::Bytes(head));
    }
    known.blobs = now;
    if !same {
        known.skeleton = Some(parts.skeleton);
    }
    out
}

/// The first bytes of a continued stream.
pub fn continue_head(n: u64, id: Option<&[u8; ID_LEN]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(28);
    out.extend_from_slice(if id.is_some() { CONTINUE_ID } else { CONTINUE });
    out.extend_from_slice(&n.to_be_bytes());
    if let Some(id) = id {
        out.extend_from_slice(id);
    }
    out
}

/// Whether a page holds only zeros.
pub fn page_is_zero(page: &[u8]) -> bool {
    let (head, words, tail) = {
        // SAFETY: any bytes are a valid u64.
        unsafe { page.align_to::<u64>() }
    };
    head.iter().all(|b| *b == 0) && words.iter().all(|w| *w == 0) && tail.iter().all(|b| *b == 0)
}

/// 32 hex characters, and nothing else.
pub fn parse_id(text: &str) -> Option<[u8; ID_LEN]> {
    if text.len() != 2 * ID_LEN || !text.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut id = [0u8; ID_LEN];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(id)
}

/// The identity as 32 hex characters.
pub fn id_hex(id: &[u8; ID_LEN]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A reader of the stream in the tests: it walks a list of page records and gives each to
    /// `f` (offset, pages, the bytes of data or None for zeros). Returns the bytes it read.
    pub(crate) fn walk(b: &[u8], mut f: impl FnMut(u64, u64, Option<&[u8]>)) -> usize {
        let mut at = 0;
        loop {
            let offset = u64::from_be_bytes(b[at..at + 8].try_into().unwrap());
            let pages = u64::from(u32::from_be_bytes(b[at + 8..at + 12].try_into().unwrap()));
            let kind = u32::from_be_bytes(b[at + 12..at + 16].try_into().unwrap());
            at += 16;
            if pages == 0 {
                return at;
            }
            if kind == KIND_DATA {
                let len = usize::try_from(pages).unwrap() * PAGE;
                f(offset, pages, Some(&b[at..at + len]));
                at += len;
            } else {
                assert_eq!(kind, KIND_ZERO);
                f(offset, pages, None);
            }
        }
    }

    #[test]
    fn test_bytes() {
        let h = header(&[
            RegionDesc {
                guest_addr: 0,
                size: 0x1000_0000,
                offset: 0,
            },
            RegionDesc {
                guest_addr: 0x1_0000_0000,
                size: 0x2000,
                offset: 0x1000_0000,
            },
        ]);
        assert_eq!(&h[..4], b"SBFH");
        assert_eq!(u32::from_be_bytes(h[4..8].try_into().unwrap()), 2);
        assert_eq!(u32::from_be_bytes(h[8..12].try_into().unwrap()), 2);
        assert_eq!(h.len(), 12 + 48);
        assert_eq!(
            u64::from_be_bytes(h[36..44].try_into().unwrap()),
            0x1_0000_0000
        );

        let f = frame_head(7, true, 100, 200, 300);
        assert_eq!(&f[..4], b"SBCH");
        assert_eq!(u64::from_be_bytes(f[4..12].try_into().unwrap()), 7);
        assert_eq!(u64::from_be_bytes(f[12..20].try_into().unwrap()), 100);
        assert_eq!(u64::from_be_bytes(f[20..28].try_into().unwrap()), 200);
        assert_eq!(u64::from_be_bytes(f[28..36].try_into().unwrap()), 300);
        assert_eq!(&frame_head(0, false, 0, 0, 0)[..4], b"SBCK");

        let id = parse_id("0123456789abcdefFEDCBA9876543210").unwrap();
        assert_eq!(id[0], 0x01);
        assert_eq!(id[15], 0x10);
        assert_eq!(id_hex(&id), "0123456789abcdeffedcba9876543210");
        assert!(parse_id("0123").is_none());
        assert!(parse_id("0123456789abcdef0123456789abcdeg").is_none());
        let c = continue_head(9, Some(&id));
        assert_eq!(&c[..4], b"SBCI");
        assert_eq!(c.len(), 28);
        assert_eq!(&c[12..], &id);
        assert_eq!(
            continue_head(9, None),
            [b"SBCC".as_slice(), &9u64.to_be_bytes()].concat()
        );

        let mut list = Vec::new();
        record_head(&mut list, 0x2000, 1, KIND_DATA);
        list.extend_from_slice(&[5u8; PAGE]);
        record_head(&mut list, 0x8000, 3, KIND_ZERO);
        end_record(&mut list);
        let mut seen = Vec::new();
        assert_eq!(
            walk(&list, |o, p, d| seen.push((o, p, d.map(|d| d[0])))),
            list.len()
        );
        assert_eq!(seen, vec![(0x2000, 1, Some(5)), (0x8000, 3, None)]);

        assert!(page_is_zero(&[0u8; PAGE]));
        let mut page = [0u8; PAGE];
        page[PAGE - 1] = 1;
        assert!(!page_is_zero(&page));
    }

    /// The GPU's part as the tests read it: the structure, or None for "the same"; each blob:
    /// id, Some(bytes) or None for known.
    pub(crate) type GpuRead = (Option<Vec<u8>>, Vec<(u64, Option<Vec<u8>>)>);

    /// A reader of the GPU's part of a frame in the tests, as the receiving place reads it.
    pub(crate) fn read_gpu(b: &[u8]) -> GpuRead {
        let be64 = |at: usize| u64::from_be_bytes(b[at..at + 8].try_into().unwrap());
        let s = usize::try_from(be64(0)).unwrap();
        let skeleton = (s != 0).then(|| b[8..8 + s].to_vec());
        let mut at = 8 + s;
        let n = u32::from_be_bytes(b[at..at + 4].try_into().unwrap());
        at += 4;
        let mut blobs = Vec::new();
        for _ in 0..n {
            let id = be64(at);
            let len = be64(at + 8);
            at += 16;
            if len == BLOB_KNOWN {
                blobs.push((id, None));
            } else {
                let len = usize::try_from(len).unwrap();
                blobs.push((id, Some(b[at..at + len].to_vec())));
                at += len;
            }
        }
        assert_eq!(at, b.len());
        (skeleton, blobs)
    }

    #[test]
    fn test_gpu_section_sends_a_blob_once() {
        let a: Blob = Arc::new(vec![1u8; 10]);
        let b: Blob = Arc::new(vec![2u8; 20]);
        let c: Blob = Arc::new(vec![3u8; 5]);
        let flat = |pieces: Vec<GpuPiece>| -> Vec<u8> {
            pieces.iter().flat_map(|p| p.bytes().to_vec()).collect()
        };
        let mut known = GpuKnown::default();
        // the first frame: the structure and every blob
        let one = flat(gpu_section(
            SideParts {
                skeleton: vec![9; 7],
                blobs: vec![a.clone(), b.clone()],
            },
            &mut known,
        ));
        let (sk, bl) = read_gpu(&one);
        assert_eq!(sk, Some(vec![9; 7]));
        assert_eq!(bl, vec![(1, Some(vec![1; 10])), (2, Some(vec![2; 20]))]);
        // the same structure, one blob kept, one gone, one new, one twice
        let two = flat(gpu_section(
            SideParts {
                skeleton: vec![9; 7],
                blobs: vec![b.clone(), c.clone(), c.clone()],
            },
            &mut known,
        ));
        let (sk, bl) = read_gpu(&two);
        assert_eq!(sk, None);
        assert_eq!(bl, vec![(2, None), (3, Some(vec![3; 5])), (3, None)]);
        // a blob that is gone and comes back as another allocation with the same bytes is new
        let a2: Blob = Arc::new(vec![1u8; 10]);
        let three = flat(gpu_section(
            SideParts {
                skeleton: vec![8; 3],
                blobs: vec![a2, c.clone()],
            },
            &mut known,
        ));
        let (sk, bl) = read_gpu(&three);
        assert_eq!(sk, Some(vec![8; 3]));
        assert_eq!(bl, vec![(4, Some(vec![1; 10])), (3, None)]);
        // a new connection knows nothing
        let mut fresh = GpuKnown::default();
        let four = flat(gpu_section(
            SideParts {
                skeleton: vec![8; 3],
                blobs: vec![c],
            },
            &mut fresh,
        ));
        assert_eq!(read_gpu(&four), (Some(vec![8; 3]), vec![(1, Some(vec![3; 5]))]));
    }
}
