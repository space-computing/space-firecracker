// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The wire format of the remote GPU of the Spacebox QEMU fork ("SPG2",
//! `hw/display/virtio-gpu-remote.c` of `space-qemu`): the message header, the framing of a
//! compressed connection, and the filter for picture data. Both ends are little endian.

use zstd_safe::zstd_sys::ZSTD_EndDirective;
use zstd_safe::{CCtx, CParameter, DCtx, InBuffer, OutBuffer, ResetDirective};

pub(crate) const SP_MAGIC: u32 = 0x3247_5053; // "SPG2"

/// a: request bytes, b: transfer data. arg0 response capacity, arg1/arg2 byte range of the
/// resource backing.
pub(crate) const SP_CTRL: u32 = 1;
/// a: `struct virtio_gpu_update_cursor`.
pub(crate) const SP_CURSOR: u32 = 2;
pub(crate) const SP_RESET: u32 = 3;
/// Either direction. a: bytes for the backing of resource arg0 at offset arg1. To the sink with
/// arg2 = 1: watch the first 16 bytes (a query result) and report when the renderer writes them.
pub(crate) const SP_MEMWRITE: u32 = 4;
/// a: `SpExpect[]`, ranges the next `SP_CTRL` makes the renderer write.
pub(crate) const SP_EXPECT: u32 = 5;
/// a: response bytes, b: read-back data.
pub(crate) const SP_RESP: u32 = 10;
/// a: `SpInput`.
pub(crate) const SP_INPUT: u32 = 11;
/// arg0: virtio-gpu event bits.
pub(crate) const SP_DISPLAY: u32 = 12;
/// The sink's answers to the guest's queries, sent ahead. arg0 = 1: capset arg1, arg2 = max
/// version << 32 | size, a = data. arg0 = 2: a = display info response. arg0 = 3: a = EDID.
pub(crate) const SP_INFO: u32 = 13;
/// To the sink. a: signed 16 bit little endian samples, arg0 rate, arg1 channels. Not resent.
pub(crate) const SP_AUDIO: u32 = 14;
/// Either direction, when the source's `SP_HELLO` has `SP_F_SCROLL`. a: one or more text lines
/// (each ending in `\n`) of the scroll channel: to the source the sink's scroll events and
/// `PING`, to the sink the guest agent's answers (`READY`).
pub(crate) const SP_SCROLL: u32 = 15;
/// To the sink. a: `u32[]` the resources the next `SP_CTRL` may write (on the GPU and by
/// uploads); the sink keeps, for each resource, the id of the last such message.
pub(crate) const SP_WMARK: u32 = 16;
/// To the sink. arg0 = N: drop every context, and every resource but those that existed at
/// message id N and were not written or destroyed after it (0 = keep nothing). Answered by
/// `SP_STATE_KEPT`.
pub(crate) const SP_STATE_RESET: u32 = 17;
/// To the source. arg0 = N as asked; a: `u32[]` the resources kept.
pub(crate) const SP_STATE_KEPT: u32 = 18;
/// To the sink. a: `SpXfer`, b: bytes for that part of a resource (kind 0: the guest's layout,
/// written with context 0; other kinds: what a sink's export made).
pub(crate) const SP_IMPORT: u32 = 19;
/// To the sink. arg0: the request id (not 0; each export has its own). a: `u32[]` resources
/// whose contents the sink sends back, in that order, as `SP_EXPORT_DATA` messages and then
/// one `SP_EXPORT_DONE`, each with the request id in arg2.
pub(crate) const SP_EXPORT: u32 = 22;
/// To the source. arg2: the request id. a: `SpXfer`, b: bytes (passed on to another sink as an
/// `SP_IMPORT`).
pub(crate) const SP_EXPORT_DATA: u32 = 23;
/// To the source. arg0 messages, arg1 bytes of the export, arg2 the request id; a: `u32[]`
/// resources not exported.
pub(crate) const SP_EXPORT_DONE: u32 = 24;
/// To the source: the sink ends on purpose; it goes on until `SP_BYE`.
pub(crate) const SP_DETACH: u32 = 25;
/// To the sink: the source has what it needs from it; the sink ends.
pub(crate) const SP_BYE: u32 = 26;
/// To the sink, the first message of a new pairing when the source's `SP_HELLO` has
/// `SP_F_SPEC`; not resent (a pairing that is lost before the answer starts again). a: the GPU
/// spec, the file as it is ([`super::spec`]). The sink checks that its renderer can do it and
/// answers with `SP_SPEC_REPLY` before it takes anything else; it sends no capsets.
pub(crate) const SP_SPEC: u32 = 27;
/// To the source, not resent. arg0: 1 = the renderer can do the spec, 0 = it cannot (the source
/// closes the connection); a: text, what the renderer cannot do.
pub(crate) const SP_SPEC_REPLY: u32 = 28;
/// To the source, from the user's renderer: the user's toggle. arg0: 1 = the local GPU renders
/// (on), 0 = the renderer inside the guest renders and the sink shows its pictures (off).
pub(crate) const SP_GPU: u32 = 29;
/// To the in-guest renderer. arg0: 1 = send pictures of the scanout (`SP_PICTURE`), 0 = stop.
/// A new pairing starts with none.
pub(crate) const SP_STREAM: u32 = 30;
/// Either direction, not resent: from the in-guest renderer to the source, and from the source
/// to the user's renderer. a: a JPEG of the scanout; arg0, arg1: the scanout's width and height
/// (the JPEG may be smaller); arg2: the renderer's count of its pictures.
pub(crate) const SP_PICTURE: u32 = 31;
/// To the user's renderer: what its toggle has made. arg0: 1 = on (the user's renderer runs the
/// guest), 0 = off (the in-guest renderer runs it and its pictures come); arg1: 1 = the source
/// could not turn it off (no in-guest renderer that can take the guest now).
pub(crate) const SP_GPU_STATE: u32 = 32;
/// First message on every connection. arg0 own session, arg1 the peer session it was paired
/// with (0 = none), arg2 highest id received from that peer.
pub(crate) const SP_HELLO: u32 = 20;
/// Nothing but the ack field.
pub(crate) const SP_ACK: u32 = 21;

/// Source: the guest is decoding video.
pub(crate) const SP_F_VIDEO: u64 = 1;
/// In `SP_HELLO`: this end can compress the connection.
pub(crate) const SP_F_ZSTD: u64 = 2;
/// In the source's `SP_HELLO`: the scroll channel goes in the stream (`SP_SCROLL`), not on the
/// sink's scroll socket.
pub(crate) const SP_F_SCROLL: u64 = 4;
/// In the source's `SP_HELLO`: the source was restored from a snapshot and has not been paired
/// since; `seq` is the last id it gave out before the snapshot. A sink that has more of its
/// messages ran on after the snapshot: it goes back to `seq` (it drops what it queued for the
/// source and takes `arg2` as the last id it gave out), and the source then resets it to
/// `seq` with `SP_STATE_RESET`.
pub(crate) const SP_F_RESTORED: u64 = 8;
/// In the source's `SP_HELLO`: the source holds the guest's GPU spec and sends it (`SP_SPEC`)
/// at a new pairing; the sink sends no capsets.
pub(crate) const SP_F_SPEC: u64 = 16;

/// Size of the header on the wire (packed).
pub(crate) const HDR_LEN: usize = 80;
/// `struct SpExpect { u32 res; u32 pad; u64 off; u64 len; }`.
#[cfg(test)]
pub(crate) const EXPECT_LEN: usize = 24;

/// In `SpZHdr::clen`: an `SpZFilter` follows the header.
const SP_Z_FILTERED: u32 = 0x8000_0000;
const SP_Z_MAX: usize = 1 << 30;
/// `struct SpZHdr { u32 clen; u32 rlen; }`.
const ZHDR_LEN: usize = 8;
/// `struct SpZFilter { u32 off; u32 bpp; u32 stride; }`.
const ZFILTER_LEN: usize = 12;

pub(crate) fn u32_at(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4)
        .map_or(0, |s| u32::from_le_bytes(s.try_into().unwrap()))
}

pub(crate) fn u64_at(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8)
        .map_or(0, |s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// `struct SpHdr`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Hdr {
    pub typ: u32,
    /// Per direction, 1.. for reliable messages; 0 = not resent.
    pub id: u64,
    /// Highest id received from the peer.
    pub ack: u64,
    pub seq: u64,
    pub a_len: u32,
    pub b_len: u32,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    /// Sender's monotonic clock in microseconds when the message was queued.
    pub t_us: i64,
    pub flags: u64,
}

impl Hdr {
    pub(crate) fn encode(&self) -> [u8; HDR_LEN] {
        let mut h = [0u8; HDR_LEN];
        h[0..4].copy_from_slice(&SP_MAGIC.to_le_bytes());
        h[4..8].copy_from_slice(&self.typ.to_le_bytes());
        h[8..16].copy_from_slice(&self.id.to_le_bytes());
        h[16..24].copy_from_slice(&self.ack.to_le_bytes());
        h[24..32].copy_from_slice(&self.seq.to_le_bytes());
        h[32..36].copy_from_slice(&self.a_len.to_le_bytes());
        h[36..40].copy_from_slice(&self.b_len.to_le_bytes());
        h[40..48].copy_from_slice(&self.arg0.to_le_bytes());
        h[48..56].copy_from_slice(&self.arg1.to_le_bytes());
        h[56..64].copy_from_slice(&self.arg2.to_le_bytes());
        h[64..72].copy_from_slice(&self.t_us.to_le_bytes());
        h[72..80].copy_from_slice(&self.flags.to_le_bytes());
        h
    }

    /// The header at the start of `h`, if it is one (`h` holds at least [`HDR_LEN`] bytes).
    pub(crate) fn decode(h: &[u8]) -> Option<Self> {
        if h.len() < HDR_LEN || u32_at(h, 0) != SP_MAGIC {
            return None;
        }
        Some(Hdr {
            typ: u32_at(h, 4),
            id: u64_at(h, 8),
            ack: u64_at(h, 16),
            seq: u64_at(h, 24),
            a_len: u32_at(h, 32),
            b_len: u32_at(h, 36),
            arg0: u64_at(h, 40),
            arg1: u64_at(h, 48),
            arg2: u64_at(h, 56),
            t_us: u64_at(h, 64).cast_signed(),
            flags: u64_at(h, 72),
        })
    }

    /// Bytes of the whole message: header, a and b.
    pub(crate) fn total(&self) -> usize {
        HDR_LEN + self.a_len as usize + self.b_len as usize
    }
}

/// Append one `SpExpect`.
pub(crate) fn push_expect(v: &mut Vec<u8>, res: u32, off: u64, len: u64) {
    v.extend_from_slice(&res.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&off.to_le_bytes());
    v.extend_from_slice(&len.to_le_bytes());
}

/// The layout of picture data in a message, for [`filter`]: the message from byte `off` to its
/// end is pixels of `bpp` bytes in rows of `stride` bytes (0 = one row).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Filter {
    pub off: u32,
    pub bpp: u32,
    pub stride: u32,
}

/// Picture data compresses poorly as it is. Each byte is replaced by its difference from a
/// prediction made of the pixel to the left, the pixel above and the pixel above left (left +
/// above - above left, per byte, wrapping). The same arithmetic as `sp_z_filter` of the QEMU
/// fork: e\[i\] = s\[i\] - s\[i - stride\], then d\[i\] = e\[i\] - e\[i - bpp\]; a term whose index is
/// negative is 0; stride 0 leaves out the first step.
pub(crate) fn filter(s: &[u8], d: &mut [u8], bpp: usize, stride: usize) {
    let n = s.len().min(d.len());
    let mut i = 0;
    while i < n && i < stride + bpp {
        let e = s[i].wrapping_sub(if stride != 0 && i >= stride {
            s[i - stride]
        } else {
            0
        });
        let el = if i < bpp {
            0
        } else {
            s[i - bpp].wrapping_sub(if stride != 0 && i >= stride + bpp {
                s[i - bpp - stride]
            } else {
                0
            })
        };
        d[i] = e.wrapping_sub(el);
        i += 1;
    }
    if stride != 0 {
        while i < n {
            d[i] = s[i]
                .wrapping_sub(s[i - stride])
                .wrapping_sub(s[i - bpp])
                .wrapping_add(s[i - bpp - stride]);
            i += 1;
        }
    } else {
        while i < n {
            d[i] = s[i].wrapping_sub(s[i - bpp]);
            i += 1;
        }
    }
}

/// Undo [`filter`] in place (`sp_z_unfilter`).
pub(crate) fn unfilter(d: &mut [u8], bpp: usize, stride: usize) {
    for i in bpp..d.len() {
        d[i] = d[i].wrapping_add(d[i - bpp]);
    }
    if stride != 0 {
        for i in stride..d.len() {
            d[i] = d[i].wrapping_add(d[i - stride]);
        }
    }
}

/// The writer's side of a compressed connection: one zstd stream for the life of the
/// connection, flushed after every message (`sp_z_pack`).
pub(crate) struct ZPacker {
    cctx: CCtx<'static>,
    out: Vec<u8>,
    tmp: Vec<u8>,
}

impl std::fmt::Debug for ZPacker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZPacker").finish_non_exhaustive()
    }
}

impl ZPacker {
    pub(crate) fn new() -> Self {
        ZPacker {
            cctx: CCtx::create(),
            out: Vec::new(),
            tmp: Vec::new(),
        }
    }

    /// Start a new stream (a new connection) at `level`.
    pub(crate) fn restart(&mut self, level: i32) {
        let _ = self.cctx.reset(ResetDirective::SessionOnly);
        let _ = self.cctx.set_parameter(CParameter::CompressionLevel(level));
    }

    /// `msg` as `SpZHdr [SpZFilter] data`; None on failure (the connection must start again).
    pub(crate) fn pack(&mut self, msg: &[u8], f: Option<Filter>) -> Option<&[u8]> {
        let f =
            f.filter(|f| f.bpp != 0 && f.off as usize >= HDR_LEN && (f.off as usize) < msg.len());
        let hl = ZHDR_LEN + if f.is_some() { ZFILTER_LEN } else { 0 };
        let need = hl + msg.len() + (msg.len() >> 7) + 1024;
        if msg.len() >= SP_Z_MAX {
            return None;
        }
        if self.out.len() < need {
            self.out.resize(need, 0);
        }
        let (head, body) = self.out.split_at_mut(hl);
        let mut o = OutBuffer::around(body);
        let last: &[u8] = if let Some(f) = f {
            let off = f.off as usize;
            let n = msg.len() - off;
            if self.tmp.len() < n {
                self.tmp.resize(n, 0);
            }
            filter(
                &msg[off..],
                &mut self.tmp[..n],
                f.bpp as usize,
                f.stride as usize,
            );
            head[ZHDR_LEN..ZHDR_LEN + 4].copy_from_slice(&f.off.to_le_bytes());
            head[ZHDR_LEN + 4..ZHDR_LEN + 8].copy_from_slice(&f.bpp.to_le_bytes());
            head[ZHDR_LEN + 8..ZHDR_LEN + 12].copy_from_slice(&f.stride.to_le_bytes());
            let mut i = InBuffer::around(&msg[..off]);
            while i.pos < i.src.len() {
                let r =
                    self.cctx
                        .compress_stream2(&mut o, &mut i, ZSTD_EndDirective::ZSTD_e_continue);
                if r.is_err() || o.pos() == o.capacity() {
                    return None;
                }
            }
            &self.tmp[..n]
        } else {
            msg
        };
        let mut i = InBuffer::around(last);
        loop {
            match self
                .cctx
                .compress_stream2(&mut o, &mut i, ZSTD_EndDirective::ZSTD_e_flush)
            {
                Err(_) => return None,
                Ok(0) => break,
                Ok(_) if o.pos() == o.capacity() => return None,
                Ok(_) => {}
            }
        }
        let clen = u32::try_from(o.pos()).ok()? | if f.is_some() { SP_Z_FILTERED } else { 0 };
        let total = hl + o.pos();
        head[0..4].copy_from_slice(&clen.to_le_bytes());
        head[4..8].copy_from_slice(&u32::try_from(msg.len()).ok()?.to_le_bytes());
        Some(&self.out[..total])
    }
}

/// The reader's side of a compressed connection (`sp_z_unpack`).
pub(crate) struct ZUnpacker {
    dctx: DCtx<'static>,
}

impl std::fmt::Debug for ZUnpacker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZUnpacker").finish_non_exhaustive()
    }
}

impl ZUnpacker {
    pub(crate) fn new() -> Self {
        ZUnpacker {
            dctx: DCtx::create(),
        }
    }

    /// Start a new stream (a new connection).
    pub(crate) fn restart(&mut self) {
        let _ = self.dctx.reset(ResetDirective::SessionOnly);
    }

    /// Move the complete frames at the start of `rxw` into `rx` as plain messages. Ok(true) =
    /// moved something, Ok(false) = nothing complete yet, Err = bad data.
    pub(crate) fn unpack(&mut self, rxw: &mut Vec<u8>, rx: &mut Vec<u8>) -> Result<bool, ()> {
        let mut off = 0usize;
        while rxw.len() - off >= ZHDR_LEN {
            let zclen = u32_at(rxw, off);
            let rlen = u32_at(rxw, off + 4) as usize;
            let clen = (zclen & !SP_Z_FILTERED) as usize;
            let filtered = zclen & SP_Z_FILTERED != 0;
            let hl = ZHDR_LEN + if filtered { ZFILTER_LEN } else { 0 };
            if !(HDR_LEN..SP_Z_MAX).contains(&rlen) || clen > rlen + (rlen >> 7) + 1024 {
                return Err(());
            }
            if rxw.len() - off < hl + clen {
                break;
            }
            let mut zf = None;
            if filtered {
                let f = Filter {
                    off: u32_at(rxw, off + ZHDR_LEN),
                    bpp: u32_at(rxw, off + ZHDR_LEN + 4),
                    stride: u32_at(rxw, off + ZHDR_LEN + 8),
                };
                if (f.off as usize) < HDR_LEN || f.off as usize >= rlen || f.bpp == 0 || f.bpp > 64
                {
                    return Err(());
                }
                zf = Some(f);
            }
            let at = rx.len();
            rx.resize(at + rlen, 0);
            {
                let mut i = InBuffer::around(&rxw[off + hl..off + hl + clen]);
                let mut o = OutBuffer::around(&mut rx[at..]);
                while i.pos < i.src.len() || o.pos() < o.capacity() {
                    let before = i.pos + o.pos();
                    let r = self.dctx.decompress_stream(&mut o, &mut i);
                    if r.is_err() || i.pos + o.pos() == before {
                        rx.truncate(at);
                        return Err(());
                    }
                }
            }
            if let Some(f) = zf {
                unfilter(
                    &mut rx[at + f.off as usize..at + rlen],
                    f.bpp as usize,
                    f.stride as usize,
                );
            }
            off += hl + clen;
        }
        if off != 0 {
            rxw.drain(..off);
        }
        Ok(off != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // The input of the vectors: `gen()` of screen/tools/zstd-vectors.c in the track's worktree.
    #[allow(clippy::cast_possible_truncation)]
    fn r#gen(i: usize, k: usize) -> u8 {
        (i * 7 + i * i * 13 + 5 + k * 31 + (i / 9) * (i % 5)) as u8
    }

    #[test]
    fn header_roundtrip() {
        let h = Hdr {
            typ: SP_CTRL,
            id: 7,
            ack: 3,
            seq: 9,
            a_len: 24,
            b_len: 100,
            arg0: 1,
            arg1: 2,
            arg2: 3,
            t_us: -42,
            flags: SP_F_VIDEO,
        };
        let e = h.encode();
        assert_eq!(e.len(), HDR_LEN);
        assert_eq!(&e[0..4], b"SPG2");
        assert_eq!(Hdr::decode(&e), Some(h));
        assert_eq!(h.total(), 80 + 24 + 100);
        let mut bad = e;
        bad[0] = 0;
        assert_eq!(Hdr::decode(&bad), None);
        assert_eq!(Hdr::decode(&e[..79]), None);
    }

    #[test]
    fn header_layout() {
        // The offsets of the packed C struct.
        let h = Hdr {
            typ: 0x0102_0304,
            id: 0x1111,
            ack: 0x2222,
            seq: 0x3333,
            a_len: 0x44,
            b_len: 0x55,
            arg0: 0x66,
            arg1: 0x77,
            arg2: 0x88,
            t_us: 0x99,
            flags: 0xaa,
        }
        .encode();
        for (off, v) in [
            (4, 0x0102_0304u64),
            (8, 0x1111),
            (16, 0x2222),
            (24, 0x3333),
            (40, 0x66),
            (48, 0x77),
            (56, 0x88),
            (64, 0x99),
            (72, 0xaa),
        ] {
            if off == 4 {
                assert_eq!(u64::from(u32_at(&h, off)), v);
            } else {
                assert_eq!(u64_at(&h, off), v, "offset {off}");
            }
        }
        assert_eq!(u32_at(&h, 32), 0x44);
        assert_eq!(u32_at(&h, 36), 0x55);
    }

    #[test]
    fn expect_layout() {
        let mut v = Vec::new();
        push_expect(&mut v, 7, 8, 9);
        assert_eq!(v.len(), EXPECT_LEN);
        assert_eq!(u32_at(&v, 0), 7);
        assert_eq!(u32_at(&v, 4), 0);
        assert_eq!(u64_at(&v, 8), 8);
        assert_eq!(u64_at(&v, 16), 9);
    }

    // Outputs of the C code of the QEMU fork (sp_z_filter), from screen/tools/zstd-vectors.c.
    const FILTER_VECTORS: [(usize, usize, &str); 6] = [
        (
            4,
            16,
            "0519478fec54bc248cf85cc52e930063c61a577d7f807e7e887a7e7f7f8d7a7e7e7e8a757f7f8292747e7e7c8f707f8182976f7e7d7c986b80817e9c6a7e7d7f",
        ),
        (
            4,
            0,
            "243866aeec54bc248cf85cc52e930063cb339e0c6bd43aa21472da44ad207ae149b12881ea53bc3488f058c03c90f962cb4897ff67cf549f0871d65ca60e76e1",
        ),
        (
            3,
            12,
            "4357858ad82674c21062acfb034262a6a6a6aeafa6a0a4adb0a1a1a8b3b49c9ba4b5b59c9da8b8b69796a6baba9798a8bcbb9292a6bfc39293a4c1c08d8da6c7",
        ),
        (
            1,
            0,
            "62142e48627c96b0cae8fa19334d677c9bb5d2eafa1e38526c7ca0bcd5effa233d57717ca6c0daf4fa28425c767cabc5dff9fa2d47617f78b0cae4fefa324c69",
        ),
        (
            2,
            6,
            "81954276aade91b1383c38353a3a3a31353d3b3c30353f3a372c38443b3a2b354438372939493a3a263548383824394e3a3a21354d383c1f35533a3a1835563b",
        ),
        (
            8,
            32,
            "a0b4e22a8c089e4e784c18e9ba8b5c28f9c69e6f3607d8ae7f4614e6c1925425561dc038a7fc4667faf7fc0b0af5f5fa0e12f2f2fc1013f0f0fa1615ededf818",
        ),
    ];

    #[test]
    fn filter_matches_the_c_code() {
        for (k, (bpp, stride, want)) in FILTER_VECTORS.iter().enumerate() {
            let s: Vec<u8> = (0..64).map(|i| r#gen(i, k)).collect();
            let mut d = vec![0u8; 64];
            filter(&s, &mut d, *bpp, *stride);
            assert_eq!(d, unhex(want), "bpp {bpp} stride {stride}");
            unfilter(&mut d, *bpp, *stride);
            assert_eq!(d, s, "round trip bpp {bpp} stride {stride}");
        }
    }

    #[test]
    fn filter_round_trip_odd_sizes() {
        for (n, bpp, stride) in [
            (0, 4, 16),
            (3, 4, 16),
            (17, 4, 16),
            (1000, 3, 30),
            (999, 64, 0),
        ] {
            let s: Vec<u8> = (0..n).map(|i| r#gen(i, 1)).collect();
            let mut d = vec![0u8; n];
            filter(&s, &mut d, bpp, stride);
            unfilter(&mut d, bpp, stride);
            assert_eq!(d, s);
        }
    }

    // Two messages packed one after the other in one stream by the C code (zstd 1.5.7, level
    // 1), the second filtered (off 80, bpp 4, stride 64).
    const PACK1: &str = "8f000000c800000028b52ffd0048340400828c200a1098f6009a5d5a009411e70aca75e472cde9286b4b991b325a2f24d0d22ac6f6033c95077e1fdc65da3e71d44fdaa005bb14b2d7fc761492820a51d81ef19723024c2afad0e598b70e6a72c409732411bcd655b546c44910139a59d47563d83a17dca3d8e30bb7f3ce9c64ce6d4e386d5095936accb333563bee68ced641cd6f0f00";
    const PACK2: &str = "08020080500200005000000004000000400000002c10000665804080d8ca72c22324c9bdc034cc8a80fa2f8da5cef321b4f80fa1c59bc6d103cb835ecdd1ae1582727a3666b970325eedd56ff7226f5b156a41bbb2bec223d0fe189700610063002f4254c538c6e1d4505b7c9be143436ccb1203ec70edbb2cc2b42929a406cf20e99202c31ce58400bd18e17afaae12dd6cf6a20ed95af09a0ad5caa268102d32f22f6ead8c6ccc4205b130300a13bebcba2444e0dad2829085756555f5806a4a2aca01d493535303a625250649484746450b888684142408024270c0c08f4f01023d3c3b3a3903706e6c6a04d0ccc8c4048001f0e2d2127bc0b15937c0e5b7e948b61c04ff351e6d37f8f8d506dbd380fc792148959f09d9ac99e1f2c98624db31c43fac485bb0237f9762fbd6e29f5a8c557e9564b3568dcb9f5a926ca51eff27276d9d207fa528ed4752fe34aa52e54356362bd4e5031d69ed8318fefc91a1ca7b68d8ace0daf277b025db40b71fb043db1c1f7e1b6fed7e707ff6c555f9de88cdeacd2d7f0689642ba3eecfa36b8b87e26f61d76eb7e24f152eaafcc4dd66ebf2966f0246b22da1f7cfd1682bc7f78bf06b7ffbfb13c48d2a03af03d33687e6afb96997c1f93366a7ca5f7836ebe2b37c2c3fc9f68ad0dfa0b627d14fe5a83d0ad29f5096aafc09d3661f9f96df042ad932b1fa1ba9da2ac1fa916cb52b72fd99e855e546be368b18b6fc43b1644bc4ec372c6b5b88f6130600";

    fn msg1() -> Vec<u8> {
        (0..200).map(|i| r#gen(i, 9) & 0x1f).collect()
    }

    #[allow(clippy::cast_possible_truncation)]
    fn msg2() -> Vec<u8> {
        (0..80 + 512)
            .map(|i| if i < 80 { i as u8 } else { r#gen(i - 80, 3) })
            .collect()
    }

    #[test]
    fn unpack_reads_the_c_codes_stream() {
        let mut z = ZUnpacker::new();
        let mut rxw = unhex(PACK1);
        rxw.extend_from_slice(&unhex(PACK2));
        // Arrives in pieces: nothing until a frame is complete.
        let whole = std::mem::take(&mut rxw);
        let mut rx = Vec::new();
        rxw.extend_from_slice(&whole[..20]);
        assert_eq!(z.unpack(&mut rxw, &mut rx), Ok(false));
        rxw.extend_from_slice(&whole[20..]);
        assert_eq!(z.unpack(&mut rxw, &mut rx), Ok(true));
        assert!(rxw.is_empty());
        let mut want = msg1();
        want.extend_from_slice(&msg2());
        assert_eq!(rx, want);
    }

    #[test]
    fn pack_round_trip_and_c_size() {
        let mut p = ZPacker::new();
        p.restart(1);
        let a = p.pack(&msg1(), None).unwrap().to_vec();
        let f = Filter {
            off: 80,
            bpp: 4,
            stride: 64,
        };
        let b = p.pack(&msg2(), Some(f)).unwrap().to_vec();
        // The same library and level give the same bytes as the C code.
        assert_eq!(a, unhex(PACK1));
        assert_eq!(b, unhex(PACK2));
        let mut z = ZUnpacker::new();
        let mut rxw = a;
        rxw.extend_from_slice(&b);
        let mut rx = Vec::new();
        assert_eq!(z.unpack(&mut rxw, &mut rx), Ok(true));
        assert_eq!(rx.len(), 200 + 592);
        // A new connection: both sides start new streams.
        p.restart(1);
        z.restart();
        let c = p.pack(&msg1(), None).unwrap().to_vec();
        assert_eq!(c, unhex(PACK1));
        let mut rxw = c;
        let mut rx = Vec::new();
        assert_eq!(z.unpack(&mut rxw, &mut rx), Ok(true));
        assert_eq!(rx, msg1());
    }

    #[test]
    fn pack_ignores_a_filter_outside_the_message() {
        let mut p = ZPacker::new();
        p.restart(1);
        let m = msg1();
        for f in [
            Filter {
                off: 10,
                bpp: 4,
                stride: 0,
            },
            Filter {
                off: 200,
                bpp: 4,
                stride: 0,
            },
            Filter {
                off: 100,
                bpp: 0,
                stride: 0,
            },
        ] {
            let out = p.pack(&m, Some(f)).unwrap();
            assert_eq!(u32_at(out, 0) & SP_Z_FILTERED, 0);
        }
    }

    #[test]
    fn unpack_refuses_bad_frames() {
        let mut z = ZUnpacker::new();
        // rlen below a header.
        let mut rxw = vec![1, 0, 0, 0, 10, 0, 0, 0, 0];
        assert_eq!(z.unpack(&mut rxw, &mut Vec::new()), Err(()));
        // clen too large for rlen.
        let mut rxw = Vec::new();
        rxw.extend_from_slice(&5000u32.to_le_bytes());
        rxw.extend_from_slice(&100u32.to_le_bytes());
        assert_eq!(z.unpack(&mut rxw, &mut Vec::new()), Err(()));
        // A filter with bpp 0.
        let mut rxw = Vec::new();
        rxw.extend_from_slice(&(4 | SP_Z_FILTERED).to_le_bytes());
        rxw.extend_from_slice(&100u32.to_le_bytes());
        rxw.extend_from_slice(&[80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4]);
        assert_eq!(z.unpack(&mut rxw, &mut Vec::new()), Err(()));
        // Not zstd data.
        let mut rxw = Vec::new();
        rxw.extend_from_slice(&4u32.to_le_bytes());
        rxw.extend_from_slice(&100u32.to_le_bytes());
        rxw.extend_from_slice(&[1, 2, 3, 4]);
        let mut rx = Vec::new();
        assert_eq!(z.unpack(&mut rxw, &mut rx), Err(()));
        assert!(rx.is_empty());
    }
}
