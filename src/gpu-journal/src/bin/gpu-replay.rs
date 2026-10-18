// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The replay test of the journal and of the rebuild (the plan's K3 and K4).
//!
//! It plays a recorded stream (the device's `dump_path`: every message written to the renderer)
//! into renderers (sinks, usually CPU renderers), as the device does, and feeds the same
//! commands into a [`Journal`]. At each cut it continues in a fresh renderer, in two ways:
//!
//! - **export and import** (a planned switch): the fresh renderer gets the journal's rebuild and
//!   the old renderer's export of what the GPU wrote; then the rest of the stream. At the end
//!   every resource must hold the same bytes as in the run with no cut, with exactly two
//!   differences allowed (the user's choices of 2026-10-17): in a multisampled snorm resource
//!   the lowest value on one side and the lowest + 1 on the other (a renderer without
//!   `glCopyImageSubData` carries snorm through floats), and in a Z32_UNORM resource 32-bit depth
//!   values that differ by at most [`Z32_ROUNDING`] (kept through a float). Each resource that
//!   differs only so is listed with the largest difference.
//! - **rebuild alone** (a sudden loss): the fresh renderer gets the journal's rebuild only. The
//!   resources whose content came only from uploads must hold the same bytes as in the old
//!   renderer; then, so that what the GPU wrote (lost here by design) does not decide the
//!   result, both renderers clear what the GPU wrote, play the same next frames, and must then
//!   hold the same bytes everywhere: a probe of every object and of the bound state.
//!
//! usage: gpu-replay --dump FILE --a SOCK --b SOCK --c SOCK --out DIR [--cuts N]
//!        [--flushes N] [--inject-destroy-bound [--inject-at PERCENT]] [--limit N] [--until-s S]
//! (`--until-s`: the stream up to S seconds after its first message; `--limit`: its first N
//! messages; without either a stream that ends with the guest's shutdown is cut before it.)

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use gpu_journal::{
    CMD_CTX_ATTACH_RESOURCE, CMD_CTX_CREATE, CMD_CTX_DESTROY, CMD_CTX_DETACH_RESOURCE,
    CMD_RESOURCE_FLUSH, CMD_SUBMIT_3D, Journal, Msg, XFER_LEN, xfer,
};

const MAGIC: u32 = 0x3247_5053;
const HDR_LEN: usize = 80;
const SP_CTRL: u32 = 1;
const SP_CURSOR: u32 = 2;
const SP_RESET: u32 = 3;
const SP_MEMWRITE: u32 = 4;
const SP_EXPECT: u32 = 5;
const SP_WMARK: u32 = 16;
const SP_STATE_RESET: u32 = 17;
const SP_STATE_KEPT: u32 = 18;
const SP_IMPORT: u32 = 19;
const SP_HELLO: u32 = 20;
const SP_ACK: u32 = 21;
const SP_EXPORT: u32 = 22;
const SP_EXPORT_DATA: u32 = 23;
const SP_EXPORT_DONE: u32 = 24;
/// The context the tool uses for its own commands (the guest's ids are small).
const TOOL_CTX: u32 = 60;

fn u32_at(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4)
        .map_or(0, |s| u32::from_le_bytes(s.try_into().unwrap()))
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8)
        .map_or(0, |s| u64::from_le_bytes(s.try_into().unwrap()))
}

fn words(b: &[u8]) -> Vec<u32> {
    b.chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

fn bytes(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// A message of the stream (the fields the replay keeps).
#[derive(Debug, Clone)]
struct M {
    typ: u32,
    /// When the device queued it (its monotonic clock, µs).
    t_us: i64,
    args: [u64; 3],
    a: Vec<u8>,
    b: Vec<u8>,
}

/// The device's messages of a dump, each once (a dump has what was sent again after a resume
/// twice), without what does not make the renderer's state (sound, scroll, acknowledgements),
/// up to the first switch.
fn read_dump(path: &str) -> std::io::Result<Vec<M>> {
    let mut d = Vec::new();
    File::open(path)?.read_to_end(&mut d)?;
    let mut out = Vec::new();
    let (mut off, mut last) = (0usize, 0u64);
    while off + HDR_LEN <= d.len() {
        let h = &d[off..off + HDR_LEN];
        if u32_at(h, 0) != MAGIC {
            eprintln!("bad magic at {off}");
            break;
        }
        let (a_len, b_len) = (u32_at(h, 32) as usize, u32_at(h, 36) as usize);
        let end = off + HDR_LEN + a_len + b_len;
        if end > d.len() {
            break;
        }
        let id = u64_at(h, 8);
        let typ = u32_at(h, 4);
        if matches!(typ, SP_STATE_RESET | SP_IMPORT | SP_EXPORT) {
            // a switch began: what follows is not one renderer's stream any more
            eprintln!("the stream ends at a switch (message {})", out.len());
            break;
        }
        let fresh = if id == 0 {
            true
        } else if id == last + 1 || (id == 1 && last != 0) {
            last = id;
            true
        } else {
            false // sent again after a resume
        };
        if fresh
            && matches!(
                typ,
                SP_CTRL | SP_CURSOR | SP_RESET | SP_MEMWRITE | SP_EXPECT | SP_WMARK
            )
        {
            out.push(M {
                typ,
                t_us: i64::from_le_bytes(h[64..72].try_into().unwrap()),
                args: [u64_at(h, 40), u64_at(h, 48), u64_at(h, 56)],
                a: d[off + HDR_LEN..off + HDR_LEN + a_len].to_vec(),
                b: d[off + HDR_LEN + a_len..end].to_vec(),
            });
        }
        off = end;
    }
    Ok(out)
}

/// One piece of an export: its `SpXfer` and its bytes.
type Piece = ([u8; XFER_LEN], Vec<u8>);

/// What a renderer sends back that the replay waits for (an export's replies with their
/// request id).
enum Ev {
    Kept(Vec<u32>),
    Data(u64, Piece),
    Done(u64, Vec<u32>),
}

/// A connection to a renderer, as a source that does not compress.
struct Sink {
    s: UnixStream,
    id: u64,
    rx_id: Arc<AtomicU64>,
    ev: mpsc::Receiver<Ev>,
    sent: u64,
}

fn hdr(typ: u32, id: u64, ack: u64, a: usize, b: usize, args: [u64; 3]) -> [u8; HDR_LEN] {
    let mut h = [0u8; HDR_LEN];
    h[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    h[4..8].copy_from_slice(&typ.to_le_bytes());
    h[8..16].copy_from_slice(&id.to_le_bytes());
    h[16..24].copy_from_slice(&ack.to_le_bytes());
    h[32..36].copy_from_slice(&u32::try_from(a).unwrap().to_le_bytes());
    h[36..40].copy_from_slice(&u32::try_from(b).unwrap().to_le_bytes());
    h[40..48].copy_from_slice(&args[0].to_le_bytes());
    h[48..56].copy_from_slice(&args[1].to_le_bytes());
    h[56..64].copy_from_slice(&args[2].to_le_bytes());
    h
}

fn reader(mut s: UnixStream, rx_id: &AtomicU64, out: &mpsc::Sender<Ev>) {
    let mut h = [0u8; HDR_LEN];
    if s.read_exact(&mut h).is_err() {
        return; // the renderer's HELLO
    }
    loop {
        if s.read_exact(&mut h).is_err() || u32_at(&h, 0) != MAGIC {
            return;
        }
        let (a_len, b_len) = (u32_at(&h, 32) as usize, u32_at(&h, 36) as usize);
        let mut a = vec![0u8; a_len];
        let mut b = vec![0u8; b_len];
        if s.read_exact(&mut a).is_err() || s.read_exact(&mut b).is_err() {
            return;
        }
        let id = u64_at(&h, 8);
        if id != 0 {
            rx_id.fetch_max(id, Ordering::Relaxed);
        }
        let e = match u32_at(&h, 4) {
            SP_STATE_KEPT => Ev::Kept(words(&a)),
            SP_EXPORT_DATA if a.len() >= XFER_LEN => {
                Ev::Data(u64_at(&h, 56), (a[..XFER_LEN].try_into().unwrap(), b))
            }
            SP_EXPORT_DONE => Ev::Done(u64_at(&h, 56), words(&a)),
            _ => continue,
        };
        if out.send(e).is_err() {
            return;
        }
    }
}

impl Sink {
    fn connect(path: &str) -> std::io::Result<Sink> {
        let mut s = UnixStream::connect(path)?;
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let session =
            (u64::from(std::process::id()) << 32) ^ u64::from(t.subsec_nanos()) ^ t.as_secs() | 1;
        s.write_all(&hdr(SP_HELLO, 0, 0, 0, 0, [session, 0, 0]))?;
        let (tx, ev) = mpsc::channel();
        let rx_id = Arc::new(AtomicU64::new(0));
        let (r, id2) = (s.try_clone()?, rx_id.clone());
        std::thread::spawn(move || reader(r, &id2, &tx));
        Ok(Sink {
            s,
            id: 0,
            rx_id,
            ev,
            sent: 0,
        })
    }

    fn send(&mut self, typ: u32, a: &[u8], b: &[u8], args: [u64; 3]) {
        self.id += 1;
        let ack = self.rx_id.load(Ordering::Relaxed);
        let h = hdr(typ, self.id, ack, a.len(), b.len(), args);
        let mut m = Vec::with_capacity(HDR_LEN + a.len() + b.len());
        m.extend_from_slice(&h);
        m.extend_from_slice(a);
        m.extend_from_slice(b);
        self.s
            .write_all(&m)
            .expect("the renderer closed the connection");
        self.sent += 1;
        if self.sent.is_multiple_of(512) {
            let h = hdr(SP_ACK, 0, self.rx_id.load(Ordering::Relaxed), 0, 0, [0; 3]);
            let _ = self.s.write_all(&h);
        }
    }

    fn ctrl(&mut self, req: &[u8]) {
        self.send(SP_CTRL, req, &[], [0; 3]);
    }

    fn wait(&mut self) -> Ev {
        self.ev
            .recv_timeout(Duration::from_secs(600))
            .expect("no answer from the renderer in 600 s")
    }

    /// `SP_STATE_RESET` 0, as the device sends it before a rebuild.
    fn reset(&mut self) -> Vec<u32> {
        self.send(SP_STATE_RESET, &[], &[], [0; 3]);
        loop {
            if let Ev::Kept(k) = self.wait() {
                return k;
            }
        }
    }

    /// The contents of `ids`, in pieces, and the ids it did not export. The request id is the
    /// id of the `SP_EXPORT` message; every reply must carry it.
    fn export(&mut self, ids: &[u32]) -> (Vec<(u32, Piece)>, Vec<u32>) {
        self.send(SP_EXPORT, &bytes(ids), &[], [self.id + 1, 0, 0]);
        let req = self.id;
        let mut v = Vec::new();
        loop {
            match self.wait() {
                Ev::Data(r, p) => {
                    assert_eq!(r, req, "a reply of another export");
                    v.push((u32_at(&p.0, 0), p));
                }
                Ev::Done(r, missing) => {
                    assert_eq!(r, req, "a reply of another export");
                    return (v, missing);
                }
                Ev::Kept(_) => {}
            }
        }
    }

    /// The journal's rebuild of everything but `kept`.
    fn rebuild(&mut self, j: &Journal, kept: &BTreeSet<u32>) -> (u64, u64) {
        let (mut n, mut size) = (0u64, 0u64);
        j.rebuild(kept, &mut |m| {
            n += 1;
            match m {
                Msg::Ctrl(r) => {
                    size += r.len() as u64;
                    self.ctrl(&r);
                }
                Msg::Import(h, d) => {
                    size += d.len() as u64;
                    self.send(SP_IMPORT, &h, d, [0; 3]);
                }
                Msg::Cursor(c) => self.send(SP_CURSOR, c, &[], [0; 3]),
            }
        });
        (n, size)
    }
}

/// The stream as the device would have sent it; the journal follows it.
#[derive(Clone, Default)]
struct Player {
    j: Journal,
    pushes: HashMap<(u32, u64), Vec<u8>>,
    /// (ctx, sub-context) of each context, and the blend state bound in each (ctx, sub):
    /// its handle and its creation's words.
    sub: HashMap<u32, u32>,
    blend: HashMap<(u32, u32), u32>,
    blends: HashMap<(u32, u32, u32), Vec<u32>>,
}

impl Player {
    fn play(&mut self, sink: &mut Sink, m: &M) {
        match m.typ {
            SP_MEMWRITE if m.args[2] == 0 => {
                self.pushes.insert(
                    (u32::try_from(m.args[0]).unwrap_or(0), m.args[1]),
                    m.a.clone(),
                );
            }
            SP_CTRL => {
                let mut p = std::mem::take(&mut self.pushes);
                self.j.ctrl(&m.a, &m.b, &mut |res, off, len| {
                    p.remove(&(res, off)).filter(|d| d.len() as u64 == len)
                });
                if u32_at(&m.a, 0) == CMD_SUBMIT_3D {
                    self.track(&m.a);
                }
            }
            SP_CURSOR => self.j.cursor(&m.a),
            _ => {}
        }
        sink.send(m.typ, &m.a, &m.b, m.args);
    }

    /// Keep the blend states that are bound, for the made case of an object destroyed while
    /// bound.
    fn track(&mut self, req: &[u8]) {
        let ctx = u32_at(req, 16);
        let w = words(&req[32.min(req.len())..]);
        let mut i = 0;
        while i < w.len() {
            let len = (w[i] >> 16) as usize;
            if i + 1 + len > w.len() {
                break;
            }
            let c = &w[i..=i + len];
            let (cmd, obj) = (c[0] & 0xff, (c[0] >> 8) & 0xff);
            let sub = *self.sub.entry(ctx).or_default();
            match (cmd, obj) {
                (28, _) if len >= 1 => {
                    self.sub.insert(ctx, c[1]);
                }
                (1, 1) if len >= 2 => {
                    self.blends.insert((ctx, sub, c[1]), c.to_vec());
                }
                (2, 1) if len >= 1 => {
                    self.blend.insert((ctx, sub), c[1]);
                }
                _ => {}
            }
            i += 1 + len;
        }
    }

    /// The made case: the blend state bound in the last context that drew is destroyed, and
    /// its handle is used at once for another blend state (only red written), which is not
    /// bound. The renderer keeps drawing with the destroyed one until the guest binds the
    /// handle again.
    fn destroy_bound(&mut self, sink: &mut Sink) -> Option<String> {
        let (&(ctx, sub), &h) = self.blend.iter().max_by_key(|(k, _)| (k.0, k.1))?;
        let mut create = self.blends.get(&(ctx, sub, h))?.clone();
        for w in create.iter_mut().skip(4) {
            *w = (*w & !(0xf << 27)) | (1 << 27);
        }
        let mut cmds = vec![(1 << 16) | 28, sub, (1 << 16) | (1 << 8) | 3, h];
        cmds.extend(create);
        let mut r = vec![0u8; 32];
        r[0..4].copy_from_slice(&CMD_SUBMIT_3D.to_le_bytes());
        r[16..20].copy_from_slice(&ctx.to_le_bytes());
        r[24..28].copy_from_slice(&u32::try_from(cmds.len() * 4).unwrap().to_le_bytes());
        r.extend(bytes(&cmds));
        let m = M {
            typ: SP_CTRL,
            t_us: 0,
            args: [0; 3],
            a: r,
            b: Vec::new(),
        };
        self.play(sink, &m);
        Some(format!("ctx {ctx} sub {sub} blend {h}"))
    }
}

/// Clear, in a context of the tool, everything the GPU wrote (render targets and depth-stencil
/// targets at every level, all layers, all samples); buffers are zeroed by an import.
fn clear_gpu_written(sink: &mut Sink, j: &Journal) -> usize {
    let mut cc = vec![0u8; 96];
    cc[0..4].copy_from_slice(&CMD_CTX_CREATE.to_le_bytes());
    cc[16..20].copy_from_slice(&TOOL_CTX.to_le_bytes());
    cc[24..28].copy_from_slice(&6u32.to_le_bytes());
    cc[32..38].copy_from_slice(b"replay");
    sink.ctrl(&cc);
    let ids = j.gpu_written();
    let mut cmds: Vec<u32> = Vec::new();
    let mut handle = 1u32;
    for &id in &ids {
        let Some(a) = j.resource_args(id) else {
            continue;
        };
        let (target, format, bind, width, depth, array, last_level) =
            (a[0], a[1], a[2], a[3], a[5], a[6], a[7]);
        let mut at = vec![0u8; 32];
        at[0..4].copy_from_slice(&CMD_CTX_ATTACH_RESOURCE.to_le_bytes());
        at[16..20].copy_from_slice(&TOOL_CTX.to_le_bytes());
        at[24..28].copy_from_slice(&id.to_le_bytes());
        sink.ctrl(&at);
        if target == 0 {
            let h = xfer(id, 0, 0, 0, 0, 0, [0, 0, 0, width, 1, 1]);
            sink.send(SP_IMPORT, &h, &vec![0u8; width as usize], [0; 3]);
            continue;
        }
        let zs = bind & 1 != 0;
        if !zs && bind & 2 == 0 {
            continue;
        }
        let layers = if target == 3 { depth } else { array.max(1) };
        for level in 0..=last_level {
            let last = if target == 3 {
                (layers >> level).max(1) - 1
            } else {
                layers - 1
            };
            cmds.extend([
                (5 << 16) | (8 << 8) | 1,
                handle,
                id,
                format,
                level,
                last << 16,
            ]);
            if zs {
                cmds.extend([(2 << 16) | 5, 0, handle]);
                // depth 1.0 is not what the guest cleared to; 0 is as good for the probe
                cmds.extend([(8 << 16) | 7, 3, 0, 0, 0, 0, 0, 0, 0]);
            } else {
                cmds.extend([(3 << 16) | 5, 1, 0, handle]);
                cmds.extend([(8 << 16) | 7, 4, 0, 0, 0, 0, 0, 0, 0]);
            }
            cmds.extend([(2 << 16) | 5, 0, 0, (1 << 16) | (8 << 8) | 3, handle]);
            handle += 1;
        }
    }
    let mut r = vec![0u8; 32];
    r[0..4].copy_from_slice(&CMD_SUBMIT_3D.to_le_bytes());
    r[16..20].copy_from_slice(&TOOL_CTX.to_le_bytes());
    r[24..28].copy_from_slice(&u32::try_from(cmds.len() * 4).unwrap().to_le_bytes());
    r.extend(bytes(&cmds));
    sink.ctrl(&r);
    for &id in &ids {
        let mut dt = vec![0u8; 32];
        dt[0..4].copy_from_slice(&CMD_CTX_DETACH_RESOURCE.to_le_bytes());
        dt[16..20].copy_from_slice(&TOOL_CTX.to_le_bytes());
        dt[24..28].copy_from_slice(&id.to_le_bytes());
        sink.ctrl(&dt);
    }
    let mut cd = vec![0u8; 24];
    cd[0..4].copy_from_slice(&CMD_CTX_DESTROY.to_le_bytes());
    cd[16..20].copy_from_slice(&TOOL_CTX.to_le_bytes());
    sink.ctrl(&cd);
    ids.len()
}

/// Per resource: the hash of its pieces (headers and bytes), and the bytes.
fn digest(pieces: &[(u32, Piece)]) -> HashMap<u32, (u64, u64)> {
    let mut m: HashMap<u32, (u64, u64)> = HashMap::new();
    for (id, (h, b)) in pieces {
        let e = m.entry(*id).or_insert((0xcbf2_9ce4_8422_2325, 0));
        for x in h.iter().chain(b.iter()) {
            e.0 = (e.0 ^ u64::from(*x)).wrapping_mul(0x100_0000_01b3);
        }
        e.1 += b.len() as u64;
    }
    m
}

/// The rounding the user accepted on 2026-10-17 for Z32_UNORM (format 17): the value goes
/// through a float (a 24-bit significand), each conversion between a 32-bit value and a float
/// moves it by at most 2^8, and the export way has at most four between the values compared.
const Z32_ROUNDING: u32 = 4 << 8;

/// The bits of each value of a snorm format (virgl_hw.h), or `None`.
fn snorm_bits(format: u32) -> Option<u32> {
    match format {
        74..=77 | 133 | 147..=150 | 229 => Some(8),
        56..=59 | 151..=154 | 235 => Some(16),
        _ => None,
    }
}

/// Whether resource `id` differs between the exports `a` and `b` only as the user allowed:
/// the rule, how many values differ, and the largest difference.
fn allowed_rounding(
    j: &Journal,
    id: u32,
    a: &[(u32, Piece)],
    b: &[(u32, Piece)],
) -> Option<(&'static str, u64, u32)> {
    let args = j.resource_args(id)?;
    let (format, samples) = (args[1], args[8]);
    let pa: Vec<&Piece> = a.iter().filter(|p| p.0 == id).map(|p| &p.1).collect();
    let pb: Vec<&Piece> = b.iter().filter(|p| p.0 == id).map(|p| &p.1).collect();
    if pa.len() != pb.len() {
        return None;
    }
    let (mut n, mut most, mut rule) = (0u64, 0u32, "");
    for ((ha, da), (hb, db)) in pa.into_iter().zip(pb) {
        if ha != hb || da.len() != db.len() {
            return None;
        }
        if da == db {
            continue;
        }
        let kind = u32_at(ha, 4);
        if format == 17 && (kind == 1 || kind == 3) {
            rule = "z32";
            for (x, y) in words(da).into_iter().zip(words(db)) {
                let d = x.abs_diff(y);
                if d > Z32_ROUNDING {
                    return None;
                }
                n += u64::from(d != 0);
                most = most.max(d);
            }
        } else if let (Some(bits), 2, true) = (snorm_bits(format), kind, samples > 1) {
            rule = "snorm-lowest";
            let vals = |d: &[u8]| -> Vec<i32> {
                if bits == 8 {
                    d.iter().map(|&v| i32::from(v.cast_signed())).collect()
                } else {
                    d.chunks_exact(2)
                        .map(|c| i32::from(i16::from_le_bytes([c[0], c[1]])))
                        .collect()
                }
            };
            let lo = -(1i32 << (bits - 1));
            for (x, y) in vals(da).into_iter().zip(vals(db)) {
                if x != y {
                    if x.min(y) != lo || x.max(y) != lo + 1 {
                        return None;
                    }
                    n += 1;
                    most = 1;
                }
            }
        } else {
            return None;
        }
    }
    Some((rule, n, most))
}

/// `VIRGL_BIND_STAGING` and `VIRGL_BIND_CUSTOM`: buffers that live in guest memory only (the
/// device sends their bytes before every command that reads them), not renderer state.
const GUEST_MEMORY_ONLY: u32 = (1 << 19) | (1 << 17);

/// The resources a comparison covers.
fn compared(j: &Journal, ids: Vec<u32>) -> Vec<u32> {
    ids.into_iter()
        .filter(|&id| {
            j.resource_args(id)
                .is_some_and(|a| a[2] & GUEST_MEMORY_ONLY == 0)
        })
        .collect()
}

/// The resources whose pieces differ (or that only one side has).
fn differ(a: &HashMap<u32, (u64, u64)>, b: &HashMap<u32, (u64, u64)>) -> Vec<u32> {
    let mut ids: BTreeSet<u32> = a.keys().copied().collect();
    ids.extend(b.keys());
    ids.into_iter()
        .filter(|id| a.get(id) != b.get(id))
        .collect()
}

/// A picture of a kind-0 export of an 8-bit RGBA-like resource (formats 1, 2, 67, 68), PPM.
fn save_ppm(path: &str, j: &Journal, id: u32, pieces: &[(u32, Piece)]) {
    let Some(a) = j.resource_args(id) else { return };
    let (format, w, h) = (a[1], a[3] as usize, a[4] as usize);
    let mut px = vec![0u8; w * h * 4];
    for (pid, (x, b)) in pieces {
        let (kind, level, bx) = (
            u32_at(x, 4),
            u32_at(x, 8),
            (6..12).map(|k| u32_at(x, k * 4)).collect::<Vec<_>>(),
        );
        if *pid != id || kind != 0 || level != 0 {
            continue;
        }
        let (x0, y0, bw) = (bx[0] as usize, bx[1] as usize, bx[3] as usize);
        for (r, row) in b.chunks(bw * 4).enumerate() {
            let at = ((y0 + r) * w + x0) * 4;
            if at + row.len() <= px.len() {
                px[at..at + row.len()].copy_from_slice(row);
            }
        }
    }
    let bgr = matches!(format, 1 | 2);
    let mut out = format!("P6\n{w} {h}\n255\n").into_bytes();
    for p in px.chunks(4) {
        if bgr {
            out.extend([p[2], p[1], p[0]]);
        } else {
            out.extend([p[0], p[1], p[2]]);
        }
    }
    let _ = std::fs::write(path, out);
}

/// Where a stream that ends with the guest's shutdown (its programs end, their resources go) is
/// cut: after the last flush before the live resources fall below half of their most for the
/// last time.
fn before_teardown(msgs: &[M]) -> usize {
    let mut live = 0i64;
    let mut count = Vec::with_capacity(msgs.len());
    for m in msgs {
        if m.typ == SP_CTRL {
            match u32_at(&m.a, 0) {
                0x0101 | 0x0204 => live += 1,
                0x0102 => live -= 1,
                _ => {}
            }
        }
        count.push(live);
    }
    let most = count.iter().copied().max().unwrap_or(0);
    let fall = count
        .iter()
        .rposition(|&c| c * 2 >= most)
        .map_or(msgs.len(), |i| i + 1);
    (0..fall)
        .rev()
        .find(|&i| msgs[i].typ == SP_CTRL && u32_at(&msgs[i].a, 0) == CMD_RESOURCE_FLUSH)
        .map_or(fall, |i| i + 1)
}

struct Args {
    dump: String,
    a: String,
    b: String,
    c: String,
    out: String,
    cuts: usize,
    flushes: usize,
    inject: bool,
    limit: usize,
    until_s: Option<u64>,
    inject_pct: usize,
}

fn args() -> Args {
    let mut v = std::env::args().skip(1);
    let mut a = Args {
        dump: String::new(),
        a: String::new(),
        b: String::new(),
        c: String::new(),
        out: ".".into(),
        cuts: 8,
        flushes: 3,
        inject: false,
        limit: usize::MAX,
        until_s: None,
        inject_pct: 50,
    };
    while let Some(k) = v.next() {
        match k.as_str() {
            "--inject-destroy-bound" => a.inject = true,
            _ => {
                let val = v.next().unwrap_or_default();
                match k.as_str() {
                    "--dump" => a.dump = val,
                    "--a" => a.a = val,
                    "--b" => a.b = val,
                    "--c" => a.c = val,
                    "--out" => a.out = val,
                    "--cuts" => a.cuts = val.parse().unwrap_or(8),
                    "--flushes" => a.flushes = val.parse().unwrap_or(3),
                    "--limit" => a.limit = val.parse().unwrap_or(usize::MAX),
                    "--until-s" => a.until_s = val.parse().ok(),
                    "--inject-at" => a.inject_pct = val.parse().unwrap_or(50),
                    _ => panic!("unknown argument {k}"),
                }
            }
        }
    }
    a
}

fn main() {
    let a = args();
    let mut msgs = read_dump(&a.dump).expect("cannot read the dump");
    let total = msgs.len();
    msgs.truncate(a.limit);
    if let Some(s) = a.until_s {
        // the stream up to S seconds after its first message, then to the next flush
        let t0 = msgs.first().map_or(0, |m| m.t_us);
        let end = msgs
            .iter()
            .position(|m| m.t_us - t0 > i64::try_from(s).unwrap_or(i64::MAX) * 1_000_000)
            .unwrap_or(msgs.len());
        msgs.truncate(end);
    } else if a.limit == usize::MAX {
        msgs.truncate(before_teardown(&msgs));
    }
    let flushes: Vec<usize> = msgs
        .iter()
        .enumerate()
        .filter(|(_, m)| m.typ == SP_CTRL && u32_at(&m.a, 0) == CMD_RESOURCE_FLUSH)
        .map(|(i, _)| i)
        .collect();
    // Cuts right after a control command (never between its pushes and the command), spread
    // over the stream; the made case goes in at PERCENT (50) of the way.
    let ends: Vec<usize> = msgs
        .iter()
        .enumerate()
        .filter(|(_, m)| m.typ == SP_CTRL)
        .map(|(i, _)| i + 1)
        .collect();
    // the cut at k/n of the commands
    let pick = |k: usize, n: usize| ends[(ends.len() * k / n).min(ends.len() - 1)];
    let inject_at = a.inject.then(|| pick(a.inject_pct, 100));
    let cuts: Vec<usize> = (1..=a.cuts).map(|k| pick(k, a.cuts + 1)).collect();
    println!(
        "{{\"stream\": \"{}\", \"messages\": {}, \"of\": {total}, \"flushes\": {}, \"cuts\": {:?}, \"inject_at\": {}}}",
        a.dump,
        msgs.len(),
        flushes.len(),
        cuts,
        inject_at.map_or_else(|| "null".into(), |v| v.to_string())
    );
    let play = |p: &mut Player, s: &mut Sink, from: usize, to: usize| -> Option<String> {
        let mut note = None;
        for (i, m) in msgs.iter().enumerate().take(to).skip(from) {
            if Some(i) == inject_at {
                note = p.destroy_bound(s);
            }
            p.play(s, m);
        }
        note
    };
    // The run with no cut.
    let t = Instant::now();
    let mut s0 = Sink::connect(&a.a).expect("renderer a");
    let mut p0 = Player::default();
    let note = play(&mut p0, &mut s0, 0, msgs.len());
    let all = compared(&p0.j, p0.j.resource_ids());
    let (ref_pieces, ref_missing) = s0.export(&all);
    let reference = digest(&ref_pieces);
    if let Some(sc) = p0.j.scanout_resource() {
        save_ppm(&format!("{}/nocut.ppm", a.out), &p0.j, sc, &ref_pieces);
    }
    println!(
        "{{\"run\": \"nocut\", \"resources\": {}, \"exported\": {}, \"not_exported\": {:?}, \"made_case\": \"{}\", \"journal\": \"{:?}\", \"s\": {:.1}}}",
        all.len(),
        reference.len(),
        ref_missing,
        note.unwrap_or_default(),
        p0.j.stats(),
        t.elapsed().as_secs_f64()
    );
    drop(s0);
    if inject_at.is_some() {
        // the made case must change what the renderer holds, or it tests nothing
        let mut s1 = Sink::connect(&a.a).expect("renderer a");
        let mut p1 = Player::default();
        for m in &msgs {
            p1.play(&mut s1, m);
        }
        let ids = compared(&p1.j, p1.j.resource_ids());
        let (plain, _) = s1.export(&ids);
        let changed = differ(&reference, &digest(&plain));
        println!(
            "{{\"run\": \"nocut without the made case\", \"resources_that_differ\": {changed:?}}}"
        );
    }
    let mut failed = 0;
    for &k in &cuts {
        let t = Instant::now();
        let mut sa = Sink::connect(&a.a).expect("renderer a");
        let mut pa = Player::default();
        play(&mut pa, &mut sa, 0, k);
        let written = pa.j.gpu_written();

        // Export and import, then the rest of the stream.
        let mut sb = Sink::connect(&a.b).expect("renderer b");
        let kept: BTreeSet<u32> = sb.reset().into_iter().collect();
        let (n, size) = sb.rebuild(&pa.j, &kept);
        let (pieces, missing) = sa.export(&written);
        for (_, (h, d)) in &pieces {
            sb.send(SP_IMPORT, h, d, [0; 3]);
        }
        let mut pb = pa.clone();
        play(&mut pb, &mut sb, k, msgs.len());
        let all_b = compared(&pb.j, pb.j.resource_ids());
        let (b_pieces, b_missing) = sb.export(&all_b);
        let got = digest(&b_pieces);
        let mut d_export = differ(&reference, &got);
        let mut allowed = Vec::new();
        d_export.retain(
            |&id| match allowed_rounding(&pb.j, id, &ref_pieces, &b_pieces) {
                Some((rule, values, largest)) => {
                    allowed.push(format!(
                        "{{\"res\": {id}, \"rule\": \"{rule}\", \"values\": {values}, \"largest\": {largest}}}"
                    ));
                    false
                }
                None => true,
            },
        );
        if let (Some(sc), false) = (pb.j.scanout_resource(), d_export.is_empty()) {
            save_ppm(
                &format!("{}/cut{k}-export.ppm", a.out),
                &pb.j,
                sc,
                &b_pieces,
            );
        }
        drop(sb);

        // Rebuild alone: uploaded content, then the probe.
        let mut sc_ = Sink::connect(&a.c).expect("renderer c");
        let kept: BTreeSet<u32> = sc_.reset().into_iter().collect();
        sc_.rebuild(&pa.j, &kept);
        let uploads = compared(&pa.j, pa.j.upload_only());
        let (ua, _) = sa.export(&uploads);
        let (uc, _) = sc_.export(&uploads);
        let d_uploads = differ(&digest(&ua), &digest(&uc));
        for &id in &d_uploads {
            let ups: Vec<String> =
                pa.j.uploads_of(id)
                    .iter()
                    .map(|(h, d)| format!("{:?}+{}", words(h), d.len()))
                    .collect();
            println!(
                "{{\"cut\": {k}, \"res\": {id}, \"journal_uploads\": \"{}\"}}",
                ups.join(" ")
            );
            for (side, pieces) in [("a", &ua), ("c", &uc)] {
                let raw: Vec<u8> = pieces
                    .iter()
                    .filter(|p| p.0 == id)
                    .flat_map(|p| p.1.0.iter().chain(p.1.1.iter()).copied())
                    .collect();
                let _ = std::fs::write(format!("{}/cut{k}-res{id}-{side}.bin", a.out), raw);
            }
        }
        clear_gpu_written(&mut sa, &pa.j);
        clear_gpu_written(&mut sc_, &pa.j);
        let next = flushes
            .iter()
            .copied()
            .filter(|&f| f >= k)
            .nth(a.flushes.saturating_sub(1))
            .map_or(msgs.len(), |f| f + 1);
        let mut pc = pa.clone();
        play(&mut pa, &mut sa, k, next);
        play(&mut pc, &mut sc_, k, next);
        let ids = compared(&pa.j, pa.j.resource_ids());
        let (pa_pieces, _) = sa.export(&ids);
        let (pc_pieces, _) = sc_.export(&ids);
        let d_probe = differ(&digest(&pa_pieces), &digest(&pc_pieces));
        if let (Some(sc), false) = (pa.j.scanout_resource(), d_probe.is_empty()) {
            save_ppm(
                &format!("{}/cut{k}-probe-a.ppm", a.out),
                &pa.j,
                sc,
                &pa_pieces,
            );
            save_ppm(
                &format!("{}/cut{k}-probe-c.ppm", a.out),
                &pc.j,
                sc,
                &pc_pieces,
            );
        }
        let ok = d_export.is_empty() && d_uploads.is_empty() && d_probe.is_empty();
        failed += usize::from(!ok);
        let st = pa.j.stats();
        println!(
            "{{\"cut\": {k}, \"ok\": {ok}, \"rebuild_messages\": {n}, \"rebuild_bytes\": {size}, \"gpu_written\": {}, \"export_pieces\": {}, \"not_exported\": {missing:?}, \"export_way_differ\": {d_export:?}, \"export_way_allowed_rounding\": [{}], \"export_way_not_exported_at_end\": {b_missing:?}, \"upload_only\": {}, \"uploads_differ\": {d_uploads:?}, \"probe_to\": {next}, \"probe_resources\": {}, \"probe_differ\": {d_probe:?}, \"journal_upload_bytes\": {}, \"journal_log_entries\": {}, \"s\": {:.1}}}",
            written.len(),
            pieces.len(),
            allowed.join(", "),
            uploads.len(),
            ids.len(),
            st.upload_bytes,
            st.log_entries,
            t.elapsed().as_secs_f64()
        );
        for id in d_export.iter().chain(&d_uploads).chain(&d_probe).take(20) {
            println!(
                "{{\"cut\": {k}, \"differs\": {id}, \"what\": \"{}\"}}",
                pa.j.describe(*id)
                    .or_else(|| pb.j.describe(*id))
                    .unwrap_or_default()
            );
        }
    }
    println!("{{\"cuts\": {}, \"failed\": {failed}}}", cuts.len());
    assert!(failed == 0, "{failed} cuts did not hold");
}
