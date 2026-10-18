// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The journal of the remote GPU device: what the device keeps of its renderer's state so that
//! it can build that state again in a renderer that has none of it (another renderer after a
//! switch, the same one after it restarted, or one that went back to an earlier state).
//!
//! The renderer's state is made by the commands the device sends, and guest memory is not a copy
//! of it: the guest uploads through staging buffers and in the command stream, and what the GPU
//! renders never reaches guest memory. So the journal is fed every control command as it is sent
//! ([`Journal::ctrl`]) and keeps:
//!
//! - the resources with their create arguments, their backing (the guest's request) and **the
//!   uploads with their bytes**; a later upload whose box covers an earlier one at the same level
//!   replaces it, and a level whose uploads add up to more than the level itself is kept as one
//!   upload of the whole level;
//! - the contexts and the resources attached to them;
//! - for each sub-context, the ordered log of the commands that make lasting state (objects and
//!   bound state), compacted by two rules: a command that sets state is dropped when every slot it
//!   sets has been set by a later command of the same kind; an object's creation (and its
//!   destruction) is dropped only when the object is destroyed **and** no kept command binds it
//!   (the renderer keeps an object that is destroyed while bound, and a later object with the same
//!   handle is another one);
//! - the scanout, the last flush and the cursor;
//! - which resources the GPU wrote, and for each command the resources it may write (its write
//!   marks, uploads included).
//!
//! [`Journal::rebuild`] gives the messages that make a fresh renderer hold the same resources,
//! uploads, contexts, objects and bound state. What only the GPU wrote is not in the journal; a
//! planned switch takes it from the old renderer (its export). The journal has no Firecracker
//! types, so that a test tool can feed it recorded streams.

mod formats;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

pub use formats::{FORMAT_BLOCKS, FORMAT_COUNT};

pub const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const CMD_RESOURCE_UNREF: u32 = 0x0102;
pub const CMD_SET_SCANOUT: u32 = 0x0103;
pub const CMD_RESOURCE_FLUSH: u32 = 0x0104;
pub const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
pub const CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
pub const CMD_CTX_CREATE: u32 = 0x0200;
pub const CMD_CTX_DESTROY: u32 = 0x0201;
pub const CMD_CTX_ATTACH_RESOURCE: u32 = 0x0202;
pub const CMD_CTX_DETACH_RESOURCE: u32 = 0x0203;
pub const CMD_RESOURCE_CREATE_3D: u32 = 0x0204;
pub const CMD_TRANSFER_TO_HOST_3D: u32 = 0x0205;
pub const CMD_SUBMIT_3D: u32 = 0x0207;
pub const CMD_UPDATE_CURSOR: u32 = 0x0300;
pub const CMD_MOVE_CURSOR: u32 = 0x0301;

/// `struct virtio_gpu_ctrl_hdr`.
const HDR: usize = 24;
/// `struct virtio_gpu_update_cursor`.
pub const CURSOR_LEN: usize = 56;
/// `SpXfer` of the protocol: the header of an import or an export.
pub const XFER_LEN: usize = 48;
/// The largest command stream of one rebuilt `SUBMIT_3D`.
const SUBMIT_MAX: usize = 1 << 20;
/// `PIPE_BUFFER`, `PIPE_TEXTURE_3D`, `PIPE_TEXTURE_1D_ARRAY`.
const TARGET_BUFFER: u32 = 0;
const TARGET_3D: u32 = 3;
const TARGET_1D_ARRAY: u32 = 6;
/// `PIPE_IMAGE_ACCESS_WRITE`.
const IMAGE_WRITE: u32 = 2;

// virgl commands (`enum virgl_context_cmd`) and object types (`enum virgl_object_type`).
const C_CREATE_OBJECT: u32 = 1;
const C_BIND_OBJECT: u32 = 2;
const C_DESTROY_OBJECT: u32 = 3;
const C_SET_VIEWPORT_STATE: u32 = 4;
const C_SET_FRAMEBUFFER_STATE: u32 = 5;
const C_SET_VERTEX_BUFFERS: u32 = 6;
const C_CLEAR: u32 = 7;
const C_DRAW_VBO: u32 = 8;
const C_RESOURCE_INLINE_WRITE: u32 = 9;
const C_SET_SAMPLER_VIEWS: u32 = 10;
const C_SET_INDEX_BUFFER: u32 = 11;
const C_SET_CONSTANT_BUFFER: u32 = 12;
const C_SET_STENCIL_REF: u32 = 13;
const C_SET_BLEND_COLOR: u32 = 14;
const C_SET_SCISSOR_STATE: u32 = 15;
const C_BLIT: u32 = 16;
const C_RESOURCE_COPY_REGION: u32 = 17;
const C_BIND_SAMPLER_STATES: u32 = 18;
const C_SET_POLYGON_STIPPLE: u32 = 22;
const C_SET_CLIP_STATE: u32 = 23;
const C_SET_SAMPLE_MASK: u32 = 24;
const C_SET_STREAMOUT_TARGETS: u32 = 25;
const C_SET_RENDER_CONDITION: u32 = 26;
const C_SET_UNIFORM_BUFFER: u32 = 27;
const C_SET_SUB_CTX: u32 = 28;
const C_CREATE_SUB_CTX: u32 = 29;
const C_DESTROY_SUB_CTX: u32 = 30;
const C_BIND_SHADER: u32 = 31;
const C_SET_TESS_STATE: u32 = 32;
const C_SET_MIN_SAMPLES: u32 = 33;
const C_SET_SHADER_BUFFERS: u32 = 34;
const C_SET_SHADER_IMAGES: u32 = 35;
const C_LAUNCH_GRID: u32 = 37;
const C_SET_FRAMEBUFFER_STATE_NO_ATTACH: u32 = 38;
const C_SET_ATOMIC_BUFFERS: u32 = 40;
const C_GET_QUERY_RESULT_QBO: u32 = 42;
const C_TRANSFER3D: u32 = 43;
const C_COPY_TRANSFER3D: u32 = 45;
const C_SET_TWEAKS: u32 = 46;
const C_CLEAR_TEXTURE: u32 = 47;
const C_CREATE_VIDEO_CODEC: u32 = 53;
const C_DESTROY_VIDEO_CODEC: u32 = 54;
const C_CREATE_VIDEO_BUFFER: u32 = 55;
const C_DESTROY_VIDEO_BUFFER: u32 = 56;
const C_DECODE_BITSTREAM: u32 = 59;
const C_END_FRAME: u32 = 61;
const C_CLEAR_SURFACE: u32 = 62;

const O_SHADER: u32 = 4;
const O_SAMPLER_VIEW: u32 = 6;
const O_SURFACE: u32 = 8;
const O_QUERY: u32 = 9;
const O_STREAMOUT_TARGET: u32 = 10;
const O_MSAA_SURFACE: u32 = 11;
/// `VIRGL_OBJ_SHADER_OFFSET_CONT`: a later part of a long shader.
const SHADER_CONT: u32 = 1 << 31;

/// A slot of bound state: (command, shader stage or object type, slot index).
type Slot = u64;

fn slot(cmd: u32, stage: u32, index: u32) -> Slot {
    (u64::from(cmd) << 40) | (u64::from(stage & 0xff) << 32) | u64::from(index)
}

/// A slot for commands that set their whole kind of state at once.
const WHOLE: u32 = u32::MAX;

fn u32_at(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4)
        .map_or(0, |s| u32::from_le_bytes(s.try_into().unwrap()))
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8)
        .map_or(0, |s| u64::from_le_bytes(s.try_into().unwrap()))
}

fn to_usize(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// The byte range of a transfer in the backing of a resource; the same arithmetic as
/// `vrend_transfer_size` and as `sp_range` of the QEMU source, so both send the same bytes.
#[allow(clippy::too_many_arguments)]
pub fn transfer_range(
    format: u32,
    width0: u32,
    height0: u32,
    level: u32,
    stride: u32,
    layer_stride: u32,
    bx: [u32; 6],
    offset: u64,
    backing: u64,
) -> (u64, u64) {
    if offset >= backing {
        return (offset, 0);
    }
    let size = match block(format) {
        Some((bw, bh, bs)) => {
            let w = u64::from(bx[3].max(1));
            let h = u64::from(bx[4].max(1));
            let d = u64::from(bx[5].max(1));
            let lw = u64::from(minify(width0, level));
            let lh = u64::from(minify(height0, level));
            let vstride = if stride != 0 {
                u64::from(stride)
            } else {
                lw.div_ceil(bw) * bs
            };
            let vlayer = if layer_stride != 0 {
                u64::from(layer_stride)
            } else {
                lh.div_ceil(bh) * vstride
            };
            (d - 1) * vlayer + (h.div_ceil(bh) - 1) * vstride + w.div_ceil(bw) * bs
        }
        None => backing - offset, // unknown layout: everything from offset
    };
    (offset, size.min(backing - offset))
}

/// (block width, block height, bytes per block) of a format with a known layout.
fn block(format: u32) -> Option<(u64, u64, u64)> {
    let b = FORMAT_BLOCKS.get(format as usize)?;
    (b.2 >= 8).then(|| (u64::from(b.0), u64::from(b.1), u64::from(b.2) / 8))
}

fn minify(v: u32, level: u32) -> u32 {
    if level < 32 { v >> level } else { 0 }.max(1)
}

/// `SpXfer` of the protocol.
pub fn xfer(
    res: u32,
    kind: u32,
    level: u32,
    stride: u32,
    layer_stride: u32,
    sample: u32,
    bx: [u32; 6],
) -> [u8; XFER_LEN] {
    let mut h = [0u8; XFER_LEN];
    for (i, v) in [res, kind, level, stride, layer_stride, sample]
        .iter()
        .chain(bx.iter())
        .enumerate()
    {
        h[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    h
}

/// A message of a rebuild.
#[derive(Debug, PartialEq, Eq)]
pub enum Msg<'a> {
    /// A control command (sent with no sequence number: the renderer answers nothing).
    Ctrl(Vec<u8>),
    /// Bytes for a resource: `SP_IMPORT` with an `SpXfer` of kind 0.
    Import([u8; XFER_LEN], &'a [u8]),
    /// `SP_CURSOR`.
    Cursor(&'a [u8]),
}

/// An upload into a resource, as the renderer took it: the bytes of `bx` at `level` with the
/// guest's strides, from the first byte of the box on.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Upload {
    level: u32,
    stride: u32,
    layer_stride: u32,
    bx: [u32; 6],
    data: Vec<u8>,
}

fn covers(a: &[u32; 6], b: &[u32; 6]) -> bool {
    (0..3).all(|i| {
        let (a0, b0) = (u64::from(a[i]), u64::from(b[i]));
        let (a1, b1) = (
            a0 + u64::from(a[i + 3].max(1)),
            b0 + u64::from(b[i + 3].max(1)),
        );
        a0 <= b0 && b1 <= a1
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Res {
    /// Counts resources: an id that the guest uses again is another resource.
    generation: u64,
    /// The guest's create request, and its attach request.
    create: Vec<u8>,
    attach: Option<Vec<u8>>,
    backing: u64,
    target: u32,
    format: u32,
    bind: u32,
    width: u32,
    height: u32,
    depth: u32,
    array_size: u32,
    last_level: u32,
    nr_samples: u32,
    uploads: Vec<Upload>,
    upload_bytes: u64,
    gpu_written: bool,
}

impl Res {
    /// (width, height, layers) of a level, and its bytes when packed; None if its layout is
    /// not known well enough to put uploads together.
    fn level_layout(&self, level: u32) -> Option<(u32, u32, u32, u64)> {
        let (bw, bh, bs) = block(self.format)?;
        if self.target == TARGET_1D_ARRAY || self.nr_samples > 1 {
            return None;
        }
        let (w, h, layers) = if self.target == TARGET_BUFFER {
            (self.width, 1, 1)
        } else if self.target == TARGET_3D {
            (
                minify(self.width, level),
                minify(self.height, level),
                minify(self.depth, level),
            )
        } else {
            (
                minify(self.width, level),
                minify(self.height, level),
                self.array_size.max(1),
            )
        };
        let bytes = u64::from(layers) * u64::from(h).div_ceil(bh) * u64::from(w).div_ceil(bw) * bs;
        Some((w, h, layers, bytes))
    }

    /// The bytes the resource takes in the renderer (all levels, layers and samples).
    pub fn size(&self) -> u64 {
        (0..=self.last_level.min(15))
            .map(|l| self.level_layout(l).map_or(0, |v| v.3))
            .sum::<u64>()
            .max(u64::from(self.width))
            * u64::from(self.nr_samples.max(1))
    }

    /// Keep an upload: it replaces the earlier ones it covers; a level whose uploads add up to
    /// more than the level becomes one upload of the whole level.
    fn upload(&mut self, u: Upload) -> i64 {
        let before = self.upload_bytes;
        self.uploads
            .retain(|e| !(e.level == u.level && covers(&u.bx, &e.bx)));
        let level = u.level;
        self.uploads.push(u);
        let at_level: u64 = self
            .uploads
            .iter()
            .filter(|e| e.level == level)
            .map(|e| e.data.len() as u64)
            .sum();
        if let Some((w, h, layers, bytes)) = self.level_layout(level)
            && at_level > bytes
            && bytes <= 1 << 30
        {
            let whole = self.compose(level, w, h, bytes);
            self.uploads.retain(|e| e.level != level);
            self.uploads.push(Upload {
                level,
                stride: 0,
                layer_stride: 0,
                bx: [0, 0, 0, w, h, layers],
                data: whole,
            });
        }
        self.upload_bytes = self.uploads.iter().map(|e| e.data.len() as u64).sum();
        i64::try_from(self.upload_bytes).unwrap_or(i64::MAX)
            - i64::try_from(before).unwrap_or(i64::MAX)
    }

    /// The uploads of a level put together, in order, into the packed layout of the level.
    fn compose(&self, level: u32, w: u32, h: u32, bytes: u64) -> Vec<u8> {
        let mut out = vec![0u8; to_usize(bytes)];
        let Some((bw, bh, bs)) = block(self.format) else {
            return out;
        };
        let row = u64::from(w).div_ceil(bw) * bs;
        let layer = u64::from(h).div_ceil(bh) * row;
        for u in self.uploads.iter().filter(|e| e.level == level) {
            if self.target == TARGET_BUFFER {
                let at = to_usize(u64::from(u.bx[0]));
                let n = u.data.len().min(out.len().saturating_sub(at));
                out[at..at + n].copy_from_slice(&u.data[..n]);
                continue;
            }
            let sstride = if u.stride != 0 {
                u64::from(u.stride)
            } else {
                row
            };
            let slayer = if u.layer_stride != 0 {
                u64::from(u.layer_stride)
            } else {
                u64::from(h).div_ceil(bh) * sstride
            };
            let n = u64::from(u.bx[3].max(1)).div_ceil(bw) * bs;
            for z in 0..u64::from(u.bx[5].max(1)) {
                for r in 0..u64::from(u.bx[4].max(1)).div_ceil(bh) {
                    let src = z * slayer + r * sstride;
                    let dst = (u64::from(u.bx[2]) + z) * layer
                        + (u64::from(u.bx[1]) / bh + r) * row
                        + (u64::from(u.bx[0]) / bw) * bs;
                    let (src, dst) = (to_usize(src), to_usize(dst));
                    let m = to_usize(n)
                        .min(u.data.len().saturating_sub(src))
                        .min(out.len().saturating_sub(dst));
                    if m > 0 {
                        out[dst..dst + m].copy_from_slice(&u.data[src..src + m]);
                    }
                }
            }
        }
        out
    }
}

/// What a command of a sub-context's log is.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Kind {
    /// The creation of an object (or a later part of a long shader).
    Create(u64),
    Destroy(u64),
    /// Bound state, in these slots.
    Set(Vec<Slot>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    words: Vec<u32>,
    kind: Kind,
    /// Words that name an object: (index, the object it named then).
    objs: Vec<(usize, u64)>,
    /// Words that name a resource: (index, id, generation).
    res: Vec<(usize, u32, u64)>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Sub {
    log: Vec<Entry>,
    /// The last command that set each slot (an index into `log`).
    latest: HashMap<Slot, usize>,
    /// handle -> the object it names now.
    objects: HashMap<u32, u64>,
    destroyed: HashSet<u64>,
    /// Surfaces and streamout targets -> their resource (for the write marks).
    obj_res: HashMap<u64, u32>,
    /// Bound state that the GPU writes through.
    fb: Vec<u64>,
    so: Vec<u64>,
    ssbo: HashMap<u64, u32>,
    images: HashMap<u64, u32>,
    atomics: HashMap<u32, u32>,
    /// The length of the log after the last compaction.
    compacted: usize,
}

impl Sub {
    fn push(&mut self, e: Entry) {
        let i = self.log.len();
        if let Kind::Set(slots) = &e.kind {
            for s in slots {
                self.latest.insert(*s, i);
            }
        }
        self.log.push(e);
        if self.log.len() > 256 && self.log.len() > 2 * self.compacted {
            self.compact();
        }
    }

    /// Which entries of the log the two rules of the module's description keep.
    fn kept(&self) -> Vec<bool> {
        let kept_set: Vec<bool> = self
            .log
            .iter()
            .enumerate()
            .map(|(i, e)| match &e.kind {
                Kind::Set(slots) => slots.iter().any(|s| self.latest.get(s) == Some(&i)),
                _ => true,
            })
            .collect();
        let mut bound = HashSet::new();
        for (e, k) in self.log.iter().zip(&kept_set) {
            if *k && matches!(e.kind, Kind::Set(_)) {
                bound.extend(e.objs.iter().map(|o| o.1));
            }
        }
        self.log
            .iter()
            .zip(kept_set)
            .map(|(e, k)| match &e.kind {
                Kind::Set(_) => k,
                Kind::Create(o) | Kind::Destroy(o) => {
                    !self.destroyed.contains(o) || bound.contains(o)
                }
            })
            .collect()
    }

    fn compact(&mut self) {
        let kept = self.kept();
        let mut alive = HashSet::new();
        for (e, k) in self.log.iter().zip(&kept) {
            if let (true, Kind::Create(o)) = (k, &e.kind) {
                alive.insert(*o);
            }
        }
        let old = std::mem::take(&mut self.log);
        self.latest.clear();
        for (e, keep) in old.into_iter().zip(kept) {
            if keep {
                let i = self.log.len();
                if let Kind::Set(slots) = &e.kind {
                    for s in slots {
                        self.latest.insert(*s, i);
                    }
                }
                self.log.push(e);
            }
        }
        let dead: Vec<u64> = self
            .destroyed
            .iter()
            .copied()
            .filter(|o| !alive.contains(o))
            .collect();
        for o in dead {
            self.destroyed.remove(&o);
            self.obj_res.remove(&o);
        }
        self.compacted = self.log.len();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Ctx {
    create: Vec<u8>,
    attached: BTreeSet<u32>,
    subs: BTreeMap<u32, Sub>,
    /// Sub-contexts in the order they were made (0 first).
    order: Vec<u32>,
    cur: u32,
    /// Video codecs and buffers: handle -> object (one namespace per context).
    video: HashMap<u32, u64>,
    video_res: HashMap<u64, Vec<u32>>,
}

/// Sizes of what the journal holds.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub resources: u64,
    pub contexts: u64,
    pub upload_bytes: u64,
    pub gpu_written: u64,
    /// The bytes the GPU-written resources take in the renderer.
    pub gpu_written_bytes: u64,
    pub log_entries: u64,
    pub log_bytes: u64,
}

/// See the module's description.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Journal {
    resources: BTreeMap<u32, Res>,
    contexts: BTreeMap<u32, Ctx>,
    scanout: Option<Vec<u8>>,
    flush: Option<Vec<u8>>,
    cursor: Option<Vec<u8>>,
    next_obj: u64,
    next_gen: u64,
    upload_bytes: u64,
}

/// Where the bytes of an in-stream upload come from: the device reads them from guest memory
/// (it sends them anyway), a test tool from a recorded stream. (resource, offset, length).
pub type Fetch<'a> = dyn FnMut(u32, u64, u64) -> Option<Vec<u8>> + 'a;

/// The request with no fence: a rebuilt command must not signal the guest's fences.
fn unfenced(req: &[u8]) -> Vec<u8> {
    let mut r = req.to_vec();
    if r.len() >= HDR {
        r[4..16].fill(0);
        r[20] = 0;
    }
    r
}

fn hdr(typ: u32, ctx: u32, len: usize) -> Vec<u8> {
    let mut r = vec![0u8; len];
    r[0..4].copy_from_slice(&typ.to_le_bytes());
    r[16..20].copy_from_slice(&ctx.to_le_bytes());
    r
}

fn cmd_word(cmd: u32, obj: u32, len: usize) -> u32 {
    (u32::try_from(len).unwrap_or(0) << 16) | (obj << 8) | cmd
}

impl Journal {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take a control command that is being sent to the renderer: `req` is the guest's request,
    /// `data` the bytes sent with a transfer to the host (its range of the backing). Returns the
    /// resources the command may write (uploads included), for `SP_WMARK`.
    pub fn ctrl(&mut self, req: &[u8], data: &[u8], fetch: &mut Fetch<'_>) -> Vec<u32> {
        let mut marks = Vec::new();
        let typ = u32_at(req, 0);
        let ctx_id = u32_at(req, 16);
        match typ {
            CMD_RESOURCE_CREATE_2D if req.len() >= 40 => {
                self.res_create(
                    u32_at(req, 24),
                    req,
                    [
                        2,
                        u32_at(req, 28),
                        1 << 1,
                        u32_at(req, 32),
                        u32_at(req, 36),
                        1,
                        1,
                        0,
                        0,
                    ],
                );
            }
            CMD_RESOURCE_CREATE_3D if req.len() >= 72 => {
                let a: Vec<u32> = (0..9).map(|i| u32_at(req, 28 + i * 4)).collect();
                self.res_create(u32_at(req, 24), req, a.try_into().unwrap());
            }
            CMD_RESOURCE_UNREF if req.len() >= 32 => {
                let id = u32_at(req, 24);
                if let Some(r) = self.resources.remove(&id) {
                    self.upload_bytes -= r.upload_bytes.min(self.upload_bytes);
                }
                for c in self.contexts.values_mut() {
                    c.attached.remove(&id);
                }
            }
            CMD_RESOURCE_ATTACH_BACKING if req.len() >= 32 => {
                let id = u32_at(req, 24);
                let n = (u32_at(req, 28) as usize).min((req.len() - 32) / 16);
                let size = (0..n).map(|e| u64::from(u32_at(req, 40 + e * 16))).sum();
                if let Some(r) = self.resources.get_mut(&id)
                    && r.attach.is_none()
                {
                    r.attach = Some(unfenced(req));
                    r.backing = size;
                }
            }
            CMD_RESOURCE_DETACH_BACKING if req.len() >= 32 => {
                if let Some(r) = self.resources.get_mut(&u32_at(req, 24)) {
                    r.attach = None;
                    r.backing = 0;
                }
            }
            CMD_TRANSFER_TO_HOST_2D if req.len() >= 56 && !data.is_empty() => {
                let id = u32_at(req, 48);
                let bx = [
                    u32_at(req, 24),
                    u32_at(req, 28),
                    0,
                    u32_at(req, 32),
                    u32_at(req, 36),
                    1,
                ];
                self.upload(id, 0, 0, 0, bx, data.to_vec());
                marks.push(id);
            }
            CMD_TRANSFER_TO_HOST_3D if req.len() >= 72 && !data.is_empty() => {
                let id = u32_at(req, 56);
                let bx: Vec<u32> = (0..6).map(|i| u32_at(req, 24 + i * 4)).collect();
                self.upload(
                    id,
                    u32_at(req, 60),
                    u32_at(req, 64),
                    u32_at(req, 68),
                    bx.try_into().unwrap(),
                    data.to_vec(),
                );
                marks.push(id);
            }
            CMD_CTX_CREATE if req.len() >= HDR => {
                let mut subs = BTreeMap::new();
                subs.insert(0, Sub::default());
                self.contexts.insert(
                    ctx_id,
                    Ctx {
                        create: unfenced(req),
                        attached: BTreeSet::new(),
                        subs,
                        order: vec![0],
                        cur: 0,
                        video: HashMap::new(),
                        video_res: HashMap::new(),
                    },
                );
            }
            CMD_CTX_DESTROY => {
                self.contexts.remove(&ctx_id);
            }
            CMD_CTX_ATTACH_RESOURCE if req.len() >= 28 => {
                let id = u32_at(req, 24);
                if self.resources.contains_key(&id)
                    && let Some(c) = self.contexts.get_mut(&ctx_id)
                {
                    c.attached.insert(id);
                }
            }
            CMD_CTX_DETACH_RESOURCE if req.len() >= 28 => {
                if let Some(c) = self.contexts.get_mut(&ctx_id) {
                    c.attached.remove(&u32_at(req, 24));
                }
            }
            CMD_SET_SCANOUT if req.len() >= 48 => {
                if u32_at(req, 40) == 0 {
                    self.scanout = (u32_at(req, 44) != 0).then(|| unfenced(req));
                }
            }
            CMD_RESOURCE_FLUSH if req.len() >= 48 => self.flush = Some(unfenced(req)),
            CMD_SUBMIT_3D if req.len() >= 32 => {
                let size = (u32_at(req, 24) as usize).min(req.len() - 32);
                let words: Vec<u32> = req[32..32 + size]
                    .chunks_exact(4)
                    .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                    .collect();
                self.submit(ctx_id, &words, fetch, &mut marks);
            }
            _ => {}
        }
        marks.sort_unstable();
        marks.dedup();
        marks
    }

    /// A cursor command (the cursor queue).
    pub fn cursor(&mut self, req: &[u8]) {
        if req.len() < CURSOR_LEN {
            return;
        }
        match u32_at(req, 0) {
            CMD_UPDATE_CURSOR => self.cursor = Some(req[..CURSOR_LEN].to_vec()),
            CMD_MOVE_CURSOR => {
                if let Some(c) = self.cursor.as_mut() {
                    c[24..40].copy_from_slice(&req[24..40]);
                }
            }
            _ => {}
        }
    }

    fn res_create(&mut self, id: u32, req: &[u8], a: [u32; 9]) {
        if id == 0 {
            return;
        }
        if let Some(r) = self.resources.remove(&id) {
            self.upload_bytes -= r.upload_bytes.min(self.upload_bytes);
        }
        self.next_gen += 1;
        self.resources.insert(
            id,
            Res {
                generation: self.next_gen,
                create: unfenced(req),
                attach: None,
                backing: 0,
                target: a[0],
                format: a[1],
                bind: a[2],
                width: a[3],
                height: a[4],
                depth: a[5],
                array_size: a[6],
                last_level: a[7],
                nr_samples: a[8],
                uploads: Vec::new(),
                upload_bytes: 0,
                gpu_written: false,
            },
        );
    }

    fn upload(
        &mut self,
        id: u32,
        level: u32,
        stride: u32,
        layer: u32,
        bx: [u32; 6],
        data: Vec<u8>,
    ) {
        if let Some(r) = self.resources.get_mut(&id) {
            let d = r.upload(Upload {
                level,
                stride,
                layer_stride: layer,
                bx,
                data,
            });
            self.upload_bytes = self.upload_bytes.saturating_add_signed(d);
        }
    }

    fn gpu_write(&mut self, id: u32, marks: &mut Vec<u32>) {
        if let Some(r) = self.resources.get_mut(&id) {
            r.gpu_written = true;
            marks.push(id);
        }
    }

    fn generation(&self, id: u32) -> u64 {
        self.resources.get(&id).map_or(0, |r| r.generation)
    }

    /// One command stream of context `ctx_id`.
    fn submit(&mut self, ctx_id: u32, w: &[u32], fetch: &mut Fetch<'_>, marks: &mut Vec<u32>) {
        let mut i = 0usize;
        while i < w.len() {
            let len = (w[i] >> 16) as usize;
            if i + 1 + len > w.len() {
                break;
            }
            let c = &w[i..i + 1 + len];
            self.command(ctx_id, c, fetch, marks);
            i += 1 + len;
        }
    }

    #[allow(clippy::too_many_lines)]
    fn command(&mut self, ctx_id: u32, c: &[u32], fetch: &mut Fetch<'_>, marks: &mut Vec<u32>) {
        let cmd = c[0] & 0xff;
        let obj = (c[0] >> 8) & 0xff;
        let len = c.len() - 1;
        let at = |k: usize| c.get(k).copied().unwrap_or(0);
        // Uploads and GPU writes need the resources, the rest the context.
        match cmd {
            C_TRANSFER3D if len >= 13 && at(13) == 1 => {
                let res = at(1);
                if let Some(r) = self.resources.get(&res) {
                    let bx = [at(6), at(7), at(8), at(9), at(10), at(11)];
                    let (off, n) = transfer_range(
                        r.format,
                        r.width,
                        r.height,
                        at(2),
                        at(4),
                        at(5),
                        bx,
                        u64::from(at(12)),
                        r.backing,
                    );
                    if n > 0
                        && let Some(d) = fetch(res, off, n)
                    {
                        self.upload(res, at(2), at(4), at(5), bx, d);
                    }
                    marks.push(res);
                }
                return;
            }
            C_COPY_TRANSFER3D if len >= 14 && at(14) & 2 == 0 => {
                let (res, staging) = (at(1), at(12));
                let size = self.resources.get(&staging).map(|r| r.backing);
                if let (Some(r), Some(size)) = (self.resources.get(&res), size) {
                    let bx = [at(6), at(7), at(8), at(9), at(10), at(11)];
                    let (off, n) = transfer_range(
                        r.format,
                        r.width,
                        r.height,
                        at(2),
                        at(4),
                        at(5),
                        bx,
                        u64::from(at(13)),
                        size,
                    );
                    if n > 0
                        && let Some(d) = fetch(staging, off, n)
                    {
                        self.upload(res, at(2), at(4), at(5), bx, d);
                    }
                    marks.push(res);
                }
                return;
            }
            C_RESOURCE_INLINE_WRITE if len >= 11 => {
                let res = at(1);
                let bx = [at(6), at(7), at(8), at(9), at(10), at(11)];
                let data: Vec<u8> = c[12..].iter().flat_map(|v| v.to_le_bytes()).collect();
                self.upload(res, at(2), at(4), at(5), bx, data);
                marks.push(res);
                return;
            }
            C_BLIT if len >= 4 => return self.gpu_write(at(4), marks),
            C_RESOURCE_COPY_REGION if len >= 1 => return self.gpu_write(at(1), marks),
            C_CLEAR_TEXTURE if len >= 1 => return self.gpu_write(at(1), marks),
            C_GET_QUERY_RESULT_QBO if len >= 2 => return self.gpu_write(at(2), marks),
            _ => {}
        }
        let mut writes: Vec<u32> = Vec::new();
        let generation = |j: &Journal, id: u32| j.generation(id);
        let gens: HashMap<u32, u64> = match cmd {
            C_CREATE_OBJECT
                if matches!(
                    obj,
                    O_SAMPLER_VIEW | O_SURFACE | O_MSAA_SURFACE | O_STREAMOUT_TARGET
                ) =>
            {
                [(at(2), generation(self, at(2)))].into()
            }
            C_CREATE_OBJECT if obj == O_QUERY => [(at(4), generation(self, at(4)))].into(),
            C_SET_VERTEX_BUFFERS => (0..len / 3)
                .map(|k| (at(3 + 3 * k), generation(self, at(3 + 3 * k))))
                .collect(),
            C_SET_INDEX_BUFFER | C_SET_UNIFORM_BUFFER => {
                let k = if cmd == C_SET_INDEX_BUFFER { 1 } else { 5 };
                [(at(k), generation(self, at(k)))].into()
            }
            C_SET_SHADER_BUFFERS => (0..len.saturating_sub(2) / 3)
                .map(|k| (at(5 + 3 * k), generation(self, at(5 + 3 * k))))
                .collect(),
            C_SET_SHADER_IMAGES => (0..len.saturating_sub(2) / 5)
                .map(|k| (at(7 + 5 * k), generation(self, at(7 + 5 * k))))
                .collect(),
            C_SET_ATOMIC_BUFFERS => (0..len.saturating_sub(1) / 3)
                .map(|k| (at(4 + 3 * k), generation(self, at(4 + 3 * k))))
                .collect(),
            C_CREATE_VIDEO_BUFFER => (5..=len)
                .map(|k| (at(k), generation(self, at(k))))
                .collect(),
            _ => HashMap::new(),
        };
        let Some(ctx) = self.contexts.get_mut(&ctx_id) else {
            return;
        };
        let next_obj = &mut self.next_obj;
        let mut new_obj = || {
            *next_obj += 1;
            *next_obj
        };
        let rref = |k: usize| -> (usize, u32, u64) {
            let id = c.get(k).copied().unwrap_or(0);
            (k, id, gens.get(&id).copied().unwrap_or(0))
        };
        match cmd {
            C_SET_SUB_CTX if len >= 1 => {
                if ctx.subs.contains_key(&at(1)) {
                    ctx.cur = at(1);
                }
                return;
            }
            C_CREATE_SUB_CTX if len >= 1 => {
                if let std::collections::btree_map::Entry::Vacant(e) = ctx.subs.entry(at(1)) {
                    e.insert(Sub::default());
                    ctx.order.push(at(1));
                }
                return;
            }
            C_DESTROY_SUB_CTX if len >= 1 && at(1) != 0 => {
                ctx.subs.remove(&at(1));
                ctx.order.retain(|&s| s != at(1));
                if ctx.cur == at(1) {
                    ctx.cur = 0;
                }
                return;
            }
            _ => {}
        }
        let cur = ctx.cur;
        let (video, video_res) = (&mut ctx.video, &mut ctx.video_res);
        let Some(sub) = ctx.subs.get_mut(&cur) else {
            return;
        };
        let oref = |sub: &Sub, k: usize| -> Option<(usize, u64)> {
            let h = c.get(k).copied().unwrap_or(0);
            (h != 0)
                .then(|| sub.objects.get(&h).map(|o| (k, *o)))
                .flatten()
        };
        let set = |slots: Vec<Slot>, objs: Vec<(usize, u64)>, res: Vec<(usize, u32, u64)>| Entry {
            words: c.to_vec(),
            kind: Kind::Set(slots),
            objs,
            res,
        };
        let range = |cmd: u32, stage: u32, start: u32, n: usize| -> Vec<Slot> {
            if n == 0 {
                return vec![slot(cmd, stage, WHOLE)];
            }
            (0..u32::try_from(n).unwrap_or(0))
                .map(|k| slot(cmd, stage, start.wrapping_add(k)))
                .collect()
        };
        match cmd {
            C_CREATE_OBJECT if len >= 1 => {
                let h = at(1);
                if obj == O_SHADER && len >= 3 && at(3) & SHADER_CONT != 0 {
                    if let Some(&o) = sub.objects.get(&h) {
                        sub.push(Entry {
                            words: c.to_vec(),
                            kind: Kind::Create(o),
                            objs: Vec::new(),
                            res: Vec::new(),
                        });
                    }
                    return;
                }
                if let Some(old) = sub.objects.insert(h, 0) {
                    sub.destroyed.insert(old); // replaced
                }
                let o = new_obj();
                sub.objects.insert(h, o);
                let res = match obj {
                    O_SAMPLER_VIEW | O_SURFACE | O_MSAA_SURFACE | O_STREAMOUT_TARGET => {
                        if matches!(obj, O_SURFACE | O_MSAA_SURFACE | O_STREAMOUT_TARGET) {
                            sub.obj_res.insert(o, at(2));
                        }
                        vec![rref(2)]
                    }
                    O_QUERY if len >= 4 => vec![rref(4)],
                    _ => Vec::new(),
                };
                sub.push(Entry {
                    words: c.to_vec(),
                    kind: Kind::Create(o),
                    objs: Vec::new(),
                    res,
                });
            }
            C_DESTROY_OBJECT if len >= 1 => {
                if let Some(o) = sub.objects.remove(&at(1)) {
                    sub.destroyed.insert(o);
                    sub.push(Entry {
                        words: c.to_vec(),
                        kind: Kind::Destroy(o),
                        objs: Vec::new(),
                        res: Vec::new(),
                    });
                }
            }
            C_BIND_OBJECT if len >= 1 => {
                let e = set(
                    vec![slot(cmd, obj, 0)],
                    oref(sub, 1).into_iter().collect(),
                    Vec::new(),
                );
                sub.push(e);
            }
            C_BIND_SHADER if len >= 2 => {
                let e = set(
                    vec![slot(cmd, at(2), 0)],
                    oref(sub, 1).into_iter().collect(),
                    Vec::new(),
                );
                sub.push(e);
            }
            C_SET_VIEWPORT_STATE if len >= 1 => {
                let e = set(range(cmd, 0, at(1), (len - 1) / 6), Vec::new(), Vec::new());
                sub.push(e);
            }
            C_SET_SCISSOR_STATE if len >= 1 => {
                let e = set(range(cmd, 0, at(1), (len - 1) / 2), Vec::new(), Vec::new());
                sub.push(e);
            }
            C_SET_FRAMEBUFFER_STATE if len >= 2 => {
                let n = (at(1) as usize).min(len - 2);
                let objs: Vec<(usize, u64)> = std::iter::once(2)
                    .chain(3..3 + n)
                    .filter_map(|k| oref(sub, k))
                    .collect();
                sub.fb = objs.iter().map(|o| o.1).collect();
                let e = set(vec![slot(cmd, 0, 0)], objs, Vec::new());
                sub.push(e);
            }
            C_SET_VERTEX_BUFFERS => {
                let res = (0..len / 3).map(|k| rref(3 + 3 * k)).collect();
                let e = set(vec![slot(cmd, 0, 0)], Vec::new(), res);
                sub.push(e);
            }
            C_SET_SAMPLER_VIEWS | C_BIND_SAMPLER_STATES if len >= 2 => {
                let objs = (3..=len).filter_map(|k| oref(sub, k)).collect();
                let e = set(range(cmd, at(1), at(2), len - 2), objs, Vec::new());
                sub.push(e);
            }
            C_SET_INDEX_BUFFER => {
                let res = if len >= 1 { vec![rref(1)] } else { Vec::new() };
                let e = set(vec![slot(cmd, 0, 0)], Vec::new(), res);
                sub.push(e);
            }
            C_SET_CONSTANT_BUFFER if len >= 2 => {
                let e = set(vec![slot(cmd, at(1), at(2))], Vec::new(), Vec::new());
                sub.push(e);
            }
            C_SET_UNIFORM_BUFFER if len >= 5 => {
                let e = set(vec![slot(cmd, at(1), at(2))], Vec::new(), vec![rref(5)]);
                sub.push(e);
            }
            C_SET_STENCIL_REF
            | C_SET_BLEND_COLOR
            | C_SET_POLYGON_STIPPLE
            | C_SET_CLIP_STATE
            | C_SET_SAMPLE_MASK
            | C_SET_MIN_SAMPLES
            | C_SET_TESS_STATE
            | C_SET_FRAMEBUFFER_STATE_NO_ATTACH => {
                let e = set(vec![slot(cmd, 0, 0)], Vec::new(), Vec::new());
                sub.push(e);
            }
            C_SET_STREAMOUT_TARGETS if len >= 1 => {
                let objs: Vec<(usize, u64)> = (2..=len).filter_map(|k| oref(sub, k)).collect();
                sub.so = objs.iter().map(|o| o.1).collect();
                let e = set(vec![slot(cmd, 0, 0)], objs, Vec::new());
                sub.push(e);
            }
            C_SET_RENDER_CONDITION if len >= 1 => {
                let e = set(
                    vec![slot(cmd, 0, 0)],
                    oref(sub, 1).into_iter().collect(),
                    Vec::new(),
                );
                sub.push(e);
            }
            C_SET_SHADER_BUFFERS if len >= 2 => {
                let n = (len - 2) / 3;
                for k in 0..n {
                    let s = (u64::from(at(1)) << 32)
                        | u64::from(at(2).wrapping_add(u32::try_from(k).unwrap_or(0)));
                    sub.ssbo.insert(s, at(5 + 3 * k));
                }
                let res = (0..n).map(|k| rref(5 + 3 * k)).collect();
                let e = set(range(cmd, at(1), at(2), n), Vec::new(), res);
                sub.push(e);
            }
            C_SET_SHADER_IMAGES if len >= 2 => {
                let n = (len - 2) / 5;
                for k in 0..n {
                    let s = (u64::from(at(1)) << 32)
                        | u64::from(at(2).wrapping_add(u32::try_from(k).unwrap_or(0)));
                    if at(4 + 5 * k) & IMAGE_WRITE != 0 {
                        sub.images.insert(s, at(7 + 5 * k));
                    } else {
                        sub.images.remove(&s);
                    }
                }
                let res = (0..n).map(|k| rref(7 + 5 * k)).collect();
                let e = set(range(cmd, at(1), at(2), n), Vec::new(), res);
                sub.push(e);
            }
            C_SET_ATOMIC_BUFFERS if len >= 1 => {
                let n = (len - 1) / 3;
                for k in 0..n {
                    sub.atomics.insert(
                        at(1).wrapping_add(u32::try_from(k).unwrap_or(0)),
                        at(4 + 3 * k),
                    );
                }
                let res = (0..n).map(|k| rref(4 + 3 * k)).collect();
                let e = set(range(cmd, 0, at(1), n), Vec::new(), res);
                sub.push(e);
            }
            C_SET_TWEAKS if len >= 1 => {
                let e = set(vec![slot(cmd, 0, at(1))], Vec::new(), Vec::new());
                sub.push(e);
            }
            C_CREATE_VIDEO_CODEC | C_CREATE_VIDEO_BUFFER if len >= 1 => {
                let o = new_obj();
                video.insert(at(1), o);
                let res = if cmd == C_CREATE_VIDEO_BUFFER {
                    video_res.insert(o, (5..=len).map(at).filter(|&r| r != 0).collect());
                    (5..=len).filter(|&k| at(k) != 0).map(rref).collect()
                } else {
                    Vec::new()
                };
                sub.push(Entry {
                    words: c.to_vec(),
                    kind: Kind::Create(o),
                    objs: Vec::new(),
                    res,
                });
            }
            C_DESTROY_VIDEO_CODEC | C_DESTROY_VIDEO_BUFFER if len >= 1 => {
                if let Some(o) = video.remove(&at(1)) {
                    video_res.remove(&o);
                    sub.destroyed.insert(o);
                    sub.push(Entry {
                        words: c.to_vec(),
                        kind: Kind::Destroy(o),
                        objs: Vec::new(),
                        res: Vec::new(),
                    });
                }
            }
            // What the GPU writes when it draws.
            C_DRAW_VBO | C_CLEAR => {
                writes.extend(sub.fb.iter().filter_map(|o| sub.obj_res.get(o)));
                if cmd == C_DRAW_VBO {
                    writes.extend(sub.so.iter().filter_map(|o| sub.obj_res.get(o)));
                    writes.extend(sub.ssbo.values());
                    writes.extend(sub.images.values());
                    writes.extend(sub.atomics.values());
                }
            }
            C_LAUNCH_GRID => {
                writes.extend(sub.ssbo.values());
                writes.extend(sub.images.values());
                writes.extend(sub.atomics.values());
            }
            C_CLEAR_SURFACE if len >= 2 => {
                if let Some(o) = sub.objects.get(&at(2)) {
                    writes.extend(sub.obj_res.get(o));
                }
            }
            C_DECODE_BITSTREAM | C_END_FRAME if len >= 2 => {
                if let Some(o) = video.get(&at(2)) {
                    writes.extend(video_res.get(o).into_iter().flatten());
                }
            }
            _ => {}
        }
        for id in writes {
            if id != 0 {
                self.gpu_write(id, marks);
            }
        }
    }

    /// The resources the GPU wrote that exist now, the scanout first: what a planned switch
    /// exports from the old renderer.
    pub fn gpu_written(&self) -> Vec<u32> {
        let scanout = self.scanout.as_ref().map_or(0, |s| u32_at(s, 44));
        let mut v: Vec<u32> = self
            .resources
            .iter()
            .filter(|(_, r)| r.gpu_written)
            .map(|(&id, _)| id)
            .collect();
        if let Some(i) = v.iter().position(|&id| id == scanout) {
            v.remove(i);
            v.insert(0, scanout);
        }
        v
    }

    /// The scanout's resource, if one is shown.
    pub fn scanout_resource(&self) -> Option<u32> {
        self.scanout.as_ref().map(|s| u32_at(s, 44))
    }

    pub fn resource_ids(&self) -> Vec<u32> {
        self.resources.keys().copied().collect()
    }

    /// The resources that hold uploads and that the GPU never wrote (their whole content came
    /// from the guest).
    pub fn upload_only(&self) -> Vec<u32> {
        self.resources
            .iter()
            .filter(|(_, r)| !r.gpu_written && !r.uploads.is_empty())
            .map(|(&id, _)| id)
            .collect()
    }

    pub fn stats(&self) -> Stats {
        let mut s = Stats {
            resources: self.resources.len() as u64,
            contexts: self.contexts.len() as u64,
            upload_bytes: self.upload_bytes,
            ..Default::default()
        };
        for r in self.resources.values().filter(|r| r.gpu_written) {
            s.gpu_written += 1;
            s.gpu_written_bytes += r.size();
        }
        for sub in self.contexts.values().flat_map(|c| c.subs.values()) {
            s.log_entries += sub.log.len() as u64;
            s.log_bytes += sub
                .log
                .iter()
                .map(|e| 4 * e.words.len() as u64)
                .sum::<u64>();
        }
        s
    }

    /// Build the state again in a renderer that holds only the resources in `kept` (with their
    /// contents and backing): `out` gets the messages in order (see the protocol: contexts,
    /// resources and their backing, uploads, attachments, each context's journal, the scanout
    /// and a flush, the cursor).
    pub fn rebuild(&self, kept: &BTreeSet<u32>, out: &mut dyn FnMut(Msg<'_>)) {
        for c in self.contexts.values() {
            out(Msg::Ctrl(c.create.clone()));
        }
        for &id in self.resources.keys() {
            if !kept.contains(&id) {
                self.rebuild_resource(id, out);
            }
        }
        for (&ctx_id, c) in &self.contexts {
            self.rebuild_ctx(ctx_id, c, out);
        }
        if let Some(s) = &self.scanout {
            out(Msg::Ctrl(s.clone()));
            if let Some(f) = &self.flush {
                out(Msg::Ctrl(f.clone()));
            }
        }
        if let Some(c) = &self.cursor {
            out(Msg::Cursor(c));
        }
    }

    /// One resource: its creation, its backing and its uploads.
    pub fn rebuild_resource(&self, id: u32, out: &mut dyn FnMut(Msg<'_>)) {
        let Some(r) = self.resources.get(&id) else {
            return;
        };
        out(Msg::Ctrl(r.create.clone()));
        if let Some(a) = &r.attach {
            out(Msg::Ctrl(a.clone()));
        }
        for u in &r.uploads {
            let h = xfer(id, 0, u.level, u.stride, u.layer_stride, 0, u.bx);
            out(Msg::Import(h, &u.data));
        }
    }

    /// The scanout and the last flush, to show the picture again.
    pub fn scanout_cmds(&self) -> Vec<Vec<u8>> {
        self.scanout
            .iter()
            .chain(self.scanout.as_ref().and(self.flush.as_ref()))
            .cloned()
            .collect()
    }

    /// The last cursor (an `UPDATE_CURSOR` at the last position).
    pub fn cursor_cmd(&self) -> Option<&[u8]> {
        self.cursor.as_deref()
    }

    fn rebuild_ctx(&self, ctx_id: u32, c: &Ctx, out: &mut dyn FnMut(Msg<'_>)) {
        let live = |id: u32, g: u64| self.resources.get(&id).is_some_and(|r| r.generation == g);
        // Objects whose resource is gone are not made again, and words that name them, or a
        // resource that is gone, become 0 (nothing bound): the guest destroyed what they name,
        // so its later commands do not use them.
        let mut skipped: HashSet<u64> = HashSet::new();
        let mut referenced: BTreeSet<u32> = BTreeSet::new();
        let kept: HashMap<u32, Vec<bool>> =
            c.subs.iter().map(|(&s, sub)| (s, sub.kept())).collect();
        for (s, sub) in &c.subs {
            for (e, _) in sub.log.iter().zip(&kept[s]).filter(|x| *x.1) {
                if let Kind::Create(o) = e.kind
                    && e.res.iter().any(|&(_, id, g)| !live(id, g))
                {
                    skipped.insert(o);
                }
                referenced.extend(e.res.iter().filter(|&&(_, id, g)| live(id, g)).map(|r| r.1));
            }
        }
        let extra: Vec<u32> = referenced.difference(&c.attached).copied().collect();
        for &id in c.attached.iter().chain(&extra) {
            if self.resources.contains_key(&id) {
                let mut r = hdr(CMD_CTX_ATTACH_RESOURCE, ctx_id, 32);
                r[24..28].copy_from_slice(&id.to_le_bytes());
                out(Msg::Ctrl(r));
            }
        }
        let mut words: Vec<u32> = Vec::new();
        let flush = |words: &mut Vec<u32>, out: &mut dyn FnMut(Msg<'_>)| {
            if words.is_empty() {
                return;
            }
            let mut r = hdr(CMD_SUBMIT_3D, ctx_id, 32);
            r[24..28].copy_from_slice(&u32::try_from(words.len() * 4).unwrap().to_le_bytes());
            r.extend(words.iter().flat_map(|w| w.to_le_bytes()));
            out(Msg::Ctrl(r));
            words.clear();
        };
        for &s in &c.order {
            let Some(sub) = c.subs.get(&s) else { continue };
            if s != 0 {
                words.extend([cmd_word(C_CREATE_SUB_CTX, 0, 1), s]);
            }
            words.extend([cmd_word(C_SET_SUB_CTX, 0, 1), s]);
            for (e, _) in sub.log.iter().zip(&kept[&s]).filter(|x| *x.1) {
                if let Kind::Create(o) | Kind::Destroy(o) = e.kind
                    && skipped.contains(&o)
                {
                    continue;
                }
                let start = words.len();
                words.extend_from_slice(&e.words);
                for &(k, o) in &e.objs {
                    if skipped.contains(&o) {
                        words[start + k] = 0;
                    }
                }
                for &(k, id, g) in &e.res {
                    if !live(id, g) {
                        words[start + k] = 0;
                    }
                }
                if words.len() * 4 >= SUBMIT_MAX {
                    flush(&mut words, out);
                    words.extend([cmd_word(C_SET_SUB_CTX, 0, 1), s]);
                }
            }
        }
        words.extend([cmd_word(C_SET_SUB_CTX, 0, 1), c.cur]);
        flush(&mut words, out);
        for id in extra {
            let mut r = hdr(CMD_CTX_DETACH_RESOURCE, ctx_id, 32);
            r[24..28].copy_from_slice(&id.to_le_bytes());
            out(Msg::Ctrl(r));
        }
    }

    /// The format, size and kind of a resource, for tools: (target, format, bind, width,
    /// height, depth, array size, levels - 1, samples, GPU-written, upload bytes).
    pub fn describe(&self, id: u32) -> Option<String> {
        let r = self.resources.get(&id)?;
        Some(format!(
            "res={id} target={} format={} bind={:#x} {}x{}x{} array={} last_level={} samples={} gpu_written={} uploads={} upload_bytes={} size={}",
            r.target,
            r.format,
            r.bind,
            r.width,
            r.height,
            r.depth,
            r.array_size,
            r.last_level,
            r.nr_samples,
            u8::from(r.gpu_written),
            r.uploads.len(),
            r.upload_bytes,
            r.size()
        ))
    }

    /// (target, format, bind, width, height, depth, array size, last level, samples) of a
    /// resource.
    pub fn resource_args(&self, id: u32) -> Option<[u32; 9]> {
        let r = self.resources.get(&id)?;
        Some([
            r.target,
            r.format,
            r.bind,
            r.width,
            r.height,
            r.depth,
            r.array_size,
            r.last_level,
            r.nr_samples,
        ])
    }

    /// The uploads of a resource as kind-0 imports (header, bytes), for tools that compare a
    /// renderer's contents with what the guest uploaded.
    pub fn uploads_of(&self, id: u32) -> Vec<([u8; XFER_LEN], &[u8])> {
        self.resources.get(&id).map_or_else(Vec::new, |r| {
            r.uploads
                .iter()
                .map(|u| {
                    (
                        xfer(id, 0, u.level, u.stride, u.layer_stride, 0, u.bx),
                        &u.data[..],
                    )
                })
                .collect()
        })
    }

    /// The 64-bit backing size of a resource (0 = none).
    pub fn backing(&self, id: u32) -> u64 {
        self.resources.get(&id).map_or(0, |r| r.backing)
    }

    /// The fence id field of a request (for tools).
    pub fn fence_id(req: &[u8]) -> u64 {
        u64_at(req, 8)
    }
}

#[cfg(test)]
mod tests;
