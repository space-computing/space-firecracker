// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A virtio-gpu device (virgl 3D) that renders nothing on the host.
//!
//! It is the source half of the remote GPU of the Spacebox QEMU fork, written for Firecracker
//! (`hw/display/virtio-gpu-remote.c` of `space-qemu`, the functions `sp_source_*`): every
//! control command goes to the renderer on the user's device (the sink) together with the guest
//! memory it refers to. The device keeps what that needs (the resources with their format, size
//! and backing in guest memory) and what lets it answer the guest without waiting for the
//! network:
//!
//! - Commands whose answer carries nothing are answered at once; fenced ones up to a window of
//!   commands and an age ahead of the sink, a longer age while the guest decodes video
//!   ([`Gpu::may_answer_early`]).
//! - Reads of query result buffers are answered from guest memory, which the sink keeps current
//!   (it watches the buffers), and parked while the result is not in yet.
//! - Capability queries are answered from the GPU spec ([`super::spec`], `spec_path`) from the
//!   first moment, with no renderer; every renderer checks at its pairing that it can do the
//!   spec (`SP_SPEC`), and one that cannot is not paired. Display and EDID queries are answered
//!   from what the sink sent ahead (`SP_INFO`).
//!
//! The connection ([`super::link`]) resumes after a loss: both ends keep what the other has not
//! acknowledged. Every command that is sent also goes into the journal ([`gpu_journal`]), from
//! which the device builds the renderer's state again in a renderer that holds none of it: a
//! sink that restarted, or the other renderer of a switch. With the renderer inside the guest
//! (`guest_renderer_socket_path`: the same sink, run in the guest on the guest's CPU, which
//! connects out through vsock to the device), the user's renderer that detaches hands its state
//! over (a planned switch: the journal, then what only its GPU wrote, the scanout first); one that
//! is gone or silent for 10 s is replaced (a sudden loss: the journal only, then the guest agent
//! makes every program draw again); and while the in-guest renderer runs, the device keeps trying
//! the user's renderer, which is attached again by a planned switch when it connects. The
//! in-guest renderer's state is in guest memory: a snapshot, a move or a checkpoint takes it with
//! the device's own at the same instant, so the device waits for it and exports from it at none
//! of them, and after a restore it connects again and resumes.
//!
//! The device's events run on the screen's thread (`fc_screen`, [`crate::devices::screen`]),
//! which the VMM thread pauses at every stop of the guest; what the VMM thread does with the
//! device (the save, the restore, the resume) runs while that thread is paused.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gpu_journal::{FORMAT_BLOCKS, FORMAT_COUNT, Journal, Msg, transfer_range};
use utils::time::TimerFd;
use vmm_sys_util::eventfd::EventFd;

use super::agent::Agent;
use super::input::{Input, InputKind, translate};
use super::link::{DelayStat, Link, RxEvent, now_us};
use super::protocol::{
    Filter, HDR_LEN, Hdr, SP_ACK, SP_AUDIO, SP_BYE, SP_CTRL, SP_CURSOR, SP_DETACH, SP_DISPLAY,
    SP_EXPECT, SP_EXPORT, SP_EXPORT_DATA, SP_EXPORT_DONE, SP_F_RESTORED, SP_F_SCROLL, SP_F_SPEC,
    SP_F_VIDEO, SP_F_ZSTD, SP_GPU, SP_GPU_STATE, SP_HELLO, SP_IMPORT, SP_INFO, SP_INPUT,
    SP_MEMWRITE, SP_PICTURE, SP_RESET, SP_RESP, SP_SCROLL, SP_SPEC, SP_SPEC_REPLY, SP_STATE_KEPT,
    SP_STATE_RESET, SP_STREAM, SP_WMARK, push_expect, u32_at, u64_at,
};
use super::spec::Spec;
use super::{CTRL_QUEUE, CURSOR_QUEUE, GPU_NUM_QUEUES};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::queue::{
    FIRECRACKER_MAX_QUEUE_SIZE, InvalidAvailIdx, Queue, QueueConfig, QueueError,
};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::impl_device_type;
use crate::logger::{error, info, warn};
use crate::seccomp::BpfProgram;
use crate::vmm_config::gpu::GpuConfig;
use crate::vstate::memory::{Bytes, GuestAddress, GuestMemoryMmap};
use vm_memory::GuestMemoryBackend;

pub const GPU_DEV_ID: &str = "gpu";

const VIRTIO_GPU_F_VIRGL: u64 = 0;
const VIRTIO_GPU_F_EDID: u64 = 1;
const VIRTIO_GPU_F_CONTEXT_INIT: u64 = 4;

const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const CMD_RESOURCE_UNREF: u32 = 0x0102;
const CMD_RESOURCE_FLUSH: u32 = 0x0104;
const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
const CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
const CMD_GET_CAPSET_INFO: u32 = 0x0108;
const CMD_GET_CAPSET: u32 = 0x0109;
const CMD_GET_EDID: u32 = 0x010a;
const CMD_RESOURCE_CREATE_BLOB: u32 = 0x010c;
const CMD_CTX_CREATE: u32 = 0x0200;
const CMD_RESOURCE_CREATE_3D: u32 = 0x0204;
const CMD_TRANSFER_TO_HOST_3D: u32 = 0x0205;
const CMD_TRANSFER_FROM_HOST_3D: u32 = 0x0206;
const CMD_SUBMIT_3D: u32 = 0x0207;
const CMD_RESOURCE_MAP_BLOB: u32 = 0x0208;
const CMD_RESOURCE_UNMAP_BLOB: u32 = 0x0209;
const CMD_UPDATE_CURSOR: u32 = 0x0300;
const RESP_OK_NODATA: u32 = 0x1100;
const RESP_OK_CAPSET_INFO: u32 = 0x1102;
const RESP_OK_CAPSET: u32 = 0x1103;
const RESP_ERR_UNSPEC: u32 = 0x1200;
const FLAG_FENCE: u32 = 1;
/// `VIRTIO_GPU_EVENT_DISPLAY` of `events_read`: the display information changed.
const VIRTIO_GPU_EVENT_DISPLAY: u64 = 1;

const CAPSET_VIRGL: u32 = 1;
const CAPSET_VIRGL2: u32 = 2;
/// The capsets the device advertises, by index (the spec has exactly these).
pub(crate) const CAPSET_IDS: [u32; 2] = [CAPSET_VIRGL, CAPSET_VIRGL2];

/// `struct virtio_gpu_ctrl_hdr`.
const HDR: usize = 24;
/// `struct virtio_gpu_update_cursor`.
const CURSOR_LEN: usize = 56;
/// The largest request taken from the guest (a command stream is far smaller).
const MAX_REQ: usize = 64 << 20;
/// The largest number of backing entries of one resource (`virtio_gpu_create_mapping_iov`).
const MAX_ENTRIES: u32 = 16384;
/// Send times of fenced commands the sink has not answered yet.
const FQ_LEN: usize = 512;
/// `VIRGL_QUERY_STATE_WAIT_HOST`.
const QUERY_STATE_WAIT_HOST: u32 = 2;

const ACK_PERIOD: Duration = Duration::from_millis(100);
const STATS_PERIOD: Duration = Duration::from_secs(5);
const RECONNECT: Duration = Duration::from_millis(250);
const BACKLOG_RETRY: Duration = Duration::from_millis(1);
/// With an in-guest renderer: how long the user's renderer may be gone or silent before the
/// in-guest renderer takes over.
const TAKEOVER_US: i64 = 10_000_000;
/// With no in-guest renderer: how long a renderer that was paired and is lost is waited for (the
/// guest's commands wait for it, and it resumes) before the device serves the guest alone and
/// the renderer starts empty when it comes back: longer than the cut of 60 s that the screen
/// track's D1 (c) resumes (the agent's choice, 2026-10-19).
const LOST_WAIT_US: i64 = 120_000_000;
/// How long the in-guest renderer that runs the guest and is lost is waited for (a renderer that
/// restarts, or its link after a reset of vsock, is back within it) before the device serves the
/// guest alone and that renderer starts empty when it comes back: the guest's shutdown stops it,
/// and the guest's last GPU work must not wait for it.
const GUEST_LOST_WAIT_US: i64 = 5_000_000;
/// How long a device that no renderer has paired with since it was made waits for its first
/// one before it serves the guest alone (the user's renderer is opened before the guest starts;
/// a guest whose user's device is not attached must still run and shut down).
const FIRST_WAIT_US: i64 = 5_000_000;
/// Before a snapshot: how long the device waits for its renderer to answer and acknowledge
/// everything.
const SAVE_WAIT_US: i64 = 2_000_000;
/// A renderer that cannot do the spec is tried again this long after its refusal.
const SPEC_RETRY_US: i64 = 5_000_000;
/// After a rollback the redraw (K6) comes this long after the VM resumes, so that the first
/// picture is the snapshot's (the user's choice of 2026-10-17).
const ROLLBACK_REDRAW_US: i64 = 2_000_000;
/// A picture of the in-guest renderer for the user's renderer is dropped while more than this
/// waits to be sent on the user's link (a newer one comes).
const PICTURE_BACKLOG: usize = 1 << 20;
/// The user's toggle off waits this long for an in-guest renderer that is not connected (after a
/// switch back it connects again within a second) before it is refused.
const OFF_WAIT_US: i64 = 5_000_000;
/// The guest's cursor (`struct virtio_gpu_update_cursor` names a resource of 64 x 64, 32 bit).
const CURSOR_BYTES: u64 = 64 * 64 * 4;
/// A piece of a renderer's export, as an `SP_IMPORT` (the header, the bytes).
type Piece = (Vec<u8>, Vec<u8>);

/// What the device's last save was readied for (`prepare_save`, `prepare_move`,
/// `prepare_checkpoint`): the saved state says what a rollback to it lacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SaveKind {
    /// A snapshot: the device waited for its renderer and exported what the GPU drew.
    Snapshot,
    /// The stop of a move (a snapshot of the state only): nothing waited for, nothing exported;
    /// the connections closed.
    Move,
    /// A checkpoint of a running guest: nothing waited for, nothing exported, the connections
    /// kept.
    Checkpoint,
}

/// How many of the resources shown last are exported first at a snapshot (the compositor's swap
/// chain).
const SCANOUT_KEEP: usize = 4;
/// A snapshot's export of what the GPU drew (the shown resources, then the rest) goes on while
/// the renderer sends: it ends when it is complete, when the renderer is gone, or when the
/// renderer has sent nothing for this long. A slow link makes the snapshot longer, not
/// incomplete.
const SAVE_EXPORT_SILENCE_US: i64 = 2_000_000;

/// The connections: the user's renderer, and the renderer inside the guest.
pub(crate) const USER: usize = 0;
pub(crate) const GUEST: usize = 1;
const CONN_NAMES: [&str; 2] = ["the user's renderer", "the in-guest renderer"];

/// The layout of picture data about to be sent (`sp_tx_hint`), for the compression filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hint {
    bpp: u32,
    stride: u32,
    /// It is the b part of the message (else the a part).
    in_b: bool,
}

/// `sp_source_hint`: the data about to be sent is pixels of a texture. stride 0 = the rows are
/// as wide as the texture's level. Buffers (one row) and block-compressed formats get none.
fn hint_for(tex: Option<&Resource>, level: u32, stride: u32, in_b: bool) -> Option<Hint> {
    let tex = tex?;
    let (bw, bh, bits) = *FORMAT_BLOCKS.get(tex.format as usize)?;
    if tex.height <= 1 || (tex.format as usize) >= FORMAT_COUNT || bits < 8 || bw != 1 || bh != 1 {
        return None;
    }
    let bs = u32::from(bits / 8);
    let lw = if level < 32 { tex.width >> level } else { 0 }.max(1);
    Some(Hint {
        bpp: bs,
        stride: if stride != 0 { stride } else { lw * bs },
        in_b,
    })
}

#[derive(Debug, Clone)]
pub(crate) struct Resource {
    format: u32,
    width: u32,
    height: u32,
    /// (guest address, length) of each backing entry, in order.
    backing: Option<Vec<(u64, u32)>>,
}

impl Resource {
    fn backing_size(&self) -> u64 {
        self.backing
            .as_ref()
            .map_or(0, |b| b.iter().map(|e| u64::from(e.1)).sum())
    }
}

/// A guest command not answered yet: where its answer goes.
#[derive(Debug)]
struct Cmd {
    head: u16,
    writable: Vec<(GuestAddress, u32)>,
}

/// `SpPending`: a command sent to the sink with a sequence number.
#[derive(Debug)]
struct Pending {
    /// None once the guest has its answer (`early`).
    cmd: Option<Cmd>,
    typ: u32,
    res: u32,
    off: u64,
    len: u64,
    seq: u64,
    t0: i64,
    early: bool,
    /// Fenced and waiting for the sink; counted in `wait_out`.
    fence_wait: bool,
    /// ... and the sink's answer brings data; counted in `hard_out`.
    hard: bool,
    /// The request's fence, for an answer made here when the renderer is lost.
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
}

/// `SpParked`: a guest read of a query result buffer whose result is not in yet.
#[derive(Debug)]
struct Parked {
    cmd: Cmd,
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    res: u32,
    t0: i64,
}

/// A connection to a renderer, and its protocol state (`sp` of the QEMU source).
#[derive(Debug)]
pub(crate) struct Conn {
    pub(crate) link: Link,
    /// The renderer's session this connection is paired with; 0 = none, the next HELLO starts
    /// the renderer empty.
    pub(crate) peer_session: u64,
    pub(crate) hello_done: bool,
    pub(crate) rx_id: u64,
    rx_id_acked: u64,
    /// When the connection was lost (or the device made).
    lost_at: i64,
    /// The renderer said it is ending on purpose (`SP_DETACH`).
    detaching: bool,
    /// Keep connecting to it.
    pub(crate) wanted: bool,
    /// The resources listed in an `SP_WMARK` on this pairing since its newest mark point: the
    /// newest message id that the device may ask this renderer to reset to (`SP_STATE_RESET`
    /// N keeps what was not written after N). A resource written again before the next point
    /// needs no new mark: one mark after the point already makes the renderer's `written` of
    /// it newer than every point. A new pairing or a state reset is a point; so must be any
    /// later message id that the device keeps to reset to (a snapshot).
    marked: HashSet<u32>,
    /// The device was restored from a snapshot and has not been paired with this renderer
    /// since: its HELLO says so (`SP_F_RESTORED`).
    pub(crate) restored: bool,
    /// The renderer of `peer_session` said that it can do the spec (`SP_SPEC_REPLY`). A new
    /// pairing is sent the spec and runs nothing before the answer; a pairing lost before it
    /// starts again ([`Gpu::disconnected`]).
    pub(crate) spec_ok: bool,
    /// The renderer said that it cannot do the spec, and has not said otherwise since: it is
    /// tried again [`SPEC_RETRY_US`] after `refused_at`, and the device switches to it no more.
    pub(crate) refused: bool,
    refused_at: i64,
    /// Its refusals (logged at 1, 2, 4, ...).
    n_refused: u64,
}

impl Conn {
    fn up(&self) -> bool {
        self.link.is_connected() && self.hello_done && self.spec_ok
    }
}

/// Where a switch to another renderer (or a rebuild of the same one) is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Waiting for the new renderer's HELLO.
    Connect,
    /// `SP_STATE_RESET` sent; waiting for `SP_STATE_KEPT`.
    Reset,
    /// Waiting for the old renderer to answer what it was sent.
    Drain,
    /// The scanout's export from the old renderer goes to the new one.
    Scanout,
    /// The rest of the export.
    Rest,
}

/// A switch: the state of renderer `to` is built again from the journal; with `from` (a
/// planned switch), what only the GPU wrote is taken from it.
#[derive(Debug)]
pub(crate) struct Switch {
    pub(crate) from: Option<usize>,
    pub(crate) to: usize,
    pub(crate) phase: Phase,
    t0: i64,
    kept: BTreeSet<u32>,
    scanout: Option<u32>,
    msgs: u64,
    bytes: u64,
    chunks: u64,
    chunk_bytes: u64,
    why: &'static str,
    /// The message id that the new renderer is reset to (`SP_STATE_RESET` N): 0 = it keeps
    /// nothing; after a rollback, the last id of the snapshot.
    reset_to: u64,
    /// The request id of the export the switch waits for (0 = none).
    export: u64,
}

/// A snapshot's export while it is taken.
#[derive(Debug, Default)]
struct SnapExport {
    /// Its request id: the replies carry it.
    id: u64,
    done: bool,
    /// What came, as `SP_IMPORT`s.
    pieces: Vec<Piece>,
    /// The resources the renderer said it did not export (`SP_EXPORT_DONE`).
    skipped: Vec<u32>,
}

/// Queries of the guest that the sink's information answers, by how they were handled.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct QueryCounts {
    pub capset_info: u64,
    pub capset: u64,
    pub display_info: u64,
    pub edid: u64,
    /// Forwarded to the sink before any `SP_INFO` had arrived on this sink's session.
    pub forwarded_before_info: u64,
    /// Forwarded although the sink's information had arrived.
    pub forwarded_after_info: u64,
}

/// The device's counters (the `sp.*` statistics of the QEMU source), reported every 5 s.
#[derive(Debug, Default)]
pub(crate) struct Counters {
    n_ctrl: u64,
    n_submit: u64,
    submit_bytes: u64,
    n_xfer: u64,
    xfer_bytes: u64,
    n_mem: u64,
    mem_bytes: u64,
    n_back: u64,
    back_bytes: u64,
    tx_bytes: u64,
    n_early: u64,
    n_local: u64,
    n_waited: u64,
    n_ahead: u64,
    /// ... of which with the age of video.
    n_ahead_video: u64,
    n_defer: u64,
    defer_bytes: u64,
    n_reconnect: u64,
    /// Input of the sink, and the part of it with no input device to take it.
    n_input: u64,
    n_input_dropped: u64,
    /// Replies (`SP_EXPORT_DATA`, `SP_EXPORT_DONE`) of an export that is not the one waited for
    /// (a late reply of an export that ended without it): dropped.
    pub(crate) export_stale: u64,
    /// Spacing of the guest's screen updates (`RESOURCE_FLUSH`).
    flush: DelayStat,
    flush_last: i64,
    /// Time from sending a command to the sink's answer.
    delay: DelayStat,
    /// How much later than the fastest one a message arrived.
    rxd: DelayStat,
    rx_min: i64,
    rx_min_prev: i64,
    rx_min_t0: i64,
    pub queries: QueryCounts,
    pub sound: SoundCounts,
    /// `SP_WMARK` messages sent, the ids in them, and the ids left out (marked already).
    n_wmark: u64,
    wmark_ids: u64,
    wmark_skipped: u64,
    /// The in-guest renderer's pictures passed to the user's renderer, their bytes, those dropped
    /// for the user's link's backlog, and those that came with no stream asked (in the interval).
    pub(crate) n_picture: u64,
    picture_bytes: u64,
    pub(crate) pictures_dropped: u64,
    pub(crate) pictures_late: u64,
}

/// The sound device's samples sent on this connection (since the start).
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SoundCounts {
    pub messages: u64,
    pub bytes: u64,
    /// Played while no sink was connected: not sent.
    pub not_sent: u64,
    /// Due to be played, but the guest had not queued them yet.
    pub short_bytes: u64,
}

/// The keyboard and the tablet.
type InputPair = (Arc<Mutex<Input>>, Arc<Mutex<Input>>);

/// [`Gpu::traffic`]: pictures passed on, and (sent, received) message ids of each renderer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GpuTraffic {
    /// The in-guest renderer's pictures passed to the user's renderer since the start.
    pub pictures: u64,
    /// The user's renderer: the last message id sent, the last received.
    pub user: (u64, u64),
    /// The in-guest renderer: the last message id sent, the last received.
    pub guest: (u64, u64),
}

#[derive(Debug)]
pub struct Gpu {
    avail_features: u64,
    acked_features: u64,
    activate_event: EventFd,

    device_state: DeviceState,
    pub(crate) queues: Vec<Queue>,
    queue_events: Vec<EventFd>,

    /// `struct virtio_gpu_config`: events_read, events_clear, num_scanouts, num_capsets.
    config: [u8; 16],
    /// What the device was made from (`GET /vm/config`).
    pub(crate) cfg: GpuConfig,

    /// The user's renderer, and the in-guest renderer if one is configured.
    pub(crate) conns: Vec<Conn>,
    /// The renderer that runs the guest's commands.
    pub(crate) active: usize,
    pub(crate) switch: Option<Switch>,
    /// What the renderer's state is made of (see [`gpu_journal`]).
    pub(crate) journal: Journal,
    /// Bytes pushed for the command being sent, which the journal keeps as uploads.
    pushed: HashMap<(u32, u64), Vec<u8>>,
    pub(crate) retry_timer: TimerFd,
    pub(crate) ack_timer: TimerFd,
    pub(crate) stats_timer: TimerFd,
    pub(crate) runtime_events_registered: bool,
    stats_out: Option<File>,
    debug_wait: bool,
    debug_shown: u32,

    /// This device's session (`sp.session`).
    session: u64,
    /// Any `SP_INFO` has arrived from the renderer whose information the guest is shown.
    info_seen: bool,
    /// A renderer sent capsets in `SP_INFO` (a sink that does not know the spec): said once;
    /// the guest is shown the spec's.
    caps_ignored_said: bool,
    /// The user's renderer has sent its information (the guest is shown its display).
    user_info: bool,
    pub(crate) n_switch: u64,
    tx_hint: Option<Hint>,

    // The source's state.
    resources: HashMap<u32, Resource>,
    seq: u64,
    pending: HashMap<u64, Pending>,
    /// (ctx << 32 | query handle) -> resource id.
    queries: HashMap<u64, u32>,
    /// Resource ids used as query result buffers.
    query_bufs: HashSet<u32>,
    /// Buffers that live only in renderer memory.
    custom_bufs: HashSet<u32>,
    parked: VecDeque<Parked>,
    ctx_name: Vec<String>,
    ctx_qpoll: [u32; 64],
    /// The GPU spec: the capsets the guest is shown, and what each renderer checks.
    pub(crate) spec: Spec,
    dinfo: Option<Vec<u8>>,
    edid: Option<Vec<u8>>,
    /// The guest decodes video until about then: one second after its last decode command.
    video_until: i64,

    tx_limit: usize,
    fence_window: u32,
    /// Answered early, not yet finished by the sink.
    fence_out: u32,
    /// Fenced commands waiting for the sink.
    wait_out: u32,
    /// ... of which the answer brings data.
    hard_out: u32,
    fq: [i64; FQ_LEN],
    fq_head: usize,
    fq_len: usize,
    fence_age_us: i64,
    /// `fence_age_us` while the guest decodes video.
    fence_age_video_us: i64,
    rtt_min_cur: i64,
    rtt_min_prev: i64,
    rtt_min_t0: i64,
    rtt_us: i64,

    pub(crate) counters: Counters,
    /// The in-guest renderer's pictures passed to the user's renderer since the start.
    pictures_all: u64,
    /// Used elements were added to a queue: advance its used index and interrupt.
    used: [bool; GPU_NUM_QUEUES],

    /// The keyboard and the tablet that the sink's input goes to (`input` of the config).
    inputs: Option<InputPair>,
    /// The channel to the guest agent (`agent_socket_path` of the config).
    pub(crate) agent: Option<Agent>,
    /// The agent is to make every program draw again, when it is connected (after a restore
    /// its vsock connection is new).
    redraw_pending: bool,
    /// A rollback rebuilt the renderer: the redraw waits for the VM's resume, then
    /// [`ROLLBACK_REDRAW_US`].
    pub(crate) redraw_after_resume: bool,
    /// When that redraw is due (microseconds of [`now_us`]); checked every 100 ms.
    pub(crate) redraw_at: Option<i64>,
    /// When the VM last resumed in this process (`kick`).
    resumed_at: Option<i64>,
    /// The resources shown last (`SET_SCANOUT`), the newest last: the compositor's swap chain.
    scanned: Vec<u32>,
    /// The request id of the last export asked of a renderer (each export has its own; the
    /// first one is random, so that a reply to another device or process is not taken).
    export_seq: u64,
    /// A snapshot's export while it is taken.
    snap_export: Option<SnapExport>,
    /// What the GPU drew into the resources it wrote (the shown ones first) at the last snapshot
    /// (for the side file), or, in a restored device, at the snapshot it was restored from:
    /// imported into a renderer that is reset to the snapshot and does not keep them (a
    /// rollback), so that they hold what the guest believes they hold. Dropped once the guest
    /// runs on.
    pub(crate) scanout_saved: Vec<Piece>,
    /// The resources the GPU wrote whose content that snapshot lacks (an export did not
    /// complete, or the renderer could not answer): in the side file; a rollback that does not
    /// keep one of them logs it (the redraw still comes 2 s after the resume). Dropped with
    /// `scanout_saved`.
    pub(crate) saved_missing: Vec<u32>,

    /// A snapshot is being taken: no command of the guest is taken.
    saving: bool,
    /// What the last save was readied for.
    pub(crate) save_kind: SaveKind,
    /// Which renderers were wanted before the snapshot closed the connections: wanted again
    /// when the VM resumes (`kick`).
    saved_wanted: Option<Vec<bool>>,
    /// When the device was made (or restored): the start of [`FIRST_WAIT_US`].
    made_at: i64,
    /// The device serves the guest alone (`alone`): said once in the log each time it begins.
    alone_said: bool,
    /// Commands of a lost renderer answered here since the last line about them, and when that
    /// line was written ([`Self::say_answered_lost`]).
    answered_lost: u64,
    answered_lost_said: i64,
    /// A renderer has paired with this device (or with the device of the state it was restored
    /// from): no first wait any more.
    paired_once: bool,
    /// Restored: at the resume every key and button that the guest holds is released (the
    /// releases sent after the state was taken went to the VM of before).
    pub(crate) release_at_kick: bool,

    /// The user's toggle is off (`SP_GPU`): the in-guest renderer runs the guest, and the user's
    /// link stays up for input, sound, the cursor and the pictures. Cleared when that link is lost:
    /// a user's renderer that comes back starts with it on.
    pub(crate) gpu_off: bool,
    /// The user turned it on; the switch back waits for the switch under way.
    gpu_on_pending: bool,
    /// When the user turned it off ([`OFF_WAIT_US`]).
    gpu_off_at: i64,
    /// The in-guest renderer was asked for pictures (`SP_STREAM`) on its current pairing.
    pub(crate) stream_on: bool,
    /// What the user's renderer was last told of its toggle (`SP_GPU_STATE`) on this pairing: on,
    /// or off; and that it used its toggle and has not been told what it made. A renderer that has
    /// not used it is told nothing.
    pub(crate) gpu_state_said: Option<bool>,
    gpu_state_owed: bool,
}

fn random_session() -> u64 {
    loop {
        let mut v = [0u8; 8];
        // SAFETY: getrandom writes at most 8 bytes into v.
        let n = unsafe { libc::getrandom(v.as_mut_ptr().cast(), 8, 0) };
        let x = u64::from_le_bytes(v);
        if n == 8 && x != 0 {
            return x;
        }
    }
}

impl Gpu {
    /// A device made from `cfg`, with the spec of its `spec_path`. Its I/O threads start now and
    /// run under `filter` (the `vmm` seccomp filter); connecting starts when the event loop runs.
    pub fn new(cfg: GpuConfig, filter: Arc<BpfProgram>) -> std::io::Result<Self> {
        let spec = Spec::load(&cfg.spec_path, &CAPSET_IDS)?;
        Self::with_spec(cfg, spec, filter)
    }

    /// A device made from `cfg` with `spec` (the spec of a snapshot).
    pub(crate) fn with_spec(
        cfg: GpuConfig,
        spec: Spec,
        filter: Arc<BpfProgram>,
    ) -> std::io::Result<Self> {
        let queue_events = (0..GPU_NUM_QUEUES)
            .map(|_| EventFd::new(libc::EFD_NONBLOCK))
            .collect::<Result<Vec<_>, _>>()?;
        let open = |p: &Option<String>| -> std::io::Result<Option<File>> {
            p.as_ref()
                .map(|p| OpenOptions::new().create(true).append(true).open(p))
                .transpose()
        };
        let stats_out = open(&cfg.stats_path)?;
        let dump = cfg.dump_path.as_ref().map(File::create).transpose()?;
        let conn = |link| Conn {
            link,
            peer_session: 0,
            hello_done: false,
            rx_id: 0,
            rx_id_acked: 0,
            lost_at: now_us(),
            detaching: false,
            wanted: true,
            marked: HashSet::new(),
            restored: false,
            spec_ok: false,
            refused: false,
            refused_at: 0,
            n_refused: 0,
        };
        let mut conns = vec![conn(Link::new(
            "fc_gpu",
            cfg.socket_path.clone(),
            cfg.zstd_level(),
            filter.clone(),
            dump,
        )?)];
        if let Some(p) = &cfg.guest_renderer_socket_path {
            // Inside the guest: not compressed (memory to memory; zstd would cost the guest's CPU
            // and the device's). It connects to the device; paired when it takes over.
            let mut c = conn(Link::listen("fc_gpu_guest", p.clone(), 0, filter, None)?);
            c.wanted = false;
            conns.push(c);
        }
        let agent = cfg
            .agent_socket_path
            .as_deref()
            .map(Agent::new)
            .transpose()?;
        let mut retry_timer = TimerFd::new();
        retry_timer.arm(BACKLOG_RETRY, None);
        let mut ack_timer = TimerFd::new();
        ack_timer.arm(ACK_PERIOD, Some(ACK_PERIOD));
        let mut stats_timer = TimerFd::new();
        if stats_out.is_some() {
            stats_timer.arm(STATS_PERIOD, Some(STATS_PERIOD));
        }
        let mut gpu = Gpu {
            avail_features: (1 << VIRTIO_F_VERSION_1)
                | (1 << VIRTIO_GPU_F_VIRGL)
                | (1 << VIRTIO_GPU_F_EDID)
                | (1 << VIRTIO_GPU_F_CONTEXT_INIT),
            acked_features: 0,
            activate_event: EventFd::new(libc::EFD_NONBLOCK)?,
            device_state: DeviceState::Inactive,
            queues: vec![Queue::new(FIRECRACKER_MAX_QUEUE_SIZE); GPU_NUM_QUEUES],
            queue_events,
            config: [0; 16],
            conns,
            active: USER,
            switch: None,
            journal: Journal::new(),
            pushed: HashMap::new(),
            retry_timer,
            ack_timer,
            stats_timer,
            runtime_events_registered: false,
            stats_out,
            debug_wait: cfg.debug_wait.unwrap_or(false),
            debug_shown: 0,
            session: random_session(),
            info_seen: false,
            caps_ignored_said: false,
            user_info: false,
            n_switch: 0,
            tx_hint: None,
            resources: HashMap::new(),
            seq: 0,
            pending: HashMap::new(),
            queries: HashMap::new(),
            query_bufs: HashSet::new(),
            custom_bufs: HashSet::new(),
            parked: VecDeque::new(),
            ctx_name: vec![String::new(); 64],
            ctx_qpoll: [0; 64],
            spec,
            dinfo: None,
            edid: None,
            video_until: 0,
            tx_limit: cfg.tx_limit_bytes(),
            fence_window: cfg.fence_window(),
            fence_out: 0,
            wait_out: 0,
            hard_out: 0,
            fq: [0; FQ_LEN],
            fq_head: 0,
            fq_len: 0,
            fence_age_us: cfg.fence_age_us(),
            fence_age_video_us: cfg.fence_age_video_us(),
            rtt_min_cur: i64::MAX,
            rtt_min_prev: i64::MAX,
            rtt_min_t0: 0,
            rtt_us: 0,
            counters: Counters {
                rx_min: i64::MAX,
                rx_min_prev: i64::MAX,
                ..Default::default()
            },
            pictures_all: 0,
            used: [false; GPU_NUM_QUEUES],
            inputs: None,
            agent,
            redraw_pending: false,
            redraw_after_resume: false,
            redraw_at: None,
            resumed_at: None,
            scanned: Vec::new(),
            export_seq: random_session(),
            snap_export: None,
            scanout_saved: Vec::new(),
            saved_missing: Vec::new(),
            saving: false,
            save_kind: SaveKind::Snapshot,
            saved_wanted: None,
            made_at: now_us(),
            alone_said: false,
            answered_lost: 0,
            answered_lost_said: 0,
            paired_once: false,
            release_at_kick: false,
            gpu_off: false,
            gpu_on_pending: false,
            gpu_off_at: 0,
            stream_on: false,
            gpu_state_said: None,
            gpu_state_owed: false,
            cfg,
        };
        // One scanout; the two virgl capsets, of the spec.
        gpu.set_config(2, 1);
        gpu.set_config(3, u32::try_from(CAPSET_IDS.len()).unwrap());
        let msg = format!(
            "spacebox remote gpu: the spec {}: {}",
            gpu.spec.digest(),
            gpu.spec.describe()
        );
        gpu.log_info(&msg);
        Ok(gpu)
    }

    /// The keyboard and the tablet that take the sink's input.
    pub fn set_inputs(&mut self, keyboard: Arc<Mutex<Input>>, tablet: Arc<Mutex<Input>>) {
        self.inputs = Some((keyboard, tablet));
    }

    fn config_word(&self, i: usize) -> u32 {
        u32_at(&self.config, i * 4)
    }

    fn set_config(&mut self, i: usize, v: u32) {
        self.config[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn activate_event(&self) -> &EventFd {
        &self.activate_event
    }

    fn mem(&self) -> Option<GuestMemoryMmap> {
        self.device_state.active_state().map(|s| s.mem.clone())
    }

    /// A line for the statistics file (the QEMU source writes these to its stderr) and, for
    /// information and errors, Firecracker's log.
    fn report(&mut self, line: &str) {
        if let Some(f) = self.stats_out.as_mut() {
            let _ = writeln!(f, "{line}");
        }
    }

    fn log_info(&mut self, msg: &str) {
        info!("{msg}");
        self.report(msg);
    }

    pub(crate) fn log_info_line(&mut self, msg: &str) {
        self.log_info(msg);
    }

    fn log_error(&mut self, msg: &str) {
        error!("{msg}");
        self.report(msg);
    }

    pub(crate) fn log_error_line(&mut self, msg: &str) {
        self.log_error(msg);
    }

    // ---- sending -------------------------------------------------------------------------

    /// `sp_send_full`: queue a message for renderer `ci`. `reliable = false`: sent at most
    /// once, on the current connection only.
    #[allow(clippy::too_many_arguments)]
    fn send_on(
        &mut self,
        ci: usize,
        reliable: bool,
        typ: u32,
        seq: u64,
        a: &[u8],
        b: &[u8],
        arg0: u64,
        arg1: u64,
        arg2: u64,
    ) {
        let t_us = now_us();
        let hint = self.tx_hint.take();
        let c = &mut self.conns[ci];
        if !reliable && !c.link.is_connected() {
            return;
        }
        if reliable && c.hello_done && !c.spec_ok {
            // A new pairing before the renderer's yes to the spec: the renderer drops what comes
            // before its answer, so a reliable message would be written, dropped, and its id
            // given again after the queue is forgotten; the renderer then took the next message
            // with that id as one it had (a switch that waited for ever, G4's F4). What the
            // guest does meanwhile is in the journal, which the renderer gets after its yes.
            return;
        }
        let h = Hdr {
            typ,
            id: 0,
            ack: 0,
            seq,
            a_len: u32::try_from(a.len()).unwrap_or(u32::MAX),
            b_len: u32::try_from(b.len()).unwrap_or(u32::MAX),
            arg0,
            arg1,
            arg2,
            t_us,
            flags: if self.video_until > t_us {
                SP_F_VIDEO
            } else {
                0
            },
        };
        let filter = hint
            .filter(|h| (if h.in_b { b.len() } else { a.len() }) >= 4096)
            .map(|h| Filter {
                off: u32::try_from(HDR_LEN + if h.in_b { a.len() } else { 0 }).unwrap_or(u32::MAX),
                bpp: h.bpp,
                stride: h.stride,
            });
        let mut data = Vec::with_capacity(HDR_LEN + a.len() + b.len());
        data.extend_from_slice(&h.encode());
        data.extend_from_slice(a);
        data.extend_from_slice(b);
        self.counters.tx_bytes += data.len() as u64;
        c.link.push(data, reliable, c.rx_id, t_us, filter);
        c.rx_id_acked = c.rx_id;
    }

    /// A message for the renderer that runs the guest's commands.
    #[allow(clippy::too_many_arguments)]
    fn send_full(
        &mut self,
        reliable: bool,
        typ: u32,
        seq: u64,
        a: &[u8],
        b: &[u8],
        arg0: u64,
        arg1: u64,
        arg2: u64,
    ) {
        self.send_on(self.active, reliable, typ, seq, a, b, arg0, arg1, arg2);
    }

    #[allow(clippy::too_many_arguments)]
    fn send(&mut self, typ: u32, seq: u64, a: &[u8], b: &[u8], arg0: u64, arg1: u64, arg2: u64) {
        self.send_full(true, typ, seq, a, b, arg0, arg1, arg2);
    }

    fn send_ack(&mut self, ci: usize) {
        self.send_on(ci, false, SP_ACK, 0, &[], &[], 0, 0, 0);
    }

    /// The renderer that runs the guest's commands is there and takes them.
    fn active_up(&self) -> bool {
        self.conns[self.active].up() && self.switch.is_none()
    }

    /// The sound device played `samples` (`spacebox_remote_audio_out` of the QEMU source, which
    /// sends them on the main connection when the sound connection of its own is off, as in the
    /// trial): one unreliable message, sent only while the sink is there.
    pub(crate) fn send_audio(&mut self, rate: u32, channels: u32, samples: &[u8], short: u64) {
        let s = &mut self.counters.sound;
        s.short_bytes += short;
        if samples.is_empty() {
            return;
        }
        // the user's device plays it whichever renderer runs the guest (the toggle off)
        let ci = if self.conns[USER].up() {
            USER
        } else {
            self.active
        };
        if !self.conns[ci].up() {
            s.not_sent += samples.len() as u64;
            return;
        }
        s.messages += 1;
        s.bytes += samples.len() as u64;
        self.send_on(
            ci,
            false,
            SP_AUDIO,
            0,
            samples,
            &[],
            u64::from(rate),
            u64::from(channels),
            0,
        );
    }

    /// `sp_source_input`: the sink's input to the keyboard or the tablet, as QEMU's input layer
    /// passes it to its virtio-input devices (a key is sent with its own sync).
    fn input(&mut self, a: &[u8]) {
        if a.len() < 12 {
            return;
        }
        self.counters.n_input += 1;
        let Some((kbd, tab)) = &self.inputs else {
            self.counters.n_input_dropped += 1;
            return;
        };
        let (kind, x, v) = (u32_at(a, 0), u32_at(a, 4), u32_at(a, 8).cast_signed());
        if kind == 0 {
            kbd.lock().expect("Poisoned lock").sync();
            tab.lock().expect("Poisoned lock").sync();
            return;
        }
        match translate(kind, x, v) {
            Some((InputKind::Keyboard, ev)) => {
                let mut k = kbd.lock().expect("Poisoned lock");
                k.queue_events_of_report(&ev);
                k.sync();
            }
            Some((InputKind::Tablet, ev)) => {
                tab.lock()
                    .expect("Poisoned lock")
                    .queue_events_of_report(&ev);
            }
            None => self.counters.n_input_dropped += 1,
        }
    }

    /// Lines of the agent for the user's renderer (its scroll channel).
    pub(crate) fn agent_lines(&mut self, lines: &[u8]) {
        if !lines.is_empty() && self.conns[USER].up() {
            self.send_on(USER, true, SP_SCROLL, 0, lines, &[], 0, 0, 0);
        }
    }

    // ---- guest memory --------------------------------------------------------------------

    /// Copy between a range of a resource's backing and `buf`; returns the bytes done
    /// (`iov_to_buf` / `iov_from_buf`).
    fn backing_copy(
        mem: &GuestMemoryMmap,
        backing: &[(u64, u32)],
        mut off: u64,
        buf: &mut [u8],
        write: bool,
    ) -> usize {
        let mut done = 0usize;
        for &(addr, len) in backing {
            if done == buf.len() {
                break;
            }
            let len = u64::from(len);
            if off >= len {
                off -= len;
                continue;
            }
            let n = usize::try_from((len - off).min((buf.len() - done) as u64)).unwrap();
            let at = GuestAddress(addr + off);
            let r = if write {
                mem.write_slice(&buf[done..done + n], at)
            } else {
                mem.read_slice(&mut buf[done..done + n], at)
            };
            if r.is_err() {
                break;
            }
            done += n;
            off = 0;
        }
        done
    }

    fn read_backing(&self, mem: &GuestMemoryMmap, res: u32, off: u64, len: u64) -> Vec<u8> {
        let Some(b) = self.resources.get(&res).and_then(|r| r.backing.as_ref()) else {
            return Vec::new();
        };
        let mut buf = vec![0u8; usize::try_from(len).unwrap_or(0)];
        let n = Self::backing_copy(mem, b, off, &mut buf, false);
        buf.truncate(n);
        buf
    }

    fn write_backing(&self, mem: &GuestMemoryMmap, res: u32, off: u64, data: &[u8]) -> bool {
        let Some(b) = self.resources.get(&res).and_then(|r| r.backing.as_ref()) else {
            return false;
        };
        let mut d = data.to_vec();
        Self::backing_copy(mem, b, off, &mut d, true);
        true
    }

    /// `sp_source_push_mem`: send a piece of a resource's guest memory to the sink's copy of it.
    fn push_mem(&mut self, mem: &GuestMemoryMmap, res: u32, off: u64, len: u64, watch: u64) {
        if len == 0
            || self
                .resources
                .get(&res)
                .and_then(|r| r.backing.as_ref())
                .is_none()
        {
            return;
        }
        let data = self.read_backing(mem, res, off, len);
        self.counters.n_mem += 1;
        self.counters.mem_bytes += data.len() as u64;
        self.send(SP_MEMWRITE, 0, &data, &[], u64::from(res), off, watch);
        if watch == 0 {
            // an in-stream upload's bytes, for the journal
            self.pushed.insert((res, off), data);
        }
    }

    /// `sp_source_defer`: an upload of 4096 bytes or more into a buffer that lives only in the
    /// renderer's memory (`VIRGL_BIND_CUSTOM`) carries nothing the renderer will use (the video
    /// decoder reads the bitstream again when the decode command arrives), so it is not sent.
    fn defer(&mut self, res: u32, len: u64) -> bool {
        if len < 4096 || !self.custom_bufs.contains(&res) {
            return false;
        }
        self.counters.n_defer += 1;
        self.counters.defer_bytes += len;
        true
    }

    fn range_of(
        &self,
        res: u32,
        level: u32,
        stride: u32,
        layer: u32,
        bx: [u32; 6],
        offset: u64,
    ) -> Option<(u64, u64)> {
        let r = self.resources.get(&res)?;
        r.backing.as_ref()?;
        Some(transfer_range(
            r.format,
            r.width,
            r.height,
            level,
            stride,
            layer,
            bx,
            offset,
            r.backing_size(),
        ))
    }

    /// `sp_source_scan_submit`: the virgl command stream can make the renderer read or write a
    /// resource's guest memory without a virtio-gpu transfer command (in-stream and copy
    /// transfers, query results, memory info, video decode). Send what the renderer will read;
    /// list what it will write. Returns whether the guest needs data from the sink.
    fn scan_submit(
        &mut self,
        mem: &GuestMemoryMmap,
        ctx_id: u32,
        cmds: &[u8],
        expect: &mut Vec<u8>,
    ) -> bool {
        let ndw = cmds.len() / 4;
        let mut i = 0usize;
        while i < ndw {
            let hdr = u32_at(cmds, i * 4);
            let len = (hdr >> 16) as usize;
            let cmd = hdr & 0xff;
            let obj = (hdr >> 8) & 0xff;
            if i + 1 + len > ndw {
                break;
            }
            let mut c = [0u32; 16];
            for (k, w) in c.iter_mut().enumerate().take((len + 1).min(16)) {
                *w = u32_at(cmds, (i + k) * 4);
            }
            let bx = [c[6], c[7], c[8], c[9], c[10], c[11]];
            match cmd {
                // VIRGL_CCMD_TRANSFER3D: res, level, usage, stride, layer_stride, box, data
                // offset, direction (1 = to the renderer)
                43 if len >= 13 => {
                    if let Some((off, n)) =
                        self.range_of(c[1], c[2], c[4], c[5], bx, u64::from(c[12]))
                    {
                        if c[13] == 1 {
                            if !self.defer(c[1], n) {
                                self.tx_hint =
                                    hint_for(self.resources.get(&c[1]), c[2], c[4], false);
                                self.push_mem(mem, c[1], off, n, 0);
                            }
                        } else if n > 0 && !self.query_bufs.contains(&c[1]) {
                            push_expect(expect, c[1], off, n);
                        }
                    }
                }
                // VIRGL_CCMD_COPY_TRANSFER3D: texture, level, usage, stride, layer_stride, box,
                // staging resource, staging offset, flags (bit 1: from the renderer)
                45 if len >= 14 => {
                    let tex = self.resources.get(&c[1]).cloned();
                    let staging = self
                        .resources
                        .get(&c[12])
                        .filter(|r| r.backing.is_some())
                        .map(Resource::backing_size);
                    if let (Some(t), Some(size)) = (tex, staging) {
                        let (off, n) = transfer_range(
                            t.format,
                            t.width,
                            t.height,
                            c[2],
                            c[4],
                            c[5],
                            bx,
                            u64::from(c[13]),
                            size,
                        );
                        if c[14] & 2 == 0 {
                            self.tx_hint = hint_for(Some(&t), c[2], c[4], false);
                            self.push_mem(mem, c[12], off, n, 0);
                        } else if n > 0 {
                            push_expect(expect, c[12], off, n);
                        }
                    }
                }
                // VIRGL_CCMD_CREATE_OBJECT, VIRGL_OBJECT_QUERY: handle, type, offset, result
                // resource
                1 if obj == 9 && len >= 4 => {
                    self.queries
                        .insert((u64::from(ctx_id) << 32) | u64::from(c[1]), c[4]);
                    self.query_bufs.insert(c[4]);
                    if self.debug_wait {
                        let name = self
                            .ctx_name
                            .get(ctx_id as usize)
                            .cloned()
                            .unwrap_or_else(|| "?".into());
                        self.report(&format!(
                            "[SPACEBOX-QUERY] create ctx={ctx_id} ({name}) type={} res={}",
                            c[2] & 0xffff,
                            c[4]
                        ));
                    }
                }
                // VIRGL_CCMD_DESTROY_OBJECT
                3 if obj == 9 && len >= 1 => {
                    self.queries
                        .remove(&((u64::from(ctx_id) << 32) | u64::from(c[1])));
                }
                // VIRGL_CCMD_GET_QUERY_RESULT: the guest has just marked its result buffer
                // "waiting"; the renderer writes the result there. The sink watches the buffer
                // and sends the result when it is in, so the guest's polls cost no round trip.
                21 if len >= 1 => {
                    if let Some(&res) = self
                        .queries
                        .get(&((u64::from(ctx_id) << 32) | u64::from(c[1])))
                        && res != 0
                    {
                        self.push_mem(mem, res, 0, 16, 1);
                    }
                }
                // VIRGL_CCMD_DECODE_BITSTREAM: decoder, target, description buffer, bitstream
                // buffer, bitstream size. The renderer reads both buffers from guest memory
                // when it gets this command.
                59 => {
                    self.video_until = now_us() + 1_000_000;
                    if len >= 5 {
                        if let Some(r) = self.resources.get(&c[3]).filter(|r| r.backing.is_some()) {
                            let n = r.backing_size().min(u64::from(r.width));
                            self.push_mem(mem, c[3], 0, n, 0);
                        }
                        if let Some(r) = self.resources.get(&c[4]).filter(|r| r.backing.is_some()) {
                            let n = r.backing_size().min(u64::from(c[5]));
                            self.push_mem(mem, c[4], 0, n, 0);
                        }
                    }
                }
                // VIRGL_CCMD_GET_MEMORY_INFO: resource
                50 if len >= 1 => {
                    if let Some(r) = self.resources.get(&c[1]).filter(|r| r.backing.is_some()) {
                        push_expect(expect, c[1], 0, r.backing_size().min(64));
                    }
                }
                _ => {}
            }
            i += 1 + len;
        }
        !expect.is_empty()
    }

    // ---- the guest's commands ------------------------------------------------------------

    /// Write an answer for `cmd` into its writable descriptors and complete it.
    fn answer(&mut self, mem: &GuestMemoryMmap, queue: usize, cmd: &Cmd, resp: &[u8]) {
        let mut done = 0usize;
        for &(addr, len) in &cmd.writable {
            if done >= resp.len() {
                break;
            }
            let n = (len as usize).min(resp.len() - done);
            if mem.write_slice(&resp[done..done + n], addr).is_err() {
                break;
            }
            done += n;
        }
        if let Err(err) = self.queues[queue].add_used(cmd.head, u32::try_from(done).unwrap()) {
            error!("gpu: cannot add a used element: {err}");
        }
        self.used[queue] = true;
    }

    fn nodata(flags: u32, fence_id: u64, ctx_id: u32) -> [u8; HDR] {
        let mut r = [0u8; HDR];
        r[0..4].copy_from_slice(&RESP_OK_NODATA.to_le_bytes());
        if flags & FLAG_FENCE != 0 {
            r[4..8].copy_from_slice(&FLAG_FENCE.to_le_bytes());
            r[8..16].copy_from_slice(&fence_id.to_le_bytes());
            r[16..20].copy_from_slice(&ctx_id.to_le_bytes());
        }
        r
    }

    /// `sp_source_query`: capability and display queries have a 5 second limit in the guest
    /// kernel; on a busy link the answer can arrive later than that, and then the guest's
    /// desktop falls back to software rendering. Capability queries are answered from the spec,
    /// display and EDID queries from what the sink sent ahead. Returns false if this query must
    /// be forwarded.
    fn query(&mut self, mem: &GuestMemoryMmap, cmd: &Cmd, req: &[u8], typ: u32) -> bool {
        match self.query_answer(req, typ) {
            Some(r) => {
                self.answer(mem, CTRL_QUEUE, cmd, &r);
                true
            }
            None => {
                if matches!(
                    typ,
                    CMD_GET_CAPSET_INFO | CMD_GET_CAPSET | CMD_GET_DISPLAY_INFO | CMD_GET_EDID
                ) {
                    if self.info_seen {
                        self.counters.queries.forwarded_after_info += 1;
                    } else {
                        self.counters.queries.forwarded_before_info += 1;
                    }
                }
                false
            }
        }
    }

    /// The answer to a query that the device has, counted.
    fn query_answer(&mut self, req: &[u8], typ: u32) -> Option<Vec<u8>> {
        match typ {
            CMD_GET_CAPSET_INFO if req.len() >= 32 => {
                let index = u32_at(req, 24) as usize;
                let c = CAPSET_IDS.get(index).and_then(|&id| self.spec.capset(id))?;
                let mut r = vec![0u8; 40];
                r[0..4].copy_from_slice(&RESP_OK_CAPSET_INFO.to_le_bytes());
                r[24..28].copy_from_slice(&c.id.to_le_bytes());
                r[28..32].copy_from_slice(&c.ver.to_le_bytes());
                r[32..36].copy_from_slice(&u32::try_from(c.data.len()).unwrap().to_le_bytes());
                self.counters.queries.capset_info += 1;
                Some(r)
            }
            CMD_GET_CAPSET if req.len() >= 32 => {
                let (id, ver) = (u32_at(req, 24), u32_at(req, 28));
                // A renderer fills a virgl capset the same way for every version (Mesa asks
                // for version 0), so the id alone selects the data.
                let c = self.spec.capset(id).filter(|c| ver <= c.ver)?;
                let mut r = vec![0u8; HDR];
                r[0..4].copy_from_slice(&RESP_OK_CAPSET.to_le_bytes());
                r.extend_from_slice(&c.data);
                self.counters.queries.capset += 1;
                Some(r)
            }
            CMD_GET_DISPLAY_INFO => self
                .dinfo
                .clone()
                .inspect(|_| self.counters.queries.display_info += 1),
            CMD_GET_EDID if req.len() >= 32 && u32_at(req, 24) == 0 => self
                .edid
                .clone()
                .inspect(|_| self.counters.queries.edid += 1),
            _ => None,
        }
    }

    fn fq_push(&mut self, t0: i64) {
        if self.fq_len < FQ_LEN {
            self.fq[(self.fq_head + self.fq_len) % FQ_LEN] = t0;
            self.fq_len += 1;
        }
    }

    fn fq_pop(&mut self) {
        if self.fq_len > 0 {
            self.fq_head = (self.fq_head + 1) % FQ_LEN;
            self.fq_len -= 1;
        }
    }

    /// `sp_source_may_answer_early`: may a fenced command be answered here, before the sink has
    /// run it? Not while an older fenced command waits for data from the sink. Otherwise yes
    /// for the first `fence_window` commands the sink has not answered; beyond that only while
    /// the sink keeps up: the oldest unanswered command was sent no longer ago than two
    /// shortest round trips plus `fence_age`.
    ///
    /// The age is `fence_age_video` while the guest decodes video (until one second after its
    /// last decode, the time of `SP_F_VIDEO`, so the pauses between a clip's frames keep it).
    /// Decoding a large video loads the link, the sink's answers come up to about 150 ms late,
    /// and with the short age the guest's player waits for them and drops frames. The sink
    /// shows video frames by the guest's clock anyway. Without video the short age bounds how
    /// much later than the guest the user sees an answer to the input.
    fn may_answer_early(&mut self) -> bool {
        let out = self.fence_out + self.wait_out;
        let rtt_min = self.rtt_min_cur.min(self.rtt_min_prev);
        if self.hard_out != 0 {
            return false;
        }
        if out < self.fence_window {
            return true;
        }
        let now = now_us();
        let video = self.video_until > now;
        let age = if video {
            self.fence_age_video_us
        } else {
            self.fence_age_us
        };
        if age == 0 || self.fq_len == 0 || self.fq_len >= FQ_LEN / 2 || rtt_min == i64::MAX {
            return false;
        }
        if now - self.fq[self.fq_head] < 2 * rtt_min + age {
            self.counters.n_ahead += 1;
            if video {
                self.counters.n_ahead_video += 1;
            }
            return true;
        }
        false
    }

    /// Bookkeeping of `RESOURCE_ATTACH_BACKING`: the entries, if every one is guest memory
    /// (`virtio_gpu_create_mapping_iov`).
    fn backing_entries(mem: &GuestMemoryMmap, req: &[u8]) -> Option<Vec<(u64, u32)>> {
        let n = u32_at(req, 28);
        if n > MAX_ENTRIES {
            return None;
        }
        let n = n as usize;
        if req.len() < 32 + n * 16 {
            return None;
        }
        let v: Vec<(u64, u32)> = (0..n)
            .map(|e| (u64_at(req, 32 + e * 16), u32_at(req, 40 + e * 16)))
            .collect();
        v.iter()
            .all(|&(a, l)| l == 0 || mem.check_range(GuestAddress(a), l as usize))
            .then_some(v)
    }

    /// The journal takes a command that is about to be sent, and the renderer learns what the
    /// command may write (`SP_WMARK`). The bytes of the command's in-stream uploads are those
    /// [`Self::push_mem`] sent.
    fn journal_ctrl(&mut self, req: &[u8], data: &[u8]) {
        let mut pushed = std::mem::take(&mut self.pushed);
        let marks = self.journal.ctrl(req, data, &mut |res, off, len| {
            pushed.remove(&(res, off)).filter(|d| d.len() as u64 == len)
        });
        if let Some(s) = self.journal.scanout_resource()
            && self.scanned.last() != Some(&s)
        {
            self.scanned.retain(|&r| r != s);
            self.scanned.push(s);
            if self.scanned.len() > SCANOUT_KEEP {
                self.scanned.remove(0);
            }
        }
        let marked = &mut self.conns[self.active].marked;
        let a: Vec<u8> = marks
            .iter()
            .filter(|&&m| marked.insert(m))
            .flat_map(|m| m.to_le_bytes())
            .collect();
        self.counters.wmark_skipped += (marks.len() - a.len() / 4) as u64;
        if !a.is_empty() {
            self.counters.n_wmark += 1;
            self.counters.wmark_ids += (a.len() / 4) as u64;
            self.send(SP_WMARK, 0, &a, &[], 0, 0, 0);
        }
    }

    /// `sp_source_one`: one command of the guest.
    fn source_one(&mut self, mem: &GuestMemoryMmap, cmd: Cmd, req: Vec<u8>) {
        let typ = u32_at(&req, 0);
        let flags = u32_at(&req, 4);
        let fence_id = u64_at(&req, 8);
        let ctx_id = u32_at(&req, 16);
        let fenced = flags & FLAG_FENCE != 0;
        let resp_cap: u64 = cmd.writable.iter().map(|w| u64::from(w.1)).sum();
        if typ == CMD_RESOURCE_FLUSH {
            let now = now_us();
            if self.counters.flush_last != 0 {
                let d = now - self.counters.flush_last;
                self.counters.flush.add(d);
            }
            self.counters.flush_last = now;
        }
        if self.query(mem, &cmd, &req, typ) {
            return;
        }
        self.seq += 1;
        let seq = self.seq;
        let mut p = Pending {
            cmd: Some(cmd),
            typ,
            res: 0,
            off: 0,
            len: 0,
            seq,
            t0: now_us(),
            early: false,
            fence_wait: false,
            hard: false,
            flags,
            fence_id,
            ctx_id,
        };
        let (mut off, mut len) = (0u64, 0u64);
        let mut needs_sink = false;

        match typ {
            CMD_CTX_CREATE if req.len() >= 96 && ctx_id < 64 => {
                let name = &req[32..32 + 23];
                let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                self.ctx_name[ctx_id as usize] = String::from_utf8_lossy(&name[..end]).into_owned();
            }
            CMD_RESOURCE_CREATE_2D if req.len() >= 40 => {
                self.res_create(
                    u32_at(&req, 24),
                    u32_at(&req, 28),
                    u32_at(&req, 32),
                    u32_at(&req, 36),
                );
            }
            CMD_RESOURCE_CREATE_3D if req.len() >= 72 => {
                let id = u32_at(&req, 24);
                self.res_create(id, u32_at(&req, 32), u32_at(&req, 40), u32_at(&req, 44));
                // PIPE_BUFFER with VIRGL_BIND_CUSTOM
                if u32_at(&req, 28) == 0 && u32_at(&req, 36) & (1 << 17) != 0 {
                    self.custom_bufs.insert(id);
                } else {
                    self.custom_bufs.remove(&id);
                }
            }
            CMD_RESOURCE_ATTACH_BACKING if req.len() >= 32 => {
                let id = u32_at(&req, 24);
                if self.resources.get(&id).is_some_and(|r| r.backing.is_none()) {
                    let entries = Self::backing_entries(mem, &req);
                    if let Some(r) = self.resources.get_mut(&id) {
                        r.backing = entries;
                    }
                }
            }
            CMD_RESOURCE_DETACH_BACKING if req.len() >= 32 => {
                if let Some(r) = self.resources.get_mut(&u32_at(&req, 24)) {
                    r.backing = None;
                }
            }
            CMD_RESOURCE_UNREF if req.len() >= 32 => {
                let id = u32_at(&req, 24);
                if self.resources.remove(&id).is_some() {
                    self.query_bufs.remove(&id);
                    self.custom_bufs.remove(&id);
                }
            }
            CMD_TRANSFER_TO_HOST_2D if req.len() >= 56 => {
                // rect x, y, w, h at 24; offset at 40; resource at 48
                let id = u32_at(&req, 48);
                let bx = [
                    u32_at(&req, 24),
                    u32_at(&req, 28),
                    0,
                    u32_at(&req, 32),
                    u32_at(&req, 36),
                    1,
                ];
                if let Some(r) = self.range_of(id, 0, 0, 0, bx, u64_at(&req, 40)) {
                    (off, len) = r;
                }
            }
            CMD_TRANSFER_TO_HOST_3D | CMD_TRANSFER_FROM_HOST_3D if req.len() >= 72 => {
                // box at 24; offset at 48; resource, level, stride, layer_stride at 56
                let id = u32_at(&req, 56);
                let bx = [
                    u32_at(&req, 24),
                    u32_at(&req, 28),
                    u32_at(&req, 32),
                    u32_at(&req, 36),
                    u32_at(&req, 40),
                    u32_at(&req, 44),
                ];
                if let Some(r) = self.range_of(
                    id,
                    u32_at(&req, 60),
                    u32_at(&req, 64),
                    u32_at(&req, 68),
                    bx,
                    u64_at(&req, 48),
                ) {
                    (off, len) = r;
                    p.res = id;
                    if typ == CMD_TRANSFER_TO_HOST_3D && self.defer(id, len) {
                        len = 0;
                    }
                }
            }
            _ => {}
        }

        // Data that the renderer reads with this command goes with it.
        let mut extra = Vec::new();
        let mut hint = None;
        if len != 0 && typ != CMD_TRANSFER_FROM_HOST_3D {
            let (id, level, stride) = if typ == CMD_TRANSFER_TO_HOST_2D {
                (u32_at(&req, 48), 0, 0)
            } else {
                (u32_at(&req, 56), u32_at(&req, 60), u32_at(&req, 64))
            };
            hint = hint_for(self.resources.get(&id), level, stride, true);
            extra = self.read_backing(mem, id, off, len);
            self.counters.n_xfer += 1;
            self.counters.xfer_bytes += len;
        }
        if typ == CMD_SUBMIT_3D {
            self.counters.n_submit += 1;
            self.counters.submit_bytes += req.len() as u64;
            if req.len() >= 32 {
                let size = (u32_at(&req, 24) as usize).min(req.len() - 32);
                let mut expect = Vec::new();
                needs_sink = self.scan_submit(mem, ctx_id, &req[32..32 + size], &mut expect);
                if !expect.is_empty() {
                    self.send(SP_EXPECT, 0, &expect, &[], 0, 0, 0);
                }
            }
        }
        self.journal_ctrl(&req, &extra);
        self.tx_hint = hint;
        self.counters.n_ctrl += 1;
        p.off = off;
        p.len = len;

        if typ == CMD_TRANSFER_FROM_HOST_3D
            && p.res != 0
            && self.hard_out == 0
            && self.query_bufs.contains(&p.res)
        {
            // The guest's copy of a query result buffer is kept current by the sink's watch,
            // so there is nothing to fetch.
            self.counters.n_local += 1;
            self.seq -= 1;
            if ctx_id < 64 {
                self.ctx_qpoll[ctx_id as usize] += 1;
            }
            let state = u32::from_le_bytes(
                self.read_backing(mem, p.res, 0, 4)
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            let cmd = p.cmd.take().unwrap();
            if state == QUERY_STATE_WAIT_HOST {
                // Not in yet. Hold the read until the sink reports the result (or 200 ms
                // pass), so a guest that loops on it does not spin.
                self.parked.push_back(Parked {
                    cmd,
                    flags,
                    fence_id,
                    ctx_id,
                    res: p.res,
                    t0: now_us(),
                });
                return;
            }
            self.answer(
                mem,
                CTRL_QUEUE,
                &cmd,
                &Self::nodata(flags, fence_id, ctx_id),
            );
            return;
        }

        if matches!(
            typ,
            CMD_GET_CAPSET_INFO
                | CMD_GET_CAPSET
                | CMD_GET_DISPLAY_INFO
                | CMD_GET_EDID
                | CMD_TRANSFER_FROM_HOST_3D
                | CMD_RESOURCE_CREATE_BLOB
                | CMD_RESOURCE_MAP_BLOB
                | CMD_RESOURCE_UNMAP_BLOB
        ) {
            needs_sink = true;
        }

        // Most commands return nothing but "done". Waiting for the sink to say so costs a
        // network round trip, and for fenced commands that round trip is what paces the guest's
        // frames. Answer here instead: commands still reach the sink in order, so rendering is
        // unchanged; only the moment the guest hears "done" moves.
        if !needs_sink && self.fence_window != 0 {
            if !fenced {
                self.counters.n_local += 1;
                self.send(SP_CTRL, 0, &req, &extra, resp_cap, off, len);
                let cmd = p.cmd.take().unwrap();
                self.answer(mem, CTRL_QUEUE, &cmd, &Self::nodata(0, 0, 0));
                return;
            }
            // The guest kernel treats a signalled fence as signalling every older fence too.
            // While a fenced command waits for data from the sink (a read back), a later fence
            // must not be answered first, or the guest reads its memory before the data is
            // there. Commands that wait only because of the window do not hold later ones.
            if self.may_answer_early() {
                self.fq_push(p.t0);
                self.counters.n_early += 1;
                self.fence_out += 1;
                p.early = true;
                let cmd = p.cmd.take().unwrap();
                self.pending.insert(seq, p);
                self.send(SP_CTRL, seq, &req, &extra, resp_cap, off, len);
                self.answer(
                    mem,
                    CTRL_QUEUE,
                    &cmd,
                    &Self::nodata(flags, fence_id, ctx_id),
                );
                return;
            }
        }
        self.counters.n_waited += 1;
        if self.debug_wait {
            let shown = self.debug_shown;
            self.debug_shown = self.debug_shown.wrapping_add(1);
            if shown % 200 < 30 {
                let id = u32_at(&req, 56);
                let r = if typ == CMD_TRANSFER_FROM_HOST_3D {
                    self.resources.get(&id).cloned()
                } else {
                    None
                };
                let line = format!(
                    "[SPACEBOX-WAIT] type={typ:#x} fenced={} ctx={ctx_id} len={} from_host_res={} fmt={} {}x{} box={},{}+{}x{} bytes={len} fence_out={} wait_out={} hard_out={} needs_sink={}",
                    u32::from(fenced),
                    req.len(),
                    if r.is_some() { id } else { 0 },
                    r.as_ref().map_or(0, |r| r.format),
                    r.as_ref().map_or(0, |r| r.width),
                    r.as_ref().map_or(0, |r| r.height),
                    u32_at(&req, 24),
                    u32_at(&req, 28),
                    u32_at(&req, 36),
                    u32_at(&req, 40),
                    self.fence_out,
                    self.wait_out,
                    self.hard_out,
                    u32::from(needs_sink),
                );
                self.report(&line);
            }
        }
        if fenced {
            self.fq_push(p.t0);
            p.fence_wait = true;
            self.wait_out += 1;
            if needs_sink {
                p.hard = true;
                self.hard_out += 1;
            }
        }
        self.pending.insert(seq, p);
        self.send(SP_CTRL, seq, &req, &extra, resp_cap, off, len);
    }

    fn res_create(&mut self, id: u32, format: u32, width: u32, height: u32) {
        if id != 0 && !self.resources.contains_key(&id) {
            self.resources.insert(
                id,
                Resource {
                    format,
                    width,
                    height,
                    backing: None,
                },
            );
        }
    }

    /// `sp_source_handle_ctrl`: take the guest's commands while the sink is there and the
    /// network keeps up.
    pub(crate) fn process_ctrl_queue(&mut self) -> Result<(), InvalidAvailIdx> {
        let Some(mem) = self.mem() else {
            return Ok(());
        };
        let alone = self.alone();
        if !(self.active_up() || alone) || self.saving {
            // resumed by the sink's HELLO, or when a switch is done; meanwhile the queries that
            // the device can answer are (the kernel's probe reads the capsets within 5 s of
            // the device coming up, before any renderer may be there)
            if !self.saving {
                self.answer_queries_ahead(&mem)?;
            }
            return Ok(());
        }
        if self.switch.is_none()
            && (!self.scanout_saved.is_empty() || !self.saved_missing.is_empty())
            && self.resumed_at.is_some()
        {
            // the guest runs on: the saved content is not what its buffers hold any more
            self.scanout_saved = Vec::new();
            self.saved_missing = Vec::new();
        }
        loop {
            if !alone && self.conns[self.active].link.backlog() > self.tx_limit {
                // Let the network drain before taking more work from the guest.
                self.retry_timer.arm(BACKLOG_RETRY, None);
                break;
            }
            let Some((cmd, req)) = self.pop_request(&mem)? else {
                break;
            };
            self.source_one(&mem, cmd, req);
        }
        if alone {
            self.serve_alone();
        }
        Ok(())
    }

    /// The next well-formed request of the control queue; a malformed one is answered with an
    /// error here.
    fn pop_request(
        &mut self,
        mem: &GuestMemoryMmap,
    ) -> Result<Option<(Cmd, Vec<u8>)>, InvalidAvailIdx> {
        loop {
            let Some(head) = self.queues[CTRL_QUEUE].pop()? else {
                return Ok(None);
            };
            let mut req = Vec::new();
            let mut writable = Vec::new();
            let mut bad = false;
            let mut next = Some(head);
            let index = head.index;
            while let Some(d) = next {
                if d.is_write_only() {
                    writable.push((d.addr, d.len));
                } else if req.len() + d.len as usize <= MAX_REQ {
                    let start = req.len();
                    req.resize(start + d.len as usize, 0);
                    bad |= mem.read_slice(&mut req[start..], d.addr).is_err();
                } else {
                    bad = true;
                }
                next = d.next_descriptor();
            }
            let cmd = Cmd {
                head: index,
                writable,
            };
            if bad || req.len() < HDR {
                let mut resp = [0u8; HDR];
                resp[0..4].copy_from_slice(&RESP_ERR_UNSPEC.to_le_bytes());
                self.answer(mem, CTRL_QUEUE, &cmd, &resp);
                continue;
            }
            return Ok(Some((cmd, req)));
        }
    }

    /// With no renderer to send to: answer the queries at the head of the control queue that
    /// the device has the answer of (the capsets always, from the spec), in order, up to the
    /// first command that waits for a renderer.
    fn answer_queries_ahead(&mut self, mem: &GuestMemoryMmap) -> Result<(), InvalidAvailIdx> {
        while let Some((cmd, req)) = self.pop_request(mem)? {
            match self.query_answer(&req, u32_at(&req, 0)) {
                Some(r) => self.answer(mem, CTRL_QUEUE, &cmd, &r),
                None => {
                    self.queues[CTRL_QUEUE].undo_pop();
                    break;
                }
            }
        }
        Ok(())
    }

    /// No renderer runs the guest's commands now and none is waited for: the renderer that runs
    /// the guest is not paired, and it would start empty when it comes (no renderer has paired
    /// since the device was made, for [`FIRST_WAIT_US`]; or it detached; or, with no in-guest
    /// renderer to switch to, it was lost for [`LOST_WAIT_US`], and is let go here); or a takeover
    /// waits for an in-guest renderer that has not connected yet (it starts empty and gets
    /// everything from the journal, so nothing needs to wait for it). The
    /// device then serves the guest alone ([`Self::serve_alone`]): a guest whose user's device
    /// is not attached runs, shuts down and reboots, where its commands waited for ever and the
    /// guest's shutdown stopped at its console (fc-switch, 2026-10-19).
    fn alone(&mut self) -> bool {
        if self.saving {
            return false;
        }
        if let Some(sw) = &self.switch {
            return self.takeover_waits(sw);
        }
        let a = self.active;
        if self.conns[a].up() {
            return false;
        }
        let now = now_us();
        // the user's renderer is replaced by the in-guest renderer (`check_takeover`); with no
        // in-guest renderer it is waited for long, the in-guest renderer itself briefly
        let wait = if a == GUEST {
            Some(GUEST_LOST_WAIT_US)
        } else if !self.has_fallback() {
            Some(LOST_WAIT_US)
        } else {
            None
        };
        // (a renderer whose new pairing waits for its answer to the spec is not the lost one:
        // its session is the new renderer's)
        if let Some(wait) = wait
            && self.conns[a].peer_session != 0
            && !self.conns[a].hello_done
            && now - self.conns[a].lost_at > wait
        {
            // it starts empty when it comes back, and gets the state from the journal
            self.conns[a].peer_session = 0;
            self.log_info(&format!(
                "spacebox remote gpu: {} lost for {} s{}: let go",
                CONN_NAMES[a],
                wait / 1_000_000,
                if a == GUEST {
                    ""
                } else {
                    ", and no in-guest renderer"
                }
            ));
        }
        self.conns[a].peer_session == 0 && (self.paired_once || now - self.made_at > FIRST_WAIT_US)
    }

    /// A takeover (a switch with no old renderer) that waits for its new renderer, which has not
    /// connected: the guest is served alone meanwhile.
    fn takeover_waits(&self, sw: &Switch) -> bool {
        sw.from.is_none() && sw.phase == Phase::Connect && !self.conns[sw.to].link.is_connected()
    }

    /// An in-guest renderer that the guest's state can move to: configured, and not one that
    /// cannot do the spec.
    fn has_fallback(&self) -> bool {
        self.conns.len() > GUEST && !self.conns[GUEST].refused
    }

    /// Serve the guest with no renderer: what waits for a renderer is answered here (as when a
    /// renderer is lost: fences done, reads from guest memory, query results 0), and what was
    /// queued for it is dropped, since the renderer that comes next starts empty and is built
    /// from the journal, which has every command. Nothing is drawn meanwhile.
    fn serve_alone(&mut self) {
        if !self.alone_said {
            self.alone_said = true;
            self.log_info(
                "spacebox remote gpu: no renderer: the device answers the guest's commands itself until one is paired",
            );
        }
        self.drop_pending();
        // what was queued for a renderer that is not there; not the queue of a pairing under
        // way (its spec may not be written yet)
        let a = self.active;
        if !self.conns[a].hello_done {
            self.conns[a].link.forget();
        }
    }

    /// The cursor queue: each element is answered at once; the cursor goes to the sink.
    pub(crate) fn process_cursor_queue(&mut self) -> Result<(), InvalidAvailIdx> {
        let Some(mem) = self.mem() else {
            return Ok(());
        };
        while let Some(head) = self.queues[CURSOR_QUEUE].pop()? {
            let mut req = Vec::new();
            let mut next = Some(head);
            while let Some(d) = next {
                if !d.is_write_only() && req.len() < CURSOR_LEN {
                    let start = req.len();
                    let n = (d.len as usize).min(CURSOR_LEN - start);
                    req.resize(start + n, 0);
                    if mem.read_slice(&mut req[start..], d.addr).is_err() {
                        req.truncate(start);
                    }
                }
                next = d.next_descriptor();
            }
            if req.len() == CURSOR_LEN {
                self.journal.cursor(&req);
                // during a switch the new renderer gets the last cursor when it is done
                if self.switch.is_none() {
                    self.send(SP_CURSOR, 0, &req, &[], 0, 0, 0);
                }
                if self.gpu_off && self.active != USER && self.conns[USER].up() {
                    // the user's renderer shows the cursor over the in-guest renderer's pictures;
                    // it does not hold the guest's resources now, so a new image comes with its
                    // pixels
                    let px = self.cursor_pixels(&mem, &req);
                    self.send_on(USER, true, SP_CURSOR, 0, &req, &px, 0, 0, 0);
                }
            } else {
                warn!("gpu: cursor size incorrect {} vs {CURSOR_LEN}", req.len());
            }
            let cmd = Cmd {
                head: head.index,
                writable: Vec::new(),
            };
            self.answer(&mem, CURSOR_QUEUE, &cmd, &[]);
        }
        Ok(())
    }

    /// The pixels of the cursor that `req` (`struct virtio_gpu_update_cursor`) sets, from its
    /// resource's backing in guest memory; none for a move, or a resource that is not a cursor's.
    fn cursor_pixels(&self, mem: &GuestMemoryMmap, req: &[u8]) -> Vec<u8> {
        let res = u32_at(req, 40);
        if u32_at(req, 0) != CMD_UPDATE_CURSOR
            || !self.resources.get(&res).is_some_and(|r| {
                r.width == 64 && r.height == 64 && r.backing_size() >= CURSOR_BYTES
            })
        {
            return Vec::new();
        }
        let px = self.read_backing(mem, res, 0, CURSOR_BYTES);
        if px.len() as u64 == CURSOR_BYTES {
            px
        } else {
            Vec::new()
        }
    }

    /// Advance the used rings that got elements and interrupt the guest.
    pub(crate) fn notify_used(&mut self) {
        for q in 0..GPU_NUM_QUEUES {
            if std::mem::take(&mut self.used[q]) {
                self.queues[q].advance_used_ring_idx();
                if let Some(s) = self.device_state.active_state()
                    && let Err(err) = s
                        .interrupt
                        .trigger(VirtioInterruptType::Queue(u16::try_from(q).unwrap()))
                {
                    error!("gpu: cannot signal queue {q}: {err:?}");
                }
            }
        }
    }

    // ---- what the sink sends -------------------------------------------------------------

    /// `sp_source_resp`.
    fn resp(&mut self, mem: &GuestMemoryMmap, h: &Hdr, a: &[u8], b: &[u8]) {
        let seq = h.seq;
        let Some(t0) = self.pending.get(&seq).map(|p| p.t0) else {
            return; // dropped by a reset
        };
        self.rtt_us = now_us() - t0;
        if t0 + self.rtt_us - self.rtt_min_t0 > 5_000_000 {
            self.rtt_min_prev = self.rtt_min_cur;
            self.rtt_min_cur = i64::MAX;
            self.rtt_min_t0 = t0 + self.rtt_us;
        }
        self.rtt_min_cur = self.rtt_min_cur.min(self.rtt_us);
        self.counters.delay.add(self.rtt_us);
        let p = self.pending.remove(&seq).unwrap();
        if p.early || p.fence_wait {
            self.fq_pop();
        }
        if p.early {
            self.fence_out = self.fence_out.saturating_sub(1);
            return;
        }
        if p.fence_wait {
            self.wait_out = self.wait_out.saturating_sub(1);
        }
        if p.hard {
            self.hard_out = self.hard_out.saturating_sub(1);
        }
        if p.typ == CMD_TRANSFER_FROM_HOST_3D && !b.is_empty() {
            let n = usize::try_from((b.len() as u64).min(p.len)).unwrap();
            self.write_backing(mem, p.res, p.off, &b[..n]);
        }
        if let Some(cmd) = p.cmd {
            self.answer(mem, CTRL_QUEUE, &cmd, a);
        }
    }

    /// `sp_source_unpark`: answer parked reads of resource `res` (0 = all older than
    /// `max_age_us`).
    fn unpark(&mut self, mem: &GuestMemoryMmap, res: u32, max_age_us: i64) {
        let now = now_us();
        let mut i = 0;
        while i < self.parked.len() {
            let k = &self.parked[i];
            if (res != 0 && k.res == res) || (res == 0 && now - k.t0 > max_age_us) {
                let k = self.parked.remove(i).unwrap();
                self.answer(
                    mem,
                    CTRL_QUEUE,
                    &k.cmd,
                    &Self::nodata(k.flags, k.fence_id, k.ctx_id),
                );
            } else {
                i += 1;
            }
        }
    }

    /// `sp_source_info`: the display and the EDID. The guest's capsets are the spec's, not a
    /// renderer's.
    fn info(&mut self, h: &Hdr, a: &[u8]) {
        self.info_seen = true;
        match h.arg0 {
            1 => {
                if !self.caps_ignored_said {
                    self.caps_ignored_said = true;
                    self.log_info(
                        "spacebox remote gpu: a renderer sent its capsets; the guest is shown the spec's",
                    );
                }
            }
            2 => {
                // A display that the guest has not been shown: it reads the display again (a
                // guest booted with no screen gets the in-guest renderer's size, one whose user's
                // renderer comes later that renderer's).
                let changed = self.dinfo.as_deref() != Some(a);
                self.dinfo = Some(a.to_vec());
                if changed && self.is_activated() {
                    self.display_event(VIRTIO_GPU_EVENT_DISPLAY);
                }
            }
            3 => self.edid = Some(a.to_vec()),
            _ => {}
        }
    }

    fn display_event(&mut self, bits: u64) {
        let ev = self.config_word(0) | u32::try_from(bits).unwrap_or(0);
        self.set_config(0, ev);
        if let Some(s) = self.device_state.active_state()
            && let Err(err) = s.interrupt.trigger(VirtioInterruptType::Config)
        {
            error!("gpu: cannot signal a config change: {err:?}");
        }
    }

    /// What renderer `ci` sent.
    fn dispatch(&mut self, ci: usize, h: &Hdr, a: &[u8], b: &[u8]) {
        let mem = self.mem();
        // The guest is shown the user's renderer's display; the in-guest renderer's only until the
        // user's has been seen (the in-guest renderer runs at the same size).
        let shown = ci == USER || !self.user_info;
        match h.typ {
            SP_RESP => {
                if let Some(mem) = mem {
                    self.resp(&mem, h, a, b);
                }
                self.switch_drained();
            }
            SP_INPUT => self.input(a),
            SP_SCROLL => {
                if let Some(ag) = self.agent.as_mut() {
                    ag.send(a);
                }
            }
            SP_MEMWRITE => {
                if let Some(mem) = mem {
                    let res = u32::try_from(h.arg0).unwrap_or(0);
                    if self.write_backing(&mem, res, h.arg1, a) {
                        self.counters.n_back += 1;
                        self.counters.back_bytes += a.len() as u64;
                    }
                    self.unpark(&mem, res, 0);
                }
            }
            SP_INFO if shown => {
                self.user_info |= ci == USER;
                self.info(h, a);
            }
            SP_DISPLAY if shown => self.display_event(h.arg0),
            SP_STATE_KEPT => self.switch_kept(ci, a),
            SP_EXPORT_DATA | SP_EXPORT_DONE => self.export_reply(ci, h, a, b),
            SP_DETACH => self.detach(ci),
            SP_GPU if ci == USER => self.user_toggle(h.arg0 != 0),
            SP_PICTURE if ci == GUEST => self.picture(h, a),
            _ => {}
        }
    }

    // ---- the user's toggle ---------------------------------------------------------------

    /// The user's toggle (`SP_GPU`): off is the planned switch to the in-guest renderer with the
    /// user's link kept up (input, sound, the cursor and the in-guest renderer's pictures go on
    /// it); on is the planned switch back to the user's renderer (the journal and the in-guest
    /// renderer's export, as a new attach). The sink says its toggle again when its pairing
    /// resumes.
    fn user_toggle(&mut self, on: bool) {
        let changed = on == self.gpu_off || (on && self.active != USER);
        self.gpu_off = !on;
        self.gpu_on_pending = on;
        self.gpu_state_owed = true;
        if !on {
            self.gpu_off_at = now_us();
        }
        if changed {
            self.log_info(&format!(
                "spacebox remote gpu: the user turned the GPU acceleration {}",
                if on { "on" } else { "off" }
            ));
        }
        self.toggle_settle();
    }

    /// After a change of the toggle, of a switch or of a link: the switch that the toggle asks for
    /// is made once no other switch is under way (off: to the in-guest renderer, if one can take
    /// the guest; on: back to the user's renderer); the in-guest renderer sends pictures while it
    /// runs the guest with the toggle off and the user's link up; the user's renderer is told
    /// what is in effect.
    fn toggle_settle(&mut self) {
        let user_up = self.conns[USER].up();
        if self.switch.is_none() && user_up {
            if self.gpu_on_pending && self.active == GUEST {
                let from = self.conns[GUEST].up().then_some(GUEST);
                self.start_switch(from, USER, "the user turned the GPU acceleration on");
            } else if self.gpu_off && self.active == USER {
                if self.has_fallback() && self.conns[GUEST].link.reachable() {
                    self.start_switch(
                        Some(USER),
                        GUEST,
                        "the user turned the GPU acceleration off",
                    );
                } else if self.has_fallback() && now_us() - self.gpu_off_at < OFF_WAIT_US {
                    // its link connects again after a switch back: the ack timer looks again
                } else {
                    self.gpu_off = false;
                    self.log_info(
                        "spacebox remote gpu: no in-guest renderer can take the guest now: the GPU acceleration stays on",
                    );
                    self.gpu_state_said = Some(true);
                    self.gpu_state_owed = false;
                    self.send_on(USER, true, SP_GPU_STATE, 0, &[], &[], 1, 1, 0);
                }
            }
        }
        if self.active == USER && self.switch.is_none() {
            self.gpu_on_pending = false;
        }
        if self.conns.len() > GUEST && self.conns[GUEST].up() {
            let want = self.gpu_off && user_up && self.active == GUEST && self.switch.is_none();
            if want != self.stream_on {
                self.stream_on = want;
                self.send_on(GUEST, true, SP_STREAM, 0, &[], &[], u64::from(want), 0, 0);
                self.log_info(&format!(
                    "spacebox remote gpu: the in-guest renderer's pictures {}",
                    if want {
                        "asked for: the user's renderer shows them"
                    } else {
                        "stopped"
                    }
                ));
            }
        }
        if user_up && self.switch.is_none() {
            let on = self.active == USER;
            let changed = self.gpu_state_said.is_some_and(|s| s != on);
            // (not while what the toggle asks for still waits)
            let waits = (on && self.gpu_off) || (!on && self.gpu_on_pending);
            if (self.gpu_state_owed || changed) && (on || self.gpu_off) && !waits {
                self.gpu_state_said = Some(on);
                self.gpu_state_owed = false;
                self.send_on(USER, true, SP_GPU_STATE, 0, &[], &[], u64::from(on), 0, 0);
            }
        }
    }

    /// A picture of the in-guest renderer (`SP_PICTURE`): passed to the user's renderer while
    /// the stream is on; dropped while more than [`PICTURE_BACKLOG`] waits on the user's link.
    fn picture(&mut self, h: &Hdr, a: &[u8]) {
        if !self.stream_on || !self.conns[USER].up() {
            self.counters.pictures_late += 1;
            return;
        }
        if self.conns[USER].link.backlog() > PICTURE_BACKLOG {
            self.counters.pictures_dropped += 1;
            return;
        }
        self.counters.n_picture += 1;
        self.pictures_all += 1;
        self.counters.picture_bytes += a.len() as u64;
        self.send_on(USER, false, SP_PICTURE, 0, a, &[], h.arg0, h.arg1, h.arg2);
    }

    /// `sp_rx_delay`.
    fn rx_delay(&mut self, t_us: i64) {
        if t_us == 0 {
            return;
        }
        let c = &mut self.counters;
        let now = now_us();
        let mut d = now - t_us;
        if now - c.rx_min_t0 > 10_000_000 {
            c.rx_min_prev = c.rx_min;
            c.rx_min = i64::MAX;
            c.rx_min_t0 = now;
        }
        c.rx_min = c.rx_min.min(d);
        d -= c.rx_min.min(c.rx_min_prev);
        c.rxd.add(d);
    }

    /// `sp_hello` of renderer `ci`. A renderer that does not resume this device's session holds
    /// nothing of the guest: it gets the state again from the journal (a switch, or a rebuild of
    /// the same renderer after it restarted).
    fn hello(&mut self, ci: usize, h: &Hdr) {
        let session = self.session;
        let c = &mut self.conns[ci];
        if c.hello_done {
            return;
        }
        let resume = c.peer_session != 0 && h.arg0 == c.peer_session && h.arg1 == session;
        let z_on = c.link.z_level() != 0 && h.flags & SP_F_ZSTD != 0;
        c.link.set_z_on(z_on);
        c.hello_done = true;
        let restored = std::mem::take(&mut c.restored);
        let tx_id = c.link.lock().q.tx_id;
        if ci == GUEST {
            // every connection of the in-guest renderer starts with no pictures
            self.stream_on = false;
        }
        let c = &mut self.conns[ci];
        if resume && restored && h.arg2 > tx_id {
            // The renderer ran on after the snapshot (a rollback). It goes back with this
            // device's stream to the snapshot's last id (SP_F_RESTORED), and keeps what did
            // not change after it; the rest is built again.
            c.link.start(z_on, tx_id);
            self.counters.n_reconnect += 1;
            self.log_info(&format!(
                "spacebox remote gpu: {} ran on after the snapshot: it has {} of this device's messages, the snapshot {tx_id}",
                CONN_NAMES[ci], h.arg2
            ));
            if ci == self.active && self.switch.is_none() {
                self.start_switch_to(None, ci, "the renderer ran on after the snapshot", tx_id);
            } else {
                // not the renderer that runs the guest: it starts empty when it is wanted
                self.conns[ci].peer_session = 0;
                self.disconnected(ci);
            }
        } else if resume {
            let tx_id = c.link.lock().q.tx_id;
            c.link.start(z_on, h.arg2);
            self.counters.n_reconnect += 1;
            self.log_info(&format!(
                "spacebox remote gpu: resumed, peer has {} of {tx_id} messages",
                h.arg2
            ));
        } else {
            c.link.forget();
            c.rx_id = 0;
            c.rx_id_acked = 0;
            c.peer_session = h.arg0;
            c.detaching = false;
            c.marked.clear();
            c.spec_ok = false;
            c.link.start(z_on, 0);
            if ci == USER {
                self.gpu_state_said = None;
                self.gpu_state_owed = false;
            }
            // the renderer runs nothing of this device before it said that it can do the spec
            let spec = self.spec.text().to_vec();
            self.send_on(ci, false, SP_SPEC, 0, &spec, &[], 0, 0, 0);
            let msg = format!(
                "spacebox remote gpu: {} attached (session {:#x}); the spec {} sent",
                CONN_NAMES[ci],
                h.arg0,
                self.spec.digest()
            );
            self.log_info(&msg);
            return;
        }
        self.paired(ci);
    }

    /// The renderer's answer to the spec (`SP_SPEC_REPLY`) of a new pairing.
    fn spec_reply(&mut self, ci: usize, h: &Hdr, a: &[u8]) {
        let c = &mut self.conns[ci];
        if c.spec_ok {
            return;
        }
        if h.arg0 == 1 {
            c.spec_ok = true;
            c.refused = false;
            if ci == USER {
                self.info_seen = false;
            }
            let msg = format!(
                "spacebox remote gpu: {} can do the spec {}",
                CONN_NAMES[ci],
                self.spec.digest()
            );
            self.log_info(&msg);
            self.renderer_empty(ci);
            self.paired(ci);
            return;
        }
        c.refused = true;
        c.refused_at = now_us();
        c.n_refused += 1;
        c.peer_session = 0;
        let n = c.n_refused;
        if n.is_power_of_two() {
            let msg = format!(
                "spacebox remote gpu: {} cannot do the spec {} (refusal {n}):{} it is not paired; tried again in {} s",
                CONN_NAMES[ci],
                self.spec.digest(),
                String::from_utf8_lossy(a),
                SPEC_RETRY_US / 1_000_000
            );
            self.log_error(&msg);
        }
        if self.switch.as_ref().is_some_and(|s| s.to == ci) {
            self.give_up_switch(ci);
        }
        self.disconnected(ci);
        if let Err(err) = self.process_ctrl_queue() {
            error!("gpu: control queue: {err}");
        }
    }

    /// The switch to renderer `to` cannot be made: it cannot do the spec. The guest goes on with
    /// the renderer it had, or, when that one is gone or ends, alone until a renderer pairs.
    fn give_up_switch(&mut self, to: usize) {
        let Some(sw) = self.switch.take() else {
            return;
        };
        self.log_error(&format!(
            "spacebox remote gpu: switch to {} ({}) given up: it cannot do the spec",
            CONN_NAMES[to], sw.why
        ));
        match sw.from {
            Some(f) if self.conns[f].detaching => {
                // it ends, and its state can go nowhere
                self.send_on(f, true, SP_BYE, 0, &[], &[], 0, 0, 0);
                self.conns[f].peer_session = 0;
            }
            // the old renderer runs the guest on
            Some(_) => {}
            None => {
                // the renderer that was lost is let go: the guest is served alone, and a renderer
                // that pairs next is built from the journal
                let a = self.active;
                self.conns[a].peer_session = 0;
            }
        }
        self.conns[to].wanted = to == USER;
    }

    /// A pairing is complete (resumed, or a new one whose renderer can do the spec).
    fn paired(&mut self, ci: usize) {
        if let Err(err) = self.process_ctrl_queue() {
            error!("gpu: control queue: {err}");
        }
        if self.redraw_pending {
            // a redraw that waited for the renderer (`redraw`)
            self.redraw();
        }
        self.paired_once = true;
        if ci == self.active {
            // what the renderer sent of the keys while it was not paired was lost: no key or
            // button stays held in the guest
            self.release_inputs();
        }
        self.toggle_settle();
    }

    /// Release every key and button that the guest holds (a release that the renderer sent
    /// while no device was paired, or that went to the VM of before a restore, never came).
    fn release_inputs(&mut self) {
        if let Some((kbd, tab)) = &self.inputs {
            let n = kbd.lock().expect("Poisoned lock").release_held()
                + tab.lock().expect("Poisoned lock").release_held();
            if n > 0 {
                self.log_info(&format!(
                    "spacebox remote gpu: {n} keys or buttons that the guest held released"
                ));
            }
        }
    }

    /// Renderer `ci` holds nothing of this guest.
    fn renderer_empty(&mut self, ci: usize) {
        if ci == USER
            && let Some(sw) = self.switch.as_ref()
            && sw.to != USER
            && self.takeover_waits(sw)
        {
            // the in-guest renderer has not come: the user's renderer, back, takes the guest
            let to = sw.to;
            self.switch = None;
            self.conns[to].wanted = false;
            self.log_info(&format!(
                "spacebox remote gpu: the switch to {} is given up: the user's renderer is back first",
                CONN_NAMES[to]
            ));
            self.start_switch(None, USER, "the user's renderer came back");
            return;
        }
        match self.switch.as_ref().map(|s| s.to) {
            Some(to) if to == ci => self.switch_reset(),
            // it waits until the switch under way is done
            Some(_) => {}
            None if ci == self.active => {
                if self.seq != 0 || self.journal.stats().resources != 0 {
                    self.start_switch(None, ci, "the renderer restarted");
                }
            }
            None if ci == USER => {
                // what only the GPU wrote is taken from the renderer that runs the guest, if it is
                // there; from a lost one nothing can be (the journal only, then the redraw)
                let a = self.active;
                let from = self.conns[a].up().then_some(a);
                self.start_switch(from, USER, "the user's renderer connected")
            }
            None => {}
        }
    }

    /// Begin to build the state of renderer `to` again; `from`: the old renderer, which
    /// still runs and gives what only the GPU wrote (a planned switch). Without it the
    /// renderer is lost: what it was sent and has not answered is answered here.
    fn start_switch(&mut self, from: Option<usize>, to: usize, why: &'static str) {
        self.start_switch_to(from, to, why, 0);
    }

    /// [`Self::start_switch`], the new renderer reset to message id `reset_to` (what it holds
    /// of this device and did not change after that id is kept).
    fn start_switch_to(
        &mut self,
        from: Option<usize>,
        to: usize,
        why: &'static str,
        reset_to: u64,
    ) {
        self.log_info(&format!(
            "spacebox remote gpu: switch to {} ({why}) begins",
            CONN_NAMES[to]
        ));
        if from.is_none() {
            self.drop_pending();
        }
        self.switch = Some(Switch {
            from,
            to,
            phase: Phase::Connect,
            t0: now_us(),
            kept: BTreeSet::new(),
            scanout: None,
            msgs: 0,
            bytes: 0,
            chunks: 0,
            chunk_bytes: 0,
            why,
            reset_to,
            export: 0,
        });
        let c = &mut self.conns[to];
        c.wanted = true;
        if c.up() {
            self.switch_reset();
        } else {
            // it starts empty
            c.peer_session = 0;
            self.retry_timer.arm(Duration::from_millis(1), None);
        }
    }

    /// The new renderer is there: it drops what it may hold of an earlier pairing.
    fn switch_reset(&mut self) {
        let Some(sw) = self.switch.as_mut() else {
            return;
        };
        sw.phase = Phase::Reset;
        let (to, n) = (sw.to, sw.reset_to);
        self.conns[to].marked.clear();
        self.send_on(to, true, SP_STATE_RESET, 0, &[], &[], n, 0, 0);
    }

    fn switch_kept(&mut self, ci: usize, a: &[u8]) {
        let Some(sw) = self.switch.as_mut() else {
            return;
        };
        if sw.to != ci || sw.phase != Phase::Reset {
            return;
        }
        sw.kept = a
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();
        if sw.from.is_some() {
            sw.phase = Phase::Drain;
            self.switch_drained();
        } else {
            let kept = sw.kept.clone();
            self.send_rebuild(ci, &kept, None);
            self.import_saved_scanouts(ci, &kept);
            self.finish_switch();
        }
    }

    /// A restored device rebuilds a renderer before the guest ran on: the resources the GPU
    /// wrote that the renderer did not keep get what the GPU had drawn into them at the
    /// snapshot, then the scanout is shown again.
    fn import_saved_scanouts(&mut self, to: usize, kept: &BTreeSet<u32>) {
        let saved = std::mem::take(&mut self.scanout_saved);
        let (mut n, mut bytes, mut ids) = (0u64, 0u64, BTreeSet::new());
        for (a, b) in &saved {
            let res = u32_at(a, 0);
            if kept.contains(&res) || !self.journal.gpu_written().contains(&res) {
                continue;
            }
            self.send_on(to, true, SP_IMPORT, 0, a, b, 0, 0, 0);
            n += 1;
            bytes += b.len() as u64;
            ids.insert(res);
        }
        if n == 0 {
            return;
        }
        for r in self.journal.scanout_cmds() {
            self.send_on(to, true, SP_CTRL, 0, &r, &[], 0, 0, 0);
        }
        if let Some(sw) = self.switch.as_mut() {
            sw.chunks += n;
            sw.chunk_bytes += bytes;
        }
        self.log_info(&format!(
            "spacebox remote gpu: the content of the resources {ids:?} saved at the snapshot imported ({n} pieces, {bytes} bytes)"
        ));
    }

    /// The resources the GPU wrote: those shown last first (the compositor's swap chain), then
    /// the rest.
    fn written_shown_first(&self) -> (Vec<u32>, Vec<u32>) {
        let written = self.journal.gpu_written();
        let shown: Vec<u32> = self
            .scanned
            .iter()
            .copied()
            .filter(|r| written.contains(r))
            .collect();
        let rest: Vec<u32> = written
            .iter()
            .copied()
            .filter(|r| !shown.contains(r))
            .collect();
        (shown, rest)
    }

    /// At a snapshot, after the drain: what the GPU drew, exported by the renderer, for the side
    /// file. First the resources shown last (the compositor's swap chain), then every other
    /// resource the GPU wrote: a rollback resets the renderer to the snapshot and drops what was
    /// written after it, and the guest's programs go on using what they drew before the snapshot
    /// (a compositor's swap chain, the cached pictures of a shell's panel) without drawing it
    /// again. Each export goes on while the renderer sends ([`SAVE_EXPORT_SILENCE_US`]); what an
    /// export that does not complete was to bring is recorded as missing (`saved_missing`), and
    /// the snapshot is taken all the same (a move must not depend on the export).
    fn save_scanouts(&mut self) {
        self.scanout_saved = Vec::new();
        self.saved_missing = Vec::new();
        let (shown, rest) = self.written_shown_first();
        // nothing shown, nothing saved: there is no picture to keep
        if shown.is_empty() {
            return;
        }
        let a = self.active;
        if self.switch.is_some() || !self.conns[a].up() {
            self.save_missing_all(if self.switch.is_some() {
                "a switch is under way"
            } else {
                "the renderer is gone"
            });
            return;
        }
        for (ids, what) in [
            (shown, "the shown resources"),
            (rest, "the other resources the GPU wrote"),
        ] {
            if ids.is_empty() {
                continue;
            }
            let t0 = now_us();
            let got = self.snapshot_export(&ids);
            let named = if ids.len() <= 8 {
                format!("{ids:?}")
            } else {
                format!("({} resources)", ids.len())
            };
            let ms = (now_us() - t0) / 1000;
            match got {
                Ok((pieces, skipped)) => {
                    let bytes: usize = pieces.iter().map(|(_, b)| b.len()).sum();
                    self.log_info(&format!(
                        "spacebox remote gpu: snapshot: {what} {named} saved ({} pieces, {bytes} bytes, {ms} ms){}",
                        pieces.len(),
                        if skipped.is_empty() {
                            String::new()
                        } else {
                            format!("; the renderer did not export {skipped:?}")
                        }
                    ));
                    self.scanout_saved.extend(pieces);
                    self.saved_missing.extend(skipped);
                }
                Err(why) => {
                    self.log_info(&format!(
                        "spacebox remote gpu: snapshot: {what} {named} not saved: the export did not complete ({why}; {ms} ms)"
                    ));
                    self.saved_missing.extend(ids);
                }
            }
        }
        if !self.saved_missing.is_empty() {
            self.log_incomplete("an export did not complete");
        }
    }

    /// At a snapshot whose renderer cannot export now: everything the GPU wrote is missing from
    /// it (if anything is shown).
    fn save_missing_all(&mut self, why: &str) {
        self.scanout_saved = Vec::new();
        let (shown, rest) = self.written_shown_first();
        self.saved_missing = if shown.is_empty() {
            Vec::new()
        } else {
            [shown, rest].concat()
        };
        if !self.saved_missing.is_empty() {
            self.log_incomplete(why);
        }
    }

    fn log_incomplete(&mut self, why: &str) {
        self.log_info(&format!(
            "spacebox remote gpu: snapshot: its GPU content is incomplete ({why}): {} resources not saved {:?}, recorded in the side file; a rollback to it that lacks them logs it",
            self.saved_missing.len(),
            self.saved_missing
        ));
    }

    /// The request id of a new export.
    fn next_export_id(&mut self) -> u64 {
        self.export_seq = self.export_seq.wrapping_add(1).max(1);
        self.export_seq
    }

    /// One export of `ids` from the active renderer during a snapshot. It goes on while the
    /// renderer sends: once it is complete, its pieces and the resources the renderer did not
    /// export; otherwise why it did not complete (the renderer is gone, or it sent nothing for
    /// [`SAVE_EXPORT_SILENCE_US`]).
    fn snapshot_export(&mut self, ids: &[u32]) -> Result<(Vec<Piece>, Vec<u32>), &'static str> {
        let a = self.active;
        let id = self.next_export_id();
        self.snap_export = Some(SnapExport {
            id,
            ..Default::default()
        });
        let req: Vec<u8> = ids.iter().flat_map(|r| r.to_le_bytes()).collect();
        self.send(SP_EXPORT, 0, &req, &[], id, 0, 0);
        let mut heard = (self.conns[a].link.rx_total(), now_us());
        let why = loop {
            self.take_remote(a);
            if self.snap_export.as_ref().is_some_and(|e| e.done) {
                break None;
            }
            if !self.conns[a].up() {
                break Some("the renderer is gone");
            }
            let (rx, now) = (self.conns[a].link.rx_total(), now_us());
            if rx != heard.0 {
                heard = (rx, now);
            }
            let left = heard.1 + SAVE_EXPORT_SILENCE_US - now;
            if left <= 0 {
                break Some("the renderer sent nothing for 2 s");
            }
            self.conns[a]
                .link
                .wait(Duration::from_micros(left.clamp(1, 10_000).unsigned_abs()));
        };
        let e = self.snap_export.take().unwrap_or_default();
        match why {
            None => Ok((e.pieces, e.skipped)),
            Some(why) => Err(why),
        }
    }

    /// A reply of an export (`SP_EXPORT_DATA`, `SP_EXPORT_DONE`, arg2 its request id): it goes
    /// to the snapshot's or the switch's export that waits for it; a reply of another export
    /// (a late one, of an export that ended without it) is dropped and counted.
    fn export_reply(&mut self, ci: usize, h: &Hdr, a: &[u8], b: &[u8]) {
        let rid = h.arg2;
        if ci == self.active
            && let Some(e) = self.snap_export.as_mut()
            && e.id == rid
        {
            if h.typ == SP_EXPORT_DATA {
                e.pieces.push((a.to_vec(), b.to_vec()));
            } else {
                e.done = true;
                e.skipped = a.chunks_exact(4).map(|c| u32_at(c, 0)).collect();
            }
            return;
        }
        if rid != 0
            && self
                .switch
                .as_ref()
                .is_some_and(|sw| sw.from == Some(ci) && sw.export == rid)
        {
            if h.typ == SP_EXPORT_DATA {
                self.switch_chunk(ci, a, b);
            } else {
                self.switch_export_done(ci, h, a);
            }
            return;
        }
        self.counters.export_stale += 1;
        if h.typ == SP_EXPORT_DONE {
            self.log_info(&format!(
                "spacebox remote gpu: {} ended export {rid:#x}, which is not the export waited for: its replies are dropped ({} replies of other exports dropped so far)",
                CONN_NAMES[ci], self.counters.export_stale
            ));
        }
    }

    /// In a planned switch, once the old renderer has answered everything: first the scanout,
    /// so that the picture comes back after one resource, then the rest.
    fn switch_drained(&mut self) {
        let Some(sw) = self.switch.as_ref() else {
            return;
        };
        if sw.phase != Phase::Drain || !self.pending.is_empty() {
            return;
        }
        let (from, to, kept) = (sw.from.unwrap(), sw.to, sw.kept.clone());
        let written = self.journal.gpu_written();
        match self.journal.scanout_resource() {
            Some(s) if written.first() == Some(&s) && !kept.contains(&s) => {
                self.send_rebuild(to, &kept, Some(s));
                let id = self.next_export_id();
                self.send_on(from, true, SP_EXPORT, 0, &s.to_le_bytes(), &[], id, 0, 0);
                let sw = self.switch.as_mut().unwrap();
                sw.scanout = Some(s);
                sw.phase = Phase::Scanout;
                sw.export = id;
            }
            _ => self.switch_rest(from, to),
        }
    }

    /// The rest of the rebuild, and the export of everything the GPU wrote but the scanout.
    fn switch_rest(&mut self, from: usize, to: usize) {
        let sw = self.switch.as_mut().unwrap();
        let mut kept = sw.kept.clone();
        kept.extend(sw.scanout);
        let scanout = sw.scanout;
        sw.phase = Phase::Rest;
        self.send_rebuild(to, &kept, None);
        let ids: Vec<u8> = self
            .journal
            .gpu_written()
            .into_iter()
            .filter(|&id| Some(id) != scanout)
            .flat_map(u32::to_le_bytes)
            .collect();
        if ids.is_empty() {
            self.finish_switch();
        } else {
            let id = self.next_export_id();
            self.send_on(from, true, SP_EXPORT, 0, &ids, &[], id, 0, 0);
            self.switch.as_mut().unwrap().export = id;
        }
    }

    /// A piece of the old renderer's export: it goes to the new renderer.
    fn switch_chunk(&mut self, ci: usize, a: &[u8], b: &[u8]) {
        let Some(sw) = self.switch.as_mut() else {
            return;
        };
        if sw.from != Some(ci) || !matches!(sw.phase, Phase::Scanout | Phase::Rest) {
            return;
        }
        sw.chunks += 1;
        sw.chunk_bytes += b.len() as u64;
        let to = sw.to;
        self.send_on(to, true, SP_IMPORT, 0, a, b, 0, 0, 0);
    }

    fn switch_export_done(&mut self, ci: usize, h: &Hdr, a: &[u8]) {
        let Some(sw) = self.switch.as_ref() else {
            return;
        };
        if sw.from != Some(ci) {
            return;
        }
        let (phase, to, t0) = (sw.phase, sw.to, sw.t0);
        if !a.is_empty() {
            let ids: Vec<u32> = a
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect();
            self.log_error(&format!(
                "spacebox remote gpu: the old renderer did not export {ids:?}"
            ));
        }
        match phase {
            Phase::Scanout => {
                for r in self.journal.scanout_cmds() {
                    self.send_on(to, true, SP_CTRL, 0, &r, &[], 0, 0, 0);
                }
                self.log_info(&format!(
                    "spacebox remote gpu: switch: the scanout is shown again after {} ms ({} bytes)",
                    (now_us() - t0) / 1000,
                    h.arg1
                ));
                self.switch_rest(ci, to);
            }
            Phase::Rest => {
                for r in self.journal.scanout_cmds() {
                    self.send_on(to, true, SP_CTRL, 0, &r, &[], 0, 0, 0);
                }
                self.finish_switch();
            }
            _ => {}
        }
    }

    /// Send the journal's state to renderer `to` (all but `kept`, or resource `only`).
    fn send_rebuild(&mut self, to: usize, kept: &BTreeSet<u32>, only: Option<u32>) {
        let j = std::mem::take(&mut self.journal);
        let (mut msgs, mut bytes) = (0u64, 0u64);
        {
            let mut out = |m: Msg<'_>| {
                msgs += 1;
                match m {
                    Msg::Ctrl(r) => {
                        bytes += r.len() as u64;
                        self.send_on(to, true, SP_CTRL, 0, &r, &[], 0, 0, 0);
                    }
                    Msg::Import(h, d) => {
                        bytes += d.len() as u64;
                        self.send_on(to, true, SP_IMPORT, 0, &h, d, 0, 0, 0);
                    }
                    Msg::Cursor(c) => self.send_on(to, true, SP_CURSOR, 0, c, &[], 0, 0, 0),
                }
            };
            match only {
                Some(id) => j.rebuild_resource(id, &mut out),
                None => j.rebuild(kept, &mut out),
            }
        }
        self.journal = j;
        if let Some(sw) = self.switch.as_mut() {
            sw.msgs += msgs;
            sw.bytes += bytes;
        }
    }

    fn finish_switch(&mut self) {
        let Some(sw) = self.switch.take() else {
            return;
        };
        // (before the old renderer's link closes: what that does sees the new renderer active)
        self.active = sw.to;
        if let Some(f) = sw.from
            && f != sw.to
        {
            if self.conns[f].detaching {
                self.send_on(f, true, SP_BYE, 0, &[], &[], 0, 0, 0);
                self.conns[f].peer_session = 0;
            } else if f == USER && self.gpu_off {
                // the toggle: the user's link stays up for input, sound, the cursor and the
                // pictures; its renderer is reset and built again when the toggle is on
            } else {
                // the in-guest renderer waits for the next time, when it starts empty
                self.conns[f].wanted = f == USER;
                self.disconnected(f);
                self.conns[f].peer_session = 0;
            }
        }
        if let Some(c) = self.journal.cursor_cmd().map(<[u8]>::to_vec) {
            self.send(SP_CURSOR, 0, &c, &[], 0, 0, 0);
        }
        self.n_switch += 1;
        let st = self.journal.stats();
        self.log_info(&format!(
            "spacebox remote gpu: switch to {} ({}) done in {} ms: rebuilt {} messages, {} bytes; imported {} pieces, {} bytes; journal: {} resources, {} upload bytes, {} log entries",
            CONN_NAMES[sw.to],
            sw.why,
            (now_us() - sw.t0) / 1000,
            sw.msgs,
            sw.bytes,
            sw.chunks,
            sw.chunk_bytes,
            st.resources,
            st.upload_bytes,
            st.log_entries
        ));
        let missing = if sw.from.is_none() {
            std::mem::take(&mut self.saved_missing)
        } else {
            Vec::new()
        };
        let written = self.journal.gpu_written();
        let lacking: Vec<u32> = missing
            .into_iter()
            .filter(|r| !sw.kept.contains(r) && written.contains(r))
            .collect();
        if sw.from.is_none() && sw.reset_to != 0 {
            // a rollback to a snapshot whose export did not complete: what the renderer lacks
            // holds nothing the guest drew until the redraw
            if !lacking.is_empty() {
                self.log_info(&format!(
                    "spacebox remote gpu: the snapshot's GPU content was incomplete: the resources {lacking:?} were not saved at the snapshot and the renderer did not keep them"
                ));
            }
            // a rollback: what changed after the snapshot is drawn again (K6), but only 2 s
            // after the VM resumes, so that the picture is first the snapshot's (the user's
            // choice, also for a snapshot whose GPU content is incomplete)
            match self.resumed_at {
                Some(t) => self.redraw_at = Some(t + ROLLBACK_REDRAW_US),
                None => self.redraw_after_resume = true,
            }
        } else if sw.from.is_none() {
            // what only the GPU wrote is gone: every program draws again (K6)
            self.redraw();
        }
        self.toggle_settle();
        if let Err(err) = self.process_ctrl_queue() {
            error!("gpu: control queue: {err}");
        }
    }

    /// Ask the guest agent to make every program draw again; if it is not connected (after a
    /// restore it connects again), as soon as it is, and only while the renderer that runs the
    /// guest is there: the agent changes the monitor's scale and back, and the compositor that
    /// applies a scale waits for its GPU work, so with no renderer it did not answer the agent
    /// in time and the scale stayed changed (a takeover, fix-gpu, 2026-10-18). A redraw that
    /// waits for the renderer is asked for when the renderer is paired again (`hello`).
    pub(crate) fn redraw(&mut self) {
        let renderer = self.active_up();
        match self.agent.as_mut() {
            Some(ag) if ag.is_connected() && renderer => {
                ag.send(b"REDRAW\n");
                self.redraw_pending = false;
                self.log_info("spacebox remote gpu: asked the guest agent to redraw");
            }
            Some(_) => self.redraw_pending = true,
            None => {}
        }
    }

    /// The guest agent connected.
    pub(crate) fn agent_connected(&mut self) {
        if self.redraw_pending {
            self.redraw();
        }
    }

    /// The renderer is lost: what waits for it is answered here. Fenced commands are done as
    /// far as the guest can tell (their output is lost with what only the GPU wrote); reads get
    /// what guest memory holds; query results that were not in yet read as done (0), so that
    /// the guest does not wait for them forever.
    fn drop_pending(&mut self) {
        let Some(mem) = self.mem() else {
            self.pending.clear();
            return;
        };
        let mut pend: Vec<Pending> = self.pending.drain().map(|(_, p)| p).collect();
        pend.sort_by_key(|p| p.seq);
        let n = pend.len();
        for p in pend {
            if let Some(cmd) = p.cmd {
                self.answer(
                    &mem,
                    CTRL_QUEUE,
                    &cmd,
                    &Self::nodata(p.flags, p.fence_id, p.ctx_id),
                );
            }
        }
        self.fence_out = 0;
        self.wait_out = 0;
        self.hard_out = 0;
        self.fq_head = 0;
        self.fq_len = 0;
        let bufs: Vec<u32> = self.query_bufs.iter().copied().collect();
        for res in bufs {
            if u32::from_le_bytes(
                self.read_backing(&mem, res, 0, 4)
                    .try_into()
                    .unwrap_or([0; 4]),
            ) == QUERY_STATE_WAIT_HOST
            {
                // VIRGL_QUERY_STATE_DONE, a result of 0
                let mut q = [0u8; 16];
                q[0] = 1;
                self.write_backing(&mem, res, 0, &q);
            }
        }
        self.unpark(&mem, 0, -1);
        self.answered_lost += n as u64;
        self.say_answered_lost();
    }

    /// The line about the commands of a lost renderer answered here, at most once a second with
    /// their count since the last line (with no renderer every run of the control queue answers
    /// some: about 900 lines in the first 10 s of a boot with no screen, G3's F2).
    fn say_answered_lost(&mut self) {
        let now = now_us();
        if self.answered_lost == 0 || now - self.answered_lost_said < 1_000_000 {
            return;
        }
        let n = std::mem::take(&mut self.answered_lost);
        self.answered_lost_said = now;
        self.log_info(&format!(
            "spacebox remote gpu: {n} commands of the lost renderer were answered here"
        ));
    }

    /// Renderer `ci` ends on purpose: with an in-guest renderer that is connected (or whose
    /// connection waits) the guest's state moves there first; with none there, the renderer
    /// ends at once and the guest is served alone until the in-guest renderer takes over.
    fn detach(&mut self, ci: usize) {
        self.conns[ci].detaching = true;
        if ci == USER {
            // it ends: the toggle ends with it
            self.gpu_off = false;
            self.gpu_on_pending = false;
        }
        self.log_info(&format!("spacebox remote gpu: {} detaches", CONN_NAMES[ci]));
        if ci == self.active
            && self.switch.is_none()
            && ci == USER
            && self.has_fallback()
            && self.conns[GUEST].link.reachable()
        {
            self.start_switch(Some(USER), GUEST, "the user's renderer detached");
        } else if self.switch.as_ref().is_none_or(|s| s.from != Some(ci)) {
            // nothing to take from it; the next renderer gets the state from the journal
            self.send_on(ci, true, SP_BYE, 0, &[], &[], 0, 0, 0);
            self.conns[ci].peer_session = 0;
        }
    }

    fn on_message(&mut self, ci: usize, h: Hdr, a: Vec<u8>, b: Vec<u8>) {
        if h.typ == SP_HELLO {
            self.hello(ci, &h);
            return;
        }
        let c = &mut self.conns[ci];
        if !c.hello_done {
            return;
        }
        c.link.acked(h.ack);
        if h.id != 0 {
            if h.id <= c.rx_id {
                return; // resent, already handled
            }
            if h.id != c.rx_id + 1 {
                let msg = format!(
                    "spacebox remote gpu: message {} after {}, closing",
                    h.id, c.rx_id
                );
                self.log_error(&msg);
                self.disconnected(ci);
                return;
            }
            c.rx_id = h.id;
        }
        if h.typ == SP_SPEC_REPLY {
            self.spec_reply(ci, &h, &a);
            return;
        }
        if !self.conns[ci].spec_ok {
            // a renderer that has not said that it can do the spec is sent nothing and takes
            // nothing
            return;
        }
        if h.typ != SP_ACK {
            self.rx_delay(h.t_us);
            self.dispatch(ci, &h, &a, &b);
        }
        let c = &self.conns[ci];
        if c.link.is_connected() && c.rx_id - c.rx_id_acked >= 256 {
            self.send_ack(ci);
        }
    }

    /// `sp_disconnected`: both ends keep their state; the device reconnects and the stream
    /// continues from the last message the other end received.
    pub(crate) fn disconnected(&mut self, ci: usize) {
        let c = &mut self.conns[ci];
        if !c.link.is_connected() {
            return;
        }
        c.link.disconnect();
        // While the in-guest renderer runs, the user's socket is tried every 250 ms, and a forward
        // with no renderer behind it takes the connection and closes it: that is not a loss.
        let was_up = c.hello_done && c.spec_ok;
        c.hello_done = false;
        if !c.spec_ok {
            // a pairing whose renderer had not answered the spec starts again
            c.peer_session = 0;
        }
        if was_up {
            // the 10 s of the takeover count from the last time it ran
            c.lost_at = now_us();
        }
        let wanted = c.wanted;
        if ci == USER && (was_up || ci == self.active) {
            self.log_info("spacebox remote gpu: connection lost, reconnecting");
        } else if ci != USER {
            self.log_info(&format!(
                "spacebox remote gpu: {} disconnected",
                CONN_NAMES[ci]
            ));
        }
        if wanted {
            self.retry_timer.arm(RECONNECT, None);
        }
        if ci == GUEST {
            self.stream_on = false;
        }
        if ci == USER && was_up && (self.gpu_off || self.gpu_on_pending) {
            // a sudden loss with the toggle off: the in-guest renderer runs the guest on, with no
            // pictures; the user's renderer that comes back is a new pairing, which starts with
            // the toggle on
            self.gpu_off = false;
            self.gpu_on_pending = false;
            self.conns[USER].peer_session = 0;
            self.log_info(
                "spacebox remote gpu: the user's renderer is lost while the GPU acceleration is off: the in-guest renderer runs the guest on, with no pictures",
            );
        }
        if let Some(sw) = self.switch.as_mut() {
            if sw.to == ci {
                // it starts again from the beginning when it is back
                sw.phase = Phase::Connect;
                self.conns[ci].peer_session = 0;
            } else if sw.from == Some(ci) {
                // a planned switch whose old renderer went: what only the GPU wrote is lost
                sw.from = None;
                sw.scanout = None;
                self.drop_pending();
                if self.conns[self.switch.as_ref().unwrap().to].up() {
                    self.switch_reset();
                }
            }
        }
        self.toggle_settle();
    }

    /// Handle what renderer `ci`'s reader thread passed on.
    pub(crate) fn process_remote(&mut self, ci: usize) {
        let _ = self.conns[ci].link.rx_event.read();
        self.take_remote(ci);
        self.notify_used();
    }

    /// Handle what renderer `ci`'s reader thread has passed on so far.
    fn take_remote(&mut self, ci: usize) {
        while let Some(ev) = self.conns[ci].link.try_recv() {
            let c = &self.conns[ci];
            match ev {
                RxEvent::Msg { cgen, hdr, a, b } => {
                    if c.link.is_connected() && cgen == c.link.cgen {
                        self.on_message(ci, hdr, a, b);
                    }
                }
                RxEvent::Closed { cgen, reason } => {
                    if c.link.is_connected() && cgen == c.link.cgen {
                        if let Some(r) = reason {
                            self.log_error(&format!("spacebox remote gpu: {r}, closing"));
                        }
                        self.disconnected(ci);
                    }
                }
            }
        }
    }

    /// The retry timer: connect the renderers that are wanted (`sp_source_connect`), or take
    /// commands again after the network has drained.
    pub(crate) fn process_retry(&mut self) {
        self.retry_timer.read();
        let mut again = false;
        for ci in 0..self.conns.len() {
            let c = &self.conns[ci];
            if c.link.is_connected() || !c.wanted {
                continue;
            }
            if c.refused && now_us() - c.refused_at < SPEC_RETRY_US {
                again = true;
                continue;
            }
            let hello = Hdr {
                typ: SP_HELLO,
                arg0: self.session,
                arg1: c.peer_session,
                arg2: c.rx_id,
                seq: if c.restored { c.link.lock().q.tx_id } else { 0 },
                flags: SP_F_SPEC
                    | if c.link.z_level() != 0 { SP_F_ZSTD } else { 0 }
                    | if self.agent.is_some() { SP_F_SCROLL } else { 0 }
                    | if c.restored { SP_F_RESTORED } else { 0 },
                ..Default::default()
            };
            if self.conns[ci].link.connect(&hello) {
                // The user's socket is tried every 250 ms while the in-guest renderer runs; say so
                // only for the renderer that runs the guest.
                if ci == self.active {
                    let msg = format!(
                        "spacebox remote gpu: source connected to {}",
                        self.conns[ci].link.path()
                    );
                    self.log_info(&msg);
                }
            } else {
                again = true;
            }
        }
        if again {
            self.retry_timer.arm(RECONNECT, None);
        }
        if self.active_up()
            && let Err(err) = self.process_ctrl_queue()
        {
            error!("gpu: control queue: {err}");
        }
        self.notify_used();
    }

    /// With an in-guest renderer: the user's renderer that is gone, or silent with work pending,
    /// for 10 s is replaced by the in-guest renderer.
    fn check_takeover(&mut self) {
        if !self.has_fallback()
            || self.switch.is_some()
            || self.active != USER
            || self.saved_wanted.is_some()
        {
            // (not while the VM is paused after a snapshot: the connections are closed; not to
            // an in-guest renderer that cannot do the spec)
            return;
        }
        let now = now_us();
        let u = &self.conns[USER];
        let gone = if u.up() {
            self.pending
                .values()
                .map(|p| p.t0)
                .min()
                .is_some_and(|t| now - t > TAKEOVER_US)
        } else {
            now - u.lost_at > TAKEOVER_US
        };
        if !gone {
            return;
        }
        if u.link.is_connected() {
            self.log_error(
                "spacebox remote gpu: the user's renderer has not answered for 10 s, closing",
            );
            self.disconnected(USER);
        }
        // it starts empty when it comes back
        self.conns[USER].peer_session = 0;
        self.start_switch(None, GUEST, "the user's renderer was gone for 10 s");
    }

    /// `sp_ack_timer`, every 100 ms.
    pub(crate) fn process_ack_timer(&mut self) {
        self.ack_timer.read();
        if !self.parked.is_empty()
            && let Some(mem) = self.mem()
        {
            self.unpark(&mem, 0, 200_000);
        }
        for ci in 0..self.conns.len() {
            let c = &self.conns[ci];
            if c.up() && c.rx_id != c.rx_id_acked {
                self.send_ack(ci);
            }
        }
        if let Some(ag) = self.agent.as_mut() {
            ag.flush();
        }
        if let Some(t) = self.redraw_at
            && now_us() >= t
        {
            self.redraw_at = None;
            self.log_info(
                "spacebox remote gpu: the redraw after the rollback is due (2 s after the resume)",
            );
            self.redraw();
        }
        self.check_takeover();
        self.say_answered_lost();
        if self.gpu_off && self.active == USER && self.switch.is_none() {
            // a toggle off that waits for the in-guest renderer's link
            self.toggle_settle();
        }
        // the wait for a first or a lost renderer may have ended with commands waiting
        if self.conns[self.active].up() {
            self.alone_said = false;
        } else if self.alone()
            && let Err(err) = self.process_ctrl_queue()
        {
            error!("gpu: control queue: {err}");
        }
        self.notify_used();
    }

    // ---- snapshots ---------------------------------------------------------------------

    /// Everything sent has been answered and acknowledged: nothing of the guest waits for a
    /// renderer, and no renderer needs anything sent again.
    fn settled(&self) -> bool {
        self.switch.is_none()
            && self.pending.is_empty()
            && self.parked.is_empty()
            && self.conns.iter().all(|c| c.link.lock().q.unacked == 0)
    }

    /// Before a snapshot (the VM is paused): take no more commands, and wait at most 2 s until
    /// the renderer has answered and acknowledged everything (a renderer that is gone is not
    /// waited for longer: what it has not answered is in the snapshot, and is sent again or
    /// answered when the device is restored). Then the snapshot is a mark point of every
    /// connection, and the connections close: what a renderer sends from now on is for the
    /// VM that resumes (it reconnects, `kick`), not for the snapshot.
    fn save_prepare(&mut self) {
        if self.active == GUEST {
            self.guest_save_prepare();
            return;
        }
        let t0 = now_us();
        self.saving = true;
        loop {
            for ci in 0..self.conns.len() {
                self.take_remote(ci);
            }
            // a parked read is answered after 200 ms at the latest, as by the ack timer
            if !self.parked.is_empty()
                && let Some(mem) = self.mem()
            {
                self.unpark(&mem, 0, 200_000);
            }
            if self.settled() {
                break;
            }
            let left = t0 + SAVE_WAIT_US - now_us();
            if left <= 0 {
                break;
            }
            for ci in 0..self.conns.len() {
                if self.conns[ci].link.is_connected() && self.conns[ci].hello_done {
                    let c = &self.conns[ci];
                    if c.rx_id != c.rx_id_acked {
                        self.send_ack(ci);
                    }
                }
            }
            let a = self.active;
            self.conns[a]
                .link
                .wait(Duration::from_micros(left.clamp(1, 10_000).unsigned_abs()));
        }
        self.notify_used();
        let settled = self.settled();
        let unacked: u64 = self
            .conns
            .iter()
            .map(|c| c.link.lock().q.unacked as u64)
            .sum();
        self.log_info(&format!(
            "spacebox remote gpu: snapshot: {} after {} ms ({} commands not answered, {} parked, {} bytes not acknowledged{})",
            if settled {
                "everything answered"
            } else {
                "not everything answered"
            },
            (now_us() - t0) / 1000,
            self.pending.len(),
            self.parked.len(),
            unacked,
            if self.switch.is_some() {
                ", a switch under way"
            } else {
                ""
            }
        ));
        if settled {
            self.save_scanouts();
        } else {
            self.save_missing_all("not everything was answered before the snapshot");
        }
        for ci in 0..self.conns.len() {
            if self.conns[ci].up() && self.conns[ci].rx_id != self.conns[ci].rx_id_acked {
                self.send_ack(ci);
            }
        }
        let wanted = self.conns.iter().map(|c| c.wanted).collect();
        for ci in 0..self.conns.len() {
            self.conns[ci].marked.clear();
            self.conns[ci].wanted = false;
            let c = &mut self.conns[ci];
            if c.link.is_connected() {
                c.link.disconnect();
                c.hello_done = false;
            }
        }
        // a switch under way is not finished; its renderer starts empty (see persist)
        self.saved_wanted.get_or_insert(wanted);
        self.saving = false;
    }

    /// Before a snapshot while the in-guest renderer runs the guest: its state is in the guest's
    /// memory, which the snapshot holds at this same instant, so nothing is waited for and nothing
    /// is exported (with the vCPUs paused it could not answer anyway). After a restore it connects
    /// again and resumes; a renderer that takes the guest from it later gets what its GPU drew by
    /// a planned switch. The snapshot is a mark point, and the connections close, as always.
    fn guest_save_prepare(&mut self) {
        self.scanout_saved = Vec::new();
        self.saved_missing = Vec::new();
        let wanted = self.conns.iter().map(|c| c.wanted).collect();
        let pending = self.pending.len();
        for c in &mut self.conns {
            c.marked.clear();
            c.wanted = false;
            if c.link.is_connected() {
                c.link.disconnect();
                c.hello_done = false;
            }
        }
        self.saved_wanted.get_or_insert(wanted);
        self.log_info(&format!(
            "spacebox remote gpu: snapshot: the in-guest renderer runs the guest; its state is in the guest's memory: nothing waited for or exported ({pending} commands not answered go with the state)"
        ));
    }

    /// The stop of a move (a snapshot of the state only): the guest goes on at the destination,
    /// whose device resumes the same renderer, so nothing is waited for and nothing is exported
    /// (what was not answered or acknowledged is in the state and goes on there). The stop is a
    /// mark point, and the connections close, as at a snapshot. A VM that goes on here after it
    /// (the way back of a move whose destination ran) says that it was restored, so that a
    /// renderer that the destination's device ran on goes back to this stop.
    fn move_prepare(&mut self) {
        let wanted = self.conns.iter().map(|c| c.wanted).collect();
        let pending = self.pending.len();
        let unacked: u64 = self
            .conns
            .iter()
            .map(|c| c.link.lock().q.unacked as u64)
            .sum();
        for c in &mut self.conns {
            c.marked.clear();
            c.wanted = false;
            c.restored = true;
            if c.link.is_connected() {
                c.link.disconnect();
                c.hello_done = false;
            }
        }
        self.saved_wanted.get_or_insert(wanted);
        self.log_info(&format!(
            "spacebox remote gpu: the stop of a move: {pending} commands not answered and {unacked} bytes not acknowledged go with the state; the connections closed"
        ));
    }

    /// A checkpoint of a running guest: the guest goes on at once, so nothing is waited for,
    /// nothing is exported and no connection closes. The checkpoint is a mark point of every
    /// connection: a resource written after it is marked again, so that a renderer that ran on
    /// after it can be reset to it (a takeover from it).
    fn checkpoint_prepare(&mut self) {
        for c in &mut self.conns {
            c.marked.clear();
        }
    }

    /// The VM resumes (after a snapshot, or a restore): connect to the renderers again.
    fn resume_kick(&mut self) {
        let now = now_us();
        if std::mem::take(&mut self.release_at_kick) {
            self.release_inputs();
        }
        self.resumed_at = Some(now);
        if std::mem::take(&mut self.redraw_after_resume) {
            self.redraw_at = Some(now + ROLLBACK_REDRAW_US);
        }
        if let Some(w) = self.saved_wanted.take() {
            for (c, w) in self.conns.iter_mut().zip(w) {
                c.wanted = w;
            }
        }
        // the waits for a renderer that is not there count from the VM's resume (a restored
        // device was made long before it may run)
        for c in &mut self.conns {
            if !c.up() {
                c.lost_at = now;
            }
        }
        self.retry_timer.arm(Duration::from_millis(1), None);
        if self.is_activated()
            && let Err(err) = self.process_cursor_queue()
        {
            error!("gpu: cursor queue: {err}");
        }
        self.notify_used();
    }

    /// What the test of a checkpoint's consistency reads of the device at each stop of the guest
    /// (`crate::devices::screen`): the in-guest renderer's pictures passed on since the start, and
    /// the last message id sent to and received from each renderer.
    pub(crate) fn traffic(&self) -> GpuTraffic {
        let ids = |ci: usize| {
            self.conns
                .get(ci)
                .map_or((0, 0), |c| (c.link.lock().q.tx_id, c.rx_id))
        };
        GpuTraffic {
            pictures: self.pictures_all,
            user: ids(USER),
            guest: ids(GUEST),
        }
    }

    /// `sp_stats`, every 5 s: the same lines as the QEMU source, so that the same tools read
    /// them, and the query counters of this device.
    pub(crate) fn process_stats_timer(&mut self) {
        self.stats_timer.read();
        let link = &self.conns[self.active].link;
        let (wire_tx, txd, backlog, unacked, z_on, tx_id) = {
            let mut st = link.lock();

            (
                std::mem::take(&mut st.wire_tx),
                std::mem::take(&mut st.txd),
                st.q.backlog,
                st.q.unacked,
                st.z_on,
                st.q.tx_id,
            )
        };
        let (wire_rx, rx_bytes) = link.take_rx_counts();
        let mut lines = Vec::new();
        let ms = |v: i64| v as f64 / 1000.0;
        let c = &self.counters;
        let f = c.flush;
        lines.push(format!(
            "[SPACEBOX-REMOTE] source screen updates={} gaps over 12 ms={} over 25 ms={} over 50 ms={} longest_ms={:.1}",
            f.n,
            f.over12,
            f.over25,
            f.over50,
            ms(f.max)
        ));
        let d = c.delay;
        lines.push(format!(
            "[SPACEBOX-REMOTE] source answers from the sink={} over 12 ms={} over 25 ms={} over 50 ms={} longest_ms={:.1}",
            d.n,
            d.over12,
            d.over25,
            d.over50,
            ms(d.max)
        ));
        lines.push(format!(
            "[SPACEBOX-REMOTE] source messages written={} queue-to-written over 12 ms={} over 25 ms={} over 50 ms={} longest_ms={:.1}",
            txd.n,
            txd.over12,
            txd.over25,
            txd.over50,
            ms(txd.max)
        ));
        let r = c.rxd;
        lines.push(format!(
            "[SPACEBOX-REMOTE] source messages received={} later than the fastest by over 12 ms={} over 25 ms={} over 50 ms={} longest_ms={:.1}",
            r.n,
            r.over12,
            r.over25,
            r.over50,
            ms(r.max)
        ));
        let mut pend = format!("[SPACEBOX-REMOTE] source pending={}", self.pending.len());
        if let Some(o) = self.pending.values().min_by_key(|p| p.seq) {
            pend.push_str(&format!(
                " oldest: seq={} type={:#x} early={} age_ms={}",
                o.seq,
                o.typ,
                u32::from(o.early),
                (now_us() - o.t0) / 1000
            ));
        }
        let rtt_min = self.rtt_min_cur.min(self.rtt_min_prev);
        pend.push_str(&format!(
            " last_seq={} answered_here={} fence_early={} waited={} fence_out={} rtt_ms={:.1} not_sent={} not_sent_bytes={} early_by_age={} rtt_min_ms={:.1} early_by_video_age={}",
            self.seq,
            c.n_local,
            c.n_early,
            c.n_waited,
            self.fence_out,
            ms(self.rtt_us),
            c.n_defer,
            c.defer_bytes,
            c.n_ahead,
            if rtt_min == i64::MAX { 0.0 } else { ms(rtt_min) },
            c.n_ahead_video
        ));
        lines.push(pend);
        for i in 0..64 {
            if self.ctx_qpoll[i] != 0 {
                lines.push(format!(
                    "[SPACEBOX-REMOTE] source query polls answered here: ctx={i} ({}) {}",
                    self.ctx_name[i], self.ctx_qpoll[i]
                ));
                self.ctx_qpoll[i] = 0;
            }
        }
        lines.push(format!(
            "[SPACEBOX-REMOTE] source ctrl={} submit={} submit_bytes={} xfer={} xfer_bytes={} mem={} mem_bytes={} back={} back_bytes={} tx_bytes={} rx_bytes={} backlog={} unacked={} reconnects={} wire_tx_bytes={} wire_rx_bytes={} compressed={}",
            c.n_ctrl,
            c.n_submit,
            c.submit_bytes,
            c.n_xfer,
            c.xfer_bytes,
            c.n_mem,
            c.mem_bytes,
            c.n_back,
            c.back_bytes,
            c.tx_bytes,
            rx_bytes,
            backlog,
            unacked,
            c.n_reconnect,
            wire_tx,
            wire_rx,
            u32::from(z_on)
        ));
        // Not in the QEMU source: the queries answered here and forwarded (since the start),
        // the sink's input (all, and what no device took), and the connection's ids.
        let q = c.queries;
        lines.push(format!(
            "[SPACEBOX-REMOTE] source queries answered here: capset_info={} capset={} display_info={} edid={} forwarded: before the information={} after it={} input={} input_dropped={} tx_id={tx_id} rx_id={} session={:#x} peer={:#x}",
            q.capset_info,
            q.capset,
            q.display_info,
            q.edid,
            q.forwarded_before_info,
            q.forwarded_after_info,
            c.n_input,
            c.n_input_dropped,
            self.conns[self.active].rx_id,
            self.session,
            self.conns[self.active].peer_session,
        ));
        // Not in the QEMU source: which renderer runs the guest, the switch under way, and
        // the journal (since the start).
        let up = |ci: usize| match self.conns.get(ci) {
            None => "none",
            Some(c) if c.up() => "up",
            Some(_) => "down",
        };
        lines.push(format!(
            "[SPACEBOX-REMOTE] source renderers: active={} switch={} switches={} user={} guest={}",
            if self.active == USER { "user" } else { "guest" },
            self.switch.as_ref().map_or_else(
                || "none".into(),
                |s| format!("{:?}", s.phase).to_lowercase()
            ),
            self.n_switch,
            up(USER),
            up(GUEST)
        ));
        lines.push(format!(
            "[SPACEBOX-REMOTE] source toggle: gpu={} stream={} pictures={} picture_bytes={} dropped={} late={}",
            if self.gpu_off { "off" } else { "on" },
            u32::from(self.stream_on),
            self.counters.n_picture,
            self.counters.picture_bytes,
            self.counters.pictures_dropped,
            self.counters.pictures_late
        ));
        let j = self.journal.stats();
        lines.push(format!(
            "[SPACEBOX-REMOTE] source journal: resources={} contexts={} upload_bytes={} gpu_written={} gpu_written_bytes={} log_entries={} log_bytes={} wmarks={} wmark_ids={} wmark_skipped={}",
            j.resources,
            j.contexts,
            j.upload_bytes,
            j.gpu_written,
            j.gpu_written_bytes,
            j.log_entries,
            j.log_bytes,
            self.counters.n_wmark,
            self.counters.wmark_ids,
            self.counters.wmark_skipped
        ));
        // The devices beside the GPU (since the start): the events given to the guest's input
        // devices, the sound sent on this connection, and the agent's channel.
        if let Some((kbd, tab)) = &self.inputs {
            let k = kbd.lock().expect("Poisoned lock").counters;
            let t = tab.lock().expect("Poisoned lock").counters;
            lines.push(format!(
                "[SPACEBOX-REMOTE] source input devices: keyboard events={} dropped={} tablet events={} dropped={}",
                k.delivered, k.dropped, t.delivered, t.dropped
            ));
        }
        let sd = c.sound;
        lines.push(format!(
            "[SPACEBOX-REMOTE] source sound on the main connection: messages={} bytes={} not_sent_bytes={} short_bytes={}",
            sd.messages, sd.bytes, sd.not_sent, sd.short_bytes
        ));
        if let Some(ag) = &self.agent {
            let a = ag.counters;
            lines.push(format!(
                "[SPACEBOX-REMOTE] source agent: connected={} connections={} lines_to_agent={} lines_from_agent={} dropped={}",
                u32::from(ag.is_connected()),
                a.connections,
                a.lines_out,
                a.lines_in,
                a.dropped
            ));
        }
        let c = &mut self.counters;
        c.flush = DelayStat::default();
        c.delay = DelayStat::default();
        c.rxd = DelayStat::default();
        c.n_local = 0;
        c.n_early = 0;
        c.n_waited = 0;
        c.n_ahead = 0;
        c.n_ahead_video = 0;
        c.n_defer = 0;
        c.defer_bytes = 0;
        c.n_ctrl = 0;
        c.n_submit = 0;
        c.submit_bytes = 0;
        c.n_xfer = 0;
        c.xfer_bytes = 0;
        c.n_mem = 0;
        c.mem_bytes = 0;
        c.n_back = 0;
        c.back_bytes = 0;
        c.tx_bytes = 0;
        c.n_picture = 0;
        c.picture_bytes = 0;
        c.pictures_dropped = 0;
        c.pictures_late = 0;
        for l in lines {
            self.report(&l);
        }
    }
}

impl VirtioDevice for Gpu {
    impl_device_type!(VirtioDeviceType::Gpu);

    fn id(&self) -> &str {
        GPU_DEV_ID
    }

    fn num_queues(&self) -> usize {
        self.queues.len()
    }

    fn queue_config(&self, index: usize) -> Option<&QueueConfig> {
        self.queues.get(index).map(|queue| &queue.config)
    }

    fn queue_config_mut(&mut self, index: usize) -> Option<&mut QueueConfig> {
        self.queues.get_mut(index).map(|queue| &mut queue.config)
    }

    fn queue_event(&self, index: usize) -> Option<&EventFd> {
        self.queue_events.get(index)
    }

    fn queue_positions(&self) -> Vec<(u16, u16)> {
        crate::devices::virtio::device::positions_of(&self.queues)
    }

    fn watched_ranges(&self) -> Vec<(usize, GuestAddress, usize, &'static str)> {
        crate::devices::virtio::device::watched_of(&self.queues)
    }

    fn queue_pending(&self) -> Vec<u16> {
        crate::devices::virtio::device::pending_of(&self.queues)
    }

    fn reset_queues(&mut self) {
        self.queues.iter_mut().for_each(Queue::reset);
    }

    fn mark_queue_memory_dirty(&mut self, mem: &GuestMemoryMmap) -> Result<(), QueueError> {
        for queue in &mut self.queues {
            queue.initialize(mem)?;
        }
        Ok(())
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .deref()
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn config_as_bytes(&self) -> &[u8] {
        &self.config
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // Only events_clear (offset 4) is writable.
        if offset == 4 && data.len() == 4 {
            let clear = u32_at(data, 0);
            let ev = self.config_word(0) & !clear;
            self.set_config(0, ev);
        }
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn deactivate(&mut self) {
        self.device_state = DeviceState::Inactive;
    }

    /// `virtio_gpu_reset` and `sp_source_reset`: the resources and the commands waiting for
    /// the sink are dropped without an answer; the sink is told to reset.
    fn _reset(&mut self) -> bool {
        info!(
            "gpu: reset ({} commands were waiting for the sink)",
            self.pending.len()
        );
        self.resources.clear();
        self.pending.clear();
        self.journal = Journal::new();
        self.switch = None;
        self.fence_out = 0;
        self.wait_out = 0;
        self.hard_out = 0;
        self.fq_head = 0;
        self.fq_len = 0;
        self.custom_bufs.clear();
        self.parked.clear();
        self.set_config(0, 0);
        self.used = [false; GPU_NUM_QUEUES];
        self.send(SP_RESET, 0, &[], &[], 0, 0, 0);
        true
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        for q in self.queues.iter_mut() {
            q.initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }
        self.activate_event
            .write(1)
            .map_err(|_| ActivateError::EventFd)?;
        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        Ok(())
    }

    fn prepare_save(&mut self) {
        self.save_kind = SaveKind::Snapshot;
        self.save_prepare();
    }

    fn prepare_move(&mut self) {
        self.save_kind = SaveKind::Move;
        self.move_prepare();
    }

    fn prepare_checkpoint(&mut self) {
        self.save_kind = SaveKind::Checkpoint;
        self.checkpoint_prepare();
    }

    fn kick(&mut self) {
        self.resume_kick();
        if self.is_activated() {
            self.notify_queue_events();
        }
    }
}

mod persist;
pub use persist::{
    GpuConstructorArgs, GpuPersistError, GpuSideState, GpuState, SIDE_LOST, SideParts, side_path,
};

#[cfg(test)]
mod tests;
