// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The GPU device in a snapshot (Firecracker's `Persist`).
//!
//! The snapshot's state file holds what the guest sees of the device (the virtio state, the
//! config space), its configuration, its session with each renderer (the session ids, the ids
//! of the two streams) and what the renderer told it (capsets, display, EDID). What the device
//! keeps of the renderer's state is larger than the 10 MB that Firecracker reads of a state
//! file (the journal's kept uploads are tens of MB): the journal, the resources with their
//! backing, the commands not answered yet and the messages no renderer has acknowledged go
//! into a file beside the snapshot, [`side_path`] (`<snapshot>.gpu`), tied to the state by a
//! random id. A restore without it, or with another snapshot's, fails.
//!
//! Before the save the device takes no more commands and waits, at most 2 s, until its
//! renderer has answered every command and acknowledged every message
//! ([`Gpu::prepare_save`](super::Gpu)); then it asks the renderer for what the GPU drew into
//! the resources it wrote (for a rollback, which drops what was written after the snapshot):
//! each export goes on while the renderer sends, and ends when it is complete, when the
//! renderer is gone, or after 2 s in which the renderer sent nothing. What an export that does
//! not complete lacks is recorded in the side file (`scanout_missing`), and the snapshot is
//! taken all the same; a rollback that lacks it logs it, and its redraw comes 2 s after the
//! resume as after every rollback. Then the device closes its connections. The snapshot is a mark
//! point of every connection (`Conn::marked`): a resource that is written after it is listed
//! in an `SP_WMARK` again, so that a renderer that ran on after the snapshot can be reset to
//! the snapshot's last message id.
//!
//! On restore the device connects to the renderer of the snapshot and says in its HELLO that
//! it was restored (`SP_F_RESTORED`, with the last id it gave out before the snapshot). A
//! renderer of the same session with exactly that many of its messages resumes (a live move:
//! what it had not acknowledged is sent again). One that has more ran on after the snapshot (a
//! rollback): it goes back with the stream to that id, and the device resets it to that id
//! (`SP_STATE_RESET` N keeps what did not change after the snapshot) and builds the rest again
//! from the journal. A renderer that does not know the device starts empty and gets all of it.

use std::collections::{HashSet, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gpu_journal::Journal;
use serde::{Deserialize, Serialize};

use super::{Cmd, Conn, Gpu, Parked, Pending, Resource, now_us};
use crate::devices::virtio::device::VirtioDeviceType;
use crate::devices::virtio::gpu::GPU_NUM_QUEUES;
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;
use crate::seccomp::BpfProgram;
use crate::snapshot::Persist;
use crate::vmm_config::gpu::GpuConfig;
use crate::vstate::memory::{GuestAddress, GuestMemoryMmap};

/// The first bytes of a side file.
const SIDE_MAGIC: &[u8; 8] = b"SPGPU002";

/// The file beside the snapshot `snapshot_path` that holds the GPU device's large state.
pub fn side_path(snapshot_path: &Path) -> PathBuf {
    let mut p = snapshot_path.as_os_str().to_owned();
    p.push(".gpu");
    PathBuf::from(p)
}

/// A connection of the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuConnState {
    /// The renderer's session (0 = none: it starts empty).
    pub peer_session: u64,
    /// The last id received from it, and the last id given out to it.
    pub rx_id: u64,
    pub tx_id: u64,
    pub detaching: bool,
    pub wanted: bool,
}

/// The GPU device's state in the snapshot's state file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuState {
    pub virtio_state: VirtioDeviceState,
    /// The configuration (`PUT /gpu`) as JSON: its optional fields are left out when unset,
    /// which bitcode cannot read back.
    pub config: String,
    pub config_space: [u8; 16],
    /// This device's session.
    pub session: u64,
    /// The id of the side file that belongs to this state.
    pub side_id: u64,
    pub conns: Vec<GpuConnState>,
    pub active: usize,
    /// A switch was under way (the snapshot's wait ran out): its renderer starts empty.
    pub switching: bool,
    pub seq: u64,
    pub info_seen: bool,
    pub user_info: bool,
    pub n_switch: u64,
    /// The renderer's capsets: (id, version, data).
    pub caps: Vec<(u32, u32, Vec<u8>)>,
    pub dinfo: Option<Vec<u8>>,
    pub edid: Option<Vec<u8>>,
    pub ctx_name: Vec<String>,
    pub redraw_pending: bool,
    /// The large state, read from or written to the side file (not in the state file).
    #[serde(skip)]
    pub side: Option<Arc<GpuSideState>>,
}

/// A resource of the device's bookkeeping: id, format, width, height, backing entries.
type ResourceState = (u32, u32, u32, u32, Option<Vec<(u64, u32)>>);

/// A command not answered yet: the head of its descriptor chain and its writable parts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CmdState {
    pub head: u16,
    pub writable: Vec<(u64, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingState {
    pub cmd: Option<CmdState>,
    pub typ: u32,
    pub res: u32,
    pub off: u64,
    pub len: u64,
    pub seq: u64,
    pub early: bool,
    pub fence_wait: bool,
    pub hard: bool,
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParkedState {
    pub cmd: CmdState,
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
    pub res: u32,
}

/// The GPU device's large state: the side file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuSideState {
    pub side_id: u64,
    pub journal: Journal,
    pub resources: Vec<ResourceState>,
    /// (ctx << 32 | query handle, resource), query result buffers, custom buffers.
    pub queries: Vec<(u64, u32)>,
    pub query_bufs: Vec<u32>,
    pub custom_bufs: Vec<u32>,
    pub pending: Vec<PendingState>,
    pub parked: Vec<ParkedState>,
    /// For each connection: the reliable messages its renderer has not acknowledged.
    pub unacked: Vec<Vec<(u64, Vec<u8>)>>,
    /// What the GPU drew into the resources it wrote (those shown last first), as `SP_IMPORT`s
    /// (header, bytes), exported at the snapshot (imported at a rollback).
    pub scanout_saved: Vec<(Vec<u8>, Vec<u8>)>,
    /// The resources the GPU wrote whose content the snapshot lacks (an export did not
    /// complete, or the renderer could not answer): a rollback that does not keep one of them
    /// logs it.
    pub scanout_missing: Vec<u32>,
}

impl GpuSideState {
    /// The side file: the magic, the bitcode of the state, and its CRC64.
    pub fn write_to(&self, w: &mut impl Write) -> Result<(), GpuPersistError> {
        let data = bitcode::serialize(self).map_err(|e| GpuPersistError::Side(e.to_string()))?;
        w.write_all(SIDE_MAGIC)?;
        w.write_all(&(data.len() as u64).to_le_bytes())?;
        w.write_all(&data)?;
        w.write_all(&crc64::crc64(0, &data).to_le_bytes())?;
        Ok(())
    }

    pub fn read_from(r: &mut impl Read) -> Result<Self, GpuPersistError> {
        let mut head = [0u8; 16];
        r.read_exact(&mut head)?;
        if &head[..8] != SIDE_MAGIC {
            return Err(GpuPersistError::Side(
                "not a side file of this version".into(),
            ));
        }
        let len = usize::try_from(u64::from_le_bytes(head[8..16].try_into().unwrap()))
            .map_err(|_| GpuPersistError::Side("too long".into()))?;
        let mut data = vec![0u8; len];
        r.read_exact(&mut data)?;
        let mut crc = [0u8; 8];
        r.read_exact(&mut crc)?;
        if crc64::crc64(0, &data) != u64::from_le_bytes(crc) {
            return Err(GpuPersistError::Side("CRC mismatch".into()));
        }
        bitcode::deserialize(&data).map_err(|e| GpuPersistError::Side(e.to_string()))
    }
}

#[derive(Debug)]
pub struct GpuConstructorArgs {
    pub mem: GuestMemoryMmap,
    /// The `vmm` seccomp filter, for the device's I/O threads.
    pub filter: Arc<BpfProgram>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum GpuPersistError {
    /// Virtio state: {0}
    VirtioState(#[from] VirtioStateError),
    /// The GPU device's configuration in the snapshot: {0}
    Config(#[from] serde_json::Error),
    /// The GPU device cannot be made: {0}
    Create(#[from] std::io::Error),
    /// The GPU device's side file of the snapshot is missing
    NoSide,
    /// The GPU device's side file belongs to another snapshot
    OtherSide,
    /// The GPU device's side file: {0}
    Side(String),
    /// The GPU device's state is not valid: {0}
    Invalid(&'static str),
}

fn cmd_state(c: &Cmd) -> CmdState {
    CmdState {
        head: c.head,
        writable: c.writable.iter().map(|(a, l)| (a.0, *l)).collect(),
    }
}

fn cmd_of(c: &CmdState) -> Cmd {
    Cmd {
        head: c.head,
        writable: c
            .writable
            .iter()
            .map(|&(a, l)| (GuestAddress(a), l))
            .collect(),
    }
}

fn random_id() -> u64 {
    let mut v = [0u8; 8];
    // SAFETY: getrandom writes at most 8 bytes into v.
    unsafe { libc::getrandom(v.as_mut_ptr().cast(), 8, 0) };
    u64::from_le_bytes(v)
}

impl Persist<'_> for Gpu {
    type State = GpuState;
    type ConstructorArgs = GpuConstructorArgs;
    type Error = GpuPersistError;

    fn save(&self) -> Self::State {
        let side_id = random_id();
        let mut resources: Vec<ResourceState> = self
            .resources
            .iter()
            .map(|(&id, r)| (id, r.format, r.width, r.height, r.backing.clone()))
            .collect();
        resources.sort_by_key(|r| r.0);
        let mut pending: Vec<PendingState> = self
            .pending
            .values()
            .map(|p| PendingState {
                cmd: p.cmd.as_ref().map(cmd_state),
                typ: p.typ,
                res: p.res,
                off: p.off,
                len: p.len,
                seq: p.seq,
                early: p.early,
                fence_wait: p.fence_wait,
                hard: p.hard,
                flags: p.flags,
                fence_id: p.fence_id,
                ctx_id: p.ctx_id,
            })
            .collect();
        pending.sort_by_key(|p| p.seq);
        let side = GpuSideState {
            side_id,
            journal: self.journal.clone(),
            resources,
            queries: self.queries.iter().map(|(&k, &v)| (k, v)).collect(),
            query_bufs: self.query_bufs.iter().copied().collect(),
            custom_bufs: self.custom_bufs.iter().copied().collect(),
            pending,
            parked: self
                .parked
                .iter()
                .map(|k| ParkedState {
                    cmd: cmd_state(&k.cmd),
                    flags: k.flags,
                    fence_id: k.fence_id,
                    ctx_id: k.ctx_id,
                    res: k.res,
                })
                .collect(),
            unacked: self
                .conns
                .iter()
                .map(|c| c.link.lock().q.unacked_messages())
                .collect(),
            scanout_saved: self.scanout_saved.clone(),
            scanout_missing: self.saved_missing.clone(),
        };
        // The wanted renderers are those before the snapshot closed the connections.
        let wanted: Vec<bool> = match &self.saved_wanted {
            Some(w) => w.clone(),
            None => self.conns.iter().map(|c| c.wanted).collect(),
        };
        GpuState {
            virtio_state: VirtioDeviceState::from_device(self, &self.queues),
            config: serde_json::to_string(&self.cfg).unwrap(),
            config_space: self.config,
            session: self.session,
            side_id,
            conns: self
                .conns
                .iter()
                .zip(wanted)
                .map(|(c, wanted)| GpuConnState {
                    peer_session: c.peer_session,
                    rx_id: c.rx_id,
                    tx_id: c.link.lock().q.tx_id,
                    detaching: c.detaching,
                    wanted,
                })
                .collect(),
            active: self.active,
            switching: self.switch.is_some(),
            seq: self.seq,
            info_seen: self.info_seen,
            user_info: self.user_info,
            n_switch: self.n_switch,
            caps: self
                .caps
                .iter()
                .flatten()
                .map(|c| (c.id, c.ver, c.data.clone()))
                .collect(),
            dinfo: self.dinfo.clone(),
            edid: self.edid.clone(),
            ctx_name: self.ctx_name.clone(),
            // a redraw that waits for the resume after a rollback is one to do in a restored
            // copy (it asks when its agent connects)
            redraw_pending: self.redraw_pending
                || self.redraw_after_resume
                || self.redraw_at.is_some(),
            side: Some(Arc::new(side)),
        }
    }

    fn restore(args: Self::ConstructorArgs, state: &Self::State) -> Result<Self, Self::Error> {
        let side = state.side.as_ref().ok_or(GpuPersistError::NoSide)?;
        if side.side_id != state.side_id {
            return Err(GpuPersistError::OtherSide);
        }
        let cfg: GpuConfig = serde_json::from_str(&state.config)?;
        let mut gpu = Gpu::new(cfg, args.filter)?;
        if state.conns.len() != gpu.conns.len()
            || side.unacked.len() != gpu.conns.len()
            || state.active >= gpu.conns.len()
            || state.ctx_name.len() != gpu.ctx_name.len()
            || state.caps.len() > gpu.caps.len()
        {
            return Err(GpuPersistError::Invalid(
                "its renderers or tables do not match",
            ));
        }
        if state.virtio_state.avail_features != gpu.avail_features {
            return Err(GpuPersistError::Invalid("its features"));
        }
        gpu.queues = state.virtio_state.build_queues_checked(
            &args.mem,
            VirtioDeviceType::Gpu,
            GPU_NUM_QUEUES,
            FIRECRACKER_MAX_QUEUE_SIZE,
        )?;
        gpu.acked_features = state.virtio_state.acked_features;
        gpu.config = state.config_space;
        gpu.session = state.session;
        let now = now_us();
        for ((c, s), unacked) in gpu.conns.iter_mut().zip(&state.conns).zip(&side.unacked) {
            restore_conn(c, s, unacked, now);
        }
        gpu.active = state.active;
        if state.switching {
            // the renderer that was being built starts empty
            gpu.conns[state.active].peer_session = 0;
        }
        gpu.seq = state.seq;
        gpu.info_seen = state.info_seen;
        gpu.user_info = state.user_info;
        gpu.n_switch = state.n_switch;
        for (slot, (id, ver, data)) in gpu.caps.iter_mut().zip(&state.caps) {
            *slot = Some(super::Capset {
                id: *id,
                ver: *ver,
                data: data.clone(),
            });
        }
        gpu.dinfo = state.dinfo.clone();
        gpu.edid = state.edid.clone();
        gpu.ctx_name = state.ctx_name.clone();
        gpu.redraw_pending = state.redraw_pending;

        gpu.journal = side.journal.clone();
        gpu.scanout_saved = side.scanout_saved.clone();
        gpu.saved_missing = side.scanout_missing.clone();
        gpu.resources = side
            .resources
            .iter()
            .map(|(id, format, width, height, backing)| {
                (
                    *id,
                    Resource {
                        format: *format,
                        width: *width,
                        height: *height,
                        backing: backing.clone(),
                    },
                )
            })
            .collect();
        gpu.queries = side.queries.iter().copied().collect();
        gpu.query_bufs = side.query_bufs.iter().copied().collect::<HashSet<_>>();
        gpu.custom_bufs = side.custom_bufs.iter().copied().collect::<HashSet<_>>();
        for p in &side.pending {
            // the send times of another host's clock mean nothing here
            if p.early || p.fence_wait {
                gpu.fq_push(now);
            }
            gpu.fence_out += u32::from(p.early);
            gpu.wait_out += u32::from(p.fence_wait);
            gpu.hard_out += u32::from(p.hard);
            gpu.pending.insert(
                p.seq,
                Pending {
                    cmd: p.cmd.as_ref().map(cmd_of),
                    typ: p.typ,
                    res: p.res,
                    off: p.off,
                    len: p.len,
                    seq: p.seq,
                    t0: now,
                    early: p.early,
                    fence_wait: p.fence_wait,
                    hard: p.hard,
                    flags: p.flags,
                    fence_id: p.fence_id,
                    ctx_id: p.ctx_id,
                },
            );
        }
        gpu.parked = side
            .parked
            .iter()
            .map(|k| Parked {
                cmd: cmd_of(&k.cmd),
                flags: k.flags,
                fence_id: k.fence_id,
                ctx_id: k.ctx_id,
                res: k.res,
                t0: now,
            })
            .collect::<VecDeque<_>>();
        let msg = format!(
            "spacebox remote gpu: restored from a snapshot: session {:#x}, {} resources, {} commands not answered, the renderer's stream at {} of {} messages{}",
            gpu.session,
            gpu.resources.len(),
            gpu.pending.len(),
            state.conns[state.active].rx_id,
            state.conns[state.active].tx_id,
            if gpu.saved_missing.is_empty() {
                String::new()
            } else {
                format!(
                    "; the snapshot's GPU content is incomplete: {} resources not saved {:?}",
                    gpu.saved_missing.len(),
                    gpu.saved_missing
                )
            }
        );
        gpu.log_info_line(&msg);
        Ok(gpu)
    }
}

fn restore_conn(c: &mut Conn, s: &GpuConnState, unacked: &[(u64, Vec<u8>)], now: i64) {
    c.peer_session = s.peer_session;
    c.rx_id = s.rx_id;
    c.rx_id_acked = s.rx_id;
    c.detaching = s.detaching;
    c.wanted = s.wanted;
    c.lost_at = now;
    c.restored = true;
    c.link.lock().q.restore(s.tx_id, unacked, now);
}
