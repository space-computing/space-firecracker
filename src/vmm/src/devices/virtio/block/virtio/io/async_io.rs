// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::alloc::{Layout, alloc_zeroed, dealloc, handle_alloc_error};
use std::collections::VecDeque;
use std::fmt::Debug;
use std::fs::File;
use std::os::fd::RawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;
use std::ptr::NonNull;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use slab::Slab;
use vm_memory::{GuestMemoryBackend, GuestMemoryError};
use vmm_sys_util::eventfd::EventFd;

use crate::devices::virtio::block::virtio::io::RequestError;
use crate::devices::virtio::block::virtio::{IO_URING_NUM_ENTRIES, PendingRequest};
use crate::io_uring::operation::{Cqe, OpCode, Operation};
use crate::io_uring::restriction::Restriction;
use crate::io_uring::{IoUring, IoUringError};
use crate::logger::{error, log_dev_preview_warning};
use crate::vstate::memory::{Bytes, GuestAddress, GuestMemoryExtension, GuestMemoryMmap};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum AsyncIoError {
    /// Not implemented
    NotImplemented,
    /// IO: {0}
    IO(std::io::Error),
    /// IoUring: {0}
    IoUring(IoUringError),
    /// Submit: {0}
    Submit(std::io::Error),
    /// SyncAll: {0}
    SyncAll(std::io::Error),
    /// EventFd: {0}
    EventFd(std::io::Error),
    /// GuestMemory: {0}
    GuestMemory(GuestMemoryError),
    /// An aligned buffer of {0} bytes cannot be made
    AlignedBuffer(u64),
}

/// The alignment that `O_DIRECT` asks of the requests of a file: offsets and lengths that are
/// multiples of `offset`, and memory at a multiple of `mem` (both powers of two).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectAlignment {
    pub offset: u32,
    pub mem: u32,
}

/// The alignment taken for a regular file opened with `O_DIRECT`: the page size, which no
/// logical block of the hosts' disks exceeds.
const FILE_DIRECT_ALIGNMENT: u32 = 4096;

const BLKSSZGET: libc::Ioctl = 0x1268;

impl DirectAlignment {
    /// No alignment: a file opened with no `O_DIRECT`.
    pub const NONE: DirectAlignment = DirectAlignment { offset: 1, mem: 1 };

    /// The alignment of a file opened with `O_DIRECT`. For a block device it is its logical
    /// block size (`BLKSSZGET`), for the offsets and for the memory: the kernel asks of the
    /// memory of direct I/O the DMA alignment of the device's queue, which is never larger
    /// than its logical block. For a regular file it is `FILE_DIRECT_ALIGNMENT`.
    pub fn of_direct_file(file: &File) -> DirectAlignment {
        let is_block_device = file
            .metadata()
            .map(|m| m.file_type().is_block_device())
            .unwrap_or(false);
        let mut size = FILE_DIRECT_ALIGNMENT;
        if is_block_device {
            let mut logical: u32 = 0;
            // SAFETY: file is a valid fd, BLKSSZGET writes an int.
            if unsafe { libc::ioctl(file.as_raw_fd(), BLKSSZGET, &mut logical) } == 0
                && logical >= 512
                && logical.is_power_of_two()
            {
                size = logical;
            }
        }
        DirectAlignment {
            offset: size,
            mem: size,
        }
    }

    fn covers(&self, offset: u64, len: u32) -> bool {
        offset.is_multiple_of(u64::from(self.offset)) && len.is_multiple_of(self.offset)
    }

    fn covers_mem(&self, addr: usize) -> bool {
        addr.is_multiple_of(self.mem as usize)
    }
}

/// The device blocks that the engines of one drive have in work. A drive with more than one
/// queue has an engine for each queue, on a thread of its own: a read-modify-write of one engine
/// and a request of another engine on the same device blocks do not run at the same time, as
/// within one engine (two writes of the guest to different sectors of one device block would
/// otherwise each write back the other's old sectors).
#[derive(Debug, Default)]
pub struct DriveBlocks {
    inner: Mutex<DriveBlocksInner>,
    released: Condvar,
}

#[derive(Debug, Default)]
struct DriveBlocksInner {
    claims: Slab<Claim>,
    // The number of claims of read-modify-writes.
    rmw: usize,
    // The number of releases so far, so that a wait for one misses none.
    releases: u64,
    engines: Vec<EngineSlot>,
}

#[derive(Debug)]
struct EngineSlot {
    // A job of the engine waits for a claim of another engine.
    waits: bool,
    // Wakes the engine's thread (the completion event of its ring), so that it tries again.
    wake: EventFd,
}

#[derive(Debug, Clone, Copy)]
struct Claim {
    engine: usize,
    start: u64,
    end: u64,
    rmw: bool,
}

/// The longest wait of a thread for a release of another engine before it looks again.
const RELEASE_WAIT: Duration = Duration::from_millis(10);

impl DriveBlocks {
    fn lock(&self) -> std::sync::MutexGuard<'_, DriveBlocksInner> {
        self.inner.lock().expect("Poisoned drive blocks lock")
    }

    /// Adds an engine, woken by `wake`; returns its number.
    fn register(&self, wake: EventFd) -> usize {
        let mut inner = self.lock();
        inner.engines.push(EngineSlot { waits: false, wake });
        inner.engines.len() - 1
    }

    /// Claims the device blocks `start..end` for a job of `engine`, unless they conflict with a
    /// claim of another engine (the two overlap and one of them is a read-modify-write); then
    /// the engine is woken at the next release.
    fn try_claim(&self, engine: usize, start: u64, end: u64, rmw: bool) -> Option<usize> {
        let mut inner = self.lock();
        if rmw || inner.rmw > 0 {
            let conflict = inner.claims.iter().any(|(_, c)| {
                c.engine != engine && (rmw || c.rmw) && c.start < end && start < c.end
            });
            if conflict {
                inner.engines[engine].waits = true;
                return None;
            }
        }
        if rmw {
            inner.rmw += 1;
        }
        Some(inner.claims.insert(Claim {
            engine,
            start,
            end,
            rmw,
        }))
    }

    /// Claims the device blocks `start..end` as a read-modify-write, waiting for the claims of
    /// other engines that conflict. The caller holds no claim, so the wait ends.
    fn claim_waiting(&self, engine: usize, start: u64, end: u64) -> usize {
        loop {
            let seen = self.releases();
            if let Some(slot) = self.try_claim(engine, start, end, true) {
                return slot;
            }
            self.wait_release(seen);
        }
    }

    fn release(&self, slot: usize) {
        let mut inner = self.lock();
        let claim = inner.claims.remove(slot);
        if claim.rmw {
            inner.rmw -= 1;
        }
        Self::released(&mut inner);
        drop(inner);
        self.released.notify_all();
    }

    /// Releases every claim of `engine` (its jobs were thrown away).
    fn release_engine(&self, engine: usize) {
        let mut inner = self.lock();
        let slots: Vec<usize> = inner
            .claims
            .iter()
            .filter(|(_, c)| c.engine == engine)
            .map(|(slot, _)| slot)
            .collect();
        if slots.is_empty() {
            return;
        }
        for slot in slots {
            let claim = inner.claims.remove(slot);
            if claim.rmw {
                inner.rmw -= 1;
            }
        }
        Self::released(&mut inner);
        drop(inner);
        self.released.notify_all();
    }

    fn released(inner: &mut DriveBlocksInner) {
        inner.releases += 1;
        for slot in inner.engines.iter_mut().filter(|e| e.waits) {
            slot.waits = false;
            if let Err(err) = slot.wake.write(1) {
                error!("Failed to wake a block queue: {:?}", err);
            }
        }
    }

    fn releases(&self) -> u64 {
        self.lock().releases
    }

    /// Waits until a release after the count `seen`, or for `RELEASE_WAIT`.
    fn wait_release(&self, seen: u64) {
        let inner = self.lock();
        if inner.releases == seen {
            let _ = self
                .released
                .wait_timeout(inner, RELEASE_WAIT)
                .expect("Poisoned drive blocks lock");
        }
    }

    // Test-only: the number of claims.
    #[cfg(test)]
    pub(crate) fn claims(&self) -> usize {
        self.lock().claims.len()
    }
}

/// Memory for the aligned operations of a request: whole device blocks, at the memory
/// alignment of `O_DIRECT`, zeroed when made.
#[derive(Debug)]
struct AlignedBuf {
    ptr: NonNull<u8>,
    layout: Layout,
}

// SAFETY: The buffer is owned memory of the heap, used by one thread at a time.
unsafe impl Send for AlignedBuf {}

impl AlignedBuf {
    /// A buffer of `len` bytes, or none when the memory cannot be had.
    fn try_new(len: usize, align: u32) -> Option<AlignedBuf> {
        let layout = Layout::from_size_align(len.max(1), align as usize).ok()?;
        // SAFETY: the layout has a size that is not zero.
        let ptr = NonNull::new(unsafe { alloc_zeroed(layout) })?;
        Some(AlignedBuf { ptr, layout })
    }

    fn new(len: usize, align: u32) -> AlignedBuf {
        Self::try_new(len, align).unwrap_or_else(|| {
            handle_alloc_error(Layout::from_size_align(len.max(1), align as usize).unwrap())
        })
    }

    fn addr(&self) -> usize {
        self.ptr.as_ptr() as usize
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: the buffer holds `layout.size()` initialized bytes.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.layout.size()) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: the buffer holds `layout.size()` initialized bytes, owned by this value.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.layout.size()) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        // SAFETY: allocated with this layout in `new`.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) }
    }
}

#[derive(Debug)]
pub struct AsyncFileEngine {
    file: File,
    ring: IoUring<Op>,
    completion_evt: EventFd,
    align: DirectAlignment,
    is_block_device: bool,
    // The reads and writes of the guest that the engine has taken and not yet answered.
    jobs: Slab<Job>,
    // Jobs that wait for a job that overlaps them, in their order.
    waiting: VecDeque<usize>,
    // Jobs whose next operation found the ring full; they go on at the next completion.
    stalled: VecDeque<usize>,
    // The number of jobs that read, change and write device blocks.
    rmw_jobs: usize,
    // Answers that the engine has taken from the ring and not yet given to the device.
    ready: VecDeque<Done>,
    // The result of the last write of the engine's own (the zeros at the ends of a discard).
    own_result: Option<i32>,
    // The device blocks in work of the drive's engines, and the number of this engine among
    // them, for a drive with more than one queue.
    blocks: Option<(Arc<DriveBlocks>, usize)>,
    // Test-only: the number of completions of the ring that pass before the injector below
    // turns completions into I/O errors.
    #[cfg(test)]
    pub(crate) pass_completions: u32,
    // Test-only: the number of completions still to come that are turned into an I/O error,
    // as a disk that fails them.
    #[cfg(test)]
    pub(crate) fail_completions: u32,
    // Test-only: the number of `fsync` calls of the file.
    #[cfg(test)]
    pub(crate) sync_all_calls: u32,
    // Test-only: the number of requests that went through an aligned buffer.
    #[cfg(test)]
    pub(crate) bounced_jobs: u32,
}

#[derive(Debug)]
pub struct WrappedRequest {
    addr: Option<GuestAddress>,
    req: PendingRequest,
}

impl WrappedRequest {
    fn new(req: PendingRequest) -> Self {
        WrappedRequest { addr: None, req }
    }

    fn new_with_dirty_tracking(addr: GuestAddress, req: PendingRequest) -> Self {
        WrappedRequest {
            addr: Some(addr),
            req,
        }
    }

    fn mark_dirty_mem_and_unwrap(self, mem: &GuestMemoryMmap, count: u32) -> PendingRequest {
        if let Some(addr) = self.addr {
            mem.mark_dirty(addr, count as usize)
        }

        self.req
    }
}

/// The user data of an operation in the ring.
#[derive(Debug)]
enum Op {
    Flush(WrappedRequest),
    Job(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Waits for a job that overlaps it.
    Waiting,
    /// One operation on the guest's memory, as the request asked.
    Direct,
    /// The aligned range is read into the buffer.
    Read,
    /// The device block at the start of a write, which the write covers in part, is read.
    Head,
    /// The device block at the end of a write, which the write covers in part, is read.
    Tail,
    /// The buffer is written over the aligned range.
    Write,
}

/// A read or a write of the guest (or a write of the engine's own, with no request). One that
/// `O_DIRECT` cannot take as it is goes through a buffer of the whole device blocks that it
/// touches; a write that covers some of them only in part reads them first. Each job has at
/// most one operation in the ring.
#[derive(Debug)]
struct Job {
    write: bool,
    wrapped: Option<WrappedRequest>,
    offset: u64,
    len: u32,
    host_addr: usize,
    // The whole device blocks that the request touches.
    start: u64,
    end: u64,
    // A write that does not cover whole device blocks: it reads them, changes its part and
    // writes them, so no request that overlaps it runs at the same time.
    rmw: bool,
    direct: bool,
    buf: Option<AlignedBuf>,
    edge: Option<AlignedBuf>,
    step: Step,
    // The claim of the device blocks among the drive's engines.
    claim: Option<usize>,
}

impl Job {
    fn overlaps(&self, other: &Job) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Whether the two may not run at the same time: they overlap and one is a
    /// read-modify-write.
    fn conflicts(&self, other: &Job) -> bool {
        (self.rmw || other.rmw) && self.overlaps(other)
    }

    fn head_off(&self) -> usize {
        usize::try_from(self.offset - self.start).unwrap()
    }

    /// The bytes of the guest's range that an operation over the aligned range moved.
    fn guest_count(&self, transferred: u32) -> u32 {
        let head = u32::try_from(self.head_off()).unwrap();
        transferred.saturating_sub(head).min(self.len)
    }
}

/// An answer of a request: its completion, and for a read through a buffer the bytes that go
/// to the guest's memory.
#[derive(Debug)]
struct Done {
    cqe: Cqe<WrappedRequest>,
    copy: Option<(AlignedBuf, usize)>,
}

/// The whole blocks of `block` bytes inside the range of `len` bytes at `offset`, if any.
pub(crate) fn blocks_inside(offset: u64, len: u32, block: u64) -> Option<(u64, u32)> {
    let start = offset.next_multiple_of(block);
    let end = (offset + u64::from(len)) / block * block;
    (end > start).then(|| (start, u32::try_from(end - start).unwrap()))
}

/// The parts of the range of `len` bytes at `offset` outside the whole blocks `inside` of it.
pub(crate) fn parts_outside(offset: u64, len: u32, inside: Option<(u64, u32)>) -> Vec<(u64, u32)> {
    let end = offset + u64::from(len);
    let Some((start, n)) = inside else {
        return vec![(offset, len)];
    };
    let inside_end = start + u64::from(n);
    let mut parts = Vec::new();
    if offset < start {
        parts.push((offset, u32::try_from(start - offset).unwrap()));
    }
    if inside_end < end {
        parts.push((inside_end, u32::try_from(end - inside_end).unwrap()));
    }
    parts
}

fn raw_result<T: Debug>(cqe: &Cqe<T>) -> i32 {
    match cqe.result() {
        Ok(count) => i32::try_from(count).unwrap_or(i32::MAX),
        Err(err) => err.raw_os_error().unwrap_or(-libc::EIO),
    }
}

impl AsyncFileEngine {
    fn new_ring(file: &File, completion_fd: RawFd) -> Result<IoUring<Op>, IoUringError> {
        IoUring::new(
            u32::from(IO_URING_NUM_ENTRIES),
            vec![file],
            vec![
                // Make sure we only allow operations on pre-registered fds.
                Restriction::RequireFixedFds,
                // Allowlist of opcodes.
                Restriction::AllowOpCode(OpCode::Read),
                Restriction::AllowOpCode(OpCode::Write),
                Restriction::AllowOpCode(OpCode::Fsync),
            ],
            Some(completion_fd),
        )
    }

    fn is_block_device(file: &File) -> bool {
        file.metadata()
            .map(|m| m.file_type().is_block_device())
            .unwrap_or(false)
    }

    /// An engine over `file`, whose requests are aligned to `align` (`DirectAlignment::NONE`
    /// for a file opened with no `O_DIRECT`). The engines of the queues of one drive share
    /// `blocks`.
    pub fn from_file(
        file: File,
        align: DirectAlignment,
        blocks: Option<Arc<DriveBlocks>>,
    ) -> Result<AsyncFileEngine, AsyncIoError> {
        log_dev_preview_warning("Async file IO", Option::None);

        let completion_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(AsyncIoError::EventFd)?;
        let ring =
            Self::new_ring(&file, completion_evt.as_raw_fd()).map_err(AsyncIoError::IoUring)?;
        let is_block_device = Self::is_block_device(&file);
        let blocks = match blocks {
            Some(blocks) => {
                let wake = completion_evt.try_clone().map_err(AsyncIoError::EventFd)?;
                let engine = blocks.register(wake);
                Some((blocks, engine))
            }
            None => None,
        };

        Ok(AsyncFileEngine {
            file,
            ring,
            completion_evt,
            align,
            is_block_device,
            jobs: Slab::new(),
            waiting: VecDeque::new(),
            stalled: VecDeque::new(),
            rmw_jobs: 0,
            ready: VecDeque::new(),
            own_result: None,
            blocks,
            #[cfg(test)]
            pass_completions: 0,
            #[cfg(test)]
            fail_completions: 0,
            #[cfg(test)]
            sync_all_calls: 0,
            #[cfg(test)]
            bounced_jobs: 0,
        })
    }

    /// A new file of the drive. The requests that are taken end on the old file first; their
    /// answers are kept for the device.
    pub fn update_file(&mut self, file: File, align: DirectAlignment) -> Result<(), AsyncIoError> {
        let ring = Self::new_ring(&file, self.completion_evt.as_raw_fd())
            .map_err(AsyncIoError::IoUring)?;

        self.drain(false)?;
        self.is_block_device = Self::is_block_device(&file);
        self.file = file;
        self.ring = ring;
        self.align = align;
        Ok(())
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn alignment(&self) -> DirectAlignment {
        self.align
    }

    pub fn completion_evt(&self) -> &EventFd {
        &self.completion_evt
    }

    pub fn push_read(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
    ) -> Result<(), RequestError<AsyncIoError>> {
        self.push_job(false, offset, mem, addr, count, req)
    }

    pub fn push_write(
        &mut self,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
    ) -> Result<(), RequestError<AsyncIoError>> {
        self.push_job(true, offset, mem, addr, count, req)
    }

    fn push_job(
        &mut self,
        write: bool,
        offset: u64,
        mem: &GuestMemoryMmap,
        addr: GuestAddress,
        count: u32,
        req: PendingRequest,
    ) -> Result<(), RequestError<AsyncIoError>> {
        let host_addr = match mem.get_slice(addr, count as usize) {
            Ok(slice) => slice.ptr_guard_mut().as_ptr() as usize,
            Err(err) => {
                return Err(RequestError {
                    req,
                    error: AsyncIoError::GuestMemory(err),
                });
            }
        };
        let wrapped = if write {
            WrappedRequest::new(req)
        } else {
            WrappedRequest::new_with_dirty_tracking(addr, req)
        };

        let block = u64::from(self.align.offset);
        let start = offset - offset % block;
        let end = (offset + u64::from(count)).next_multiple_of(block);
        let covers = self.align.covers(offset, count);
        let direct = covers && self.align.covers_mem(host_addr);
        let rmw = write && !covers;
        let mut job = Job {
            write,
            wrapped: Some(wrapped),
            offset,
            len: count,
            host_addr,
            start,
            end,
            rmw,
            direct,
            buf: None,
            edge: None,
            step: Step::Waiting,
            claim: None,
        };
        if !direct {
            // The operations of the ring move at most `u32::MAX` bytes; such a request (and
            // one whose buffer the host cannot give) is answered with an error.
            let buf = u32::try_from(end - start)
                .ok()
                .and_then(|len| AlignedBuf::try_new(len as usize, self.align.mem));
            let Some(mut buf) = buf else {
                return Err(RequestError {
                    req: job.wrapped.unwrap().req,
                    error: AsyncIoError::AlignedBuffer(end - start),
                });
            };
            if write {
                // The guest's data is taken now; the guest does not change it until the answer.
                let head = job.head_off();
                if let Err(err) =
                    mem.read_slice(&mut buf.as_mut_slice()[head..head + count as usize], addr)
                {
                    return Err(RequestError {
                        req: job.wrapped.unwrap().req,
                        error: AsyncIoError::GuestMemory(err),
                    });
                }
            }
            job.buf = Some(buf);
            #[cfg(test)]
            {
                self.bounced_jobs += 1;
            }
        }

        let key = self.jobs.insert(job);
        if rmw {
            self.rmw_jobs += 1;
        }
        if self.blocked(key, self.waiting.len()) || !self.claim(key) {
            self.waiting.push_back(key);
            return Ok(());
        }
        let first = self.first_step(key);
        match self.push_step(key, first) {
            Ok(()) => Ok(()),
            Err(error) => {
                let job = self.remove_job(key);
                Err(RequestError {
                    req: job.wrapped.unwrap().req,
                    error,
                })
            }
        }
    }

    /// Whether job `key` must wait: it conflicts with a job in the ring, or overlaps one of
    /// the first `earlier` waiting jobs that it may not pass.
    fn blocked(&self, key: usize, earlier: usize) -> bool {
        let job = &self.jobs[key];
        if self.rmw_jobs == 0 {
            return false;
        }
        self.jobs
            .iter()
            .any(|(k, other)| k != key && other.step != Step::Waiting && job.conflicts(other))
            || self
                .waiting
                .iter()
                .take(earlier)
                .any(|&k| k != key && job.conflicts(&self.jobs[k]))
    }

    /// Claims the device blocks of job `key` among the drive's engines; false when a job of
    /// another engine holds them (the engine is woken when it lets them go).
    fn claim(&mut self, key: usize) -> bool {
        let Some((blocks, engine)) = &self.blocks else {
            return true;
        };
        let job = &mut self.jobs[key];
        if job.claim.is_some() {
            return true;
        }
        match blocks.try_claim(*engine, job.start, job.end, job.rmw) {
            Some(slot) => {
                job.claim = Some(slot);
                true
            }
            None => false,
        }
    }

    fn first_step(&self, key: usize) -> Step {
        let job = &self.jobs[key];
        let block = u64::from(self.align.offset);
        if job.direct {
            Step::Direct
        } else if !job.write {
            Step::Read
        } else if !job.offset.is_multiple_of(block) {
            Step::Head
        } else if !(job.offset + u64::from(job.len)).is_multiple_of(block) {
            Step::Tail
        } else {
            Step::Write
        }
    }

    fn step_after(&self, key: usize, step: Step) -> Option<Step> {
        let job = &self.jobs[key];
        let block = u64::from(self.align.offset);
        match step {
            Step::Head
                if job.end - job.start > block
                    && !(job.offset + u64::from(job.len)).is_multiple_of(block) =>
            {
                Some(Step::Tail)
            }
            Step::Head | Step::Tail => Some(Step::Write),
            _ => None,
        }
    }

    /// Puts the operation of `step` of job `key` in the ring.
    fn push_step(&mut self, key: usize, step: Step) -> Result<(), AsyncIoError> {
        let block = self.align.offset;
        let mem_align = self.align.mem;
        let job = &mut self.jobs[key];
        job.step = step;
        let op = match step {
            Step::Direct if job.write => {
                Operation::write(0, job.host_addr, job.len, job.offset, Op::Job(key))
            }
            Step::Direct => Operation::read(0, job.host_addr, job.len, job.offset, Op::Job(key)),
            Step::Read | Step::Write => {
                let buf = job.buf.as_ref().unwrap();
                let len = u32::try_from(job.end - job.start).unwrap();
                if step == Step::Write {
                    Operation::write(0, buf.addr(), len, job.start, Op::Job(key))
                } else {
                    Operation::read(0, buf.addr(), len, job.start, Op::Job(key))
                }
            }
            Step::Head | Step::Tail => {
                let at = if step == Step::Head {
                    job.start
                } else {
                    job.end - u64::from(block)
                };
                let edge = job
                    .edge
                    .get_or_insert_with(|| AlignedBuf::new(block as usize, mem_align));
                edge.as_mut_slice().fill(0);
                Operation::read(0, edge.addr(), block, at, Op::Job(key))
            }
            Step::Waiting => unreachable!(),
        };
        #[cfg(test)]
        self.check_aligned(&op);
        self.ring
            .push(op)
            .map_err(|(err, _)| AsyncIoError::IoUring(err))
    }

    // Test-only: every data operation that reaches the ring is one that `O_DIRECT` takes.
    #[cfg(test)]
    fn check_aligned(&self, op: &Operation<Op>) {
        let (addr, len, offset) = (op.addr.unwrap_or(0), op.len.unwrap_or(0), op.offset);
        assert!(
            self.align.covers(offset.unwrap_or(0), len) && self.align.covers_mem(addr),
            "an operation that O_DIRECT refuses: offset {offset:?}, length {len}, memory \
             {addr:#x}, alignment {:?}",
            self.align
        );
    }

    fn remove_job(&mut self, key: usize) -> Job {
        let job = self.jobs.remove(key);
        if job.rmw {
            self.rmw_jobs -= 1;
        }
        if let (Some(slot), Some((blocks, _))) = (job.claim, &self.blocks) {
            blocks.release(slot);
        }
        job
    }

    /// Ends job `key` with the result `res` (bytes of the guest's range, or an error).
    fn finish_job(&mut self, key: usize, res: i32) {
        let job = self.remove_job(key);
        let head = job.head_off();
        let copy = match (job.write, job.direct, res >= 0) {
            (false, false, true) => job.buf.map(|buf| (buf, head)),
            _ => None,
        };
        match job.wrapped {
            Some(wrapped) => self.ready.push_back(Done {
                cqe: Cqe::new(res, wrapped),
                copy,
            }),
            None => self.own_result = Some(res),
        }
    }

    /// Takes the completion of an operation of the ring.
    fn handle_cqe(&mut self, cqe: Cqe<Op>) {
        let res = raw_result(&cqe);
        let key = match cqe.user_data() {
            Op::Flush(wrapped) => {
                self.ready.push_back(Done {
                    cqe: Cqe::new(res, wrapped),
                    copy: None,
                });
                return;
            }
            Op::Job(key) => key,
        };
        if res < 0 {
            // A failed operation fails the whole request; it runs again from its start.
            self.finish_job(key, res);
            return;
        }
        let transferred = u32::try_from(res).unwrap();
        let job = &mut self.jobs[key];
        match job.step {
            Step::Direct => self.finish_job(key, res),
            Step::Read | Step::Write => {
                let count = job.guest_count(transferred);
                self.finish_job(key, i32::try_from(count).unwrap());
            }
            step @ (Step::Head | Step::Tail) => {
                // The bytes of the block outside the guest's range go into the buffer; a
                // short read (the end of a file) leaves zeros.
                let block = u64::from(self.align.offset);
                let at = if step == Step::Head {
                    job.start
                } else {
                    job.end - block
                };
                let guest_end = job.offset + u64::from(job.len);
                let edge = job.edge.as_ref().unwrap();
                let read = &edge.as_slice()[..transferred as usize];
                let buf = job.buf.as_mut().unwrap().as_mut_slice();
                for (from, to) in [
                    (at, job.offset.min(at + block)),
                    (guest_end.max(at), at + block),
                ] {
                    let (from, to) = (from.max(at), to.min(at + block));
                    if from >= to {
                        continue;
                    }
                    let (e0, e1) = (
                        usize::try_from(from - at).unwrap(),
                        usize::try_from(to - at).unwrap(),
                    );
                    let b0 = usize::try_from(from - job.start).unwrap();
                    let e1r = e1.min(read.len());
                    if e0 < e1r {
                        buf[b0..b0 + (e1r - e0)].copy_from_slice(&read[e0..e1r]);
                    }
                }
                let next = self.step_after(key, step).unwrap();
                self.continue_job(key, next);
            }
            Step::Waiting => unreachable!(),
        }
    }

    /// Puts the next operation of job `key` in the ring; when the ring is full the job goes on
    /// at the next completion.
    fn continue_job(&mut self, key: usize, step: Step) {
        match self.push_step(key, step) {
            Ok(()) => {}
            Err(AsyncIoError::IoUring(err)) if err.is_throttling_err() => {
                self.stalled.push_back(key);
            }
            Err(err) => {
                error!("Failed to submit an aligned block operation: {:?}", err);
                self.finish_job(key, -libc::EIO);
            }
        }
    }

    /// Starts what can start: the stalled jobs, then the waiting jobs that no job blocks.
    fn run_deferred(&mut self) {
        while let Some(&key) = self.stalled.front() {
            let step = self.jobs[key].step;
            match self.push_step(key, step) {
                Ok(()) => {
                    self.stalled.pop_front();
                }
                Err(AsyncIoError::IoUring(err)) if err.is_throttling_err() => return,
                Err(err) => {
                    self.stalled.pop_front();
                    error!("Failed to submit an aligned block operation: {:?}", err);
                    self.finish_job(key, -libc::EIO);
                }
            }
        }
        let mut i = 0;
        while i < self.waiting.len() {
            let key = self.waiting[i];
            if self.blocked(key, i) || !self.claim(key) {
                i += 1;
                continue;
            }
            let first = self.first_step(key);
            match self.push_step(key, first) {
                Ok(()) => {
                    self.waiting.remove(i);
                }
                Err(AsyncIoError::IoUring(err)) if err.is_throttling_err() => {
                    self.jobs[key].step = Step::Waiting;
                    return;
                }
                Err(err) => {
                    self.waiting.remove(i);
                    error!("Failed to submit a block request: {:?}", err);
                    self.finish_job(key, -libc::EIO);
                }
            }
        }
    }

    /// Takes the completions in the ring and starts what they let start.
    fn take_completions(&mut self) -> Result<(), AsyncIoError> {
        while let Some(cqe) = self.take_ring_cqe()? {
            self.handle_cqe(cqe);
        }
        self.run_deferred();
        if self.ring.pending_sqes().map_err(AsyncIoError::IoUring)? > 0 {
            self.kick_submission_queue()?;
        }
        Ok(())
    }

    fn signal_ready(&self) {
        if let Err(err) = self.completion_evt.write(1) {
            error!("Failed to signal block completions: {:?}", err);
        }
    }

    pub fn push_flush(&mut self, req: PendingRequest) -> Result<(), RequestError<AsyncIoError>> {
        let wrapped_user_data = WrappedRequest::new(req);

        self.ring
            .push(Operation::fsync(0, Op::Flush(wrapped_user_data)))
            .map_err(|(io_uring_error, data)| RequestError {
                req: match data {
                    Op::Flush(wrapped) => wrapped.req,
                    Op::Job(_) => unreachable!(),
                },
                error: AsyncIoError::IoUring(io_uring_error),
            })
    }

    /// Discards `range` (byte offset and length): the requests in flight end first, then the
    /// range is discarded (`BLKDISCARD` on a block device, a punched hole in a file). Their
    /// answers stay with the engine and are taken as usual. On a block device whose blocks are
    /// larger than a sector, the whole blocks inside the range are discarded and the parts at
    /// its ends are written with zeros (a read-modify-write of the blocks they are in), as a
    /// punched hole in a file reads as zeros.
    pub fn discard(&mut self, range: (u64, u32)) -> Result<u32, AsyncIoError> {
        self.drain(false)?;
        // The device blocks of the range are claimed among the drive's engines, as a
        // read-modify-write: no request of another queue on them runs at the same time.
        let block = u64::from(self.align.offset);
        let claim = self.blocks.as_ref().map(|(blocks, engine)| {
            let start = range.0 - range.0 % block;
            let end = (range.0 + u64::from(range.1)).next_multiple_of(block);
            (blocks.clone(), blocks.claim_waiting(*engine, start, end))
        });
        let res = self.discard_claimed(range);
        if let Some((blocks, slot)) = claim {
            blocks.release(slot);
        }
        res
    }

    fn discard_claimed(&mut self, range: (u64, u32)) -> Result<u32, AsyncIoError> {
        let (offset, len) = range;
        let block = u64::from(self.align.offset);
        if self.is_block_device && block > 1 {
            let inside = blocks_inside(offset, len, block);
            if let Some(inside) = inside {
                super::sync_io::file_discard_range(&self.file, inside).map_err(AsyncIoError::IO)?;
            }
            for (at, part) in parts_outside(offset, len, inside) {
                self.write_zeros(at, part)?;
            }
            return Ok(len);
        }
        super::sync_io::file_discard_range(&self.file, range).map_err(AsyncIoError::IO)
    }

    /// Writes zeros over `len` bytes at `offset` through an aligned buffer and waits for it.
    /// Nothing else is in flight (the caller drained the engine).
    fn write_zeros(&mut self, offset: u64, len: u32) -> Result<(), AsyncIoError> {
        let block = u64::from(self.align.offset);
        let start = offset - offset % block;
        let end = (offset + u64::from(len)).next_multiple_of(block);
        let buf = u32::try_from(end - start)
            .ok()
            .and_then(|n| AlignedBuf::try_new(n as usize, self.align.mem))
            .ok_or(AsyncIoError::AlignedBuffer(end - start))?;
        let key = self.jobs.insert(Job {
            write: true,
            wrapped: None,
            offset,
            len,
            host_addr: 0,
            start,
            end,
            rmw: true,
            direct: false,
            buf: Some(buf),
            edge: None,
            step: Step::Waiting,
            // The discard holds the claim of its blocks.
            claim: None,
        });
        self.rmw_jobs += 1;
        self.own_result = None;
        let first = self.first_step(key);
        if let Err(err) = self.push_step(key, first) {
            self.remove_job(key);
            return Err(err);
        }
        self.drain(false)?;
        match self.own_result.take() {
            Some(res) if res < 0 => Err(AsyncIoError::IO(std::io::Error::from_raw_os_error(-res))),
            Some(res) if u32::try_from(res) == Ok(len) => Ok(()),
            _ => Err(AsyncIoError::IO(std::io::Error::from_raw_os_error(
                libc::EIO,
            ))),
        }
    }

    pub fn kick_submission_queue(&mut self) -> Result<(), AsyncIoError> {
        self.ring
            .submit()
            .map(|_| ())
            .map_err(AsyncIoError::IoUring)
    }

    /// Ends every request that the engine has taken: a request through an aligned buffer runs
    /// all of its operations, and a request that waits for another runs after it. The answers
    /// stay with the engine (taken by `pop`), or are thrown away with `discard_cqes`.
    pub fn drain(&mut self, discard_cqes: bool) -> Result<(), AsyncIoError> {
        if discard_cqes {
            self.ring
                .submit_and_wait_all()
                .map(|_| ())
                .map_err(AsyncIoError::IoUring)?;
            // Drain the completion queue so that we may deallocate the user_data fields.
            while self.do_pop()?.is_some() {}
            self.jobs.clear();
            self.waiting.clear();
            self.stalled.clear();
            self.rmw_jobs = 0;
            self.ready.clear();
            if let Some((blocks, engine)) = &self.blocks {
                blocks.release_engine(*engine);
            }
            return Ok(());
        }

        loop {
            self.ring
                .submit_and_wait_all()
                .map(|_| ())
                .map_err(AsyncIoError::IoUring)?;
            while let Some(cqe) = self.take_ring_cqe()? {
                self.handle_cqe(cqe);
            }
            self.run_deferred();
            if self.ring.num_ops() == 0 {
                if self.waiting.is_empty() {
                    break;
                }
                // What is left waits for the blocks that a job of another queue holds; that
                // job ends in the kernel, and its thread lets them go.
                let Some((blocks, _)) = self.blocks.clone() else {
                    break;
                };
                let seen = blocks.releases();
                self.run_deferred();
                if self.ring.num_ops() == 0 {
                    blocks.wait_release(seen);
                }
            }
        }
        debug_assert!(self.jobs.is_empty() && self.waiting.is_empty());
        if !self.ready.is_empty() {
            // The answers are given to the device at its next completion event.
            self.signal_ready();
        }
        Ok(())
    }

    pub fn drain_and_flush(&mut self, discard_cqes: bool) -> Result<(), AsyncIoError> {
        self.drain(discard_cqes)?;

        // Sync data out to physical media on host.
        // We don't need to call flush first since all the ops are performed through io_uring
        // and Rust shouldn't manage any data in its internal buffers.
        #[cfg(test)]
        {
            self.sync_all_calls += 1;
        }
        self.file.sync_all().map_err(AsyncIoError::SyncAll)?;

        Ok(())
    }

    fn do_pop(&mut self) -> Result<Option<Cqe<Op>>, AsyncIoError> {
        self.ring.pop().map_err(AsyncIoError::IoUring)
    }

    fn take_ring_cqe(&mut self) -> Result<Option<Cqe<Op>>, AsyncIoError> {
        let cqe = self.do_pop()?;
        #[cfg(test)]
        let cqe = cqe.map(|cqe| {
            if self.pass_completions > 0 {
                self.pass_completions -= 1;
                cqe
            } else if self.fail_completions > 0 {
                self.fail_completions -= 1;
                Cqe::new(-libc::EIO, cqe.user_data())
            } else {
                cqe
            }
        });
        Ok(cqe)
    }

    /// The next answer of a request, with the guest's memory that it wrote marked as changed.
    pub fn pop(
        &mut self,
        mem: &GuestMemoryMmap,
    ) -> Result<Option<Cqe<PendingRequest>>, AsyncIoError> {
        if self.ready.is_empty() {
            self.take_completions()?;
        }
        let Some(done) = self.ready.pop_front() else {
            return Ok(None);
        };
        let mut cqe = done.cqe;
        if let Some((buf, head)) = done.copy {
            let count = cqe.count() as usize;
            let wrapped = cqe.user_data();
            let addr = wrapped.addr.unwrap();
            cqe = match mem.write_slice(&buf.as_slice()[head..head + count], addr) {
                Ok(()) => Cqe::new(i32::try_from(count).unwrap(), wrapped),
                Err(err) => {
                    error!("Failed to copy a block read to guest memory: {:?}", err);
                    Cqe::new(-libc::EFAULT, wrapped)
                }
            };
        }
        let count = cqe.count();
        Ok(Some(cqe.map_user_data(|wrapped_user_data| {
            wrapped_user_data.mark_dirty_mem_and_unwrap(mem, count)
        })))
    }

    // Test-only: the number of jobs that wait for a job that overlaps them.
    #[cfg(test)]
    pub(crate) fn waiting_jobs(&self) -> usize {
        self.waiting.len()
    }

    // Test-only: the number of jobs that the engine has taken and not yet ended.
    #[cfg(test)]
    pub(crate) fn taken_jobs(&self) -> usize {
        self.jobs.len()
    }
}

impl Drop for AsyncFileEngine {
    fn drop(&mut self) {
        // The buffers of the jobs are freed only after the kernel is done with them.
        if !self.jobs.is_empty()
            && let Err(err) = self.ring.submit_and_wait_all()
        {
            error!("Failed to end block operations on drop: {:?}", err);
        }
        if let Some((blocks, engine)) = &self.blocks {
            blocks.release_engine(*engine);
        }
    }
}
