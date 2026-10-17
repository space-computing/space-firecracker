// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use event_manager::{EventOps, Events, MutEventSubscriber, SubscriberOps};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use super::device::{BlockResources, DISK_ERROR_EVT};
use super::io::{BlockIoError, FileEngine, async_io};
use super::metrics::BlockDeviceMetrics;
use super::{
    FinishedRequest, IoErr, KeptRequestState, PendingRequest, ProcessingResult, Request,
    VirtioBlockError,
};
use crate::EventManager;
use crate::devices::virtio::device::ActiveState;
use crate::devices::virtio::persist::QueueState;
use crate::devices::virtio::queue::{InvalidAvailIdx, QueueError};
use crate::devices::virtio::transport::VirtioInterruptType;
use crate::logger::{IncMetric, error, warn};
use crate::rate_limiter::RateLimiter;
use crate::seccomp::{BpfProgram, apply_filter};
use crate::snapshot::Persist;

/// Runtime state and processing logic for an active block device.
#[derive(Debug)]
pub(crate) struct BlockWorker {
    pub(crate) resources: BlockResources,
    pub(crate) active_state: ActiveState,
    pub(crate) rate_limiter: Arc<Mutex<RateLimiter>>,
    pub(crate) is_blocked: Arc<AtomicBool>,
    pub(crate) discard_supported: bool,
    pub(crate) metrics: Arc<BlockDeviceMetrics>,
    // The drive's disk error that waits for the Vmm (one for all of its queues).
    pub(crate) disk_error: Arc<AtomicBool>,
    // How long a worker thread polls after its last work (zero: no polling).
    pub(crate) poll: Duration,
    // The worker polls: a kick of the guest is served with the notification left off.
    pub(crate) polling: bool,
}

/// Worker state and control channel side (recv ctl msg)
#[derive(Debug)]
struct ThreadedWorker {
    state: WorkerState,
    control_evt: EventFd,
    from_vmm: Receiver<ControlMsg>,
    to_vmm: Sender<ControlResponse>,
    // The last turn of the event loop served the guest (its queue, its completions, or a
    // resume): the worker then polls. A worker that was only started (at a boot, or at a load
    // before the guest runs) does not.
    served: bool,
}

/// Data-path ownership state of the worker thread.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum WorkerState {
    Parked,
    Running(BlockWorker),
    Paused(BlockWorker),
    Finished,
}

#[allow(clippy::large_enum_variant)]
enum ControlMsg {
    Start(BlockWorker),
    UpdateDiskImage { path: String, read_only: bool },
    Reset,
    Pause(FlushMode),
    GetQueueState,
    MarkQueueMemoryDirty,
    Kick { resume: bool },
    // The end of the stop of a checkpoint of a running guest.
    Continue,
    Finish(FlushMode),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum ControlResponse {
    DiskUpdated(Result<u64, VirtioBlockError>), // returns nsectors on success
    Reset(BlockResources),
    Paused,
    // The queue and the requests that a disk error kept on it.
    QueueState(QueueState, Vec<KeptRequestState>),
    QueueMemoryDirty(Result<(), QueueError>),
}

/// VMM-side handle for controlling and joining a block worker thread.
#[derive(Debug)]
pub(crate) struct WorkerHandle {
    to_worker: Sender<ControlMsg>,
    from_worker: Receiver<ControlResponse>,
    control_evt: EventFd,
    join: JoinHandle<()>,
    queue_evt: EventFd,
}

/// Determines how pending I/O is handled when a worker pauses or finishes.
#[derive(Clone, Copy)]
pub(crate) enum FlushMode {
    Drain,
    DrainAndFlush,
}

macro_rules! unwrap_async_file_engine_or_return {
    ($file_engine: expr) => {
        match $file_engine {
            FileEngine::Async(engine) => engine,
            FileEngine::Sync(_) => {
                error!("The block device doesn't use an async IO engine");
                return;
            }
        }
    };
}

impl BlockWorker {
    /// Process a single event in the Virtio queue.
    ///
    /// This function is called by the event manager when the guest notifies us
    /// about new buffers in the queue.
    pub(crate) fn process_queue_event(&mut self) {
        self.metrics.queue_event_count.inc();
        if let Err(err) = self.resources.queue_evt.read() {
            error!("Failed to get queue event: {:?}", err);
            self.metrics.event_fails.inc();
        } else if self.is_blocked.load(Ordering::Relaxed) {
            self.metrics.rate_limiter_throttled_events.inc();
        } else if self.resources.is_io_engine_throttled {
            self.metrics.io_engine_throttled_events.inc();
        } else if self.resources.stopped_on_error {
            // The queue is taken again when the guest is resumed.
        } else {
            // While the worker polls, the guest's notification stays off.
            self.process_queue_with(!self.polling).unwrap()
        }
    }

    /// Device specific function for peaking inside a queue and processing descriptors. When
    /// the queue is empty the guest's notification is armed.
    pub(super) fn process_queue(&mut self) -> Result<(), InvalidAvailIdx> {
        self.process_queue_with(true)
    }

    /// Takes the requests of the queue; with `arm` the guest's notification is armed when the
    /// queue is empty, else it is left as it is (a worker that polls looks again by itself).
    fn process_queue_with(&mut self, arm: bool) -> Result<(), InvalidAvailIdx> {
        if !self.resources.queue.config.ready || self.resources.stopped_on_error {
            return Ok(());
        }
        if !self.resources.kept.is_empty() && !self.run_kept() {
            return Ok(());
        }

        let rate_limiter = &self.rate_limiter;
        let queue = &mut self.resources.queue;
        let mut used_any = false;
        let mut failed_request = None;

        while let Some(head) = if arm {
            queue.pop_or_enable_notification()?
        } else {
            queue.pop()?
        } {
            self.metrics.remaining_reqs_count.add(queue.len().into());
            let processing_result =
                match Request::parse(&head, &self.active_state.mem, self.resources.disk.nsectors) {
                    Ok(request) => {
                        let is_rate_limited = {
                            let mut rate_limiter = rate_limiter
                                .lock()
                                .expect("Poisoned block rate limiter lock");
                            request.rate_limit(&mut rate_limiter)
                        };
                        if is_rate_limited {
                            // Stop processing the queue and return this descriptor chain to the
                            // avail ring, for later processing.
                            queue.undo_pop();
                            self.metrics.rate_limiter_throttled_events.inc();
                            break;
                        }

                        request.process(
                            &mut self.resources.disk,
                            head.index,
                            &self.active_state.mem,
                            &self.metrics,
                            self.discard_supported,
                        )
                    }
                    Err(err) => {
                        error!("Failed to parse available descriptor chain: {:?}", err);
                        self.metrics.execute_fails.inc();
                        ProcessingResult::Executed(FinishedRequest {
                            num_bytes_to_mem: 0,
                            desc_idx: head.index,
                        })
                    }
                };

            match processing_result {
                ProcessingResult::Submitted => {}
                ProcessingResult::Throttled => {
                    queue.undo_pop();
                    self.resources.is_io_engine_throttled = true;
                    break;
                }
                ProcessingResult::Executed(finished) => {
                    used_any = true;
                    queue
                        .add_used(head.index, finished.num_bytes_to_mem)
                        .unwrap_or_else(|err| {
                            error!(
                                "Failed to add available descriptor head {}: {}",
                                head.index, err
                            )
                        });
                }
                ProcessingResult::Failed(failed) => {
                    // The request was popped and stays with the device; no other is taken.
                    failed_request = Some(failed);
                    break;
                }
            }
        }
        queue.advance_used_ring_idx();

        if used_any && queue.prepare_kick() {
            self.active_state
                .interrupt
                .trigger(VirtioInterruptType::Queue(self.resources.queue_idx))
                .unwrap_or_else(|_| {
                    self.metrics.event_fails.inc();
                });
        }

        if let FileEngine::Async(ref mut engine) = self.resources.disk.file_engine
            && let Err(err) = engine.kick_submission_queue()
        {
            error!("BlockError submitting pending block requests: {:?}", err);
        }

        if !used_any {
            self.metrics.no_avail_buffer.inc();
        }

        if let Some(failed) = failed_request {
            self.keep_failed(failed);
        }

        Ok(())
    }

    /// Keeps a request that the disk failed: it is not answered, the queue takes no new
    /// request, and the Vmm is woken to stop the guest.
    fn keep_failed(&mut self, request: PendingRequest) {
        error!(
            "Block device queue {}: the disk failed a request; the guest stops and the request \
             is kept",
            self.resources.queue_idx
        );
        self.metrics.execute_fails.inc();
        self.resources.kept.push_back(request);
        self.stop_on_error();
    }

    fn stop_on_error(&mut self) {
        self.resources.stopped_on_error = true;
        if !self.disk_error.swap(true, Ordering::SeqCst)
            && let Err(err) = DISK_ERROR_EVT.write(1)
        {
            error!("Failed to signal the disk error: {:?}", err);
        }
    }

    /// Runs the kept requests again from their start, in their order. Returns whether the
    /// queue may be taken (no request is kept any more).
    fn run_kept(&mut self) -> bool {
        let mut used_any = false;
        while let Some(pending) = self.resources.kept.pop_front() {
            let desc_idx = pending.desc_idx();
            match pending.to_request().process(
                &mut self.resources.disk,
                desc_idx,
                &self.active_state.mem,
                &self.metrics,
                self.discard_supported,
            ) {
                ProcessingResult::Submitted => {}
                ProcessingResult::Throttled => {
                    self.resources.kept.push_front(pending);
                    self.resources.is_io_engine_throttled = true;
                    break;
                }
                ProcessingResult::Executed(finished) => {
                    used_any = true;
                    self.resources
                        .queue
                        .add_used(finished.desc_idx, finished.num_bytes_to_mem)
                        .unwrap_or_else(|err| {
                            error!(
                                "Failed to add available descriptor head {}: {}",
                                finished.desc_idx, err
                            )
                        });
                }
                ProcessingResult::Failed(failed) => {
                    self.resources.kept.push_front(failed);
                    self.stop_on_error();
                    break;
                }
            }
        }
        if used_any {
            let queue = &mut self.resources.queue;
            queue.advance_used_ring_idx();
            if queue.prepare_kick() {
                self.active_state
                    .interrupt
                    .trigger(VirtioInterruptType::Queue(self.resources.queue_idx))
                    .unwrap_or_else(|_| {
                        self.metrics.event_fails.inc();
                    });
            }
        }
        if let FileEngine::Async(ref mut engine) = self.resources.disk.file_engine
            && let Err(err) = engine.kick_submission_queue()
        {
            error!("BlockError submitting pending block requests: {:?}", err);
        }
        self.resources.kept.is_empty()
    }

    fn process_async_completion_queue(&mut self) {
        if !self.resources.queue.config.ready {
            return;
        }

        let engine = unwrap_async_file_engine_or_return!(&mut self.resources.disk.file_engine);
        let queue = &mut self.resources.queue;
        let mut failed_requests = Vec::new();

        loop {
            match engine.pop(&self.active_state.mem) {
                Err(error) => {
                    error!("Failed to read completed io_uring entry: {:?}", error);
                    break;
                }
                Ok(None) => break,
                Ok(Some(cqe)) => {
                    let res = cqe.result();
                    let user_data = cqe.user_data();

                    let (pending, res) = match res {
                        Ok(count) => (user_data, Ok(count)),
                        Err(error) => (
                            user_data,
                            Err(IoErr::FileEngine(BlockIoError::Async(
                                async_io::AsyncIoError::IO(error),
                            ))),
                        ),
                    };
                    // A request that the disk failed is kept and stops the guest. (A read or
                    // a write that moved fewer bytes than asked is answered as before.)
                    if res.is_err() {
                        failed_requests.push(pending);
                        continue;
                    }
                    let finished = pending.finish(&self.active_state.mem, res, &self.metrics);
                    queue
                        .add_used(finished.desc_idx, finished.num_bytes_to_mem)
                        .unwrap_or_else(|err| {
                            error!(
                                "Failed to add available descriptor head {}: {}",
                                finished.desc_idx, err
                            )
                        });
                }
            }
        }
        queue.advance_used_ring_idx();

        if queue.prepare_kick() {
            self.active_state
                .interrupt
                .trigger(VirtioInterruptType::Queue(self.resources.queue_idx))
                .unwrap_or_else(|_| {
                    self.metrics.event_fails.inc();
                });
        }

        for failed in failed_requests {
            self.keep_failed(failed);
        }
    }

    pub(crate) fn process_async_completion_event(&mut self) {
        let engine = unwrap_async_file_engine_or_return!(&mut self.resources.disk.file_engine);

        if let Err(err) = engine.completion_evt().read() {
            error!("Failed to get async completion event: {:?}", err);
        } else {
            self.process_async_completion_queue();

            if self.resources.is_io_engine_throttled {
                self.resources.is_io_engine_throttled = false;
                self.process_queue_with(!self.polling).unwrap()
            }
        }
    }

    /// One look of a worker that polls: the completions of the engine, then the new requests
    /// of the guest, with its notification left off. Returns whether it found work.
    pub(crate) fn poll_once(&mut self) -> bool {
        if !self.resources.queue.config.ready
            || self.resources.stopped_on_error
            || self.is_blocked.load(Ordering::Relaxed)
        {
            return false;
        }
        let used_before = self.resources.queue.next_used;
        if matches!(self.resources.disk.file_engine, FileEngine::Async(_)) {
            self.process_async_completion_queue();
            if self.resources.is_io_engine_throttled
                && self.resources.queue.next_used != used_before
            {
                self.resources.is_io_engine_throttled = false;
            }
        }
        let mut found = self.resources.queue.next_used != used_before;
        if !self.resources.is_io_engine_throttled && !self.resources.queue.is_empty() {
            found = true;
            self.process_queue_with(false).unwrap();
        }
        found
    }

    /// The end of polling: the guest's notification is armed and the queue looked at once more,
    /// so that a request that came in between is taken.
    pub(crate) fn arm(&mut self) {
        self.polling = false;
        if self.resources.queue.config.ready
            && !self.is_blocked.load(Ordering::Relaxed)
            && !self.resources.is_io_engine_throttled
        {
            self.process_queue().unwrap();
        }
    }

    pub(crate) fn drain_and_flush(&mut self, discard: bool) {
        if let Err(err) = self.resources.disk.file_engine.drain_and_flush(discard) {
            error!("Failed to drain ops and flush block data: {:?}", err);
        }
    }

    pub(crate) fn drain(&mut self, discard: bool) {
        if let Err(err) = self.resources.disk.file_engine.drain(discard) {
            error!("Failed to drain ops: {:?}", err);
        }
    }

    /// Prepare device for being snapshotted.
    pub(crate) fn prepare_save(&mut self, flush_mode: FlushMode) {
        // Fsync errors are non-fatal; other drain errors are broken invariants.
        let result = match flush_mode {
            FlushMode::Drain => self.resources.disk.file_engine.drain(false),
            FlushMode::DrainAndFlush => self.resources.disk.file_engine.drain_and_flush(false),
        };
        match result {
            Ok(()) => {}
            Err(BlockIoError::Async(async_io::AsyncIoError::SyncAll(err))) => {
                error!("Failed to flush block data for snapshot: {:?}", err);
            }
            Err(BlockIoError::Sync(err)) => {
                error!("Failed to flush block data for snapshot: {:?}", err);
            }
            Err(err) => panic!("Failed to drain block IO engine for snapshot: {err:?}"),
        }
        if matches!(&self.resources.disk.file_engine, FileEngine::Async(_)) {
            self.process_async_completion_queue();
        }
    }

    /// Update the backing file and return the new sector count.
    pub fn update_disk_image(
        &mut self,
        disk_image_path: String,
        read_only: bool,
    ) -> Result<u64, VirtioBlockError> {
        self.resources.disk.update(disk_image_path, read_only)?;
        Ok(self.resources.disk.nsectors)
    }
}

impl WorkerHandle {
    /// Spawn a parked block worker thread.
    pub(crate) fn spawn(
        seccomp_filter: Arc<BpfProgram>,
        queue_evt: EventFd,
        name: String,
    ) -> Result<Self, std::io::Error> {
        // handle writes and worker reads the control eventfd
        let control_evt = EventFd::new(libc::EFD_NONBLOCK)?;
        let handle_evt = control_evt.try_clone()?;

        let (to_worker, from_vmm) = channel::<ControlMsg>();
        let (to_vmm, from_worker) = channel::<ControlResponse>();

        let join = thread::Builder::new().name(name).spawn(move || {
            // Create epoll before applying the filter, which does not allow epoll_create1.
            let event_manager =
                EventManager::new().expect("Failed to create block worker EventManager");

            if let Err(err) = apply_filter(&seccomp_filter) {
                panic!("Failed to apply seccomp filter on block worker: {err}");
            }

            run_worker_loop(event_manager, control_evt, from_vmm, to_vmm);
        })?;

        Ok(Self {
            to_worker,
            from_worker,
            control_evt: handle_evt,
            join,
            queue_evt,
        })
    }

    pub(crate) fn queue_event(&self) -> &EventFd {
        &self.queue_evt
    }

    /// Send a control request to the worker thread.
    ///
    /// Channels and control eventfd failures are invariants if broken, state cannot be recovered.
    fn request(&self, msg: ControlMsg) {
        self.to_worker
            .send(msg)
            .expect("Failed to send request to block worker");
        self.control_evt
            .write(1)
            .expect("Failed to notify block worker");
    }

    fn request_response(&self, msg: ControlMsg) -> ControlResponse {
        self.request(msg);
        self.from_worker
            .recv()
            .expect("Failed to receive block worker response")
    }

    /// Transfer data-path resources to the worker thread and start processing.
    pub(crate) fn start(&self, worker: BlockWorker) {
        self.request(ControlMsg::Start(worker));
    }

    /// Stop processing and return the data-path resources to the VMM thread.
    /// The caller must reset the returned resources before reuse.
    pub(crate) fn reset(&self) -> BlockResources {
        match self.request_response(ControlMsg::Reset) {
            ControlResponse::Reset(resources) => resources,
            response => panic!("Unexpected block worker reset response: {response:?}"),
        }
    }

    /// Replace the worker's backing file and return its new sector count.
    pub(crate) fn update_disk_image(
        &self,
        disk_image_path: String,
        read_only: bool,
    ) -> Result<u64, VirtioBlockError> {
        let msg = ControlMsg::UpdateDiskImage {
            path: disk_image_path,
            read_only,
        };
        match self.request_response(msg) {
            ControlResponse::DiskUpdated(result) => result,
            response => panic!("Unexpected block worker disk update response: {response:?}"),
        }
    }

    /// Pause data-path processing after completing pending I/O.
    pub(crate) fn pause(&self, flush_mode: FlushMode) {
        match self.request_response(ControlMsg::Pause(flush_mode)) {
            ControlResponse::Paused => {}
            response => panic!("Unexpected block worker pause response: {response:?}"),
        }
    }

    /// Read queue state, and the requests that a disk error kept, from a paused worker.
    pub(crate) fn get_queue_state(&self) -> (QueueState, Vec<KeptRequestState>) {
        match self.request_response(ControlMsg::GetQueueState) {
            ControlResponse::QueueState(state, kept) => (state, kept),
            response => panic!("Unexpected block worker queue state response: {response:?}"),
        }
    }

    /// The end of the stop of a checkpoint of a running guest: a paused worker takes its queue
    /// again. A request that a disk error kept stays kept.
    pub(crate) fn continue_after_checkpoint(&self) {
        self.request(ControlMsg::Continue);
    }

    /// Mark the worker-owned virtqueue memory dirty after a snapshot.
    pub(crate) fn mark_queue_memory_dirty(&self) -> Result<(), QueueError> {
        match self.request_response(ControlMsg::MarkQueueMemoryDirty) {
            ControlResponse::QueueMemoryDirty(result) => result,
            response => {
                panic!("Unexpected block worker queue memory dirty response: {response:?}")
            }
        }
    }

    /// Resume a paused worker and process pending queue entries.
    pub(crate) fn kick(&self, resume: bool) {
        self.request(ControlMsg::Kick { resume });
    }

    /// Stop the worker and wait for its thread to exit.
    pub(crate) fn finish(self, flush_mode: FlushMode) {
        if let Err(err) = self.to_worker.send(ControlMsg::Finish(flush_mode)) {
            error!("Block worker receiver already dropped: {:?}", err);
        }

        if let Err(err) = self.control_evt.write(1) {
            error!("Block worker control event is closed: {:?}", err);
        }

        self.join.join().unwrap_or_else(|err| {
            error!("Block worker thread panicked during teardown: {:?}", err);
        });
    }
}

impl ThreadedWorker {
    const PROCESS_QUEUE: u32 = 0;
    const PROCESS_ASYNC_COMPLETION: u32 = 1;
    const PROCESS_CONTROL: u32 = 2;

    fn register_control_event(&self, ops: &mut EventOps) {
        ops.add(Events::with_data(
            &self.control_evt,
            Self::PROCESS_CONTROL,
            EventSet::IN,
        ))
        .expect("Failed to register block worker control event");
    }

    fn register_runtime_events(resources: &BlockResources, ops: &mut EventOps) {
        ops.add(Events::with_data(
            &resources.queue_evt,
            Self::PROCESS_QUEUE,
            EventSet::IN,
        ))
        .expect("Failed to register queue event");
        if let FileEngine::Async(ref engine) = resources.disk.file_engine {
            ops.add(Events::with_data(
                engine.completion_evt(),
                Self::PROCESS_ASYNC_COMPLETION,
                EventSet::IN,
            ))
            .expect("Failed to register IO engine completion event");
        }
    }

    fn unregister_runtime_events(resources: &BlockResources, ops: &mut EventOps) {
        ops.remove(Events::with_data(
            &resources.queue_evt,
            Self::PROCESS_QUEUE,
            EventSet::IN,
        ))
        .expect("Failed to unregister queue event");
        if let FileEngine::Async(ref engine) = resources.disk.file_engine {
            ops.remove(Events::with_data(
                engine.completion_evt(),
                Self::PROCESS_ASYNC_COMPLETION,
                EventSet::IN,
            ))
            .expect("Failed to unregister IO engine completion event");
        }
    }

    fn process_control_event(&mut self, ops: &mut EventOps) {
        if let Err(err) = self.control_evt.read() {
            if let WorkerState::Running(worker) | WorkerState::Paused(worker) = &self.state {
                worker.metrics.event_fails.inc();
            }
            panic!("Failed to consume block worker control event: {err:?}");
        }

        while let Ok(msg) = self.from_vmm.try_recv() {
            match msg {
                ControlMsg::Start(worker) => self.start_worker(worker, ops),
                ControlMsg::UpdateDiskImage { path, read_only } => {
                    self.update_disk_image(path, read_only)
                }
                ControlMsg::Pause(flush_mode) => self.pause_worker(flush_mode, ops),
                ControlMsg::GetQueueState => self.send_queue_state(),
                ControlMsg::MarkQueueMemoryDirty => self.mark_queue_memory_dirty(),
                ControlMsg::Kick { resume } => self.kick_worker(resume, ops),
                ControlMsg::Continue => self.continue_worker(ops),
                ControlMsg::Reset => self.reset_worker(ops),
                ControlMsg::Finish(flush_mode) => self.finish_worker(flush_mode, ops),
            }

            if self.is_finished() {
                break;
            }
        }
    }

    fn start_worker(&mut self, worker: BlockWorker, ops: &mut EventOps) {
        assert!(
            matches!(self.state, WorkerState::Parked),
            "Start requested while block worker is not parked"
        );

        Self::register_runtime_events(&worker.resources, ops);
        self.state = WorkerState::Running(worker);
    }

    /// Reply to the VMM. The handle outlives every request, so a closed channel is a
    /// broken invariant.
    fn reply(&self, response: ControlResponse) {
        self.to_vmm
            .send(response)
            .expect("Failed to send block worker response");
    }

    fn update_disk_image(&mut self, path: String, read_only: bool) {
        let result = match &mut self.state {
            WorkerState::Running(worker) | WorkerState::Paused(worker) => {
                worker.update_disk_image(path, read_only)
            }
            WorkerState::Parked => panic!("Disk image update requested while worker is parked"),
            WorkerState::Finished => {
                panic!("Disk image update requested after worker finished")
            }
        };

        self.reply(ControlResponse::DiskUpdated(result));
    }

    fn reset_worker(&mut self, ops: &mut EventOps) {
        let worker = match std::mem::replace(&mut self.state, WorkerState::Parked) {
            WorkerState::Running(worker) => {
                Self::unregister_runtime_events(&worker.resources, ops);
                worker
            }
            WorkerState::Paused(worker) => worker,
            state => {
                self.state = state;
                panic!("Reset requested while block worker is not active")
            }
        };

        drop(worker.active_state);
        self.reply(ControlResponse::Reset(worker.resources));
    }

    fn pause_worker(&mut self, flush_mode: FlushMode, ops: &mut EventOps) {
        match std::mem::replace(&mut self.state, WorkerState::Parked) {
            WorkerState::Running(mut worker) => {
                Self::unregister_runtime_events(&worker.resources, ops);
                worker.polling = false;
                worker.prepare_save(flush_mode);
                self.state = WorkerState::Paused(worker);
            }
            WorkerState::Paused(mut worker) => {
                // Nothing is in flight; a snapshot of a stopped guest still syncs the drive.
                if matches!(flush_mode, FlushMode::DrainAndFlush) {
                    worker.prepare_save(flush_mode);
                }
                self.state = WorkerState::Paused(worker);
            }
            state => {
                self.state = state;
                panic!("Pause requested while block worker is not active")
            }
        }

        self.reply(ControlResponse::Paused);
    }

    fn send_queue_state(&self) {
        let WorkerState::Paused(worker) = &self.state else {
            panic!("Queue state requested while block worker is not paused")
        };

        let kept = worker
            .resources
            .kept
            .iter()
            .map(KeptRequestState::from)
            .collect();
        self.reply(ControlResponse::QueueState(
            worker.resources.queue.save(),
            kept,
        ));
    }

    fn mark_queue_memory_dirty(&mut self) {
        let result = if let WorkerState::Paused(worker) = &mut self.state {
            let mem = worker.active_state.mem.clone();
            if worker.resources.queue.config.ready {
                worker.resources.queue.initialize(&mem)
            } else {
                Ok(())
            }
        } else {
            warn!("Queue memory dirty requested while block worker is not paused");
            Err(QueueError::NotReady)
        };

        self.reply(ControlResponse::QueueMemoryDirty(result));
    }

    fn kick_worker(&mut self, resume: bool, ops: &mut EventOps) {
        match std::mem::replace(&mut self.state, WorkerState::Parked) {
            WorkerState::Paused(worker) => {
                if !resume {
                    self.state = WorkerState::Paused(worker);
                    return;
                }
                Self::register_runtime_events(&worker.resources, ops);
                self.state = WorkerState::Running(worker);
            }
            WorkerState::Running(worker) => {
                self.state = WorkerState::Running(worker);
            }
            state => {
                warn!("Kick requested while block worker is not active");
                self.state = state;
                return;
            }
        }

        // process directly instead of going through epoll
        if let WorkerState::Running(worker) = &mut self.state {
            self.served = true;
            if resume {
                // A resume of the guest: the kept requests run again from their start, and
                // the queue is looked at with its notification armed.
                worker.resources.stopped_on_error = false;
                worker.polling = false;
            }
            let arm = !worker.polling;
            worker
                .process_queue_with(arm)
                .unwrap_or_else(|err| error!("Failed to kick block worker queue: {:?}", err));
        }
    }

    fn continue_worker(&mut self, ops: &mut EventOps) {
        match std::mem::replace(&mut self.state, WorkerState::Parked) {
            WorkerState::Paused(worker) => {
                Self::register_runtime_events(&worker.resources, ops);
                self.state = WorkerState::Running(worker);
            }
            WorkerState::Running(worker) => {
                self.state = WorkerState::Running(worker);
            }
            state => {
                warn!("Continue requested while block worker is not active");
                self.state = state;
                return;
            }
        }
        // The queue is looked at and the guest's notification armed, as after a stop.
        if let WorkerState::Running(worker) = &mut self.state {
            self.served = true;
            worker
                .process_queue()
                .unwrap_or_else(|err| error!("Failed to continue block worker queue: {:?}", err));
        }
    }

    fn finish_worker(&mut self, flush_mode: FlushMode, ops: &mut EventOps) {
        match std::mem::replace(&mut self.state, WorkerState::Finished) {
            WorkerState::Running(worker) => {
                Self::unregister_runtime_events(&worker.resources, ops);
                Self::flush_worker(worker, flush_mode);
            }
            WorkerState::Paused(worker) => Self::flush_worker(worker, flush_mode),
            WorkerState::Parked | WorkerState::Finished => {}
        }
    }

    fn flush_worker(mut worker: BlockWorker, flush_mode: FlushMode) {
        match flush_mode {
            FlushMode::Drain => worker.drain(true),
            FlushMode::DrainAndFlush => worker.drain_and_flush(true),
        }
        worker.resources.is_io_engine_throttled = false;
    }

    fn is_finished(&self) -> bool {
        matches!(self.state, WorkerState::Finished)
    }

    /// The poll window of a running worker, which then begins to poll; none for a worker that
    /// does not run or does not poll.
    fn begin_polling(&mut self) -> Option<Duration> {
        if !std::mem::take(&mut self.served) {
            return None;
        }
        match &mut self.state {
            WorkerState::Running(worker) if !worker.poll.is_zero() => {
                worker.polling = true;
                Some(worker.poll)
            }
            _ => None,
        }
    }

    /// One look of a polling worker; false when it does not run (a pause came) or found nothing.
    fn poll_once(&mut self) -> bool {
        match &mut self.state {
            WorkerState::Running(worker) if worker.polling => worker.poll_once(),
            _ => false,
        }
    }

    /// Whether the worker still polls (a pause ends it).
    fn is_polling(&self) -> bool {
        matches!(&self.state, WorkerState::Running(worker) if worker.polling)
    }

    fn end_polling(&mut self) {
        if let WorkerState::Running(worker) = &mut self.state {
            worker.arm();
        }
    }
}

/// The number of looks of a polling worker between two turns of its event loop, in which it
/// takes its control messages and the events that came while it polled.
const POLLS_PER_TURN: u32 = 64;

/// After each turn of its event loop, a running worker with a poll window looks at its queue
/// and at its completions until it finds no work for the window, with the guest's notification
/// left off (the guest then does not kick). Before it waits again it arms the notification and
/// looks once more.
fn poll(event_manager: &mut EventManager, worker: &Mutex<ThreadedWorker>) {
    let lock = || worker.lock().expect("Poisoned block worker lock");
    let Some(window) = lock().begin_polling() else {
        return;
    };
    let mut last = Instant::now();
    let mut looks = 0u32;
    loop {
        if lock().poll_once() {
            last = Instant::now();
        } else if last.elapsed() >= window {
            break;
        }
        looks = looks.wrapping_add(1);
        if looks.is_multiple_of(POLLS_PER_TURN) {
            if let Err(err) = event_manager.run_with_timeout(0) {
                error!("Block worker event loop error: {:?}", err);
            }
            let w = lock();
            if w.is_finished() || !w.is_polling() {
                return;
            }
        }
        std::hint::spin_loop();
    }
    lock().end_polling();
}

fn run_worker_loop(
    mut event_manager: EventManager,
    control_evt: EventFd,
    from_vmm: Receiver<ControlMsg>,
    to_vmm: Sender<ControlResponse>,
) {
    let worker = Arc::new(Mutex::new(ThreadedWorker {
        state: WorkerState::Parked,
        control_evt,
        from_vmm,
        to_vmm,
        served: false,
    }));
    let subscriber: Arc<Mutex<dyn MutEventSubscriber>> = worker.clone();
    event_manager.add_subscriber(subscriber);

    loop {
        if let Err(err) = event_manager.run() {
            error!("Block worker event loop error: {:?}", err);
        }
        if worker
            .lock()
            .expect("Poisoned block worker lock")
            .is_finished()
        {
            break;
        }
        poll(&mut event_manager, &worker);
        if worker
            .lock()
            .expect("Poisoned block worker lock")
            .is_finished()
        {
            break;
        }
    }
}

impl MutEventSubscriber for ThreadedWorker {
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        let source = event.data();
        let event_set = event.event_set();

        if !EventSet::IN.contains(event_set) {
            warn!(
                "Block worker received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        if let WorkerState::Running(worker) = &mut self.state {
            match source {
                Self::PROCESS_QUEUE => {
                    worker.process_queue_event();
                    self.served = true;
                }
                Self::PROCESS_ASYNC_COMPLETION => {
                    worker.process_async_completion_event();
                    self.served = true;
                }
                Self::PROCESS_CONTROL => self.process_control_event(ops),
                _ => warn!("Block: Spurious event received: {:?}", source),
            }
        } else {
            match source {
                Self::PROCESS_CONTROL => self.process_control_event(ops),
                _ => warn!(
                    "Block: The device worker is not yet activated. Spurious event received: {:?}",
                    source
                ),
            }
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        self.register_control_event(ops);
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::RECV_TIMEOUT_SEC;
    use crate::devices::virtio::block::CacheType;
    use crate::devices::virtio::block::virtio::device::{
        BlockRuntimeState, FileEngineType, VirtioBlock,
    };
    use crate::devices::virtio::block::virtio::io::AsyncFileEngine;
    use crate::devices::virtio::block::virtio::persist::VirtioBlockState;
    use crate::devices::virtio::block::virtio::request::{
        RequestHeader, VIRTIO_BLK_ID_BYTES, VIRTIO_BLK_S_OK, VIRTIO_BLK_T_DISCARD,
        VIRTIO_BLK_T_GET_ID, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT,
    };
    use crate::devices::virtio::block::virtio::test_utils::{
        default_block, default_config, read_blk_req_descriptors, set_queue,
    };
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::vstate::memory::{
        Bitmap, Bytes, GuestAddress, GuestMemoryExtension, GuestMemoryMmap,
    };
    use vm_memory::{GuestMemoryBackend, GuestMemoryRegion};

    #[test]
    fn test_control_msg_batch() {
        let mut block = default_block(FileEngineType::Sync);
        let BlockRuntimeState::Configuring(mut resources, _) =
            std::mem::replace(&mut block.state, BlockRuntimeState::Placeholder)
        else {
            unreachable!()
        };
        let resources = resources.pop().unwrap();
        let expected_queue_state = resources.queue.save();
        let queue_evt = resources.queue_evt.try_clone().unwrap();
        let worker = BlockWorker {
            resources,
            active_state: ActiveState {
                mem: default_mem(),
                interrupt: default_interrupt(),
            },
            rate_limiter: block.rate_limiter.clone(),
            is_blocked: block.lock_rate_limiter().clone_blocked_flag(),
            discard_supported: false,
            metrics: block.metrics.clone(),
            disk_error: block.disk_error.clone(),
            poll: Duration::ZERO,
            polling: false,
        };
        let handle = WorkerHandle::spawn(Arc::new(vec![]), queue_evt, "fc_test".into()).unwrap();

        handle.to_worker.send(ControlMsg::Start(worker)).unwrap();
        handle
            .to_worker
            .send(ControlMsg::Pause(FlushMode::DrainAndFlush))
            .unwrap();
        handle.to_worker.send(ControlMsg::GetQueueState).unwrap();
        handle.control_evt.write(1).unwrap();

        assert!(matches!(
            handle.from_worker.recv_timeout(RECV_TIMEOUT_SEC).unwrap(),
            ControlResponse::Paused
        ));
        match handle.from_worker.recv_timeout(RECV_TIMEOUT_SEC).unwrap() {
            ControlResponse::QueueState(queue_state, kept) => {
                assert_eq!(queue_state, expected_queue_state);
                assert!(kept.is_empty());
            }
            response => panic!("Unexpected block worker response: {response:?}"),
        }

        handle.finish(FlushMode::Drain);
    }

    #[test]
    fn test_kick_while_paused() {
        let mut block = default_block(FileEngineType::Sync);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        let BlockRuntimeState::Configuring(mut resources, _) =
            std::mem::replace(&mut block.state, BlockRuntimeState::Placeholder)
        else {
            unreachable!()
        };
        let mut resources = resources.pop().unwrap();
        resources.queue.initialize(&mem).unwrap();
        let queue_evt = resources.queue_evt.try_clone().unwrap();
        let worker = BlockWorker {
            resources,
            active_state: ActiveState {
                mem: mem.clone(),
                interrupt: default_interrupt(),
            },
            rate_limiter: block.rate_limiter.clone(),
            is_blocked: block.lock_rate_limiter().clone_blocked_flag(),
            discard_supported: false,
            metrics: block.metrics.clone(),
            disk_error: block.disk_error.clone(),
            poll: Duration::ZERO,
            polling: false,
        };
        let handle = WorkerHandle::spawn(Arc::new(vec![]), queue_evt, "fc_test".into()).unwrap();

        let pause = || {
            handle
                .to_worker
                .send(ControlMsg::Pause(FlushMode::DrainAndFlush))
                .unwrap();
            handle.control_evt.write(1).unwrap();
            assert!(matches!(
                handle.from_worker.recv_timeout(RECV_TIMEOUT_SEC).unwrap(),
                ControlResponse::Paused
            ));
        };
        let queue_state = || {
            handle.to_worker.send(ControlMsg::GetQueueState).unwrap();
            handle.control_evt.write(1).unwrap();
            match handle.from_worker.recv_timeout(RECV_TIMEOUT_SEC).unwrap() {
                ControlResponse::QueueState(state, _) => state,
                response => panic!("Unexpected block worker response: {response:?}"),
            }
        };

        handle.start(worker);
        pause();
        let paused_queue_state = queue_state();

        read_blk_req_descriptors(&vq);
        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());
        vq.dtable[1].len.set(VIRTIO_BLK_ID_BYTES);
        mem.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, request_type_addr)
            .unwrap();

        handle.kick(false);
        assert_eq!(queue_state(), paused_queue_state);
        assert_eq!(vq.used.idx.get(), 0);

        handle.kick(true);
        pause();
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(vq.used.ring[0].get().len, VIRTIO_BLK_ID_BYTES + 1);
        assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);

        handle.finish(FlushMode::Drain);
    }

    #[test]
    #[should_panic(expected = "Failed to receive block worker response")]
    fn test_parked_disk_update() {
        let worker = WorkerHandle::spawn(
            Arc::new(vec![]),
            EventFd::new(libc::EFD_NONBLOCK).unwrap(),
            "fc_test".into(),
        )
        .unwrap();

        worker.update_disk_image(String::new(), false).unwrap();
    }

    // The tests below run a drive on its worker threads, as a guest with several vCPUs has it:
    // the `Async` engine with `O_DIRECT`, EVENT_IDX, and polling. The test is the guest's
    // driver: it puts requests in the avail ring and kicks a queue only when EVENT_IDX asks for
    // it (`avail_event`), so a request that a worker would wait for a kick to see is never
    // served (no kick is lost unseen).

    // The memory: queue q at 0x10000 * (q + 1), the headers of its requests at + 0x8000, their
    // statuses at + 0x9000; the data of request n of queue q at 0x100000 + 0x40000 * q +
    // 0x2000 * n.
    const MQ_MEM: usize = 0x200000;
    // The size that a load of a state checks.
    const MQ_QSIZE: u16 = crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;
    // The bytes of the drive's file that the tests compare with a model.
    const MQ_FILE: usize = 0x40000;
    // The longest wait for a worker thread.
    const MQ_WAIT: Duration = Duration::from_secs(10);

    fn mq_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_regions(
            crate::vstate::memory::anonymous(
                [(GuestAddress(0), MQ_MEM)].into_iter(),
                true,
                crate::vmm_config::machine_config::HugePageConfig::None,
            )
            .unwrap()
            .into_iter()
            .map(|region| {
                crate::vstate::memory::GuestRegionMmapExt::dram_from_mmap_region(region, 0)
            })
            .collect(),
        )
        .unwrap()
    }

    fn queue_base(q: u16) -> u64 {
        0x10000 * (u64::from(q) + 1)
    }

    fn data_addr(q: u16, n: u16) -> u64 {
        0x100000 + 0x40000 * u64::from(q) + 0x2000 * u64::from(n)
    }

    fn status_addr(q: u16, n: u16) -> GuestAddress {
        GuestAddress(queue_base(q) + 0x9000 + u64::from(n))
    }

    /// A drive on `path` with `queues` queues on worker threads that poll for `poll_us`, its
    /// features acked as a driver acks them, its workers parked.
    fn mq_block(path: &str, queues: u16, poll_us: u32, discard: bool) -> VirtioBlock {
        let mut config = default_config(path.to_string(), FileEngineType::Async);
        config.rate_limiter = None;
        config.num_queues = std::num::NonZeroU16::new(queues);
        config.poll_us = Some(poll_us);
        config.discard = discard;
        config.blk_size = Some(512);
        config.cache_type = CacheType::Writeback;
        let mut block = VirtioBlock::new(config).unwrap();
        block.set_acked_features(block.avail_features());
        block.spawn_worker(Arc::new(vec![])).unwrap();
        block
    }

    fn mq_activate(block: &mut VirtioBlock, mem: &GuestMemoryMmap, vqs: &[VirtQueue]) {
        for (q, vq) in vqs.iter().enumerate() {
            set_queue(block, q, vq.create_queue());
        }
        block.activate(mem.clone(), default_interrupt()).unwrap();
    }

    fn mq_queues(mem: &GuestMemoryMmap, queues: u16) -> Vec<VirtQueue<'_>> {
        (0..queues)
            .map(|q| VirtQueue::new(GuestAddress(queue_base(q)), mem, MQ_QSIZE))
            .collect()
    }

    /// The driver puts request `n` of queue `q` in its avail ring, and kicks the queue when
    /// EVENT_IDX asks for it. Returns whether it kicked.
    fn post(
        block: &VirtioBlock,
        vq: &VirtQueue,
        q: u16,
        n: u16,
        request_type: u32,
        sector: u64,
        len: u32,
    ) -> bool {
        let mem = vq.memory();
        let slot = 3 * (n % (MQ_QSIZE / 3));
        let header = queue_base(q) + 0x8000 + 0x10 * u64::from(n);
        mem.write_obj(
            RequestHeader::new(request_type, sector),
            GuestAddress(header),
        )
        .unwrap();
        let data_flags = if request_type == VIRTIO_BLK_T_IN || request_type == VIRTIO_BLK_T_GET_ID {
            VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE
        } else {
            VIRTQ_DESC_F_NEXT
        };
        vq.dtable[usize::from(slot)].set(header, 16, VIRTQ_DESC_F_NEXT, slot + 1);
        vq.dtable[usize::from(slot + 1)].set(data_addr(q, n), len, data_flags, slot + 2);
        vq.dtable[usize::from(slot + 2)].set(status_addr(q, n).0, 1, VIRTQ_DESC_F_WRITE, 0);
        mem.write_obj::<u8>(0xff, status_addr(q, n)).unwrap();
        let old = vq.avail.idx.get();
        vq.avail.ring[usize::from(old % MQ_QSIZE)].set(slot);
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        let new = old.wrapping_add(1);
        vq.avail.idx.set(new);
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        // vring_need_event(avail_event, new, old)
        let event = vq.used.event.get();
        let kick = new.wrapping_sub(event).wrapping_sub(1) < new.wrapping_sub(old);
        if kick {
            block.queue_event(usize::from(q)).unwrap().write(1).unwrap();
        }
        kick
    }

    /// Waits until `n` requests of the queue are answered.
    fn wait_used(vq: &VirtQueue, n: u16) {
        let start = Instant::now();
        while vq.used.idx.get() < n {
            assert!(
                start.elapsed() < MQ_WAIT,
                "{} of {n} requests answered",
                vq.used.idx.get()
            );
            thread::sleep(Duration::from_micros(200));
        }
    }

    /// The queue answers no more than `n` requests in a while.
    fn stays_used(vq: &VirtQueue, n: u16) {
        thread::sleep(Duration::from_millis(100));
        assert_eq!(vq.used.idx.get(), n);
    }

    fn wait_disk_error(block: &mut VirtioBlock) {
        let start = Instant::now();
        while !block.take_disk_error() {
            assert!(start.elapsed() < MQ_WAIT, "no disk error");
            thread::sleep(Duration::from_micros(200));
        }
    }

    /// The next avail and next used indices of a saved queue.
    fn indices(state: &QueueState) -> (u16, u16) {
        let queue = crate::devices::virtio::queue::Queue::restore(
            crate::devices::virtio::persist::QueueConstructorArgs {
                mem: default_mem(),
                is_activated: false,
            },
            state,
        )
        .unwrap();
        (queue.next_avail.0, queue.next_used.0)
    }

    fn mq_status(mem: &GuestMemoryMmap, q: u16, n: u16) -> u32 {
        u32::from(mem.read_obj::<u8>(status_addr(q, n)).unwrap())
    }

    fn mq_file(len: usize) -> TempFile {
        let f = TempFile::new().unwrap();
        f.as_file().set_len(len as u64).unwrap();
        f
    }

    fn mq_engine(block: &mut VirtioBlock, q: usize) -> &mut AsyncFileEngine {
        match block.resources_mut()[q].disk.file_engine {
            FileEngine::Async(ref mut engine) => engine,
            FileEngine::Sync(_) => panic!("not an Async drive"),
        }
    }

    /// Writes `data` at `offset` of the file through a descriptor of its own, synced.
    fn fill_file(path: &str, offset: u64, data: &[u8]) {
        use std::os::unix::fs::FileExt;
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.write_all_at(data, offset).unwrap();
        f.sync_all().unwrap();
    }

    fn read_file(path: &str, len: usize) -> Vec<u8> {
        use std::os::unix::fs::FileExt;
        let mut buf = vec![0u8; len];
        std::fs::File::open(path)
            .unwrap()
            .read_exact_at(&mut buf, 0)
            .unwrap();
        buf
    }

    fn pattern(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| seed.wrapping_add(u8::try_from((i * 7 + i / 512 * 13) % 256).unwrap()))
            .collect()
    }

    /// Saves the state of a drive whose workers are paused, through its bytes, and makes a new
    /// drive of it on new worker threads, active on `mem`, as a load does.
    fn save_and_load(block: VirtioBlock, mem: &GuestMemoryMmap) -> VirtioBlock {
        let state = block.save();
        let bytes = bitcode::serialize(&state).unwrap();
        drop(block);
        let state: VirtioBlockState = bitcode::deserialize(&bytes).unwrap();
        let mut restored = VirtioBlock::restore(
            crate::devices::virtio::block::persist::BlockConstructorArgs { mem: mem.clone() },
            &state,
        )
        .unwrap();
        restored.spawn_worker(Arc::new(vec![])).unwrap();
        restored.activate(mem.clone(), default_interrupt()).unwrap();
        restored
    }

    #[test]
    fn test_poll_us_zero_arms_the_notification_after_each_request() {
        // No polling (upstream's worker): the queue is armed each time it is empty, so the
        // guest kicks for each request.
        let mem = mq_mem();
        let file = mq_file(MQ_FILE);
        let mut block = mq_block(file.as_path().to_str().unwrap(), 1, 0, false);
        let vqs = mq_queues(&mem, 1);
        mq_activate(&mut block, &mem, &vqs);
        for n in 0..8 {
            assert!(
                post(&block, &vqs[0], 0, n, VIRTIO_BLK_T_IN, 0, 512),
                "request {n}"
            );
            wait_used(&vqs[0], n + 1);
            // The answer comes before the queue is armed again.
            let start = Instant::now();
            while vqs[0].used.event.get() != n + 1 {
                assert!(start.elapsed() < MQ_WAIT);
                thread::sleep(Duration::from_micros(200));
            }
            assert_eq!(mq_status(&mem, 0, n), VIRTIO_BLK_S_OK);
        }
    }

    #[test]
    fn test_polling_leaves_the_notification_off_for_its_window() {
        let mem = mq_mem();
        let file = mq_file(MQ_FILE);
        let mut block = mq_block(file.as_path().to_str().unwrap(), 1, 300_000, false);
        let vqs = mq_queues(&mem, 1);
        mq_activate(&mut block, &mem, &vqs);
        let vq = &vqs[0];

        // The first request wakes the worker, which arms the queue when it is empty, so the
        // second one kicks too; then the worker polls, the guest does not kick, and each
        // request is answered.
        assert!(post(&block, vq, 0, 0, VIRTIO_BLK_T_IN, 0, 512));
        wait_used(vq, 1);
        assert!(post(&block, vq, 0, 1, VIRTIO_BLK_T_IN, 8, 512));
        wait_used(vq, 2);
        let event = vq.used.event.get();
        for n in 2..12 {
            assert!(
                !post(&block, vq, 0, n, VIRTIO_BLK_T_IN, 0, 512),
                "request {n}"
            );
            wait_used(vq, n + 1);
        }
        assert_eq!(vq.used.event.get(), event);
        // After the window the queue is armed again, and the next request kicks.
        let start = Instant::now();
        while vq.used.event.get() != 12 {
            assert!(start.elapsed() < MQ_WAIT, "the queue was not armed");
            thread::sleep(Duration::from_millis(1));
        }
        assert!(post(&block, vq, 0, 12, VIRTIO_BLK_T_IN, 0, 512));
        wait_used(vq, 13);
        for n in 0..13 {
            assert_eq!(mq_status(&mem, 0, n), VIRTIO_BLK_S_OK);
        }
    }

    #[test]
    fn test_state_saved_while_a_worker_polls_is_served_after_a_load_and_a_resume() {
        let mem = mq_mem();
        let file = mq_file(MQ_FILE);
        let path = file.as_path().to_str().unwrap().to_string();
        fill_file(&path, 0, &pattern(0x31, 0x4000));
        let mut block = mq_block(&path, 2, 1_000_000, false);
        let vqs = mq_queues(&mem, 2);
        mq_activate(&mut block, &mem, &vqs);
        for (q, vq) in vqs.iter().enumerate() {
            let q = u16::try_from(q).unwrap();
            for n in 0..3 {
                post(&block, vq, q, n, VIRTIO_BLK_T_IN, 0, 512);
                wait_used(vq, n + 1);
            }
        }

        // The guest stops while the workers poll, with a request of each queue in its avail
        // ring that no worker took and for which the guest did not kick.
        block.drain();
        for (q, vq) in vqs.iter().enumerate() {
            let q = u16::try_from(q).unwrap();
            assert!(!post(
                &block,
                vq,
                q,
                3,
                VIRTIO_BLK_T_IN,
                u64::from(q) * 8,
                512
            ));
        }
        let state = block.save();
        for queue in &state.virtio_state.queues {
            assert_eq!(indices(queue), (3, 3));
        }
        let mut block = save_and_load(block, &mem);
        // Nothing runs before the resume.
        for vq in &vqs {
            stays_used(vq, 3);
        }

        // At the resume each queue is looked at and armed again: the request in the ring is
        // served, and the guest's next request is served too.
        block.kick();
        let data = pattern(0x31, 0x4000);
        for (q, vq) in vqs.iter().enumerate() {
            let q = u16::try_from(q).unwrap();
            wait_used(vq, 4);
            assert_eq!(mq_status(&mem, q, 3), VIRTIO_BLK_S_OK);
            let mut got = vec![0u8; 512];
            mem.read_slice(&mut got, GuestAddress(data_addr(q, 3)))
                .unwrap();
            let at = usize::from(q) * 4096;
            assert_eq!(got, data[at..at + 512]);
            post(&block, vq, q, 4, VIRTIO_BLK_T_IN, 0, 512);
            wait_used(vq, 5);
            post(&block, vq, q, 5, VIRTIO_BLK_T_IN, 0, 512);
            wait_used(vq, 6);
            assert_eq!(mq_status(&mem, q, 5), VIRTIO_BLK_S_OK);
        }
    }

    #[test]
    fn test_kept_request_of_one_queue_with_polling_across_a_save_and_a_load() {
        let mem = mq_mem();
        let file = mq_file(MQ_FILE);
        let path = file.as_path().to_str().unwrap().to_string();
        fill_file(&path, 0, &pattern(0x52, 0x4000));
        let mut block = mq_block(&path, 2, 1_000_000, false);
        let vqs = mq_queues(&mem, 2);
        // The disk fails the first request of queue 1.
        mq_engine(&mut block, 1).fail_completions = 1;
        mq_activate(&mut block, &mem, &vqs);
        assert!(!block.take_disk_error());

        post(&block, &vqs[1], 1, 0, VIRTIO_BLK_T_IN, 8, 512);
        wait_disk_error(&mut block);
        stays_used(&vqs[1], 0);
        assert_eq!(mq_status(&mem, 1, 0), 0xff);
        // The guest is not stopped yet: queue 0 goes on; queue 1 takes nothing.
        post(&block, &vqs[0], 0, 0, VIRTIO_BLK_T_IN, 0, 512);
        wait_used(&vqs[0], 1);
        post(&block, &vqs[1], 1, 1, VIRTIO_BLK_T_IN, 16, 512);
        stays_used(&vqs[1], 0);

        // The stop of the guest; the stop of a checkpoint and its end keep the request kept.
        block.drain();
        block.resume_after_checkpoint();
        stays_used(&vqs[1], 0);
        block.drain();
        let state = block.save();
        assert_eq!(state.kept_requests.len(), 2);
        assert!(state.kept_requests[0].is_empty());
        assert_eq!(state.kept_requests[1].len(), 1);

        let mut block = save_and_load(block, &mem);
        stays_used(&vqs[1], 0);
        assert!(!block.take_disk_error());

        // At the resume the kept request runs again from its start, then the next one.
        block.kick();
        wait_used(&vqs[1], 2);
        let data = pattern(0x52, 0x4000);
        for (n, at) in [(0u16, 4096usize), (1, 8192)] {
            assert_eq!(mq_status(&mem, 1, n), VIRTIO_BLK_S_OK);
            let mut got = vec![0u8; 512];
            mem.read_slice(&mut got, GuestAddress(data_addr(1, n)))
                .unwrap();
            assert_eq!(got, data[at..at + 512], "request {n}");
        }
        assert_eq!(vqs[1].used.ring[0].get().id, 0);
        assert!(!block.take_disk_error());
    }

    #[test]
    fn test_drain_at_a_stop_and_at_a_checkpoint_with_polling() {
        let mem = mq_mem();
        let file = mq_file(MQ_FILE);
        let path = file.as_path().to_str().unwrap().to_string();
        let mut block = mq_block(&path, 2, 1_000_000, false);
        let vqs = mq_queues(&mem, 2);
        mq_activate(&mut block, &mem, &vqs);
        let mut model = vec![0u8; MQ_FILE];

        for (round, checkpoint) in [false, true].into_iter().enumerate() {
            let first = u16::try_from(round).unwrap() * 8;
            // Eight writes of each queue, as fast as the guest can put them.
            for (q, vq) in vqs.iter().enumerate() {
                let q = u16::try_from(q).unwrap();
                for n in first..first + 8 {
                    let data = pattern(
                        u8::try_from(n).unwrap() * 3 + u8::try_from(q).unwrap(),
                        4096,
                    );
                    mem.write_slice(&data, GuestAddress(data_addr(q, n)))
                        .unwrap();
                    let sector = 8 * (u64::from(q) * 16 + u64::from(n));
                    post(&block, vq, q, n, VIRTIO_BLK_T_OUT, sector, 4096);
                    let at = usize::try_from(sector * 512).unwrap();
                    model[at..at + 4096].copy_from_slice(&data);
                }
            }
            // The drain: after it nothing that a worker took is unanswered, and no worker
            // takes a request.
            if checkpoint {
                VirtioDevice::prepare_checkpoint(&mut block);
            } else {
                VirtioDevice::quiesce(&mut block);
            }
            let state = block.save();
            for (q, queue) in state.virtio_state.queues.iter().enumerate() {
                let (next_avail, next_used) = indices(queue);
                assert_eq!(next_avail, next_used, "round {round} queue {q}");
                assert_eq!(vqs[q].used.idx.get(), next_used);
            }
            // A request that the guest put in a ring during the stop waits for its end.
            let extra = 20 + 2 * first / 8;
            for (q, vq) in vqs.iter().enumerate() {
                let q = u16::try_from(q).unwrap();
                let taken = indices(&state.virtio_state.queues[usize::from(q)]).1;
                post(&block, vq, q, extra + q, VIRTIO_BLK_T_IN, 0, 512);
                stays_used(vq, taken);
            }
            if checkpoint {
                block.resume_after_checkpoint();
            } else {
                block.kick();
            }
            for (q, vq) in vqs.iter().enumerate() {
                wait_used(vq, 9 * (first / 8 + 1));
                let q = u16::try_from(q).unwrap();
                for n in first..first + 8 {
                    assert_eq!(mq_status(&mem, q, n), VIRTIO_BLK_S_OK);
                }
                assert_eq!(mq_status(&mem, q, extra + q), VIRTIO_BLK_S_OK);
            }
        }
        block.drain();
        assert!(read_file(&path, MQ_FILE) == model);
    }

    #[test]
    fn test_used_rings_marked_at_a_checkpoint_with_workers() {
        let mem = mq_mem();
        let file = mq_file(MQ_FILE);
        let mut block = mq_block(file.as_path().to_str().unwrap(), 2, 1_000_000, false);
        let vqs = mq_queues(&mem, 2);
        mq_activate(&mut block, &mem, &vqs);
        for (q, vq) in vqs.iter().enumerate() {
            post(
                &block,
                vq,
                u16::try_from(q).unwrap(),
                0,
                VIRTIO_BLK_T_IN,
                0,
                512,
            );
            wait_used(vq, 1);
        }
        // The stop of a checkpoint: the bitmap is reset, then the rings are marked again.
        VirtioDevice::prepare_checkpoint(&mut block);
        mem.reset_dirty();
        block.mark_queue_memory_dirty(&mem).unwrap();
        for vq in &vqs {
            let bitmap = mem.find_region(vq.used_start()).unwrap().bitmap();
            let used = usize::try_from(vq.used_start().0).unwrap();
            let avail = usize::try_from(vq.avail_start().0).unwrap();
            let desc = usize::try_from(vq.dtable_start().0).unwrap();
            assert!(bitmap.dirty_at(used) && bitmap.dirty_at(avail) && bitmap.dirty_at(desc));
        }
        assert!(
            !mem.find_region(GuestAddress(0))
                .unwrap()
                .bitmap()
                .dirty_at(0)
        );
        // The workers go on after the checkpoint.
        block.resume_after_checkpoint();
        for (q, vq) in vqs.iter().enumerate() {
            post(
                &block,
                vq,
                u16::try_from(q).unwrap(),
                1,
                VIRTIO_BLK_T_IN,
                0,
                512,
            );
            wait_used(vq, 2);
        }
    }

    /// The backings of the alignment tests: a regular file (its engine aligns to 4096 bytes)
    /// and, when `SPACE_TEST_BLOCK_4K` names one, a block device with 4096-byte logical blocks.
    fn mq_backings() -> Vec<(String, Option<TempFile>)> {
        let f = mq_file(MQ_FILE);
        let mut backings = vec![(f.as_path().to_str().unwrap().to_string(), Some(f))];
        match std::env::var("SPACE_TEST_BLOCK_4K") {
            Ok(dev) => backings.push((dev, None)),
            Err(_) => eprintln!("SPACE_TEST_BLOCK_4K is not set: no run on a 4096-byte device"),
        }
        backings
    }

    #[test]
    fn test_two_queues_write_parts_of_one_device_block_at_once() {
        // Each queue writes its own sector of the same device blocks at the same time: each
        // write is a read-modify-write of the block, and the writes of the two queues may not
        // run at the same time, or one would write back the other's old sector.
        let mem = mq_mem();
        for (path, _file) in mq_backings() {
            let mut model = pattern(0x40, MQ_FILE);
            fill_file(&path, 0, &model);
            let mut block = mq_block(&path, 2, 128, false);
            let vqs = mq_queues(&mem, 2);
            mq_activate(&mut block, &mem, &vqs);
            for round in 0..4u16 {
                for n in 0..16u16 {
                    for (q, vq) in vqs.iter().enumerate() {
                        let q = u16::try_from(q).unwrap();
                        let i = round * 16 + n;
                        let data = pattern(
                            u8::try_from(i % 200).unwrap() + u8::try_from(q).unwrap(),
                            512,
                        );
                        mem.write_slice(&data, GuestAddress(data_addr(q, n)))
                            .unwrap();
                        // Block i, sector 1 + q (and sector 4 + q of block i + 1 for longer writes).
                        let sector = 8 * u64::from(i) + 1 + u64::from(q);
                        post(&block, vq, q, n, VIRTIO_BLK_T_OUT, sector, 512);
                        let at = usize::try_from(sector * 512).unwrap();
                        model[at..at + 512].copy_from_slice(&data);
                    }
                }
                for vq in &vqs {
                    wait_used(vq, 16 * (round + 1));
                }
                for (q, vq) in vqs.iter().enumerate() {
                    for n in 0..16 {
                        assert_eq!(
                            mq_status(&mem, u16::try_from(q).unwrap(), n),
                            VIRTIO_BLK_S_OK
                        );
                    }
                    let _ = vq;
                }
                if round < 3 {
                    // The next round's requests go to the same slots: the ring wraps at 64.
                    for vq in &vqs {
                        assert_eq!(vq.used.idx.get(), 16 * (round + 1));
                    }
                }
            }
            block.drain();
            assert!(
                read_file(&path, MQ_FILE) == model,
                "{path}: the backing differs"
            );
        }
    }

    #[test]
    fn test_discard_through_the_workers() {
        let mem = mq_mem();
        for (path, _file) in mq_backings() {
            let mut model = pattern(0x77, MQ_FILE);
            fill_file(&path, 0, &model);
            let mut block = mq_block(&path, 2, 128, true);
            let vqs = mq_queues(&mem, 2);
            mq_activate(&mut block, &mem, &vqs);
            // Queue 0 writes a part of block 3 while queue 1 discards sectors 1 to 16 (whole
            // block 1 and parts of blocks 0 and 2) and sectors 41 and 42 (inside block 5).
            let data = pattern(0x11, 512);
            mem.write_slice(&data, GuestAddress(data_addr(0, 0)))
                .unwrap();
            post(&block, &vqs[0], 0, 0, VIRTIO_BLK_T_OUT, 25, 512);
            for (n, (sector, sectors)) in [(1u64, 16u32), (41, 2)].into_iter().enumerate() {
                let n = u16::try_from(n).unwrap();
                let mut range = [0u8; 16];
                range[0..8].copy_from_slice(&sector.to_le_bytes());
                range[8..12].copy_from_slice(&sectors.to_le_bytes());
                mem.write_slice(&range, GuestAddress(data_addr(1, n)))
                    .unwrap();
                post(&block, &vqs[1], 1, n, VIRTIO_BLK_T_DISCARD, 0, 16);
                let at = usize::try_from(sector * 512).unwrap();
                model[at..at + sectors as usize * 512].fill(0);
            }
            model[25 * 512..26 * 512].copy_from_slice(&data);
            wait_used(&vqs[0], 1);
            wait_used(&vqs[1], 2);
            assert_eq!(mq_status(&mem, 0, 0), VIRTIO_BLK_S_OK);
            assert_eq!(mq_status(&mem, 1, 0), VIRTIO_BLK_S_OK);
            assert_eq!(mq_status(&mem, 1, 1), VIRTIO_BLK_S_OK);
            block.drain();
            assert!(
                read_file(&path, MQ_FILE) == model,
                "{path}: the backing differs"
            );
        }
    }

    #[test]
    fn test_poll_us_needs_num_queues_and_a_bounded_window() {
        let file = mq_file(0x1000);
        let path = file.as_path().to_str().unwrap().to_string();
        let mut config = default_config(path.clone(), FileEngineType::Async);
        config.poll_us = Some(128);
        assert!(matches!(
            VirtioBlock::new(config.clone()),
            Err(VirtioBlockError::PollWithoutWorkers)
        ));
        config.poll_us = Some(0);
        VirtioBlock::new(config.clone()).unwrap();
        config.num_queues = std::num::NonZeroU16::new(2);
        config.poll_us = Some(crate::devices::virtio::block::virtio::MAX_POLL_US + 1);
        assert!(matches!(
            VirtioBlock::new(config.clone()),
            Err(VirtioBlockError::PollTooLong(_))
        ));
        config.poll_us = Some(128);
        let block = VirtioBlock::new(config.clone()).unwrap();
        assert_eq!(block.poll_window(), Duration::from_micros(128));
        assert_eq!(block.config().poll_us, Some(128));

        // The drive's state keeps the queues and the window.
        let state = block.save();
        let bytes = bitcode::serialize(&state).unwrap();
        drop(block);
        let state: VirtioBlockState = bitcode::deserialize(&bytes).unwrap();
        let restored = VirtioBlock::restore(
            crate::devices::virtio::block::persist::BlockConstructorArgs { mem: default_mem() },
            &state,
        )
        .unwrap();
        assert_eq!(restored.config().num_queues, std::num::NonZeroU16::new(2));
        assert_eq!(restored.config().poll_us, Some(128));
        assert_eq!(restored.poll_window(), Duration::from_micros(128));
    }
}
