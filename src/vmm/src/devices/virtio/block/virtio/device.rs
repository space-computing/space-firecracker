// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cmp;
use std::collections::VecDeque;
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::num::NonZeroU16;
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use vm_memory::ByteValued;
use vmm_sys_util::eventfd::EventFd;

use super::io::{DirectAlignment, DriveBlocks, FileEngine};
use super::worker::{BlockWorker, FlushMode, WorkerHandle};
use super::{
    BLOCK_QUEUE_SIZE, DEFAULT_BLOCK_NUM_QUEUES, MAX_DISCARD_SECTORS, MAX_POLL_US, PendingRequest,
    SECTOR_SHIFT, SECTOR_SIZE, VirtioBlockError,
};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::block::CacheType;
use crate::devices::virtio::block::virtio::metrics::{BlockDeviceMetrics, BlockMetricsPerDevice};
use crate::devices::virtio::device::{ActiveState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_blk::{
    VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_MQ,
    VIRTIO_BLK_F_RO, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_ID_BYTES,
};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::queue::{InvalidAvailIdx, Queue, QueueConfig, QueueError};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::impl_device_type;
use crate::logger::{IncMetric, error, warn};
use crate::rate_limiter::{BucketUpdate, RateLimiter};
use crate::seccomp::BpfProgram;
use crate::vmm_config::RateLimiterConfig;
use crate::vmm_config::drive::BlockDeviceConfig;
use crate::vstate::memory::GuestMemoryMmap;

/// The engine file type, either Sync or Async (through io_uring).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileEngineType {
    /// Use an Async engine, based on io_uring.
    Async,
    /// Use a Sync engine, based on blocking system calls.
    #[default]
    Sync,
}

/// Woken by a block device whose disk failed a request of the `Async` engine. The [`Vmm`]
/// then stops the guest (`paused_reason: disk-error`). One VMM runs in a process, so one
/// event serves every drive and every queue; the Vmm asks the drives which one failed.
///
/// [`Vmm`]: crate::Vmm
pub static DISK_ERROR_EVT: LazyLock<EventFd> = LazyLock::new(|| {
    EventFd::new(libc::EFD_NONBLOCK).expect("Cannot create the disk error eventfd")
});

/// Helper object for setting up all `Block` fields derived from its backing file.
#[derive(Debug)]
pub struct DiskProperties {
    pub file_engine: FileEngine,
    pub nsectors: u64,
    pub image_id: [u8; VIRTIO_BLK_ID_BYTES as usize],
}

impl DiskProperties {
    // Helper function that opens the file with the proper access permissions. A drive of the
    // `Async` engine opens its file with `O_DIRECT`, so that the page cache of the host is not
    // between the guest and the disk; the `Sync` engine opens it as before.
    fn open_file(
        disk_image_path: &str,
        is_disk_read_only: bool,
        file_engine_type: FileEngineType,
    ) -> Result<File, VirtioBlockError> {
        let mut options = OpenOptions::new();
        options.read(true).write(!is_disk_read_only);
        if file_engine_type == FileEngineType::Async {
            options.custom_flags(libc::O_DIRECT);
        }
        options
            .open(PathBuf::from(&disk_image_path))
            .map_err(|x| VirtioBlockError::BackingFile(x, disk_image_path.to_string()))
    }

    // The alignment that the requests of the file need: the file of an `Async` drive is
    // opened with `O_DIRECT`, so its engine aligns each request to the device's blocks.
    fn direct_alignment(file: &File, file_engine_type: FileEngineType) -> DirectAlignment {
        match file_engine_type {
            FileEngineType::Async => DirectAlignment::of_direct_file(file),
            FileEngineType::Sync => DirectAlignment::NONE,
        }
    }

    // Helper function that gets the size of the file
    fn file_size(disk_image_path: &str, disk_image: &mut File) -> Result<u64, VirtioBlockError> {
        let disk_size = disk_image
            .seek(SeekFrom::End(0))
            .map_err(|x| VirtioBlockError::BackingFile(x, disk_image_path.to_string()))?;

        // We only support disk size, which uses the first two words of the configuration space.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        if disk_size % u64::from(SECTOR_SIZE) != 0 {
            warn!(
                "Disk size {} is not a multiple of sector size {}; the remainder will not be \
                 visible to the guest.",
                disk_size, SECTOR_SIZE
            );
        }

        Ok(disk_size)
    }

    /// Create a new file for the block device using a FileEngine. The `Async` engines of the
    /// queues of one drive share `blocks`.
    pub fn new(
        disk_image_path: &str,
        is_disk_read_only: bool,
        file_engine_type: FileEngineType,
        blocks: Option<Arc<DriveBlocks>>,
    ) -> Result<Self, VirtioBlockError> {
        let mut disk_image = Self::open_file(disk_image_path, is_disk_read_only, file_engine_type)?;
        let disk_size = Self::file_size(disk_image_path, &mut disk_image)?;
        let image_id = Self::build_disk_image_id(&disk_image);
        let align = Self::direct_alignment(&disk_image, file_engine_type);

        Ok(Self {
            file_engine: FileEngine::from_file(disk_image, file_engine_type, align, blocks)
                .map_err(VirtioBlockError::FileEngine)?,
            nsectors: disk_size >> SECTOR_SHIFT,
            image_id,
        })
    }

    /// Update the path to the file backing the block device
    pub fn update(
        &mut self,
        disk_image_path: String,
        is_disk_read_only: bool,
    ) -> Result<(), VirtioBlockError> {
        let file_engine_type = match self.file_engine {
            FileEngine::Sync(_) => FileEngineType::Sync,
            FileEngine::Async(_) => FileEngineType::Async,
        };
        let mut disk_image =
            Self::open_file(&disk_image_path, is_disk_read_only, file_engine_type)?;
        let disk_size = Self::file_size(&disk_image_path, &mut disk_image)?;

        self.image_id = Self::build_disk_image_id(&disk_image);
        let align = Self::direct_alignment(&disk_image, file_engine_type);
        self.file_engine
            .update_file_path(disk_image, align)
            .map_err(VirtioBlockError::FileEngine)?;
        self.nsectors = disk_size >> SECTOR_SHIFT;

        Ok(())
    }

    fn build_device_id(disk_file: &File) -> Result<String, VirtioBlockError> {
        let blk_metadata = disk_file
            .metadata()
            .map_err(VirtioBlockError::GetFileMetadata)?;
        // This is how kvmtool does it.
        let device_id = format!(
            "{}{}{}",
            blk_metadata.st_dev(),
            blk_metadata.st_rdev(),
            blk_metadata.st_ino()
        );
        Ok(device_id)
    }

    fn build_disk_image_id(disk_file: &File) -> [u8; VIRTIO_BLK_ID_BYTES as usize] {
        let mut default_id = [0; VIRTIO_BLK_ID_BYTES as usize];
        match Self::build_device_id(disk_file) {
            Err(_) => {
                warn!("Could not generate device id. We'll use a default.");
            }
            Ok(disk_id_string) => {
                // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
                // This will also zero out any leftover bytes.
                let disk_id = disk_id_string.as_bytes();
                let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
                default_id[..bytes_to_copy].copy_from_slice(&disk_id[..bytes_to_copy]);
            }
        }
        default_id
    }
}

/// Internal type to store attributes of the block device
#[derive(Debug)]
struct BlockDeviceAttributes {
    logical_block_size: u32,
    physical_block_size: u32,
    min_io_size: u32,
    opt_io_size: u32,
}

/// Try to obtain attributes of the block device from the file descriptor if possible
fn query_blk_attrs(file: &File) -> Option<BlockDeviceAttributes> {
    let Ok(metadata) = file.metadata() else {
        return None;
    };
    let file_type = metadata.file_type();
    if !file_type.is_block_device() {
        return None;
    };

    // Have to use a macro here to pass the libc constants directly to the libc::ioctl since
    // the types of constants differ between glibc(u64) and musl(i32)
    macro_rules! block_attr {
        ($file:expr, $attr:expr) => {{
            let mut result: u32 = 0;
            // SAFETY: FFI call with correct arguments
            if unsafe { libc::ioctl($file.as_raw_fd(), $attr, &mut result) } != 0 {
                None
            } else {
                Some(result)
            }
        }};
    }

    let attrs = BlockDeviceAttributes {
        logical_block_size: block_attr!(file, libc::BLKSSZGET)?,
        physical_block_size: block_attr!(file, libc::BLKPBSZGET)?,
        min_io_size: block_attr!(file, libc::BLKIOMIN)?,
        opt_io_size: block_attr!(file, libc::BLKIOOPT)?,
    };
    Some(attrs)
}

/// Try to convert block attributes into the topology value for the virtio-block device
fn calculate_blk_size_and_topology(
    attrs: BlockDeviceAttributes,
) -> Option<(u32, VirtioBlkTopology)> {
    // It is used as a divisor, so check just in case
    if attrs.logical_block_size == 0 {
        return None;
    }

    // This can technically be replaced by `(physical / logical).trailing_zeroes()`, but it assumes
    // that the devision always results in a power of 2 value. Just in case we do the loop
    // approach.
    let mut physical_block_exp: u8 = 0;
    let mut size = attrs.physical_block_size;
    while attrs.logical_block_size < size {
        physical_block_exp += 1;
        size >>= 1;
    }

    let min_io_size =
        u16::try_from(attrs.min_io_size / attrs.logical_block_size).unwrap_or(u16::MAX);
    let opt_io_size = attrs.opt_io_size / attrs.logical_block_size;

    let topology = VirtioBlkTopology {
        physical_block_exp,
        alignment_offset: 0,
        min_io_size,
        opt_io_size,
    };
    Some((attrs.logical_block_size, topology))
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[repr(C)]
pub struct VirtioBlkTopology {
    /// number of logical blocks per physical block (log2)
    pub physical_block_exp: u8,
    /// offset of first aligned logical block
    pub alignment_offset: u8,
    /// suggested minimum I/O size in blocks
    pub min_io_size: u16,
    /// optimal (suggested maximum) I/O size in blocks
    pub opt_io_size: u32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct ConfigSpace {
    pub capacity: u64,
    pub size_max: u32,
    pub seg_max: u32,
    pub geometry: u32,
    pub blk_size: u32,
    pub topology: VirtioBlkTopology,
    pub wce: u8,
    pub unused: u8,
    pub num_queues: u16,
    pub max_discard_sectors: u32,
    pub max_discard_seg: u32,
    pub discard_sector_alignment: u32,
}

impl Default for ConfigSpace {
    fn default() -> Self {
        Self {
            capacity: 0,
            size_max: 0,
            seg_max: 0,
            geometry: 0,
            blk_size: 512,
            topology: VirtioBlkTopology {
                physical_block_exp: 0,
                alignment_offset: 0,
                min_io_size: 0,
                opt_io_size: 128,
            },
            wce: 0,
            unused: 0,
            num_queues: 1,
            max_discard_sectors: MAX_DISCARD_SECTORS,
            max_discard_seg: 1,
            discard_sector_alignment: 1,
        }
    }
}

// SAFETY: `ConfigSpace` contains only PODs in `repr(C)` or `repr(transparent)`, without padding.
unsafe impl ByteValued for ConfigSpace {}

/// Use this structure to set up the Block Device before booting the kernel.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VirtioBlockConfig {
    /// Unique identifier of the drive.
    pub drive_id: String,
    /// Part-UUID. Represents the unique id of the boot partition of this device. It is
    /// optional and it will be used only if the `is_root_device` field is true.
    pub partuuid: Option<String>,
    /// If set to true, it makes the current device the root block device.
    /// Setting this flag to true will mount the block device in the
    /// guest under /dev/vda unless the partuuid is present.
    pub is_root_device: bool,
    /// If set to true, the drive will ignore flush requests coming from
    /// the guest driver.
    #[serde(default)]
    pub cache_type: CacheType,

    /// If set to true, the drive is opened in read-only mode. Otherwise, the
    /// drive is opened as read-write.
    pub is_read_only: bool,
    /// If set to true, the device advertises discard support to the guest.
    pub discard: bool,
    /// Number of queues, each processed on a dedicated worker thread.
    /// If unset, a single queue is processed on the VMM thread.
    pub num_queues: Option<NonZeroU16>,
    /// How long, in microseconds, a worker thread looks at its queue and at its completions
    /// after its last work, with the guest's notification left off. Unset or 0: no polling.
    #[serde(default)]
    pub poll_us: Option<u32>,
    /// Path of the backing file on the host
    pub path_on_host: String,
    /// Rate Limiter for I/O operations.
    pub rate_limiter: Option<RateLimiterConfig>,
    /// The type of IO engine used by the device.
    #[serde(default)]
    #[serde(rename = "io_engine")]
    pub file_engine_type: FileEngineType,
    /// Logical block size.
    pub blk_size: Option<u32>,
    /// Block topology settings
    pub topology: Option<VirtioBlkTopology>,
}

impl TryFrom<&BlockDeviceConfig> for VirtioBlockConfig {
    type Error = VirtioBlockError;

    fn try_from(value: &BlockDeviceConfig) -> Result<Self, Self::Error> {
        if let (Some(path_on_host), None) = (&value.path_on_host, &value.socket) {
            Ok(Self {
                drive_id: value.drive_id.clone(),
                partuuid: value.partuuid.clone(),
                is_root_device: value.is_root_device,
                cache_type: value.cache_type,

                is_read_only: value.is_read_only.unwrap_or(false),
                discard: value.discard.unwrap_or(false),
                num_queues: value.num_queues,
                poll_us: value.poll_us,
                path_on_host: path_on_host.clone(),
                rate_limiter: value.rate_limiter,
                file_engine_type: value.file_engine_type.unwrap_or_default(),
                blk_size: value.blk_size,
                topology: value.topology,
            })
        } else {
            Err(VirtioBlockError::Config)
        }
    }
}

impl From<VirtioBlockConfig> for BlockDeviceConfig {
    fn from(value: VirtioBlockConfig) -> Self {
        Self {
            drive_id: value.drive_id,
            partuuid: value.partuuid,
            is_root_device: value.is_root_device,
            cache_type: value.cache_type,

            is_read_only: Some(value.is_read_only),
            discard: Some(value.discard),
            num_queues: value.num_queues,
            poll_us: value.poll_us,
            path_on_host: Some(value.path_on_host),
            rate_limiter: value.rate_limiter,
            file_engine_type: Some(value.file_engine_type),
            blk_size: value.blk_size,
            topology: value.topology,

            socket: None,
        }
    }
}

/// Virtio device for exposing block level read/write operations on a host file.
#[derive(Debug)]
pub struct VirtioBlock {
    // Virtio fields.
    pub avail_features: u64,
    pub acked_features: u64,
    pub config_space: ConfigSpace,
    pub activate_evt: EventFd,

    pub(crate) config: VirtioBlockConfig,
    pub(crate) rate_limiter: Arc<Mutex<RateLimiter>>,
    pub(crate) state: BlockRuntimeState,
    pub metrics: Arc<BlockDeviceMetrics>,
    // A disk error of a queue that the Vmm has not yet taken to stop the guest.
    pub(crate) disk_error: Arc<AtomicBool>,
}

/// State of the block data-path resources.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum BlockRuntimeState {
    // Vmm owns the runtime resources before activation
    // In threaded mode, it also owns parked worker threads
    Configuring(Vec<BlockResources>, Vec<WorkerHandle>),
    // Data path on VMM thread (single thread)
    Inline(BlockWorker),
    // Data path on a dedicated worker thread (multi thread)
    Threaded(ThreadedActive),
    // Placeholder to hold state when activating
    Placeholder,
}

/// VMM-side state when data paths run on worker threads
#[derive(Debug)]
pub(crate) struct ThreadedActive {
    pub(crate) worker_handles: Vec<WorkerHandle>,
    interrupt: Arc<dyn VirtioInterrupt>,
    queue_configs: Vec<QueueConfig>,
}

/// Runtime resources used by the block data path.
#[derive(Debug)]
pub(crate) struct BlockResources {
    pub(crate) queue: Queue,
    pub(crate) queue_evt: EventFd,
    pub(crate) queue_idx: u16,
    pub(crate) disk: DiskProperties,
    pub(crate) is_io_engine_throttled: bool,
    // The stop on a disk error (the `Async` engine). A request that the disk failed is kept,
    // not answered, and runs again from its start when the guest is resumed. While a request
    // is kept, the queue takes no new request.
    pub(crate) kept: VecDeque<PendingRequest>,
    pub(crate) stopped_on_error: bool,
}

impl BlockResources {
    /// The resources of queue `queue_idx`, with no request kept.
    pub(crate) fn new(
        queue: Queue,
        queue_idx: u16,
        disk: DiskProperties,
    ) -> Result<Self, VirtioBlockError> {
        Ok(BlockResources {
            queue,
            queue_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?,
            queue_idx,
            disk,
            is_io_engine_throttled: false,
            kept: VecDeque::new(),
            stopped_on_error: false,
        })
    }

    /// Drain pending I/O and clear engine throttling
    fn reset(&mut self) {
        self.disk
            .file_engine
            .drain(true)
            .expect("Failed to reset block IO engine");
        self.is_io_engine_throttled = false;
        self.kept.clear();
        self.stopped_on_error = false;
    }
}

impl VirtioBlock {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    pub fn new(mut config: VirtioBlockConfig) -> Result<VirtioBlock, VirtioBlockError> {
        if config.discard && config.is_read_only {
            return Err(VirtioBlockError::DiscardReadOnlyUnsupported);
        }

        Self::check_poll(&config)?;

        let num_queues = config
            .num_queues
            .map_or(DEFAULT_BLOCK_NUM_QUEUES, NonZeroU16::get);
        let blocks = Self::drive_blocks(config.file_engine_type, num_queues);
        let mut resources = Vec::with_capacity(usize::from(num_queues));
        for queue_idx in 0..num_queues {
            resources.push(BlockResources::new(
                Queue::new(BLOCK_QUEUE_SIZE),
                queue_idx,
                DiskProperties::new(
                    &config.path_on_host,
                    config.is_read_only,
                    config.file_engine_type,
                    blocks.clone(),
                )?,
            )?);
        }

        let rate_limiter = config
            .rate_limiter
            .map(RateLimiter::from)
            .unwrap_or_default();
        let rate_limiter_config: RateLimiterConfig = (&rate_limiter).into();
        config.rate_limiter = rate_limiter_config.into_option();

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_RING_F_EVENT_IDX)
            | (1u64 << VIRTIO_BLK_F_BLK_SIZE)
            | (1u64 << VIRTIO_BLK_F_TOPOLOGY)
            | (1u64 << VIRTIO_BLK_F_MQ);

        if config.cache_type == CacheType::Writeback {
            avail_features |= 1u64 << VIRTIO_BLK_F_FLUSH;
        }

        if config.is_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        }
        if config.discard {
            avail_features |= 1u64 << VIRTIO_BLK_F_DISCARD;
        }

        let mut config_space = ConfigSpace {
            capacity: resources[0].disk.nsectors.to_le(),
            num_queues: num_queues.to_le(),
            ..Default::default()
        };

        if config.blk_size.is_none() && config.topology.is_none() {
            if let Some((blk_size, topology)) =
                query_blk_attrs(resources[0].disk.file_engine.file())
                    .and_then(calculate_blk_size_and_topology)
            {
                config_space.blk_size = blk_size;
                config_space.topology = topology;
                config_space.discard_sector_alignment = blk_size / SECTOR_SIZE;
            }
        } else {
            if let Some(blk_size) = config.blk_size {
                config_space.blk_size = blk_size;
                config_space.discard_sector_alignment = blk_size / SECTOR_SIZE;
            }
            if let Some(topology) = config.topology {
                config_space.topology = topology;
            }
        }

        config.blk_size = Some(config_space.blk_size);
        config.topology = Some(config_space.topology);

        let metrics = BlockMetricsPerDevice::alloc(config.drive_id.clone());

        Ok(VirtioBlock {
            avail_features,
            acked_features: 0u64,
            config_space,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?,

            config,
            rate_limiter: Arc::new(Mutex::new(rate_limiter)),
            state: BlockRuntimeState::Configuring(resources, Vec::new()),
            metrics,
            disk_error: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Polling is done by the worker threads, so it needs `num_queues`; its window is bounded.
    pub(crate) fn check_poll(config: &VirtioBlockConfig) -> Result<(), VirtioBlockError> {
        match config.poll_us {
            Some(us) if us > MAX_POLL_US => Err(VirtioBlockError::PollTooLong(us)),
            Some(us) if us > 0 && config.num_queues.is_none() => {
                Err(VirtioBlockError::PollWithoutWorkers)
            }
            _ => Ok(()),
        }
    }

    /// The device blocks in work of the engines of a drive with more than one `Async` queue.
    pub(crate) fn drive_blocks(
        file_engine_type: FileEngineType,
        num_queues: u16,
    ) -> Option<Arc<DriveBlocks>> {
        (file_engine_type == FileEngineType::Async && num_queues > 1)
            .then(|| Arc::new(DriveBlocks::default()))
    }

    /// The poll window of the worker threads.
    pub(crate) fn poll_window(&self) -> std::time::Duration {
        std::time::Duration::from_micros(u64::from(self.config.poll_us.unwrap_or(0)))
    }

    /// Whether a disk error of this drive waits for the Vmm to stop the guest. The answer is
    /// given once.
    pub fn take_disk_error(&mut self) -> bool {
        self.disk_error.swap(false, Ordering::SeqCst)
    }

    /// Ends the requests in flight with no `fsync`, at a stop of the guest and at a checkpoint:
    /// their answers are written (or they are kept, when the disk failed them), and after it
    /// no queue takes a request or writes into guest memory until the device is kicked (or,
    /// after the stop of a checkpoint of a running guest, until `resume_after_checkpoint`).
    pub fn drain(&mut self) {
        match &mut self.state {
            BlockRuntimeState::Inline(worker) => worker.prepare_save(FlushMode::Drain),
            BlockRuntimeState::Threaded(active) => {
                for handle in &active.worker_handles {
                    handle.pause(FlushMode::Drain);
                }
            }
            BlockRuntimeState::Configuring(_, _) => {}
            BlockRuntimeState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    /// The end of the stop of a checkpoint of a running guest: the worker threads take their
    /// queues again (each looks at its queue and arms the guest's notification). A request that
    /// a disk error kept stays kept until the guest is resumed.
    pub fn resume_after_checkpoint(&mut self) {
        if let BlockRuntimeState::Threaded(active) = &self.state {
            for handle in &active.worker_handles {
                handle.continue_after_checkpoint();
            }
        }
    }

    /// Returns a copy of a device config
    pub fn config(&self) -> VirtioBlockConfig {
        self.config.clone()
    }

    pub(crate) fn resources(&self) -> &[BlockResources] {
        match &self.state {
            BlockRuntimeState::Configuring(resources, _) => resources,
            BlockRuntimeState::Inline(worker) => std::slice::from_ref(&worker.resources),
            BlockRuntimeState::Threaded(_) => {
                unreachable!("worker thread owns the runtime resources")
            }
            BlockRuntimeState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    pub(crate) fn resources_mut(&mut self) -> &mut [BlockResources] {
        match &mut self.state {
            BlockRuntimeState::Configuring(resources, _) => resources,
            BlockRuntimeState::Inline(worker) => std::slice::from_mut(&mut worker.resources),
            BlockRuntimeState::Threaded(_) => {
                unreachable!("worker thread owns the runtime resources")
            }
            BlockRuntimeState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    #[cfg(test)]
    pub(crate) fn disk(&self) -> &DiskProperties {
        &self.resources()[0].disk
    }

    pub(crate) fn lock_rate_limiter(&self) -> MutexGuard<'_, RateLimiter> {
        self.rate_limiter
            .lock()
            .expect("Poisoned block rate limiter lock")
    }

    pub(crate) fn is_threaded_active(&self) -> bool {
        matches!(self.state, BlockRuntimeState::Threaded(_))
    }

    /// Process a single event in the Virtio queue.
    ///
    /// This function is called by the event manager when the guest notifies us
    /// about new buffers in the queue.
    pub(crate) fn process_queue_event(&mut self) {
        if let BlockRuntimeState::Inline(worker) = &mut self.state {
            worker.process_queue_event();
        }
    }

    /// Process device virtio queue(s).
    pub fn process_virtio_queues(&mut self) -> Result<(), InvalidAvailIdx> {
        if let BlockRuntimeState::Inline(worker) = &mut self.state {
            worker.process_queue()
        } else {
            Ok(())
        }
    }

    pub(crate) fn process_rate_limiter_event(&mut self) {
        self.metrics.rate_limiter_event_count.inc();
        if self.lock_rate_limiter().event_handler().is_err() {
            return;
        }

        // Upon rate limiter event, call the rate limiter handler
        // and restart processing the queue.
        match &mut self.state {
            BlockRuntimeState::Inline(worker) => {
                worker.process_queue().unwrap();
            }
            BlockRuntimeState::Threaded(active) => {
                for handle in &active.worker_handles {
                    handle.kick(false);
                }
            }
            BlockRuntimeState::Configuring(_, _) => {}
            BlockRuntimeState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    pub fn process_async_completion_event(&mut self) {
        if let BlockRuntimeState::Inline(worker) = &mut self.state {
            worker.process_async_completion_event();
        }
    }

    /// Update the backing file and the config space of the block device.
    pub fn update_disk_image(&mut self, disk_image_path: String) -> Result<(), VirtioBlockError> {
        let config_path = disk_image_path.clone();
        let read_only = self.config.is_read_only;
        let nsectors = match &mut self.state {
            BlockRuntimeState::Configuring(resources, _) => {
                let (last, rest) = resources
                    .split_last_mut()
                    .expect("block device must have at least one queue");
                for resource in rest {
                    resource.disk.update(disk_image_path.clone(), read_only)?;
                }
                last.disk.update(disk_image_path, read_only)?;
                last.disk.nsectors
            }
            BlockRuntimeState::Inline(worker) => {
                worker.update_disk_image(disk_image_path, read_only)?
            }
            BlockRuntimeState::Threaded(active) => {
                let (last, rest) = active
                    .worker_handles
                    .split_last()
                    .expect("threaded block device must have at least one worker");
                for handle in rest {
                    handle.update_disk_image(disk_image_path.clone(), read_only)?;
                }
                last.update_disk_image(disk_image_path, read_only)?
            }
            BlockRuntimeState::Placeholder => unreachable!("not a runtime state"),
        };
        self.config_space.capacity = nsectors.to_le();
        self.config.path_on_host = config_path;

        // Kick the driver to pick up the changes. (But only if the device is already activated).
        if self.is_activated() {
            self.interrupt_trigger()
                .trigger(VirtioInterruptType::Config)
                .unwrap();
        }

        self.metrics.update_count.inc();
        Ok(())
    }

    /// Updates the parameters for the rate limiter
    pub fn update_rate_limiter(&mut self, bytes: BucketUpdate, ops: BucketUpdate) {
        let mut rate_limiter = self
            .rate_limiter
            .lock()
            .expect("Poisoned block rate limiter lock");
        rate_limiter.update_buckets(bytes, ops);
        self.config.rate_limiter = RateLimiterConfig::from(&*rate_limiter).into_option();
    }

    /// Retrieve the file engine type, which is fixed for the device lifetime.
    pub fn file_engine_type(&self) -> FileEngineType {
        self.config.file_engine_type
    }

    /// Prepare device for being snapshotted.
    pub fn prepare_save(&mut self) {
        match &mut self.state {
            BlockRuntimeState::Inline(worker) => worker.prepare_save(FlushMode::DrainAndFlush),
            BlockRuntimeState::Threaded(active) => {
                let (last, rest) = active
                    .worker_handles
                    .split_last()
                    .expect("threaded block device must have at least one worker");
                for handle in rest {
                    handle.pause(FlushMode::Drain);
                }
                last.pause(FlushMode::DrainAndFlush);
            }
            BlockRuntimeState::Configuring(_, _) => {}
            BlockRuntimeState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    /// Spawn a parked worker thread for the next activation.
    pub(crate) fn spawn_worker(
        &mut self,
        seccomp_filter: Arc<BpfProgram>,
    ) -> Result<(), VirtioBlockError> {
        if let BlockRuntimeState::Configuring(resources, worker_handles) = &mut self.state {
            if !worker_handles.is_empty() {
                assert_eq!(worker_handles.len(), resources.len());
                return Ok(());
            }

            let mut spawned: Vec<WorkerHandle> = Vec::with_capacity(resources.len());
            for resource in resources {
                let queue_evt = match resource.queue_evt.try_clone() {
                    Ok(queue_evt) => queue_evt,
                    Err(err) => {
                        for handle in spawned {
                            handle.finish(FlushMode::Drain);
                        }
                        return Err(VirtioBlockError::EventFd(err));
                    }
                };

                let name = format!("fc_q{}_{}", resource.queue_idx, self.config.drive_id);
                let worker = match WorkerHandle::spawn(seccomp_filter.clone(), queue_evt, name) {
                    Ok(worker) => worker,
                    Err(err) => {
                        for handle in spawned {
                            handle.finish(FlushMode::Drain);
                        }
                        return Err(VirtioBlockError::ThreadSpawn(err));
                    }
                };
                spawned.push(worker);
            }
            *worker_handles = spawned;
        }
        Ok(())
    }
}

impl VirtioDevice for VirtioBlock {
    impl_device_type!(VirtioDeviceType::Block);

    fn id(&self) -> &str {
        &self.config.drive_id
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

    fn num_queues(&self) -> usize {
        usize::from(
            self.config
                .num_queues
                .map_or(DEFAULT_BLOCK_NUM_QUEUES, NonZeroU16::get),
        )
    }

    fn queue_config(&self, index: usize) -> Option<&QueueConfig> {
        match &self.state {
            BlockRuntimeState::Configuring(resources, _) => {
                resources.get(index).map(|r| &r.queue.config)
            }
            BlockRuntimeState::Inline(worker) => {
                (index == 0).then_some(&worker.resources.queue.config)
            }
            BlockRuntimeState::Threaded(active) => active.queue_configs.get(index),
            BlockRuntimeState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    fn queue_config_mut(&mut self, index: usize) -> Option<&mut QueueConfig> {
        match &mut self.state {
            BlockRuntimeState::Configuring(resources, _) => {
                resources.get_mut(index).map(|r| &mut r.queue.config)
            }
            BlockRuntimeState::Inline(worker) => {
                (index == 0).then_some(&mut worker.resources.queue.config)
            }
            BlockRuntimeState::Threaded(active) => active.queue_configs.get_mut(index),
            BlockRuntimeState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    fn queue_event(&self, index: usize) -> Option<&EventFd> {
        match &self.state {
            BlockRuntimeState::Configuring(resources, _) => {
                resources.get(index).map(|r| &r.queue_evt)
            }
            BlockRuntimeState::Inline(worker) => {
                (index == 0).then_some(&worker.resources.queue_evt)
            }
            BlockRuntimeState::Threaded(active) => active
                .worker_handles
                .get(index)
                .map(WorkerHandle::queue_event),
            BlockRuntimeState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        match &self.state {
            BlockRuntimeState::Inline(worker) => worker.active_state.interrupt.deref(),
            BlockRuntimeState::Threaded(active) => active.interrupt.deref(),
            BlockRuntimeState::Configuring(_, _) => panic!("Device is not initialized"),
            BlockRuntimeState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    fn config_as_bytes(&self) -> &[u8] {
        self.config_space.as_slice()
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        self.metrics.cfg_fails.inc();
        warn!(
            "virtio-block: guest driver attempted to write device config (offset={:#x}, len={:#x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        assert!(!self.is_activated());

        let event_idx = self.has_feature(u64::from(VIRTIO_RING_F_EVENT_IDX));

        let BlockRuntimeState::Configuring(resources, _) = &mut self.state else {
            unreachable!("inactive device is not configurable");
        };

        // The driver can use fewer queues than the device exposes.
        for resource in resources.iter_mut() {
            if resource.queue.config.ready {
                resource
                    .queue
                    .initialize(&mem)
                    .map_err(ActivateError::QueueMemoryError)?;
                if event_idx {
                    resource.queue.enable_notif_suppression();
                }
            }
        }

        if self.activate_evt.write(1).is_err() {
            self.metrics.activate_fails.inc();
            return Err(ActivateError::EventFd);
        }

        // rate limiter updates modify buckets in place, preserving the shared flag
        let is_blocked = self.lock_rate_limiter().clone_blocked_flag();
        let poll = self.poll_window();

        let BlockRuntimeState::Configuring(mut resources, worker_handles) =
            std::mem::replace(&mut self.state, BlockRuntimeState::Placeholder)
        else {
            unreachable!("state checked before activation");
        };

        if worker_handles.is_empty() {
            assert_eq!(resources.len(), 1, "inline block must have one queue");
            self.state = BlockRuntimeState::Inline(BlockWorker {
                resources: resources.pop().unwrap(),
                rate_limiter: self.rate_limiter.clone(),
                is_blocked,
                discard_supported: self.acked_features & (1u64 << VIRTIO_BLK_F_DISCARD) != 0,
                active_state: ActiveState { mem, interrupt },
                metrics: self.metrics.clone(),
                disk_error: self.disk_error.clone(),
                poll,
                polling: false,
            });
        } else {
            assert_eq!(
                worker_handles.len(),
                resources.len(),
                "one worker must be spawned for each block queue"
            );
            let queue_configs = resources.iter().map(|r| r.queue.config.clone()).collect();
            for (resources, handle) in resources.into_iter().zip(&worker_handles) {
                handle.start(BlockWorker {
                    resources,
                    rate_limiter: self.rate_limiter.clone(),
                    is_blocked: is_blocked.clone(),
                    discard_supported: self.acked_features & (1u64 << VIRTIO_BLK_F_DISCARD) != 0,
                    active_state: ActiveState {
                        mem: mem.clone(),
                        interrupt: interrupt.clone(),
                    },
                    metrics: self.metrics.clone(),
                    disk_error: self.disk_error.clone(),
                    poll,
                    polling: false,
                });
            }
            self.state = BlockRuntimeState::Threaded(ThreadedActive {
                worker_handles,
                interrupt,
                queue_configs,
            });
        }
        Ok(())
    }

    fn is_activated(&self) -> bool {
        matches!(
            &self.state,
            BlockRuntimeState::Inline(_) | BlockRuntimeState::Threaded(_)
        )
    }

    fn deactivate(&mut self) {
        // `_reset` moves data-path resources back into the configuring state.
    }

    fn _reset(&mut self) -> bool {
        let state = std::mem::replace(&mut self.state, BlockRuntimeState::Placeholder);
        let (mut resources, worker_handles) = match state {
            BlockRuntimeState::Threaded(active) => {
                assert_eq!(
                    active.worker_handles.len(),
                    active.queue_configs.len(),
                    "active block queues must have one worker each"
                );
                let resources = active
                    .worker_handles
                    .iter()
                    .map(WorkerHandle::reset)
                    .collect();
                (resources, active.worker_handles)
            }
            BlockRuntimeState::Inline(worker) => (vec![worker.resources], Vec::new()),
            BlockRuntimeState::Configuring(resources, worker_handles) => {
                (resources, worker_handles)
            }
            BlockRuntimeState::Placeholder => unreachable!("not a runtime state"),
        };

        assert_eq!(
            resources.len(),
            self.num_queues(),
            "reset must recover every block queue"
        );

        for resource in &mut resources {
            resource.reset();
        }
        self.disk_error.store(false, Ordering::SeqCst);

        self.state = BlockRuntimeState::Configuring(resources, worker_handles);
        true
    }

    fn reset_queues(&mut self) {
        if let BlockRuntimeState::Configuring(resources, _) = &mut self.state {
            for resource in resources {
                resource.queue.reset();
            }
        }
    }

    fn kick(&mut self) {
        // A resume: the kept requests run again from their start when each queue is taken,
        // and each queue is looked at and its notification armed again (a state saved while a
        // worker polled has the guest's notification off).
        self.disk_error.store(false, Ordering::SeqCst);
        match &mut self.state {
            BlockRuntimeState::Threaded(active) => {
                for handle in &active.worker_handles {
                    handle.kick(true);
                }
            }
            BlockRuntimeState::Inline(worker) => {
                worker.resources.stopped_on_error = false;
                self.notify_queue_events();
            }
            BlockRuntimeState::Configuring(_, _) => {}
            BlockRuntimeState::Placeholder => unreachable!("not a runtime state"),
        }
    }

    fn quiesce(&mut self) {
        self.drain();
    }

    fn prepare_checkpoint(&mut self) {
        self.drain();
    }

    fn resume_after_checkpoint(&mut self) {
        VirtioBlock::resume_after_checkpoint(self);
    }

    fn mark_queue_memory_dirty(&mut self, mem: &GuestMemoryMmap) -> Result<(), QueueError> {
        match &mut self.state {
            BlockRuntimeState::Configuring(resources, _) => {
                for resource in resources {
                    if resource.queue.config.ready {
                        resource.queue.initialize(mem)?;
                    }
                }
            }
            BlockRuntimeState::Inline(worker) => {
                if worker.resources.queue.config.ready {
                    worker.resources.queue.initialize(mem)?;
                }
            }
            BlockRuntimeState::Threaded(active) => {
                for handle in &active.worker_handles {
                    handle.mark_queue_memory_dirty()?;
                }
            }
            BlockRuntimeState::Placeholder => unreachable!("not a runtime state"),
        }
        Ok(())
    }
}

impl Drop for VirtioBlock {
    fn drop(&mut self) {
        let flush_mode = match self.config.cache_type {
            CacheType::Unsafe => FlushMode::Drain,
            CacheType::Writeback => FlushMode::DrainAndFlush,
        };

        match std::mem::replace(&mut self.state, BlockRuntimeState::Placeholder) {
            BlockRuntimeState::Inline(mut worker) => match flush_mode {
                FlushMode::Drain => worker.drain(true),
                FlushMode::DrainAndFlush => worker.drain_and_flush(true),
            },
            BlockRuntimeState::Threaded(mut active) => {
                let last = active
                    .worker_handles
                    .pop()
                    .expect("threaded block device must have at least one worker");
                for handle in active.worker_handles {
                    handle.finish(FlushMode::Drain);
                }
                last.finish(flush_mode);
            }
            BlockRuntimeState::Configuring(mut resources, worker_handles) => {
                let (last, rest) = resources
                    .split_last_mut()
                    .expect("block device must have at least one queue");
                for resource in rest {
                    if let Err(err) = resource.disk.file_engine.drain(true) {
                        error!("Failed to drain ops on drop: {:?}", err);
                    }
                }
                let result = match flush_mode {
                    FlushMode::Drain => last.disk.file_engine.drain(true),
                    FlushMode::DrainAndFlush => last.disk.file_engine.drain_and_flush(true),
                };
                if let Err(err) = result {
                    error!("Failed to drain ops and flush block data: {:?}", err);
                }
                for handle in worker_handles {
                    // a parked worker owns no runtime resources, it just joins the thread
                    handle.finish(FlushMode::Drain);
                }
            }
            BlockRuntimeState::Placeholder => {}
        };
    }
}

#[cfg(test)]
mod tests {
    use std::fs::metadata;
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::thread;
    use std::time::Duration;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::check_metric_after_block;
    use crate::devices::virtio::block::virtio::request::*;
    use crate::devices::virtio::block::virtio::test_utils::{
        RequestDescriptorChain, default_block, default_block_with_path, default_mq_block,
        default_threaded_block, read_blk_req_descriptors, set_queue, set_rate_limiter,
        simulate_async_completion_event, simulate_queue_and_async_completion_events,
        simulate_queue_event,
    };
    use crate::devices::virtio::block::virtio::{DEFAULT_BLOCK_NUM_QUEUES, IO_URING_NUM_ENTRIES};
    use crate::devices::virtio::queue::{
        FIRECRACKER_MAX_QUEUE_SIZE, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
    };
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::rate_limiter::{TokenBucket, TokenType};
    use crate::seccomp::BPF_MAX_LEN;
    use crate::snapshot::Persist;
    use crate::test_utils::single_region_mem;
    use crate::vstate::memory::{Address, Bytes, GuestAddress};

    #[test]
    fn test_calculate_blk_size_and_topology() {
        let attrs = BlockDeviceAttributes {
            logical_block_size: 0,
            physical_block_size: 0,
            min_io_size: 0,
            opt_io_size: 0,
        };
        assert!(calculate_blk_size_and_topology(attrs).is_none());

        let attrs = BlockDeviceAttributes {
            logical_block_size: 512,
            physical_block_size: 512 * (1 << 3),
            min_io_size: 64 * 512,
            opt_io_size: 128 * 512,
        };
        let (logical_size, topology) = calculate_blk_size_and_topology(attrs).unwrap();
        assert_eq!(logical_size, 512);
        assert_eq!(topology.physical_block_exp, 3);
        assert_eq!(topology.alignment_offset, 0);
        assert_eq!(topology.min_io_size, 64);
        assert_eq!(topology.opt_io_size, 128);
    }

    #[test]
    fn test_from_config() {
        let block_config = BlockDeviceConfig {
            drive_id: "".to_string(),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(true),
            discard: None,
            num_queues: None,
            poll_us: None,
            path_on_host: Some("path".to_string()),
            rate_limiter: None,
            file_engine_type: Default::default(),
            blk_size: None,
            topology: None,

            socket: None,
        };
        VirtioBlockConfig::try_from(&block_config).unwrap();

        let block_config = BlockDeviceConfig {
            drive_id: "".to_string(),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: None,
            discard: None,
            num_queues: None,
            poll_us: None,
            path_on_host: None,
            rate_limiter: None,
            file_engine_type: Default::default(),
            blk_size: None,
            topology: None,

            socket: Some("sock".to_string()),
        };
        VirtioBlockConfig::try_from(&block_config).unwrap_err();

        let block_config = BlockDeviceConfig {
            drive_id: "".to_string(),
            partuuid: None,
            is_root_device: false,
            cache_type: CacheType::Unsafe,

            is_read_only: Some(true),
            discard: None,
            num_queues: None,
            poll_us: None,
            path_on_host: Some("path".to_string()),
            rate_limiter: None,
            file_engine_type: Default::default(),
            blk_size: None,
            topology: None,

            socket: Some("sock".to_string()),
        };
        VirtioBlockConfig::try_from(&block_config).unwrap_err();
    }

    #[test]
    fn test_disk_backing_file_helper() {
        let num_sectors = 2;
        let f = TempFile::new().unwrap();
        let size = u64::from(SECTOR_SIZE) * num_sectors;
        f.as_file().set_len(size).unwrap();

        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let disk_properties =
                DiskProperties::new(f.as_path().to_str().unwrap(), true, engine, None).unwrap();

            assert_eq!(size, u64::from(SECTOR_SIZE) * num_sectors);
            assert_eq!(disk_properties.nsectors, num_sectors);
            // Testing `backing_file.virtio_block_disk_image_id()` implies
            // duplicating that logic in tests, so skipping it.

            let res = DiskProperties::new("invalid-disk-path", true, engine, None);
            assert!(
                matches!(res, Err(VirtioBlockError::BackingFile(_, _))),
                "{:?}",
                res
            );
        }
    }

    #[test]
    fn test_virtio_features() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);

            assert_eq!(block.device_type(), VirtioDeviceType::Block);

            let features: u64 = (1u64 << VIRTIO_F_VERSION_1)
                | (1u64 << VIRTIO_RING_F_EVENT_IDX)
                | (1u64 << VIRTIO_BLK_F_BLK_SIZE)
                | (1u64 << VIRTIO_BLK_F_TOPOLOGY)
                | (1u64 << VIRTIO_BLK_F_MQ);

            assert_eq!(
                block.avail_features_by_page(0),
                (features & 0xffffffff) as u32,
            );
            assert_eq!(block.avail_features_by_page(1), (features >> 32) as u32);

            for i in 2..10 {
                assert_eq!(block.avail_features_by_page(i), 0u32);
            }

            for i in 0..10 {
                block.ack_features_by_page(i, u32::MAX);
            }
            assert_eq!(block.acked_features, features);
        }
    }

    #[test]
    fn test_discard_feature() {
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();
        let path = f.as_path().to_str().unwrap().to_string();
        let config = VirtioBlockConfig {
            drive_id: "discard_feature".to_string(),
            path_on_host: path.clone(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            discard: true,
            num_queues: None,
            poll_us: None,
            cache_type: CacheType::Unsafe,
            rate_limiter: None,
            file_engine_type: FileEngineType::Sync,
            blk_size: Some(4096),
            topology: None,
        };

        let mut block = VirtioBlock::new(config).unwrap();
        assert_eq!(
            block.avail_features & (1u64 << VIRTIO_BLK_F_DISCARD),
            1u64 << VIRTIO_BLK_F_DISCARD
        );
        assert_eq!(block.config_space.discard_sector_alignment, 8);

        let replacement = TempFile::new().unwrap();
        replacement.as_file().set_len(0x1000).unwrap();
        block
            .update_disk_image(replacement.as_path().to_str().unwrap().to_string())
            .unwrap();
        assert_eq!(block.config_space.discard_sector_alignment, 8);

        let async_config = VirtioBlockConfig {
            drive_id: "discard_async_unsupported".to_string(),
            path_on_host: path,
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            discard: true,
            num_queues: None,
            poll_us: None,
            cache_type: CacheType::Unsafe,
            rate_limiter: None,
            file_engine_type: FileEngineType::Async,
            blk_size: None,
            topology: None,
        };
        // Discard is supported with the Async engine too.
        let block = VirtioBlock::new(async_config).unwrap();
        assert_eq!(
            block.avail_features & (1u64 << VIRTIO_BLK_F_DISCARD),
            1u64 << VIRTIO_BLK_F_DISCARD
        );

        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();
        let read_only_config = VirtioBlockConfig {
            drive_id: "discard_read_only_unsupported".to_string(),
            path_on_host: f.as_path().to_str().unwrap().to_string(),
            is_root_device: false,
            partuuid: None,
            is_read_only: true,
            discard: true,
            num_queues: None,
            poll_us: None,
            cache_type: CacheType::Unsafe,
            rate_limiter: None,
            file_engine_type: FileEngineType::Sync,
            blk_size: None,
            topology: None,
        };
        assert!(matches!(
            VirtioBlock::new(read_only_config),
            Err(VirtioBlockError::DiscardReadOnlyUnsupported)
        ));
    }

    #[test]
    fn test_discard_requires_negotiated_feature() {
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();
        let config = VirtioBlockConfig {
            drive_id: "discard_negotiation".to_string(),
            path_on_host: f.as_path().to_str().unwrap().to_string(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            discard: true,
            num_queues: None,
            poll_us: None,
            cache_type: CacheType::Unsafe,
            rate_limiter: None,
            file_engine_type: FileEngineType::Sync,
            blk_size: None,
            topology: None,
        };

        let mut block = VirtioBlock::new(config).unwrap();
        let mem = default_mem();
        let interrupt = default_interrupt();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone(), interrupt).unwrap();

        let chain = RequestDescriptorChain::new(&vq);
        chain.set_header(RequestHeader::new(VIRTIO_BLK_T_DISCARD, 0));
        chain.data_desc.flags.set(VIRTQ_DESC_F_NEXT);
        chain.data_desc.len.set(16);

        let mut discard_range = [0_u8; 16];
        discard_range[8..12].copy_from_slice(&1_u32.to_le_bytes());
        mem.write_slice(&discard_range, GuestAddress(chain.data_desc.addr.get()))
            .unwrap();

        simulate_queue_event(&mut block, Some(true));

        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(vq.used.ring[0].get().len, 1);
        assert_eq!(
            mem.read_obj::<u32>(GuestAddress(chain.status_desc.addr.get()))
                .unwrap(),
            VIRTIO_BLK_S_UNSUPP
        );
    }

    #[test]
    fn test_config_as_bytes() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let block = default_block(engine);

            let config = block.config_as_bytes();
            // The block's backing file size is 0x1000, so there are 8 (4096/512) sectors.
            let expected_config_space = ConfigSpace {
                capacity: 8,
                ..Default::default()
            };
            assert_eq!(config, expected_config_space.as_slice());
        }
    }

    #[test]
    fn test_virtio_device_config_space_is_read_only() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);

            // Snapshot the config space before any write attempt.
            let initial_config = block.config_as_bytes().to_vec();

            // A guest write must be rejected: the config space is left unchanged
            // and the attempt is counted under cfg_fails.
            let cfg_fails_before = block.metrics.cfg_fails.count();
            block.write_config(
                0,
                ConfigSpace {
                    capacity: 0x1122334455667788,
                    ..Default::default()
                }
                .as_slice(),
            );
            assert_eq!(block.config_as_bytes(), initial_config);
            assert_eq!(block.metrics.cfg_fails.count(), cfg_fails_before + 1);
        }
    }

    #[test]
    fn test_invalid_request() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

            // Request is invalid because the first descriptor is write-only.
            vq.dtable[0]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                .unwrap();

            simulate_queue_event(&mut block, Some(true));

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 0);
        }
    }

    #[test]
    fn test_addr_out_of_bounds() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            // Default mem size is 0x10000
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);
            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

            // Read at out of bounds address.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                // Mark the next available descriptor.
                vq.avail.idx.set(1);

                vq.dtable[1].set(0x20000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);

                let used = vq.used.ring[0].get();
                let status_addr = GuestAddress(vq.dtable[2].addr.get());
                assert_eq!(used.len, 1);
                assert_eq!(
                    u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
                    VIRTIO_BLK_S_IOERR
                );
            }

            // Write at out of bounds address.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                // Mark the next available descriptor.
                vq.avail.idx.set(1);

                vq.dtable[1].set(0x20000, 0x1000, VIRTQ_DESC_F_NEXT, 2);
                mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                    .unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);

                let used = vq.used.ring[0].get();
                let status_addr = GuestAddress(vq.dtable[2].addr.get());
                assert_eq!(used.len, 1);
                assert_eq!(
                    u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
                    VIRTIO_BLK_S_IOERR
                );
            }
        }
    }

    #[test]
    fn test_request_parse_failures() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

            {
                // First descriptor no longer writable.
                vq.dtable[0].flags.set(VIRTQ_DESC_F_NEXT);
                vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);

                // Generate a seek execute error caused by a very large sector number.
                let request_header = RequestHeader::new(VIRTIO_BLK_T_OUT, 0x000f_ffff_ffff);
                mem.write_obj::<RequestHeader>(request_header, request_type_addr)
                    .unwrap();

                simulate_queue_event(&mut block, Some(true));

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 0);
            }

            {
                // Reset the queue to reuse descriptors and memory.
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                vq.dtable[1]
                    .flags
                    .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
                // Set sector to a valid number large enough that the full 0x1000 read will fail.
                let request_header = RequestHeader::new(VIRTIO_BLK_T_IN, 10);
                mem.write_obj::<RequestHeader>(request_header, request_type_addr)
                    .unwrap();

                simulate_queue_event(&mut block, Some(true));

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 0);
            }
        }
    }

    #[test]
    fn test_unsupported_request_type() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            // Currently only VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT,
            // VIRTIO_BLK_T_FLUSH and VIRTIO_BLK_T_GET_ID  are supported.
            // Generate an unsupported request.
            let request_header = RequestHeader::new(42, 0);
            mem.write_obj::<RequestHeader>(request_header, request_type_addr)
                .unwrap();

            simulate_queue_event(&mut block, Some(true));

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 1);
            assert_eq!(
                mem.read_obj::<u32>(status_addr).unwrap(),
                VIRTIO_BLK_S_UNSUPP
            );
        }
    }

    #[test]
    fn test_end_of_region() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);
            vq.dtable[1].set(0xf000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            vq.used.idx.set(0);

            mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                .unwrap();
            vq.dtable[1]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);

            check_metric_after_block!(
                &block.metrics.read_count,
                1,
                simulate_queue_and_async_completion_events(&mut block, true)
            );

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            // Added status byte length.
            assert_eq!(vq.used.ring[0].get().len, vq.dtable[1].len.get() + 1);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
        }
    }

    /// The request of the queue was not answered: it is kept and the guest stops. The kept
    /// request is then dropped, for the next case of a test.
    fn assert_kept_short_read(block: &mut VirtioBlock, vq: &VirtQueue) {
        assert_eq!(vq.used.idx.get(), 0);
        assert_eq!(block.resources()[0].kept.len(), 1);
        assert!(block.resources()[0].stopped_on_error);
        assert!(block.take_disk_error());
        block.resources_mut()[0].kept.clear();
        block.resources_mut()[0].stopped_on_error = false;
    }

    #[test]
    fn test_read_write() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            let empty_data = vec![0; 512];
            let rand_data = vmm_sys_util::rand::rand_alphanumerics(1024)
                .as_bytes()
                .to_vec();

            // Write with invalid data len (not a multiple of 512).
            {
                mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                    .unwrap();
                // Make data read only, 512 bytes in len, and set the actual value to be written.
                vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
                vq.dtable[1].len.set(511);
                mem.write_slice(&rand_data[..511], data_addr).unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 0);

                // Check that the data wasn't written to the file
                let mut buf = [0u8; 512];
                block
                    .disk()
                    .file_engine
                    .file()
                    .seek(SeekFrom::Start(0))
                    .unwrap();
                block
                    .disk()
                    .file_engine
                    .file()
                    .read_exact(&mut buf)
                    .unwrap();
                assert_eq!(buf, empty_data.as_slice());
            }

            // Write from valid address, with an overflowing length.
            {
                let mut block = default_block(engine);

                // Default mem size is 0x10000
                let mem = default_mem();
                let interrupt = default_interrupt();
                let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
                set_queue(&mut block, 0, vq.create_queue());
                block.activate(mem.clone(), interrupt).unwrap();
                read_blk_req_descriptors(&vq);
                let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

                vq.dtable[1].set(0xff00, 0x1000, VIRTQ_DESC_F_NEXT, 2);
                mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                    .unwrap();

                // Mark the next available descriptor.
                vq.avail.idx.set(1);
                vq.used.idx.set(0);

                check_metric_after_block!(
                    &block.metrics.invalid_reqs_count,
                    1,
                    simulate_queue_and_async_completion_events(&mut block, true)
                );

                let used_idx = vq.used.idx.get();
                assert_eq!(used_idx, 1);

                let status_addr = GuestAddress(vq.dtable[2].addr.get());
                assert_eq!(
                    u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
                    VIRTIO_BLK_S_IOERR
                );
            }

            // Write.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                    .unwrap();
                // Make data read only, 512 bytes in len, and set the actual value to be written.
                vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
                vq.dtable[1].len.set(512);
                mem.write_slice(&rand_data[..512], data_addr).unwrap();

                check_metric_after_block!(
                    &block.metrics.write_count,
                    1,
                    simulate_queue_and_async_completion_events(&mut block, true)
                );

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 1);
                assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
            }

            // Read with invalid data len (not a multiple of 512).
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();
                vq.dtable[1]
                    .flags
                    .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
                vq.dtable[1].len.set(511);
                mem.write_slice(empty_data.as_slice(), data_addr).unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                // The descriptor should have been discarded.
                assert_eq!(vq.used.ring[0].get().len, 0);

                // Check that no data was read.
                let mut buf = [0u8; 512];
                mem.read_slice(&mut buf, data_addr).unwrap();
                assert_eq!(buf, empty_data.as_slice());
            }

            // Read.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();
                vq.dtable[1]
                    .flags
                    .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
                vq.dtable[1].len.set(512);
                mem.write_slice(empty_data.as_slice(), data_addr).unwrap();

                check_metric_after_block!(
                    &block.metrics.read_count,
                    1,
                    simulate_queue_and_async_completion_events(&mut block, true)
                );

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                // Added status byte length.
                assert_eq!(vq.used.ring[0].get().len, vq.dtable[1].len.get() + 1);
                assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);

                // Check that the data is the same that we wrote before
                let mut buf = [0u8; 512];
                mem.read_slice(&mut buf, data_addr).unwrap();
                assert_eq!(buf, &rand_data[..512]);
            }

            // Read with error.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();
                vq.dtable[1]
                    .flags
                    .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
                mem.write_slice(empty_data.as_slice(), data_addr).unwrap();

                let size = block
                    .disk()
                    .file_engine
                    .file()
                    .seek(SeekFrom::End(0))
                    .unwrap();
                block.disk().file_engine.file().set_len(size / 2).unwrap();
                mem.write_obj(10, GuestAddress(request_type_addr.0 + 8))
                    .unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                // The descriptor should have been discarded.
                assert_eq!(vq.used.ring[0].get().len, 0);

                // Check that no data was read.
                let mut buf = [0u8; 512];
                mem.read_slice(&mut buf, data_addr).unwrap();
                assert_eq!(buf, empty_data.as_slice());
            }

            // Partial buffer error on read.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();
                vq.dtable[1]
                    .flags
                    .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);

                let size = block
                    .disk()
                    .file_engine
                    .file()
                    .seek(SeekFrom::End(0))
                    .unwrap();
                block.disk().file_engine.file().set_len(size / 2).unwrap();
                // Update sector number: stored at `request_type_addr.0 + 8`
                mem.write_obj(5, GuestAddress(request_type_addr.0 + 8))
                    .unwrap();

                // This will attempt to read past end of file.
                if engine == FileEngineType::Async {
                    // A read of 0 bytes of the `Async` engine is a disk error: kept, and the
                    // guest stops.
                    simulate_queue_event(&mut block, None);
                    complete_async(&mut block);
                    assert_kept_short_read(&mut block, &vq);
                } else {
                    simulate_queue_and_async_completion_events(&mut block, true);

                    assert_eq!(vq.used.idx.get(), 1);
                    assert_eq!(vq.used.ring[0].get().id, 0);

                    // No data since can't read past end of file, only status byte length.
                    assert_eq!(vq.used.ring[0].get().len, 1);
                    assert_eq!(
                        mem.read_obj::<u32>(status_addr).unwrap(),
                        VIRTIO_BLK_S_IOERR
                    );
                }

                // Check that no data was read since we can't read past the end of the file.
                let mut buf = [0u8; 512];
                mem.read_slice(&mut buf, data_addr).unwrap();
                assert_eq!(buf, empty_data.as_slice());
            }

            {
                // Note: this test case only works because when we truncated the file above (with
                // set_len), we did not update the sector count stored in the block device
                // itself (is still 8, even though the file length is 1024 now, e.g. has 2 sectors).
                // Normally, requests that reach past the final sector are rejected by
                // Request::parse.
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();
                vq.dtable[1]
                    .flags
                    .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
                vq.dtable[1].len.set(1024);

                mem.write_obj(1, GuestAddress(request_type_addr.0 + 8))
                    .unwrap();

                block
                    .disk()
                    .file_engine
                    .file()
                    .seek(SeekFrom::Start(512))
                    .unwrap();
                block
                    .disk()
                    .file_engine
                    .file()
                    .write_all(&rand_data[512..])
                    .unwrap();

                if engine == FileEngineType::Async {
                    // A short read of the `Async` engine is a disk error: kept, and the guest
                    // stops.
                    simulate_queue_event(&mut block, None);
                    complete_async(&mut block);
                    assert_kept_short_read(&mut block, &vq);
                } else {
                    simulate_queue_and_async_completion_events(&mut block, true);

                    assert_eq!(vq.used.idx.get(), 1);
                    assert_eq!(vq.used.ring[0].get().id, 0);

                    assert_eq!(
                        mem.read_obj::<u32>(status_addr).unwrap(),
                        VIRTIO_BLK_S_IOERR
                    );

                    // Check that we correctly read the second file sector.
                    let mut buf = [0u8; 512];
                    mem.read_slice(&mut buf, data_addr).unwrap();
                    assert_eq!(buf, rand_data[512..]);
                }
            }

            // Read at valid address, with an overflowing length.
            {
                let mut block = default_block(engine);

                // Default mem size is 0x10000
                let mem = default_mem();
                let interrupt = default_interrupt();
                let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
                set_queue(&mut block, 0, vq.create_queue());
                block.activate(mem.clone(), interrupt).unwrap();
                read_blk_req_descriptors(&vq);
                vq.dtable[1].set(0xff00, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);

                let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

                // Mark the next available descriptor.
                vq.avail.idx.set(1);
                vq.used.idx.set(0);

                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();
                vq.dtable[1]
                    .flags
                    .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);

                check_metric_after_block!(
                    &block.metrics.invalid_reqs_count,
                    1,
                    simulate_queue_and_async_completion_events(&mut block, true)
                );

                let used_idx = vq.used.idx.get();
                assert_eq!(used_idx, 1);

                let status_addr = GuestAddress(vq.dtable[2].addr.get());
                assert_eq!(
                    u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
                    VIRTIO_BLK_S_IOERR
                );
            }
        }
    }

    #[test]
    fn test_flush() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            // Flush completes successfully without a data descriptor.
            {
                vq.dtable[0].next.set(2);

                mem.write_obj::<u32>(VIRTIO_BLK_T_FLUSH, request_type_addr)
                    .unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);
                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 1);
                assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
            }

            // Flush completes successfully even with a data descriptor.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());
                vq.dtable[0].next.set(1);

                mem.write_obj::<u32>(VIRTIO_BLK_T_FLUSH, request_type_addr)
                    .unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);
                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                // status byte length.
                assert_eq!(vq.used.ring[0].get().len, 1);
                assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
            }
        }
    }

    #[test]
    fn test_get_device_id() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());
            let blk_metadata = block.disk().file_engine.file().metadata();

            // Test that the driver receives the correct device id.
            {
                vq.dtable[1].len.set(VIRTIO_BLK_ID_BYTES);

                mem.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, request_type_addr)
                    .unwrap();

                simulate_queue_event(&mut block, Some(true));
                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 21);
                assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);

                let blk_meta = blk_metadata.unwrap();
                let expected_device_id = format!(
                    "{}{}{}",
                    blk_meta.st_dev(),
                    blk_meta.st_rdev(),
                    blk_meta.st_ino()
                );

                let mut buf = [0; VIRTIO_BLK_ID_BYTES as usize];
                mem.read_slice(&mut buf, data_addr).unwrap();
                let chars_to_trim: &[char] = &['\u{0}'];
                let received_device_id = String::from_utf8(buf.to_ascii_lowercase())
                    .unwrap()
                    .trim_matches(chars_to_trim)
                    .to_string();
                assert_eq!(received_device_id, expected_device_id);
            }

            // Test that a device ID request will be discarded, if it fails to provide enough buffer
            // space.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());
                vq.dtable[1].len.set(VIRTIO_BLK_ID_BYTES - 1);

                mem.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, request_type_addr)
                    .unwrap();

                simulate_queue_event(&mut block, Some(true));
                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 0);
            }
        }
    }

    fn add_flush_requests_batch(block: &mut VirtioBlock, vq: &VirtQueue, count: u16) {
        let mem = vq.memory();
        vq.avail.idx.set(0);
        vq.used.idx.set(0);
        set_queue(block, 0, vq.create_queue());

        let hdr_addr = vq
            .end()
            .checked_align_up(std::mem::align_of::<RequestHeader>() as u64)
            .unwrap();
        // Write request header. All requests will use the same header.
        mem.write_obj(RequestHeader::new(VIRTIO_BLK_T_FLUSH, 0), hdr_addr)
            .unwrap();

        let mut status_addr = hdr_addr
            .checked_add(std::mem::size_of::<RequestHeader>() as u64)
            .unwrap()
            .checked_align_up(4)
            .unwrap();

        for i in 0..count {
            let idx = i * 2;

            let hdr_desc = &vq.dtable[idx as usize];
            hdr_desc.addr.set(hdr_addr.0);
            hdr_desc.flags.set(VIRTQ_DESC_F_NEXT);
            hdr_desc.next.set(idx + 1);

            let status_desc = &vq.dtable[idx as usize + 1];
            status_desc.addr.set(status_addr.0);
            status_desc.flags.set(VIRTQ_DESC_F_WRITE);
            status_desc.len.set(4);
            status_addr = status_addr.checked_add(4).unwrap();

            vq.avail.ring[i as usize].set(idx);
            vq.avail.idx.set(i + 1);
        }
    }

    fn check_flush_requests_batch(count: u16, vq: &VirtQueue) {
        let used_idx = vq.used.idx.get();
        assert_eq!(used_idx, count);

        for i in 0..count {
            let used = vq.used.ring[i as usize].get();
            let status_addr = vq.dtable[used.id as usize + 1].addr.get();
            assert_eq!(used.len, 1);
            assert_eq!(
                u32::from(
                    vq.memory()
                        .read_obj::<u8>(GuestAddress(status_addr))
                        .unwrap(),
                ),
                VIRTIO_BLK_S_OK
            );
        }
    }

    #[test]
    fn test_io_engine_throttling() {
        // FullSQueue BlockError
        {
            let mut block = default_block(FileEngineType::Async);

            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, IO_URING_NUM_ENTRIES * 4);
            block.resources_mut()[0].queue = vq.create_queue();
            block.activate(mem.clone(), interrupt).unwrap();

            // Run scenario that doesn't trigger FullSq BlockError: Add sq_size flush requests.
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES);
            simulate_queue_event(&mut block, Some(false));
            assert!(!block.resources()[0].is_io_engine_throttled);
            simulate_async_completion_event(&mut block, true);
            check_flush_requests_batch(IO_URING_NUM_ENTRIES, &vq);

            // Run scenario that triggers FullSqError : Add sq_size + 10 flush requests.
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES + 10);
            simulate_queue_event(&mut block, Some(false));
            assert!(block.resources()[0].is_io_engine_throttled);
            // When the async_completion_event is triggered:
            // 1. sq_size requests should be processed processed.
            // 2. is_io_engine_throttled should be set back to false.
            // 3. process_queue() should be called again.
            simulate_async_completion_event(&mut block, true);
            assert!(!block.resources()[0].is_io_engine_throttled);
            check_flush_requests_batch(IO_URING_NUM_ENTRIES, &vq);
            // check that process_queue() was called again resulting in the processing of the
            // remaining 10 ops.
            simulate_async_completion_event(&mut block, true);
            assert!(!block.resources()[0].is_io_engine_throttled);
            check_flush_requests_batch(IO_URING_NUM_ENTRIES + 10, &vq);
        }

        // FullCQueue BlockError
        {
            let mut block = default_block(FileEngineType::Async);

            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, IO_URING_NUM_ENTRIES * 4);
            block.resources_mut()[0].queue = vq.create_queue();
            block.activate(mem.clone(), interrupt).unwrap();

            // Run scenario that triggers FullCqError. Push 2 * IO_URING_NUM_ENTRIES and wait for
            // completion. Then try to push another entry.
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES);
            simulate_queue_event(&mut block, Some(false));
            assert!(!block.resources()[0].is_io_engine_throttled);
            thread::sleep(Duration::from_millis(150));
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES);
            simulate_queue_event(&mut block, Some(false));
            assert!(!block.resources()[0].is_io_engine_throttled);
            thread::sleep(Duration::from_millis(150));

            add_flush_requests_batch(&mut block, &vq, 1);
            simulate_queue_event(&mut block, Some(false));
            assert!(block.resources()[0].is_io_engine_throttled);
            simulate_async_completion_event(&mut block, true);
            assert!(!block.resources()[0].is_io_engine_throttled);
            check_flush_requests_batch(IO_URING_NUM_ENTRIES * 2, &vq);
        }
    }

    #[test]
    fn test_prepare_save() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);

            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            block.resources_mut()[0].queue = vq.create_queue();
            block.activate(mem.clone(), interrupt).unwrap();

            // Add a batch of flush requests.
            add_flush_requests_batch(&mut block, &vq, 5);
            simulate_queue_event(&mut block, None);
            block.prepare_save();

            // Check that all the pending flush requests were processed during `prepare_save()`.
            check_flush_requests_batch(5, &vq);
        }
    }

    #[test]
    fn test_bandwidth_rate_limiter() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            // Create bandwidth rate limiter that allows only 5120 bytes/s with bucket size of 8
            // bytes.
            let mut rl = RateLimiter::new(512, 0, 100, 0, 0, 0);
            // Use up the budget.
            assert!(rl.consume(512, TokenType::Bytes));

            set_rate_limiter(&mut block, rl);
            block.activate(mem.clone(), interrupt).unwrap();

            mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                .unwrap();
            // Make data read only, 512 bytes in len, and set the actual value to be written
            vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
            vq.dtable[1].len.set(512);
            mem.write_obj::<u64>(123_456_789, data_addr).unwrap();

            // Following write procedure should fail because of bandwidth rate limiting.
            {
                // Trigger the attempt to write.
                check_metric_after_block!(
                    &block.metrics.rate_limiter_throttled_events,
                    1,
                    simulate_queue_event(&mut block, Some(false))
                );

                // Assert that limiter is blocked.
                assert!(block.lock_rate_limiter().is_blocked());
                // Make sure the data is still queued for processing.
                assert_eq!(vq.used.idx.get(), 0);
            }

            // Wait for 100ms to give the rate-limiter timer a chance to replenish.
            // Wait for an extra 50ms to make sure the timerfd event makes its way from the kernel.
            thread::sleep(Duration::from_millis(150));

            // Following write procedure should succeed because bandwidth should now be available.
            {
                check_metric_after_block!(
                    &block.metrics.rate_limiter_throttled_events,
                    0,
                    block.process_rate_limiter_event()
                );
                // Validate the rate_limiter is no longer blocked.
                assert!(!block.lock_rate_limiter().is_blocked());
                // Complete async IO ops if needed
                simulate_async_completion_event(&mut block, true);

                // Make sure the data queue advanced.
                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 1);
                assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
            }
        }
    }

    #[test]
    fn test_ops_rate_limiter() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            // Create ops rate limiter that allows only 10 ops/s with bucket size of 1 ops.
            let mut rl = RateLimiter::new(0, 0, 0, 1, 0, 100);
            // Use up the budget.
            assert!(rl.consume(1, TokenType::Ops));

            set_rate_limiter(&mut block, rl);
            block.activate(mem.clone(), interrupt).unwrap();

            mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                .unwrap();
            // Make data read only, 512 bytes in len, and set the actual value to be written.
            vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
            vq.dtable[1].len.set(512);
            mem.write_obj::<u64>(123_456_789, data_addr).unwrap();

            // Following write procedure should fail because of ops rate limiting.
            {
                // Trigger the attempt to write.
                check_metric_after_block!(
                    &block.metrics.rate_limiter_throttled_events,
                    1,
                    simulate_queue_event(&mut block, Some(false))
                );

                // Assert that limiter is blocked.
                assert!(block.lock_rate_limiter().is_blocked());
                // Make sure the data is still queued for processing.
                assert_eq!(vq.used.idx.get(), 0);
            }

            // Do a second write that still fails but this time on the fast path.
            {
                // Trigger the attempt to write.
                check_metric_after_block!(
                    &block.metrics.rate_limiter_throttled_events,
                    1,
                    simulate_queue_event(&mut block, Some(false))
                );

                // Assert that limiter is blocked.
                assert!(block.lock_rate_limiter().is_blocked());
                // Make sure the data is still queued for processing.
                assert_eq!(vq.used.idx.get(), 0);
            }

            // Wait for 100ms to give the rate-limiter timer a chance to replenish.
            // Wait for an extra 50ms to make sure the timerfd event makes its way from the kernel.
            thread::sleep(Duration::from_millis(150));

            // Following write procedure should succeed because ops budget should now be available.
            {
                check_metric_after_block!(
                    &block.metrics.rate_limiter_throttled_events,
                    0,
                    block.process_rate_limiter_event()
                );
                // Validate the rate_limiter is no longer blocked.
                assert!(!block.lock_rate_limiter().is_blocked());
                // Complete async IO ops if needed
                simulate_async_completion_event(&mut block, true);

                // Make sure the data queue advanced.
                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 1);
                assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
            }
        }
    }

    #[test]
    fn test_update_disk_image() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem, interrupt).unwrap();
            let f = TempFile::new().unwrap();
            let path = f.as_path();
            let mdata = metadata(path).unwrap();
            let mut id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
            let str_id = format!("{}{}{}", mdata.st_dev(), mdata.st_rdev(), mdata.st_ino());
            let part_id = str_id.as_bytes();
            id[..cmp::min(part_id.len(), VIRTIO_BLK_ID_BYTES as usize)].clone_from_slice(
                &part_id[..cmp::min(part_id.len(), VIRTIO_BLK_ID_BYTES as usize)],
            );

            block
                .update_disk_image(String::from(path.to_str().unwrap()))
                .unwrap();

            assert_eq!(block.config().path_on_host, path.to_str().unwrap());
            assert_eq!(
                block.disk().file_engine.file().metadata().unwrap().st_ino(),
                mdata.st_ino()
            );
            assert_eq!(block.disk().image_id, id.as_slice());
        }
    }

    #[test]
    fn test_threaded_activation() {
        let mut block = default_threaded_block(FileEngineType::Sync);
        let mem = default_mem();
        let interrupt = default_interrupt();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());

        block.activate(mem.clone(), interrupt).unwrap();

        assert!(block.is_threaded_active());
        assert_eq!(block.num_queues(), usize::from(DEFAULT_BLOCK_NUM_QUEUES));
        assert_eq!(block.queue_config(0).unwrap().size, vq.size());
        assert!(block.queue_config_mut(0).is_some());
        assert!(block.queue_event(0).is_some());
    }

    #[test]
    fn test_threaded_update_disk_error() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_threaded_block(engine);
            let original_config = block.config();
            let original_capacity = block.config_space.capacity;

            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt.clone()).unwrap();

            let mut missing_disk = TempFile::new().unwrap();
            let missing_path = missing_disk.as_path().to_str().unwrap().to_string();
            missing_disk.remove().unwrap();

            assert!(block.update_disk_image(missing_path).is_err());
            assert_eq!(block.config(), original_config);
            assert_eq!(block.config_space.capacity, original_capacity);
            assert!(!interrupt.has_pending_interrupt(VirtioInterruptType::Config));
        }
    }

    #[test]
    fn test_threaded_rate_limiter() {
        let mut block = default_threaded_block(FileEngineType::Sync);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone(), default_interrupt()).unwrap();

        let bandwidth = TokenBucket::new(1000, 1001, 1002).unwrap();
        let ops = TokenBucket::new(1003, 1004, 1005).unwrap();
        block.update_rate_limiter(BucketUpdate::Update(bandwidth), BucketUpdate::Update(ops));

        // Reset the device before reactivation.
        assert!(block.reset());
        assert_eq!(
            block.config().rate_limiter,
            RateLimiterConfig::from(&*block.lock_rate_limiter()).into_option()
        );

        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem, default_interrupt()).unwrap();
        block.update_rate_limiter(BucketUpdate::Disabled, BucketUpdate::Disabled);

        assert!(block.reset());
        assert_eq!(block.config().rate_limiter, None);
        assert!(block.lock_rate_limiter().bandwidth().is_none());
        assert!(block.lock_rate_limiter().ops().is_none());
    }

    #[test]
    fn test_queue_dirty_readiness() {
        let mut block = default_mq_block(FileEngineType::Sync, 2);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        assert!(block.queue_config(0).unwrap().ready);
        assert!(!block.queue_config(1).unwrap().ready);
        block.activate(mem.clone(), default_interrupt()).unwrap();

        assert!(matches!(
            block.mark_queue_memory_dirty(&mem),
            Err(QueueError::NotReady)
        ));

        block.prepare_save();

        block.mark_queue_memory_dirty(&mem).unwrap();
    }

    #[test]
    fn test_threaded_resume() {
        let mut block = default_threaded_block(FileEngineType::Sync);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone(), default_interrupt()).unwrap();

        block.prepare_save();
        read_blk_req_descriptors(&vq);
        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());
        vq.dtable[1].len.set(VIRTIO_BLK_ID_BYTES);
        mem.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, request_type_addr)
            .unwrap();
        block.mark_queue_memory_dirty(&mem).unwrap();

        block.kick();
        // A second pause waits until the resumed worker has processed its queue.
        block.prepare_save();

        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(vq.used.ring[0].get().len, VIRTIO_BLK_ID_BYTES + 1);
        assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
    }

    #[test]
    fn test_threaded_reset_paused() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_threaded_block(engine);
            let mem = default_mem();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.set_acked_features(1);
            block.activate(mem, default_interrupt()).unwrap();
            block.prepare_save();

            assert!(block.reset());
            assert!(!block.is_activated());
            assert_eq!(block.acked_features(), 0);
            assert!(!block.queue_config(0).unwrap().ready);
        }
    }

    // The worker thread dies asynchronously, so the panic can come from `start` or from
    // `reset`. Both name the block worker.
    #[test]
    #[should_panic(expected = "block worker")]
    fn test_threaded_worker_failure() {
        let mut block = default_block(FileEngineType::Sync);
        block.config.num_queues = NonZeroU16::new(1);
        block
            .spawn_worker(Arc::new(vec![0; BPF_MAX_LEN + 1]))
            .unwrap();

        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.set_acked_features(1);
        block.activate(mem, default_interrupt()).unwrap();

        block.reset();
    }

    #[test]
    fn test_num_queues() {
        let block = default_block(FileEngineType::Sync);
        assert_eq!(block.num_queues(), 1);
        assert_eq!(u16::from_le(block.config_space.num_queues), 1);
        assert_ne!(block.avail_features() & (1u64 << VIRTIO_BLK_F_MQ), 0);

        let block = default_mq_block(FileEngineType::Sync, 3);
        assert_eq!(block.num_queues(), 3);
        assert_eq!(u16::from_le(block.config_space.num_queues), 3);
        assert_ne!(block.avail_features() & (1u64 << VIRTIO_BLK_F_MQ), 0);
        for idx in 0u16..3 {
            assert_eq!(block.resources()[usize::from(idx)].queue_idx, idx);
            assert!(block.queue_config(usize::from(idx)).is_some());
            assert!(block.queue_event(usize::from(idx)).is_some());
        }
        assert!(block.queue_config(3).is_none());
        assert!(block.queue_event(3).is_none());
    }

    #[test]
    fn test_mq_activate_reset() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_mq_block(engine, 2);
            let mem = default_mem();
            let vq0 = VirtQueue::new(GuestAddress(0), &mem, 16);
            let vq1 = VirtQueue::new(GuestAddress(0x4000), &mem, 16);
            set_queue(&mut block, 0, vq0.create_queue());
            set_queue(&mut block, 1, vq1.create_queue());
            block.activate(mem.clone(), default_interrupt()).unwrap();
            assert!(block.is_threaded_active());
            assert!(block.queue_config(1).unwrap().ready);

            assert!(block.reset());
            assert!(!block.queue_config(1).unwrap().ready);
            let BlockRuntimeState::Configuring(resources, worker_handles) = &block.state else {
                panic!("reset must leave the block device configuring");
            };
            assert_eq!(resources.len(), 2);
            assert_eq!(worker_handles.len(), 2);

            set_queue(&mut block, 0, vq0.create_queue());
            set_queue(&mut block, 1, vq1.create_queue());
            block.activate(mem, default_interrupt()).unwrap();
            assert!(block.is_threaded_active());
        }
    }

    #[test]
    fn test_mq_update_disk() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_mq_block(engine, 2);

            // Before activation, every queue's disk is updated on the VMM thread.
            let disk = TempFile::new().unwrap();
            disk.as_file().set_len(0x2000).unwrap();
            let disk_path = disk.as_path().to_str().unwrap().to_string();
            block.update_disk_image(disk_path.clone()).unwrap();
            assert_eq!(u64::from_le(block.config_space.capacity), 16);
            for resources in block.resources() {
                assert_eq!(resources.disk.nsectors, 16);
            }

            // Once active, every worker is updated.
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vqs = [
                VirtQueue::new(GuestAddress(0), &mem, 16),
                VirtQueue::new(GuestAddress(0x4000), &mem, 16),
            ];
            for (idx, vq) in vqs.iter().enumerate() {
                set_queue(&mut block, idx, vq.create_queue());
            }
            block.activate(mem, interrupt.clone()).unwrap();
            let disk = TempFile::new().unwrap();
            disk.as_file().set_len(0x3000).unwrap();
            let disk_path = disk.as_path().to_str().unwrap().to_string();
            block.update_disk_image(disk_path.clone()).unwrap();
            assert_eq!(block.config().path_on_host, disk_path);
            assert_eq!(u64::from_le(block.config_space.capacity), 24);
            assert!(
                interrupt.has_pending_interrupt(VirtioInterruptType::Config),
                "updating an active disk must notify the guest"
            );

            assert!(block.reset());
            for resources in block.resources() {
                assert_eq!(resources.disk.nsectors, 24);
            }
        }
    }

    #[test]
    fn test_reset_and_reactivation() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            for threaded in [false, true] {
                let mut block = default_block(engine);
                if threaded {
                    block.config.num_queues = NonZeroU16::new(1);
                    block.spawn_worker(Arc::new(vec![])).unwrap();
                }

                let mem = default_mem();
                let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
                set_queue(&mut block, 0, vq.create_queue());
                block.set_acked_features(1);
                block.activate(mem.clone(), default_interrupt()).unwrap();

                assert!(block.is_activated());
                assert_eq!(block.is_threaded_active(), threaded);
                assert!(block.reset());
                assert!(!block.is_activated());
                assert_eq!(block.acked_features(), 0);
                assert!(!block.queue_config(0).unwrap().ready);
                let BlockRuntimeState::Configuring(_, worker_handles) = &block.state else {
                    panic!("reset must leave the block device configuring");
                };
                assert_eq!(!worker_handles.is_empty(), threaded);

                set_queue(&mut block, 0, vq.create_queue());
                block.activate(mem, default_interrupt()).unwrap();
                assert!(block.is_activated());
                assert_eq!(block.is_threaded_active(), threaded);
            }
        }
    }

    /// Completes the requests of an Async drive that are in flight, as the event loop would.
    fn complete_async(block: &mut VirtioBlock) {
        if let FileEngine::Async(ref mut engine) = block.resources_mut()[0].disk.file_engine {
            engine.drain(false).unwrap();
        }
        thread::sleep(Duration::from_millis(150));
        block.process_async_completion_event();
    }

    fn async_engine(block: &mut VirtioBlock) -> &mut super::super::io::AsyncFileEngine {
        match block.resources_mut()[0].disk.file_engine {
            FileEngine::Async(ref mut engine) => engine,
            FileEngine::Sync(_) => panic!("not an Async drive"),
        }
    }

    /// Writes `data` at `offset` of the drive's file through a descriptor of its own (the
    /// drive's descriptor has `O_DIRECT`).
    fn write_file_at(block: &VirtioBlock, offset: u64, data: &[u8]) {
        use std::os::unix::fs::FileExt;
        OpenOptions::new()
            .write(true)
            .open(&block.config.path_on_host)
            .unwrap()
            .write_all_at(data, offset)
            .unwrap();
    }

    fn read_file_at(block: &VirtioBlock, offset: u64, len: usize) -> Vec<u8> {
        use std::os::unix::fs::FileExt;
        let mut buf = vec![0u8; len];
        File::open(&block.config.path_on_host)
            .unwrap()
            .read_exact_at(&mut buf, offset)
            .unwrap();
        buf
    }

    /// An Async drive with a read of its first sector in the queue, that its disk fails. The
    /// file is the drive's for as long as the returned `TempFile` lives.
    fn async_block_with_failed_read(
        mem: &GuestMemoryMmap,
    ) -> (VirtioBlock, VirtQueue<'_>, TempFile) {
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();
        let mut block = default_block_with_path(
            f.as_path().to_str().unwrap().to_string(),
            FileEngineType::Async,
        );
        // A queue of the size that a restore checks, after the buffers of the request.
        let vq = VirtQueue::new(GuestAddress(0x8000), mem, FIRECRACKER_MAX_QUEUE_SIZE);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone(), default_interrupt()).unwrap();
        read_blk_req_descriptors(&vq);
        vq.dtable[1].len.set(512);
        mem.write_obj::<u32>(VIRTIO_BLK_T_IN, GuestAddress(vq.dtable[0].addr.get()))
            .unwrap();
        mem.write_obj::<u8>(0xff, GuestAddress(vq.dtable[2].addr.get()))
            .unwrap();
        write_file_at(&block, 0, &[0x5a; 512]);

        async_engine(&mut block).fail_completions = 1;
        simulate_queue_event(&mut block, None);
        complete_async(&mut block);
        (block, vq, f)
    }

    #[test]
    fn test_async_disk_error_keeps_the_request() {
        let mem = default_mem();
        let (mut block, vq, _file) = async_block_with_failed_read(&mem);
        let status_addr = GuestAddress(vq.dtable[2].addr.get());
        let data_addr = GuestAddress(vq.dtable[1].addr.get());

        // The request is kept, not answered, and the Vmm is told once.
        assert_eq!(vq.used.idx.get(), 0);
        assert_eq!(mem.read_obj::<u8>(status_addr).unwrap(), 0xff);
        assert_eq!(block.resources()[0].kept.len(), 1);
        assert!(block.resources()[0].stopped_on_error);
        assert!(block.take_disk_error());
        assert!(!block.take_disk_error());

        // No request is taken while the device is stopped on the error.
        vq.avail.idx.set(2);
        vq.avail.ring[1].set(0);
        simulate_queue_event(&mut block, None);
        complete_async(&mut block);
        assert_eq!(vq.used.idx.get(), 0);
        vq.avail.idx.set(1);

        // The resume kicks the device: the kept request runs again from its start.
        block.kick();
        block.process_queue_event();
        complete_async(&mut block);
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(
            u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
            VIRTIO_BLK_S_OK
        );
        let mut buf = [0u8; 512];
        mem.read_slice(&mut buf, data_addr).unwrap();
        assert_eq!(buf, [0x5a; 512]);
        assert!(block.resources()[0].kept.is_empty());
        assert!(!block.resources()[0].stopped_on_error);
    }

    #[test]
    fn test_async_disk_error_again_at_the_resume() {
        let mem = default_mem();
        let (mut block, vq, _file) = async_block_with_failed_read(&mem);
        assert!(block.take_disk_error());

        // The disk fails the request again after the resume: it is kept again.
        block.kick();
        async_engine(&mut block).fail_completions = 1;
        block.process_queue_event();
        complete_async(&mut block);
        assert_eq!(vq.used.idx.get(), 0);
        assert_eq!(block.resources()[0].kept.len(), 1);
        assert!(block.take_disk_error());
    }

    #[test]
    fn test_kept_request_across_save_and_load() {
        let mem = default_mem();
        let (block, vq, _file) = async_block_with_failed_read(&mem);
        let status_addr = GuestAddress(vq.dtable[2].addr.get());
        let data_addr = GuestAddress(vq.dtable[1].addr.get());

        let state = block.save();
        let bytes = bitcode::serialize(&state).unwrap();
        drop(block);

        let state = bitcode::deserialize(&bytes).unwrap();
        let mut restored = VirtioBlock::restore(
            crate::devices::virtio::block::persist::BlockConstructorArgs { mem: mem.clone() },
            &state,
        )
        .unwrap();
        assert_eq!(restored.resources()[0].kept.len(), 1);
        assert!(restored.resources()[0].stopped_on_error);
        restored.activate(mem.clone(), default_interrupt()).unwrap();

        // Nothing runs before the resume.
        restored.process_queue_event();
        assert_eq!(vq.used.idx.get(), 0);

        // At the resume the kept request runs again from its start.
        restored.kick();
        restored.process_queue_event();
        complete_async(&mut restored);
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(
            u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
            VIRTIO_BLK_S_OK
        );
        let mut buf = [0u8; 512];
        mem.read_slice(&mut buf, data_addr).unwrap();
        assert_eq!(buf, [0x5a; 512]);
    }

    #[test]
    fn test_async_discard() {
        let f = TempFile::new().unwrap();
        f.as_file().write_all(&[0x5a; 0x1000]).unwrap();
        let config = VirtioBlockConfig {
            drive_id: "async_discard".to_string(),
            path_on_host: f.as_path().to_str().unwrap().to_string(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            discard: true,
            num_queues: None,
            poll_us: None,
            cache_type: CacheType::Writeback,
            rate_limiter: None,
            file_engine_type: FileEngineType::Async,
            blk_size: None,
            topology: None,
        };
        let mut block = VirtioBlock::new(config).unwrap();
        block.acked_features = block.avail_features;
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone(), default_interrupt()).unwrap();

        // A write of sector 0, and after it in the queue a discard of sectors 2 and 3.
        read_blk_req_descriptors(&vq);
        mem.write_obj(
            RequestHeader::new(VIRTIO_BLK_T_OUT, 0),
            GuestAddress(0x1000),
        )
        .unwrap();
        vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
        vq.dtable[1].len.set(512);
        mem.write_slice(&[0x11; 512], GuestAddress(0x2000)).unwrap();

        vq.dtable[3].set(0x4000, 16, VIRTQ_DESC_F_NEXT, 4);
        vq.dtable[4].set(0x5000, 16, VIRTQ_DESC_F_NEXT, 5);
        vq.dtable[5].set(0x6000, 1, VIRTQ_DESC_F_WRITE, 0);
        mem.write_obj(
            RequestHeader::new(VIRTIO_BLK_T_DISCARD, 0),
            GuestAddress(0x4000),
        )
        .unwrap();
        let mut range = [0u8; 16];
        range[0..8].copy_from_slice(&2u64.to_le_bytes());
        range[8..12].copy_from_slice(&2u32.to_le_bytes());
        mem.write_slice(&range, GuestAddress(0x5000)).unwrap();
        vq.avail.ring[1].set(3);
        vq.avail.idx.set(2);

        simulate_queue_event(&mut block, None);
        complete_async(&mut block);

        // Both are answered: the discard first, at once; the write when its completion is taken.
        assert_eq!(vq.used.idx.get(), 2);
        assert_eq!(vq.used.ring[0].get().id, 3);
        assert_eq!(vq.used.ring[1].get().id, 0);
        assert_eq!(
            u32::from(mem.read_obj::<u8>(GuestAddress(0x3000)).unwrap()),
            VIRTIO_BLK_S_OK
        );
        assert_eq!(
            u32::from(mem.read_obj::<u8>(GuestAddress(0x6000)).unwrap()),
            VIRTIO_BLK_S_OK
        );
        assert!(block.resources()[0].kept.is_empty());

        let data = read_file_at(&block, 0, 0x1000);
        assert_eq!(&data[0..512], &[0x11; 512]);
        assert_eq!(&data[512..1024], &[0x5a; 512]);
        assert_eq!(&data[1024..2048], &[0u8; 1024]);
        assert_eq!(&data[2048..], &[0x5a; 2048]);
    }

    #[test]
    fn test_drain_for_a_stop_and_a_checkpoint_has_no_fsync() {
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();
        let config = VirtioBlockConfig {
            drive_id: "drain".to_string(),
            path_on_host: f.as_path().to_str().unwrap().to_string(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            discard: false,
            num_queues: None,
            poll_us: None,
            cache_type: CacheType::Writeback,
            rate_limiter: None,
            file_engine_type: FileEngineType::Async,
            blk_size: None,
            topology: None,
        };
        let mut block = VirtioBlock::new(config).unwrap();
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone(), default_interrupt()).unwrap();

        // The stop of the guest ends the requests in flight and answers them, with no fsync.
        add_flush_requests_batch(&mut block, &vq, 5);
        simulate_queue_event(&mut block, None);
        VirtioDevice::quiesce(&mut block);
        check_flush_requests_batch(5, &vq);
        assert_eq!(async_engine(&mut block).sync_all_calls, 0);

        // So does the checkpoint variant of prepare_save.
        add_flush_requests_batch(&mut block, &vq, 5);
        simulate_queue_event(&mut block, None);
        VirtioDevice::prepare_checkpoint(&mut block);
        check_flush_requests_batch(5, &vq);
        assert_eq!(async_engine(&mut block).sync_all_calls, 0);

        // A snapshot's prepare_save syncs the drive.
        add_flush_requests_batch(&mut block, &vq, 5);
        simulate_queue_event(&mut block, None);
        block.prepare_save();
        check_flush_requests_batch(5, &vq);
        assert_eq!(async_engine(&mut block).sync_all_calls, 1);
    }

    #[test]
    fn test_async_drive_opens_with_o_direct() {
        for (engine, direct) in [(FileEngineType::Async, true), (FileEngineType::Sync, false)] {
            let mut block = default_block(engine);
            let fd = block.disk().file_engine.file().as_raw_fd();
            // SAFETY: fcntl on a descriptor of this test.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert_eq!(flags & libc::O_DIRECT != 0, direct);

            // A new path of the drive (PATCH /drives) is opened the same way.
            let f = TempFile::new().unwrap();
            f.as_file().set_len(0x1000).unwrap();
            block
                .update_disk_image(f.as_path().to_str().unwrap().to_string())
                .unwrap();
            let fd = block.disk().file_engine.file().as_raw_fd();
            // SAFETY: fcntl on a descriptor of this test.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert_eq!(flags & libc::O_DIRECT != 0, direct);
        }
    }

    // The alignment of `O_DIRECT` (requests that the device's blocks do not cover go through an
    // aligned buffer). The memory of these tests: the queue at 0, the headers at 0x1000, the
    // statuses at 0x3000, the data from 0x10000.
    const ALIGN_MEM: usize = 0x40000;
    const ALIGN_QUEUE: u16 = 32;
    // The first bytes of the backing, which the tests compare with a model.
    const MODEL_LEN: usize = 0x10000;

    /// The backings of the alignment tests: a regular file (the engine takes 4096 bytes as the
    /// alignment of a regular file) and, when `SPACE_TEST_BLOCK_4K` names one, a block device
    /// with 4096-byte logical blocks (`losetup --sector-size 4096`), whose `O_DIRECT` refuses
    /// what is not aligned to 4096 bytes.
    fn aligned_backings() -> Vec<(String, Option<TempFile>)> {
        let f = TempFile::new().unwrap();
        f.as_file().set_len(ALIGN_MEM as u64).unwrap();
        let mut backings = vec![(f.as_path().to_str().unwrap().to_string(), Some(f))];
        match std::env::var("SPACE_TEST_BLOCK_4K") {
            Ok(dev) => backings.push((dev, None)),
            Err(_) => eprintln!("SPACE_TEST_BLOCK_4K is not set: no run on a 4096-byte device"),
        }
        backings
    }

    /// An `Async` drive on `path` whose guest sees 512-byte blocks, active on `mem` with the
    /// queue `vq`.
    fn aligned_block(
        path: &str,
        discard: bool,
        mem: &GuestMemoryMmap,
        vq: &VirtQueue,
    ) -> VirtioBlock {
        let config = VirtioBlockConfig {
            drive_id: "aligned".to_string(),
            path_on_host: path.to_string(),
            is_root_device: false,
            partuuid: None,
            is_read_only: false,
            discard,
            num_queues: None,
            poll_us: None,
            cache_type: CacheType::Unsafe,
            rate_limiter: None,
            file_engine_type: FileEngineType::Async,
            blk_size: Some(512),
            topology: None,
        };
        let mut block = VirtioBlock::new(config).unwrap();
        block.acked_features = block.avail_features;
        set_queue(&mut block, 0, vq.create_queue());
        block.activate(mem.clone(), default_interrupt()).unwrap();
        block
    }

    /// Bytes that differ from sector to sector and from seed to seed.
    fn pattern(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| seed.wrapping_add(u8::try_from((i * 7 + i / 512 * 13) % 256).unwrap()))
            .collect()
    }

    /// Writes `data` at `offset` of the backing through a descriptor of its own, synced.
    fn fill_backing(path: &str, offset: u64, data: &[u8]) {
        use std::os::unix::fs::FileExt;
        let f = OpenOptions::new().write(true).open(path).unwrap();
        f.write_all_at(data, offset).unwrap();
        f.sync_all().unwrap();
    }

    fn read_backing(path: &str, len: usize) -> Vec<u8> {
        use std::os::unix::fs::FileExt;
        let mut buf = vec![0u8; len];
        File::open(path)
            .unwrap()
            .read_exact_at(&mut buf, 0)
            .unwrap();
        buf
    }

    /// Starts a new set of requests in the queue.
    fn new_round(block: &mut VirtioBlock, vq: &VirtQueue) {
        vq.avail.idx.set(0);
        vq.used.idx.set(0);
        set_queue(block, 0, vq.create_queue());
    }

    /// Puts request `n` of the round in the queue: its data at `data`, its header at
    /// 0x1000 + 0x10 * n, its status at 0x3000 + n.
    fn put_request(vq: &VirtQueue, n: u16, request_type: u32, sector: u64, data: u64, len: u32) {
        let mem = vq.memory();
        let (h, d, st) = (3 * n, 3 * n + 1, 3 * n + 2);
        let header = 0x1000 + 0x10 * u64::from(n);
        mem.write_obj(
            RequestHeader::new(request_type, sector),
            GuestAddress(header),
        )
        .unwrap();
        let data_flags = if request_type == VIRTIO_BLK_T_IN {
            VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE
        } else {
            VIRTQ_DESC_F_NEXT
        };
        vq.dtable[h as usize].set(header, 16, VIRTQ_DESC_F_NEXT, d);
        vq.dtable[d as usize].set(data, len, data_flags, st);
        vq.dtable[st as usize].set(0x3000 + u64::from(n), 1, VIRTQ_DESC_F_WRITE, 0);
        mem.write_obj::<u8>(0xff, GuestAddress(0x3000 + u64::from(n)))
            .unwrap();
        vq.avail.ring[n as usize].set(h);
        vq.avail.idx.set(n + 1);
    }

    fn status_of(mem: &GuestMemoryMmap, n: u16) -> u32 {
        u32::from(
            mem.read_obj::<u8>(GuestAddress(0x3000 + u64::from(n)))
                .unwrap(),
        )
    }

    fn run_round(block: &mut VirtioBlock) {
        simulate_queue_event(block, None);
        complete_async(block);
    }

    fn sector_range(sector: u64, len: u32) -> std::ops::Range<usize> {
        let start = usize::try_from(sector * 512).unwrap();
        start..start + len as usize
    }

    #[test]
    fn test_direct_alignment_of_the_backing() {
        // A regular file opened with O_DIRECT: 4096 bytes; a Sync drive: none.
        let mem = single_region_mem(ALIGN_MEM);
        let vq = VirtQueue::new(GuestAddress(0), &mem, ALIGN_QUEUE);
        for (path, _file) in aligned_backings() {
            let mut block = aligned_block(&path, false, &mem, &vq);
            let expected = DirectAlignment {
                offset: 4096,
                mem: 4096,
            };
            assert_eq!(async_engine(&mut block).alignment(), expected, "{path}");
        }
        let f = TempFile::new().unwrap();
        let file = File::open(f.as_path()).unwrap();
        assert_eq!(
            DiskProperties::direct_alignment(&file, FileEngineType::Sync),
            DirectAlignment::NONE
        );
    }

    #[test]
    fn test_unaligned_reads_and_writes_of_each_case() {
        // (sector, length, offset of the guest's memory from 0x10000)
        let cases: [(u64, u32, u64); 8] = [
            // Aligned: no buffer.
            (8, 4096, 0),
            // The offset is not aligned.
            (1, 4096, 0),
            // The length is not aligned.
            (8, 512, 0),
            // The memory is not aligned.
            (8, 4096, 0x200),
            // None is aligned.
            (3, 1536, 0x200),
            // Parts of two device blocks.
            (7, 1024, 0),
            // Parts of two device blocks with a whole one between them.
            (15, 5120, 0x10),
            // The end of the model's range, a part of its last device block.
            (125, 1536, 0),
        ];
        let mem = single_region_mem(ALIGN_MEM);
        let vq = VirtQueue::new(GuestAddress(0), &mem, ALIGN_QUEUE);
        for (path, _file) in aligned_backings() {
            let mut model = pattern(0x40, MODEL_LEN);
            fill_backing(&path, 0, &model);
            let mut block = aligned_block(&path, false, &mem, &vq);

            for (i, &(sector, len, mem_off)) in cases.iter().enumerate() {
                let bounced = async_engine(&mut block).bounced_jobs;
                let data = pattern(u8::try_from(i).unwrap() * 17 + 1, len as usize);
                let addr = 0x10000 + mem_off;
                mem.write_slice(&data, GuestAddress(addr)).unwrap();
                new_round(&mut block, &vq);
                put_request(&vq, 0, VIRTIO_BLK_T_OUT, sector, addr, len);
                run_round(&mut block);
                assert_eq!(vq.used.idx.get(), 1, "{path} case {i}");
                assert_eq!(status_of(&mem, 0), VIRTIO_BLK_S_OK, "{path} case {i}");
                model[sector_range(sector, len)].copy_from_slice(&data);
                assert!(
                    read_backing(&path, MODEL_LEN) == model,
                    "{path} case {i}: the backing differs from the model"
                );

                // Read it back, to another place of the memory with the same alignment.
                let back = 0x20000 + mem_off;
                mem.write_slice(&vec![0u8; len as usize], GuestAddress(back))
                    .unwrap();
                new_round(&mut block, &vq);
                put_request(&vq, 0, VIRTIO_BLK_T_IN, sector, back, len);
                run_round(&mut block);
                assert_eq!(vq.used.idx.get(), 1, "{path} case {i}");
                assert_eq!(vq.used.ring[0].get().len, len + 1, "{path} case {i}");
                assert_eq!(status_of(&mem, 0), VIRTIO_BLK_S_OK, "{path} case {i}");
                let mut got = vec![0u8; len as usize];
                mem.read_slice(&mut got, GuestAddress(back)).unwrap();
                assert!(got == data, "{path} case {i}: the read differs");

                let bounces = async_engine(&mut block).bounced_jobs - bounced;
                assert_eq!(bounces, if i == 0 { 0 } else { 2 }, "{path} case {i}");
            }
            assert_eq!(async_engine(&mut block).taken_jobs(), 0);
        }
    }

    #[test]
    fn test_requests_that_overlap_a_read_modify_write_wait() {
        let mem = single_region_mem(ALIGN_MEM);
        let vq = VirtQueue::new(GuestAddress(0), &mem, ALIGN_QUEUE);
        for (path, _file) in aligned_backings() {
            let mut model = pattern(0x40, MODEL_LEN);
            fill_backing(&path, 0, &model);
            let mut block = aligned_block(&path, false, &mem, &vq);
            // (first request, second request, whether the second waits); each request is
            // (type, sector, length).
            type Req = (u32, u64, u32);
            let rounds: [(Req, Req, bool); 5] = [
                // A write of a whole block after a write of a part of it.
                (
                    (VIRTIO_BLK_T_OUT, 1, 512),
                    (VIRTIO_BLK_T_OUT, 0, 4096),
                    true,
                ),
                // A write of a part of a block after a write of the whole block: it waits for
                // the write in flight before it reads the block.
                (
                    (VIRTIO_BLK_T_OUT, 8, 4096),
                    (VIRTIO_BLK_T_OUT, 9, 512),
                    true,
                ),
                // Two writes of parts of the same block that do not overlap for the guest.
                (
                    (VIRTIO_BLK_T_OUT, 17, 512),
                    (VIRTIO_BLK_T_OUT, 18, 512),
                    true,
                ),
                // A read of the block of a write of a part of it.
                (
                    (VIRTIO_BLK_T_OUT, 25, 512),
                    (VIRTIO_BLK_T_IN, 24, 4096),
                    true,
                ),
                // Requests of other blocks do not wait.
                (
                    (VIRTIO_BLK_T_OUT, 33, 512),
                    (VIRTIO_BLK_T_OUT, 40, 4096),
                    false,
                ),
            ];
            for (r, &(first, second, waits)) in rounds.iter().enumerate() {
                new_round(&mut block, &vq);
                let mut writes = Vec::new();
                for (n, &(t, sector, len)) in [first, second].iter().enumerate() {
                    let addr = 0x10000 + 0x4000 * n as u64;
                    if t == VIRTIO_BLK_T_OUT {
                        let data = pattern(u8::try_from(r * 2 + n).unwrap() * 11 + 3, len as usize);
                        mem.write_slice(&data, GuestAddress(addr)).unwrap();
                        writes.push((sector, len, data));
                    } else {
                        mem.write_slice(&vec![0u8; len as usize], GuestAddress(addr))
                            .unwrap();
                    }
                    put_request(&vq, u16::try_from(n).unwrap(), t, sector, addr, len);
                }
                simulate_queue_event(&mut block, None);
                assert_eq!(
                    async_engine(&mut block).waiting_jobs(),
                    usize::from(waits),
                    "{path} round {r}"
                );
                complete_async(&mut block);
                assert_eq!(vq.used.idx.get(), 2, "{path} round {r}");
                assert_eq!(status_of(&mem, 0), VIRTIO_BLK_S_OK, "{path} round {r}");
                assert_eq!(status_of(&mem, 1), VIRTIO_BLK_S_OK, "{path} round {r}");
                // The order of the queue is kept: the second ran after the first.
                for (sector, len, data) in writes {
                    model[sector_range(sector, len)].copy_from_slice(&data);
                }
                assert!(
                    read_backing(&path, MODEL_LEN) == model,
                    "{path} round {r}: the backing differs from the model"
                );
                if second.0 == VIRTIO_BLK_T_IN {
                    let mut got = vec![0u8; second.2 as usize];
                    mem.read_slice(&mut got, GuestAddress(0x14000)).unwrap();
                    assert!(
                        got == model[sector_range(second.1, second.2)],
                        "{path} round {r}: the read did not see the write before it"
                    );
                }
            }
        }
    }

    #[test]
    fn test_disk_error_in_a_read_modify_write_keeps_the_request() {
        let mem = single_region_mem(ALIGN_MEM);
        let vq = VirtQueue::new(GuestAddress(0), &mem, ALIGN_QUEUE);
        for (path, _file) in aligned_backings() {
            // The disk fails the read of the block (no operation passes), then the write of it
            // (the read passes).
            for (pass, sector) in [(0u32, 1u64), (1, 7)] {
                let mut model = pattern(0x40, MODEL_LEN);
                fill_backing(&path, 0, &model);
                let mut block = aligned_block(&path, false, &mem, &vq);
                let len = 1024;
                let data = pattern(0x99, len as usize);
                mem.write_slice(&data, GuestAddress(0x10000)).unwrap();
                new_round(&mut block, &vq);
                put_request(&vq, 0, VIRTIO_BLK_T_OUT, sector, 0x10000, len);
                async_engine(&mut block).pass_completions = pass;
                async_engine(&mut block).fail_completions = 1;
                run_round(&mut block);

                // Kept, not answered; the disk is as it was.
                assert_eq!(vq.used.idx.get(), 0, "{path} pass {pass}");
                assert_eq!(status_of(&mem, 0), 0xff);
                assert_eq!(block.resources()[0].kept.len(), 1);
                assert!(block.resources()[0].stopped_on_error);
                assert!(block.take_disk_error());
                assert_eq!(async_engine(&mut block).taken_jobs(), 0);
                assert!(read_backing(&path, MODEL_LEN) == model);

                // At the resume it runs again from its start, whole.
                block.kick();
                block.process_queue_event();
                complete_async(&mut block);
                assert_eq!(vq.used.idx.get(), 1, "{path} pass {pass}");
                assert_eq!(status_of(&mem, 0), VIRTIO_BLK_S_OK);
                assert!(block.resources()[0].kept.is_empty());
                model[sector_range(sector, len)].copy_from_slice(&data);
                assert!(
                    read_backing(&path, MODEL_LEN) == model,
                    "{path} pass {pass}"
                );
            }
        }
    }

    #[test]
    fn test_short_reads_and_writes_are_kept_and_run_again() {
        // (type, sector, length, completions that pass, bytes that the short one reports);
        // each request is kept, the guest stops, and at the resume it runs again whole.
        let cases: [(u32, u64, u32, u32, u32); 10] = [
            // Direct: a read of 0 bytes, a short read, a write of 0 bytes, a short write.
            (VIRTIO_BLK_T_IN, 8, 4096, 0, 0),
            (VIRTIO_BLK_T_IN, 8, 4096, 0, 1536),
            (VIRTIO_BLK_T_OUT, 8, 4096, 0, 0),
            (VIRTIO_BLK_T_OUT, 8, 4096, 0, 2048),
            // A read through an aligned buffer: 0 bytes; and short, though it covers the
            // guest's part of the block.
            (VIRTIO_BLK_T_IN, 1, 1024, 0, 0),
            (VIRTIO_BLK_T_IN, 1, 1024, 0, 2048),
            // A read-modify-write: the read of its block moves 0 bytes; the read passes and
            // the write is short, though it covers the guest's part.
            (VIRTIO_BLK_T_OUT, 1, 1024, 0, 0),
            (VIRTIO_BLK_T_OUT, 1, 1024, 1, 2048),
            // A read-modify-write of parts of two blocks: the read of the second moves 0
            // bytes; the write of both is short.
            (VIRTIO_BLK_T_OUT, 7, 1024, 1, 0),
            (VIRTIO_BLK_T_OUT, 7, 1024, 2, 4096),
        ];
        let mem = single_region_mem(ALIGN_MEM);
        let vq = VirtQueue::new(GuestAddress(0), &mem, ALIGN_QUEUE);
        for (path, _file) in aligned_backings() {
            for (i, &(t, sector, len, pass, short_to)) in cases.iter().enumerate() {
                let mut model = pattern(0x40, MODEL_LEN);
                fill_backing(&path, 0, &model);
                let mut block = aligned_block(&path, false, &mem, &vq);
                let data = pattern(0x99, len as usize);
                if t == VIRTIO_BLK_T_OUT {
                    mem.write_slice(&data, GuestAddress(0x10000)).unwrap();
                }
                new_round(&mut block, &vq);
                put_request(&vq, 0, t, sector, 0x10000, len);
                async_engine(&mut block).pass_completions = pass;
                async_engine(&mut block).short_completions = 1;
                async_engine(&mut block).short_to = short_to;
                run_round(&mut block);

                // Kept, not answered, and the Vmm is told.
                assert_eq!(vq.used.idx.get(), 0, "{path} case {i}");
                assert_eq!(status_of(&mem, 0), 0xff, "{path} case {i}");
                assert_eq!(block.resources()[0].kept.len(), 1, "{path} case {i}");
                assert!(block.resources()[0].stopped_on_error, "{path} case {i}");
                assert!(block.take_disk_error(), "{path} case {i}");
                assert_eq!(async_engine(&mut block).taken_jobs(), 0);

                // What the short operation moved is undone before the resume (the fake
                // reports fewer bytes than the kernel moved): the request must run again.
                if t == VIRTIO_BLK_T_IN {
                    mem.write_slice(&vec![0u8; len as usize], GuestAddress(0x10000))
                        .unwrap();
                } else {
                    fill_backing(&path, 0, &model);
                }

                block.kick();
                block.process_queue_event();
                complete_async(&mut block);
                assert_eq!(vq.used.idx.get(), 1, "{path} case {i}");
                assert_eq!(status_of(&mem, 0), VIRTIO_BLK_S_OK, "{path} case {i}");
                assert!(block.resources()[0].kept.is_empty());
                assert!(!block.resources()[0].stopped_on_error);
                if t == VIRTIO_BLK_T_IN {
                    assert_eq!(vq.used.ring[0].get().len, len + 1, "{path} case {i}");
                    let mut got = vec![0u8; len as usize];
                    mem.read_slice(&mut got, GuestAddress(0x10000)).unwrap();
                    assert!(
                        got == model[sector_range(sector, len)],
                        "{path} case {i}: the read differs"
                    );
                } else {
                    model[sector_range(sector, len)].copy_from_slice(&data);
                    assert!(
                        read_backing(&path, MODEL_LEN) == model,
                        "{path} case {i}: the backing differs from the model"
                    );
                }
            }
        }
    }

    #[test]
    fn test_read_past_the_end_of_a_shrunk_file_is_kept() {
        // The kernel's own read of 0 bytes: the drive's file is cut short under it (as a disk
        // whose program is gone), then comes back before the resume. A direct read and a read
        // through an aligned buffer.
        let mem = single_region_mem(ALIGN_MEM);
        let vq = VirtQueue::new(GuestAddress(0), &mem, ALIGN_QUEUE);
        let f = TempFile::new().unwrap();
        f.as_file().set_len(ALIGN_MEM as u64).unwrap();
        let path = f.as_path().to_str().unwrap().to_string();
        let model = pattern(0x31, MODEL_LEN);
        for (i, &(sector, len)) in [(32u64, 4096u32), (33, 1024)].iter().enumerate() {
            fill_backing(&path, 0, &model);
            let mut block = aligned_block(&path, false, &mem, &vq);
            f.as_file().set_len(0x2000).unwrap();
            mem.write_slice(&vec![0u8; len as usize], GuestAddress(0x10000))
                .unwrap();
            new_round(&mut block, &vq);
            put_request(&vq, 0, VIRTIO_BLK_T_IN, sector, 0x10000, len);
            run_round(&mut block);
            assert_eq!(vq.used.idx.get(), 0, "case {i}");
            assert_eq!(status_of(&mem, 0), 0xff, "case {i}");
            assert_eq!(block.resources()[0].kept.len(), 1, "case {i}");
            assert!(block.take_disk_error(), "case {i}");

            f.as_file().set_len(ALIGN_MEM as u64).unwrap();
            fill_backing(&path, 0, &model);
            block.kick();
            block.process_queue_event();
            complete_async(&mut block);
            assert_eq!(vq.used.idx.get(), 1, "case {i}");
            assert_eq!(status_of(&mem, 0), VIRTIO_BLK_S_OK, "case {i}");
            let mut got = vec![0u8; len as usize];
            mem.read_slice(&mut got, GuestAddress(0x10000)).unwrap();
            assert!(got == model[sector_range(sector, len)], "case {i}");
        }
    }

    #[test]
    fn test_short_head_and_tail_reads_of_a_cut_file_are_kept() {
        // The drive's file is cut short after its attach, so a write that reads the device
        // block at its start or at its end (a read-modify-write) reads fewer bytes than it
        // asked. The request is kept and the guest stops; the file comes back whole before the
        // resume, and the write runs again from its start. (sector, length, the file's length
        // after the cut)
        let cases: [(u64, u32, u64); 6] = [
            // The read of the block at the start of the write (the write starts inside a
            // block): 0 bytes; and fewer, though they cover the guest's part of the block.
            (1, 512, 0),
            (9, 512, 0x1000),
            (9, 512, 0x1800),
            // The read of the block at the end of the write (the write starts at a block): 0
            // bytes, and fewer.
            (8, 512, 0x1000),
            (8, 512, 0x1800),
            // A write over parts of two blocks: the read of the first passes, the read of the
            // second moves fewer bytes.
            (7, 1024, 0x1400),
        ];
        let mem = single_region_mem(ALIGN_MEM);
        let vq = VirtQueue::new(GuestAddress(0), &mem, ALIGN_QUEUE);
        let f = TempFile::new().unwrap();
        let path = f.as_path().to_str().unwrap().to_string();
        for (i, &(sector, len, cut)) in cases.iter().enumerate() {
            f.as_file().set_len(ALIGN_MEM as u64).unwrap();
            let mut model = pattern(0x40, MODEL_LEN);
            fill_backing(&path, 0, &model);
            let mut block = aligned_block(&path, false, &mem, &vq);
            f.as_file().set_len(cut).unwrap();
            let data = pattern(0x99, len as usize);
            mem.write_slice(&data, GuestAddress(0x10000)).unwrap();
            new_round(&mut block, &vq);
            put_request(&vq, 0, VIRTIO_BLK_T_OUT, sector, 0x10000, len);
            run_round(&mut block);

            // Kept, not answered, and the Vmm is told; nothing was written.
            assert_eq!(vq.used.idx.get(), 0, "case {i}");
            assert_eq!(status_of(&mem, 0), 0xff, "case {i}");
            assert_eq!(block.resources()[0].kept.len(), 1, "case {i}");
            assert!(block.resources()[0].stopped_on_error, "case {i}");
            assert!(block.take_disk_error(), "case {i}");
            assert_eq!(async_engine(&mut block).taken_jobs(), 0, "case {i}");
            assert_eq!(f.as_file().metadata().unwrap().len(), cut, "case {i}");

            f.as_file().set_len(ALIGN_MEM as u64).unwrap();
            fill_backing(&path, 0, &model);
            block.kick();
            block.process_queue_event();
            complete_async(&mut block);
            assert_eq!(vq.used.idx.get(), 1, "case {i}");
            assert_eq!(status_of(&mem, 0), VIRTIO_BLK_S_OK, "case {i}");
            assert!(block.resources()[0].kept.is_empty(), "case {i}");
            assert!(!block.resources()[0].stopped_on_error, "case {i}");
            model[sector_range(sector, len)].copy_from_slice(&data);
            assert!(
                read_backing(&path, MODEL_LEN) == model,
                "case {i}: the backing differs from the model"
            );
        }
    }

    #[test]
    fn test_reads_through_a_buffer_at_the_end_of_the_drive_leave_zeros() {
        // A drive whose file is not a multiple of the device block (two blocks and 1024
        // bytes): a read through the buffer of its last block ends at the end of the drive,
        // the bytes after it are zeros, and the request succeeds. The same after `PATCH
        // /drives` gave the drive this file in the place of a longer one: the drive ends at
        // the end of the new file.
        const DRIVE_LEN: usize = 0x2400;
        // (type, sector, length, whether the file was given by an update of the drive)
        let cases: [(u32, u64, u32, bool); 6] = [
            (VIRTIO_BLK_T_IN, 16, 1024, false),
            (VIRTIO_BLK_T_IN, 17, 512, false),
            // Read-modify-writes: the read of the block at the start of the write, and at
            // its end.
            (VIRTIO_BLK_T_OUT, 17, 512, false),
            (VIRTIO_BLK_T_OUT, 16, 512, false),
            (VIRTIO_BLK_T_IN, 16, 1024, true),
            (VIRTIO_BLK_T_OUT, 17, 512, true),
        ];
        let mem = single_region_mem(ALIGN_MEM);
        let vq = VirtQueue::new(GuestAddress(0), &mem, ALIGN_QUEUE);
        for (i, &(t, sector, len, updated)) in cases.iter().enumerate() {
            let f = TempFile::new().unwrap();
            let path = f.as_path().to_str().unwrap().to_string();
            let mut model = pattern(0x52, DRIVE_LEN);
            fill_backing(&path, 0, &model);
            let mut block = if updated {
                let first = TempFile::new().unwrap();
                first.as_file().set_len(ALIGN_MEM as u64).unwrap();
                let mut block = aligned_block(first.as_path().to_str().unwrap(), false, &mem, &vq);
                block.update_disk_image(path.clone()).unwrap();
                block
            } else {
                aligned_block(&path, false, &mem, &vq)
            };
            assert_eq!(u64::from_le(block.config_space.capacity), 18, "case {i}");

            let data = pattern(0x99, len as usize);
            if t == VIRTIO_BLK_T_OUT {
                mem.write_slice(&data, GuestAddress(0x10000)).unwrap();
            } else {
                mem.write_slice(&vec![0u8; len as usize], GuestAddress(0x10000))
                    .unwrap();
            }
            new_round(&mut block, &vq);
            put_request(&vq, 0, t, sector, 0x10000, len);
            run_round(&mut block);
            assert_eq!(vq.used.idx.get(), 1, "case {i}");
            assert_eq!(status_of(&mem, 0), VIRTIO_BLK_S_OK, "case {i}");
            assert!(block.resources()[0].kept.is_empty(), "case {i}");
            if t == VIRTIO_BLK_T_IN {
                assert_eq!(vq.used.ring[0].get().len, len + 1, "case {i}");
                let mut got = vec![0u8; len as usize];
                mem.read_slice(&mut got, GuestAddress(0x10000)).unwrap();
                assert!(
                    got == model[sector_range(sector, len)],
                    "case {i}: the read differs"
                );
            } else {
                // The last block is written whole: the drive's bytes with the guest's part,
                // then zeros after the end of the drive.
                model[sector_range(sector, len)].copy_from_slice(&data);
                model.resize(0x3000, 0);
                assert!(read_backing(&path, 0x3000) == model, "case {i}");
            }
        }
    }

    #[test]
    fn test_short_read_kept_across_save_and_load() {
        // A read of 0 bytes of the drive with no worker threads: kept in the state, and run
        // again at the resume after a load.
        let mem = single_region_mem(ALIGN_MEM);
        // A queue of the size that a restore checks, after the buffers of the request.
        let vq = VirtQueue::new(GuestAddress(0x20000), &mem, FIRECRACKER_MAX_QUEUE_SIZE);
        let f = TempFile::new().unwrap();
        f.as_file().set_len(ALIGN_MEM as u64).unwrap();
        let path = f.as_path().to_str().unwrap().to_string();
        let model = pattern(0x27, MODEL_LEN);
        fill_backing(&path, 0, &model);
        let mut block = aligned_block(&path, false, &mem, &vq);
        new_round(&mut block, &vq);
        put_request(&vq, 0, VIRTIO_BLK_T_IN, 8, 0x10000, 4096);
        async_engine(&mut block).short_completions = 1;
        run_round(&mut block);
        assert_eq!(vq.used.idx.get(), 0);
        assert!(block.take_disk_error());
        mem.write_slice(&[0u8; 4096], GuestAddress(0x10000))
            .unwrap();

        VirtioDevice::quiesce(&mut block);
        let state = block.save();
        let bytes = bitcode::serialize(&state).unwrap();
        drop(block);
        let state = bitcode::deserialize(&bytes).unwrap();
        let mut restored = VirtioBlock::restore(
            crate::devices::virtio::block::persist::BlockConstructorArgs { mem: mem.clone() },
            &state,
        )
        .unwrap();
        assert_eq!(restored.resources()[0].kept.len(), 1);
        assert!(restored.resources()[0].stopped_on_error);
        restored.activate(mem.clone(), default_interrupt()).unwrap();
        restored.process_queue_event();
        assert_eq!(vq.used.idx.get(), 0);

        restored.kick();
        restored.process_queue_event();
        complete_async(&mut restored);
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(status_of(&mem, 0), VIRTIO_BLK_S_OK);
        let mut got = vec![0u8; 4096];
        mem.read_slice(&mut got, GuestAddress(0x10000)).unwrap();
        assert!(got == model[sector_range(8, 4096)]);
    }

    #[test]
    fn test_drain_with_a_read_modify_write_in_flight() {
        let mem = single_region_mem(ALIGN_MEM);
        let vq = VirtQueue::new(GuestAddress(0), &mem, ALIGN_QUEUE);
        for (path, _file) in aligned_backings() {
            let mut model = pattern(0x40, MODEL_LEN);
            fill_backing(&path, 0, &model);
            let mut block = aligned_block(&path, false, &mem, &vq);
            // A stop of the guest, then a checkpoint.
            for (r, checkpoint) in [false, true].into_iter().enumerate() {
                let base = u64::try_from(r).unwrap() * 16;
                let first = pattern(0x21 + u8::try_from(r).unwrap(), 512);
                let second = pattern(0x61 + u8::try_from(r).unwrap(), 4096);
                mem.write_slice(&first, GuestAddress(0x10000)).unwrap();
                mem.write_slice(&second, GuestAddress(0x14000)).unwrap();
                new_round(&mut block, &vq);
                put_request(&vq, 0, VIRTIO_BLK_T_OUT, base + 1, 0x10000, 512);
                put_request(&vq, 1, VIRTIO_BLK_T_OUT, base, 0x14000, 4096);
                simulate_queue_event(&mut block, None);
                assert_eq!(async_engine(&mut block).taken_jobs(), 2);
                assert_eq!(async_engine(&mut block).waiting_jobs(), 1);

                // The drain ends both: the read-modify-write and the request behind it.
                if checkpoint {
                    VirtioDevice::prepare_checkpoint(&mut block);
                } else {
                    VirtioDevice::quiesce(&mut block);
                }
                assert_eq!(vq.used.idx.get(), 2, "{path} round {r}");
                assert_eq!(status_of(&mem, 0), VIRTIO_BLK_S_OK);
                assert_eq!(status_of(&mem, 1), VIRTIO_BLK_S_OK);
                assert_eq!(async_engine(&mut block).taken_jobs(), 0);
                assert!(block.resources()[0].kept.is_empty());
                model[sector_range(base + 1, 512)].copy_from_slice(&first);
                model[sector_range(base, 4096)].copy_from_slice(&second);
                assert!(read_backing(&path, MODEL_LEN) == model, "{path} round {r}");
            }
        }
    }

    #[test]
    fn test_unaligned_discard_on_a_4k_block_device() {
        let Ok(path) = std::env::var("SPACE_TEST_BLOCK_4K") else {
            eprintln!("SPACE_TEST_BLOCK_4K is not set: the test does not run");
            return;
        };
        let mem = single_region_mem(ALIGN_MEM);
        let vq = VirtQueue::new(GuestAddress(0), &mem, ALIGN_QUEUE);
        let mut model = pattern(0x40, MODEL_LEN);
        fill_backing(&path, 0, &model);
        let mut block = aligned_block(&path, true, &mem, &vq);
        let put_discard = |n: u16, sector: u64, sectors: u32| {
            let range_addr = 0x10000 + 0x100 * u64::from(n);
            let mut range = [0u8; 16];
            range[0..8].copy_from_slice(&sector.to_le_bytes());
            range[8..12].copy_from_slice(&sectors.to_le_bytes());
            mem.write_slice(&range, GuestAddress(range_addr)).unwrap();
            put_request(&vq, n, VIRTIO_BLK_T_DISCARD, 0, range_addr, 16);
        };

        // Sectors 1 to 16 (bytes 512 to 8704): the whole block 1 inside is discarded, and the
        // parts of blocks 0 and 2 are written with zeros; sectors 24 to 31 are a whole block;
        // sectors 41 and 42 are inside block 5. Each range reads as zeros after it, and the
        // rest of the blocks at its ends is kept.
        new_round(&mut block, &vq);
        put_discard(0, 1, 16);
        put_discard(1, 24, 8);
        put_discard(2, 41, 2);
        run_round(&mut block);
        assert_eq!(vq.used.idx.get(), 3);
        for n in 0..3 {
            assert_eq!(status_of(&mem, n), VIRTIO_BLK_S_OK);
        }
        model[sector_range(1, 16 * 512)].fill(0);
        model[sector_range(24, 8 * 512)].fill(0);
        model[sector_range(41, 2 * 512)].fill(0);
        assert!(read_backing(&path, MODEL_LEN) == model);
        assert_eq!(async_engine(&mut block).taken_jobs(), 0);

        // The disk fails the read of the block at an end: the discard is kept, and runs again
        // whole at the resume.
        new_round(&mut block, &vq);
        put_discard(0, 49, 2);
        async_engine(&mut block).fail_completions = 1;
        run_round(&mut block);
        assert_eq!(vq.used.idx.get(), 0);
        assert_eq!(block.resources()[0].kept.len(), 1);
        assert!(block.take_disk_error());
        assert!(read_backing(&path, MODEL_LEN) == model);
        block.kick();
        block.process_queue_event();
        complete_async(&mut block);
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(status_of(&mem, 0), VIRTIO_BLK_S_OK);
        model[sector_range(49, 2 * 512)].fill(0);
        assert!(read_backing(&path, MODEL_LEN) == model);
    }
}
