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
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

use block_io::FileEngine;
use serde::{Deserialize, Serialize};
use vm_memory::ByteValued;
use vmm_sys_util::eventfd::EventFd;

use super::io::{DirectAlignment, async_io};
use super::request::*;
use super::{
    BLOCK_QUEUE_SIZES, MAX_DISCARD_SECTORS, SECTOR_SHIFT, SECTOR_SIZE, VirtioBlockError,
    io as block_io,
};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::block::CacheType;
use crate::devices::virtio::block::virtio::metrics::{BlockDeviceMetrics, BlockMetricsPerDevice};
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_blk::{
    VIRTIO_BLK_F_BLK_SIZE, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO,
    VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_ID_BYTES,
};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::queue::{InvalidAvailIdx, Queue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::impl_device_type;
use crate::logger::{IncMetric, error, warn};
use crate::rate_limiter::{BucketUpdate, RateLimiter};
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
/// event serves every drive; the Vmm asks the drives which one failed.
///
/// [`Vmm`]: crate::Vmm
pub static DISK_ERROR_EVT: LazyLock<EventFd> = LazyLock::new(|| {
    EventFd::new(libc::EFD_NONBLOCK).expect("Cannot create the disk error eventfd")
});

/// Helper object for setting up all `Block` fields derived from its backing file.
#[derive(Debug)]
pub struct DiskProperties {
    pub file_path: String,
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

    // The alignment that the requests of the file need: the file of an `Async` drive is
    // opened with `O_DIRECT`, so its engine aligns each request to the device's blocks.
    fn direct_alignment(file: &File, file_engine_type: FileEngineType) -> DirectAlignment {
        match file_engine_type {
            FileEngineType::Async => DirectAlignment::of_direct_file(file),
            FileEngineType::Sync => DirectAlignment::NONE,
        }
    }

    /// Create a new file for the block device using a FileEngine
    pub fn new(
        disk_image_path: String,
        is_disk_read_only: bool,
        file_engine_type: FileEngineType,
    ) -> Result<Self, VirtioBlockError> {
        let mut disk_image =
            Self::open_file(&disk_image_path, is_disk_read_only, file_engine_type)?;
        let disk_size = Self::file_size(&disk_image_path, &mut disk_image)?;
        let image_id = Self::build_disk_image_id(&disk_image);
        let align = Self::direct_alignment(&disk_image, file_engine_type);

        Ok(Self {
            file_path: disk_image_path,
            file_engine: FileEngine::from_file(disk_image, file_engine_type, align)
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
        self.file_path = disk_image_path;

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
            num_queues: 0,
            max_discard_sectors: MAX_DISCARD_SECTORS,
            max_discard_seg: 1,
            discard_sector_alignment: 1,
        }
    }
}

// SAFETY: `ConfigSpace` contains only PODs in `repr(C)` or `repr(transparent)`, without padding.
unsafe impl ByteValued for ConfigSpace {}

/// Use this structure to set up the Block Device before booting the kernel.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
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

    // Transport related fields.
    pub queues: Vec<Queue>,
    pub queue_evts: [EventFd; 1],
    pub device_state: DeviceState,

    // Implementation specific fields.
    pub id: String,
    pub partuuid: Option<String>,
    pub cache_type: CacheType,
    pub root_device: bool,
    pub read_only: bool,

    // Host file and properties.
    pub disk: DiskProperties,
    pub rate_limiter: RateLimiter,
    pub is_io_engine_throttled: bool,
    pub metrics: Arc<BlockDeviceMetrics>,

    // The stop on a disk error (the `Async` engine). A request that the disk failed is kept,
    // not answered, and runs again from its start when the guest is resumed. While a request
    // is kept, the device takes no new request from the queue.
    pub kept: VecDeque<PendingRequest>,
    pub stopped_on_error: bool,
    // A disk error that the Vmm has not yet taken to stop the guest.
    pub error_pending: bool,
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

impl VirtioBlock {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    pub fn new(config: VirtioBlockConfig) -> Result<VirtioBlock, VirtioBlockError> {
        if config.discard && config.is_read_only {
            return Err(VirtioBlockError::DiscardReadOnlyUnsupported);
        }

        let disk_properties = DiskProperties::new(
            config.path_on_host,
            config.is_read_only,
            config.file_engine_type,
        )?;

        let rate_limiter = config
            .rate_limiter
            .map(RateLimiter::from)
            .unwrap_or_default();

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_RING_F_EVENT_IDX)
            | (1u64 << VIRTIO_BLK_F_BLK_SIZE)
            | (1u64 << VIRTIO_BLK_F_TOPOLOGY);

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
            capacity: disk_properties.nsectors.to_le(),
            ..Default::default()
        };

        if config.blk_size.is_none() && config.topology.is_none() {
            if let Some((blk_size, topology)) = query_blk_attrs(disk_properties.file_engine.file())
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

        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?];

        let queues = BLOCK_QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        Ok(VirtioBlock {
            avail_features,
            acked_features: 0u64,
            config_space,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?,

            queues,
            queue_evts,
            device_state: DeviceState::Inactive,

            id: config.drive_id.clone(),
            partuuid: config.partuuid,
            cache_type: config.cache_type,
            root_device: config.is_root_device,
            read_only: config.is_read_only,

            disk: disk_properties,
            rate_limiter,
            is_io_engine_throttled: false,
            metrics: BlockMetricsPerDevice::alloc(config.drive_id),

            kept: VecDeque::new(),
            stopped_on_error: false,
            error_pending: false,
        })
    }

    /// Returns a copy of a device config
    pub fn config(&self) -> VirtioBlockConfig {
        let rl: RateLimiterConfig = (&self.rate_limiter).into();
        VirtioBlockConfig {
            drive_id: self.id.clone(),
            path_on_host: self.disk.file_path.clone(),
            is_root_device: self.root_device,
            partuuid: self.partuuid.clone(),
            is_read_only: self.read_only,
            discard: self.avail_features & (1u64 << VIRTIO_BLK_F_DISCARD) != 0,
            cache_type: self.cache_type,
            rate_limiter: rl.into_option(),
            file_engine_type: self.file_engine_type(),
            blk_size: Some(self.config_space.blk_size),
            topology: Some(self.config_space.topology),
        }
    }

    /// Process a single event in the Virtio queue.
    ///
    /// This function is called by the event manager when the guest notifies us
    /// about new buffers in the queue.
    pub(crate) fn process_queue_event(&mut self) {
        self.metrics.queue_event_count.inc();
        if let Err(err) = self.queue_evts[0].read() {
            error!("Failed to get queue event: {:?}", err);
            self.metrics.event_fails.inc();
        } else if self.rate_limiter.is_blocked() {
            self.metrics.rate_limiter_throttled_events.inc();
        } else if self.is_io_engine_throttled {
            self.metrics.io_engine_throttled_events.inc();
        } else if self.stopped_on_error {
            // The queue is taken again when the guest is resumed.
        } else {
            self.process_virtio_queues().unwrap()
        }
    }

    /// Keeps a request that the disk failed: it is not answered, the device takes no new
    /// request, and the Vmm is woken to stop the guest.
    fn keep_failed(&mut self, request: PendingRequest) {
        error!(
            "Block device {}: the disk failed a request; the guest stops and the request is \
             kept",
            self.id
        );
        self.metrics.execute_fails.inc();
        self.kept.push_back(request);
        self.stopped_on_error = true;
        if !self.error_pending {
            self.error_pending = true;
            if let Err(err) = DISK_ERROR_EVT.write(1) {
                error!("Failed to signal the disk error: {:?}", err);
            }
        }
    }

    /// Whether a disk error waits for the Vmm to stop the guest. The answer is given once.
    pub fn take_disk_error(&mut self) -> bool {
        std::mem::take(&mut self.error_pending)
    }

    /// Runs the kept requests again from their start, in their order. Returns whether the
    /// queue may be taken (no request is kept any more).
    fn run_kept(&mut self) -> bool {
        let active_state = self.device_state.active_state().unwrap();
        let mut used_any = false;
        while let Some(pending) = self.kept.pop_front() {
            let desc_idx = pending.desc_idx();
            match pending.to_request().process(
                &mut self.disk,
                desc_idx,
                &active_state.mem,
                &self.metrics,
                self.acked_features & (1u64 << VIRTIO_BLK_F_DISCARD) != 0,
            ) {
                ProcessingResult::Submitted => {}
                ProcessingResult::Throttled => {
                    self.kept.push_front(pending);
                    self.is_io_engine_throttled = true;
                    break;
                }
                ProcessingResult::Executed(finished) => {
                    used_any = true;
                    self.queues[0]
                        .add_used(finished.desc_idx, finished.num_bytes_to_mem)
                        .unwrap_or_else(|err| {
                            error!(
                                "Failed to add available descriptor head {}: {}",
                                finished.desc_idx, err
                            )
                        });
                }
                ProcessingResult::Failed(failed) => {
                    self.kept.push_front(failed);
                    self.stopped_on_error = true;
                    if !self.error_pending {
                        self.error_pending = true;
                        if let Err(err) = DISK_ERROR_EVT.write(1) {
                            error!("Failed to signal the disk error: {:?}", err);
                        }
                    }
                    break;
                }
            }
        }
        if used_any {
            let queue = &mut self.queues[0];
            queue.advance_used_ring_idx();
            if queue.prepare_kick() {
                active_state
                    .interrupt
                    .trigger(VirtioInterruptType::Queue(0))
                    .unwrap_or_else(|_| {
                        self.metrics.event_fails.inc();
                    });
            }
        }
        if let FileEngine::Async(ref mut engine) = self.disk.file_engine
            && let Err(err) = engine.kick_submission_queue()
        {
            error!("BlockError submitting pending block requests: {:?}", err);
        }
        self.kept.is_empty()
    }

    /// Process device virtio queue(s).
    pub fn process_virtio_queues(&mut self) -> Result<(), InvalidAvailIdx> {
        self.process_queue(0)
    }

    pub(crate) fn process_rate_limiter_event(&mut self) {
        self.metrics.rate_limiter_event_count.inc();
        // Upon rate limiter event, call the rate limiter handler
        // and restart processing the queue.
        if self.rate_limiter.event_handler().is_ok() {
            self.process_queue(0).unwrap()
        }
    }

    /// Device specific function for peaking inside a queue and processing descriptors.
    pub fn process_queue(&mut self, queue_index: usize) -> Result<(), InvalidAvailIdx> {
        if self.stopped_on_error {
            return Ok(());
        }
        if !self.kept.is_empty() && !self.run_kept() {
            return Ok(());
        }

        // This is safe since we checked in the event handler that the device is activated.
        let active_state = self.device_state.active_state().unwrap();

        let queue = &mut self.queues[queue_index];
        let mut used_any = false;
        let mut failed_request = None;

        while let Some(head) = queue.pop_or_enable_notification()? {
            self.metrics.remaining_reqs_count.add(queue.len().into());
            let processing_result =
                match Request::parse(&head, &active_state.mem, self.disk.nsectors) {
                    Ok(request) => {
                        if request.rate_limit(&mut self.rate_limiter) {
                            // Stop processing the queue and return this descriptor chain to the
                            // avail ring, for later processing.
                            queue.undo_pop();
                            self.metrics.rate_limiter_throttled_events.inc();
                            break;
                        }

                        request.process(
                            &mut self.disk,
                            head.index,
                            &active_state.mem,
                            &self.metrics,
                            self.acked_features & (1u64 << VIRTIO_BLK_F_DISCARD) != 0,
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
                    self.is_io_engine_throttled = true;
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
            active_state
                .interrupt
                .trigger(VirtioInterruptType::Queue(0))
                .unwrap_or_else(|_| {
                    self.metrics.event_fails.inc();
                });
        }

        if let FileEngine::Async(ref mut engine) = self.disk.file_engine
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

    fn process_async_completion_queue(&mut self) {
        let engine = unwrap_async_file_engine_or_return!(&mut self.disk.file_engine);

        // This is safe since we checked in the event handler that the device is activated.
        let active_state = self.device_state.active_state().unwrap();
        let queue = &mut self.queues[0];
        let mut failed_requests = Vec::new();

        loop {
            match engine.pop(&active_state.mem) {
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
                            Err(IoErr::FileEngine(block_io::BlockIoError::Async(
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
                    let finished = pending.finish(&active_state.mem, res, &self.metrics);
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
            active_state
                .interrupt
                .trigger(VirtioInterruptType::Queue(0))
                .unwrap_or_else(|_| {
                    self.metrics.event_fails.inc();
                });
        }

        for failed in failed_requests {
            self.keep_failed(failed);
        }
    }

    pub fn process_async_completion_event(&mut self) {
        let engine = unwrap_async_file_engine_or_return!(&mut self.disk.file_engine);

        if let Err(err) = engine.completion_evt().read() {
            error!("Failed to get async completion event: {:?}", err);
        } else {
            self.process_async_completion_queue();

            if self.is_io_engine_throttled {
                self.is_io_engine_throttled = false;
                self.process_queue(0).unwrap()
            }
        }
    }

    /// Update the backing file and the config space of the block device.
    pub fn update_disk_image(&mut self, disk_image_path: String) -> Result<(), VirtioBlockError> {
        self.disk.update(disk_image_path, self.read_only)?;
        self.config_space.capacity = self.disk.nsectors.to_le(); // virtio_block_config_space();

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
        self.rate_limiter.update_buckets(bytes, ops);
    }

    /// Retrieve the file engine type.
    pub fn file_engine_type(&self) -> FileEngineType {
        match self.disk.file_engine {
            FileEngine::Sync(_) => FileEngineType::Sync,
            FileEngine::Async(_) => FileEngineType::Async,
        }
    }

    fn drain_and_flush(&mut self, discard: bool) {
        if let Err(err) = self.disk.file_engine.drain_and_flush(discard) {
            error!("Failed to drain ops and flush block data: {:?}", err);
        }
    }

    /// Prepare device for being snapshotted.
    pub fn prepare_save(&mut self) {
        if !self.is_activated() {
            return;
        }

        self.drain_and_flush(false);
        if let FileEngine::Async(ref _engine) = self.disk.file_engine {
            self.process_async_completion_queue();
        }
    }

    /// Ends the requests in flight with no `fsync`: at a stop of the guest and at a
    /// checkpoint. Their answers are written (or they are kept, when the disk failed them), so
    /// that after it the device writes nothing into guest memory until it is kicked.
    pub fn drain(&mut self) {
        if !self.is_activated() {
            return;
        }

        if let FileEngine::Async(ref mut engine) = self.disk.file_engine {
            if let Err(err) = engine.drain(false) {
                error!("Failed to drain block requests: {:?}", err);
            }
            self.process_async_completion_queue();
        }
    }
}

impl VirtioDevice for VirtioBlock {
    impl_device_type!(VirtioDeviceType::Block);

    fn id(&self) -> &str {
        &self.id
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

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .deref()
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

        for q in self.queues.iter_mut() {
            q.initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }

        let event_idx = self.has_feature(u64::from(VIRTIO_RING_F_EVENT_IDX));
        if event_idx {
            for queue in &mut self.queues {
                queue.enable_notif_suppression();
            }
        }

        if self.activate_evt.write(1).is_err() {
            self.metrics.activate_fails.inc();
            return Err(ActivateError::EventFd);
        }
        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn deactivate(&mut self) {
        self.device_state = DeviceState::Inactive;
    }

    fn _reset(&mut self) -> bool {
        if let Err(err) = self.disk.file_engine.drain(true) {
            error!("Failed to reset block IO engine: {:?}", err);
            return false;
        }
        self.is_io_engine_throttled = false;
        self.kept.clear();
        self.stopped_on_error = false;
        self.error_pending = false;
        true
    }

    fn kick(&mut self) {
        // A resume: the kept requests run again from their start when the queue is taken.
        self.stopped_on_error = false;
        self.error_pending = false;
        if self.is_activated() {
            self.notify_queue_events();
        }
    }

    fn quiesce(&mut self) {
        self.drain();
    }

    fn prepare_checkpoint(&mut self) {
        self.drain();
    }
}

impl Drop for VirtioBlock {
    fn drop(&mut self) {
        match self.cache_type {
            CacheType::Unsafe => {
                if let Err(err) = self.disk.file_engine.drain(true) {
                    error!("Failed to drain ops on drop: {:?}", err);
                }
            }
            CacheType::Writeback => {
                self.drain_and_flush(true);
            }
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
    use crate::devices::virtio::block::virtio::IO_URING_NUM_ENTRIES;
    use crate::devices::virtio::block::virtio::test_utils::{
        RequestDescriptorChain, default_block, default_block_with_path, read_blk_req_descriptors,
        set_queue, set_rate_limiter, simulate_async_completion_event,
        simulate_queue_and_async_completion_events, simulate_queue_event,
    };
    use crate::devices::virtio::queue::{
        FIRECRACKER_MAX_QUEUE_SIZE, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
    };
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::rate_limiter::TokenType;
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
                DiskProperties::new(String::from(f.as_path().to_str().unwrap()), true, engine)
                    .unwrap();

            assert_eq!(size, u64::from(SECTOR_SIZE) * num_sectors);
            assert_eq!(disk_properties.nsectors, num_sectors);
            // Testing `backing_file.virtio_block_disk_image_id()` implies
            // duplicating that logic in tests, so skipping it.

            let res = DiskProperties::new("invalid-disk-path".to_string(), true, engine);
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
                | (1u64 << VIRTIO_BLK_F_TOPOLOGY);

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
                    .disk
                    .file_engine
                    .file()
                    .seek(SeekFrom::Start(0))
                    .unwrap();
                block.disk.file_engine.file().read_exact(&mut buf).unwrap();
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
                    .disk
                    .file_engine
                    .file()
                    .seek(SeekFrom::End(0))
                    .unwrap();
                block.disk.file_engine.file().set_len(size / 2).unwrap();
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
                    .disk
                    .file_engine
                    .file()
                    .seek(SeekFrom::End(0))
                    .unwrap();
                block.disk.file_engine.file().set_len(size / 2).unwrap();
                // Update sector number: stored at `request_type_addr.0 + 8`
                mem.write_obj(5, GuestAddress(request_type_addr.0 + 8))
                    .unwrap();

                // This will attempt to read past end of file.
                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);

                // No data since can't read past end of file, only status byte length.
                assert_eq!(vq.used.ring[0].get().len, 1);
                assert_eq!(
                    mem.read_obj::<u32>(status_addr).unwrap(),
                    VIRTIO_BLK_S_IOERR
                );

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
                    .disk
                    .file_engine
                    .file()
                    .seek(SeekFrom::Start(512))
                    .unwrap();
                block
                    .disk
                    .file_engine
                    .file()
                    .write_all(&rand_data[512..])
                    .unwrap();

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
            let blk_metadata = block.disk.file_engine.file().metadata();

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
            block.queues[0] = vq.create_queue();
            block.activate(mem.clone(), interrupt).unwrap();

            // Run scenario that doesn't trigger FullSq BlockError: Add sq_size flush requests.
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES);
            simulate_queue_event(&mut block, Some(false));
            assert!(!block.is_io_engine_throttled);
            simulate_async_completion_event(&mut block, true);
            check_flush_requests_batch(IO_URING_NUM_ENTRIES, &vq);

            // Run scenario that triggers FullSqError : Add sq_size + 10 flush requests.
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES + 10);
            simulate_queue_event(&mut block, Some(false));
            assert!(block.is_io_engine_throttled);
            // When the async_completion_event is triggered:
            // 1. sq_size requests should be processed processed.
            // 2. is_io_engine_throttled should be set back to false.
            // 3. process_queue() should be called again.
            simulate_async_completion_event(&mut block, true);
            assert!(!block.is_io_engine_throttled);
            check_flush_requests_batch(IO_URING_NUM_ENTRIES, &vq);
            // check that process_queue() was called again resulting in the processing of the
            // remaining 10 ops.
            simulate_async_completion_event(&mut block, true);
            assert!(!block.is_io_engine_throttled);
            check_flush_requests_batch(IO_URING_NUM_ENTRIES + 10, &vq);
        }

        // FullCQueue BlockError
        {
            let mut block = default_block(FileEngineType::Async);

            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, IO_URING_NUM_ENTRIES * 4);
            block.queues[0] = vq.create_queue();
            block.activate(mem.clone(), interrupt).unwrap();

            // Run scenario that triggers FullCqError. Push 2 * IO_URING_NUM_ENTRIES and wait for
            // completion. Then try to push another entry.
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES);
            simulate_queue_event(&mut block, Some(false));
            assert!(!block.is_io_engine_throttled);
            thread::sleep(Duration::from_millis(150));
            add_flush_requests_batch(&mut block, &vq, IO_URING_NUM_ENTRIES);
            simulate_queue_event(&mut block, Some(false));
            assert!(!block.is_io_engine_throttled);
            thread::sleep(Duration::from_millis(150));

            add_flush_requests_batch(&mut block, &vq, 1);
            simulate_queue_event(&mut block, Some(false));
            assert!(block.is_io_engine_throttled);
            simulate_async_completion_event(&mut block, true);
            assert!(!block.is_io_engine_throttled);
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
            block.queues[0] = vq.create_queue();
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
            block.activate(mem.clone(), interrupt).unwrap();
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
                assert!(block.rate_limiter.is_blocked());
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
                assert!(!block.rate_limiter.is_blocked());
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
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            // Create ops rate limiter that allows only 10 ops/s with bucket size of 1 ops.
            let mut rl = RateLimiter::new(0, 0, 0, 1, 0, 100);
            // Use up the budget.
            assert!(rl.consume(1, TokenType::Ops));

            set_rate_limiter(&mut block, rl);

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
                assert!(block.rate_limiter.is_blocked());
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
                assert!(block.rate_limiter.is_blocked());
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
                assert!(!block.rate_limiter.is_blocked());
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

            assert_eq!(
                block.disk.file_engine.file().metadata().unwrap().st_ino(),
                mdata.st_ino()
            );
            assert_eq!(block.disk.image_id, id.as_slice());
        }
    }

    /// Completes the requests of an Async drive that are in flight, as the event loop would.
    fn complete_async(block: &mut VirtioBlock) {
        if let FileEngine::Async(ref mut engine) = block.disk.file_engine {
            engine.drain(false).unwrap();
        }
        thread::sleep(Duration::from_millis(150));
        block.process_async_completion_event();
    }

    fn async_engine(block: &mut VirtioBlock) -> &mut block_io::AsyncFileEngine {
        match block.disk.file_engine {
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
            .open(&block.disk.file_path)
            .unwrap()
            .write_all_at(data, offset)
            .unwrap();
    }

    fn read_file_at(block: &VirtioBlock, offset: u64, len: usize) -> Vec<u8> {
        use std::os::unix::fs::FileExt;
        let mut buf = vec![0u8; len];
        File::open(&block.disk.file_path)
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
        assert_eq!(block.kept.len(), 1);
        assert!(block.stopped_on_error);
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
        assert!(block.kept.is_empty());
        assert!(!block.stopped_on_error);
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
        assert_eq!(block.kept.len(), 1);
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
        assert_eq!(restored.kept.len(), 1);
        assert!(restored.stopped_on_error);
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
        assert!(block.kept.is_empty());

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
            cache_type: CacheType::Writeback,
            rate_limiter: None,
            file_engine_type: FileEngineType::Async,
            blk_size: None,
            topology: None,
        };
        let mut block = VirtioBlock::new(config).unwrap();
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        block.queues[0] = vq.create_queue();
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
            let fd = block.disk.file_engine.file().as_raw_fd();
            // SAFETY: fcntl on a descriptor of this test.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert_eq!(flags & libc::O_DIRECT != 0, direct);

            // A new path of the drive (PATCH /drives) is opened the same way.
            let f = TempFile::new().unwrap();
            f.as_file().set_len(0x1000).unwrap();
            block
                .update_disk_image(f.as_path().to_str().unwrap().to_string())
                .unwrap();
            let fd = block.disk.file_engine.file().as_raw_fd();
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
                assert_eq!(block.kept.len(), 1);
                assert!(block.stopped_on_error);
                assert!(block.take_disk_error());
                assert_eq!(async_engine(&mut block).taken_jobs(), 0);
                assert!(read_backing(&path, MODEL_LEN) == model);

                // At the resume it runs again from its start, whole.
                block.kick();
                block.process_queue_event();
                complete_async(&mut block);
                assert_eq!(vq.used.idx.get(), 1, "{path} pass {pass}");
                assert_eq!(status_of(&mem, 0), VIRTIO_BLK_S_OK);
                assert!(block.kept.is_empty());
                model[sector_range(sector, len)].copy_from_slice(&data);
                assert!(
                    read_backing(&path, MODEL_LEN) == model,
                    "{path} pass {pass}"
                );
            }
        }
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
                assert!(block.kept.is_empty());
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
        assert_eq!(block.kept.len(), 1);
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
