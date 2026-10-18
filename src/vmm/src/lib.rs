// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Virtual Machine Monitor that leverages the Linux Kernel-based Virtual Machine (KVM),
//! and other virtualization features to run a single lightweight micro-virtual
//! machine (microVM).
#![warn(missing_docs)]
#![warn(clippy::undocumented_unsafe_blocks)]
#![allow(clippy::blanket_clippy_restriction_lints)]

/// Implements platform specific functionality.
/// Supported platforms: x86_64 and aarch64.
pub mod arch;

/// High-level interface over Linux io_uring.
///
/// Aims to provide an easy-to-use interface, while making some Firecracker-specific simplifying
/// assumptions. The crate does not currently aim at supporting all io_uring features and use
/// cases. For example, it only works with pre-registered fds and read/write/fsync requests.
///
/// Requires at least kernel version 5.10.51.
/// For more information on io_uring, refer to the man pages.
/// [This pdf](https://kernel.dk/io_uring.pdf) is also very useful, though outdated at times.
pub mod io_uring;

/// # Rate Limiter
///
/// Provides a rate limiter written in Rust useful for IO operations that need to
/// be throttled.
///
/// ## Behavior
///
/// The rate limiter starts off as 'unblocked' with two token buckets configured
/// with the values passed in the `RateLimiter::new()` constructor.
/// All subsequent accounting is done independently for each token bucket based
/// on the `TokenType` used. If any of the buckets runs out of budget, the limiter
/// goes in the 'blocked' state. At this point an internal timer is set up which
/// will later 'wake up' the user in order to retry sending data. The 'wake up'
/// notification will be dispatched as an event on the FD provided by the `AsRawFD`
/// trait implementation.
///
/// The contract is that the user shall also call the `event_handler()` method on
/// receipt of such an event.
///
/// The token buckets are replenished when a called `consume()` doesn't find enough
/// tokens in the bucket. The amount of tokens replenished is automatically calculated
/// to respect the `complete_refill_time` configuration parameter provided by the user.
/// The token buckets will never replenish above their respective `size`.
///
/// Each token bucket can start off with a `one_time_burst` initial extra capacity
/// on top of their `size`. This initial extra credit does not replenish and
/// can be used for an initial burst of data.
///
/// The granularity for 'wake up' events when the rate limiter is blocked is
/// currently hardcoded to `100 milliseconds`.
///
/// ## Limitations
///
/// This rate limiter implementation relies on the *Linux kernel's timerfd* so its
/// usage is limited to Linux systems.
///
/// Another particularity of this implementation is that it is not self-driving.
/// It is meant to be used in an external event loop and thus implements the `AsRawFd`
/// trait and provides an *event-handler* as part of its API. This *event-handler*
/// needs to be called by the user on every event on the rate limiter's `AsRawFd` FD.
pub mod rate_limiter;

/// Module for handling ACPI tables.
/// Currently, we only use ACPI on x86 microVMs.
#[cfg(target_arch = "x86_64")]
pub mod acpi;
/// Handles setup and initialization a `Vmm` object.
pub mod builder;
/// The checkpoint loop (`/space/checkpoint`): the stream, the held output, the lease.
pub mod checkpoint;
/// Types for guest configuration.
pub mod cpu_config;
pub(crate) mod device_manager;
/// Emulates virtual and hardware devices.
#[allow(missing_docs)]
pub mod devices;
/// minimalist HTTP/TCP/IPv4 stack named DUMBO
pub mod dumbo;
/// Support for GDB debugging the guest
#[cfg(feature = "gdb")]
pub mod gdb;
/// Logger
pub mod logger;
/// microVM Metadata Service MMDS
pub mod mmds;
/// PCI specific emulation code.
pub mod pci;
/// Save/restore utilities.
pub mod persist;
/// Resource store for configured microVM resources.
pub mod resources;
/// microVM RPC API adapters.
pub mod rpc_interface;
/// Seccomp filter utilities.
pub mod seccomp;
/// Signal handling utilities.
pub mod signal_handler;
/// Serialization and deserialization facilities
pub mod snapshot;
/// The parts of the `/space/` endpoints that run beside the VMM: the fill of guest memory.
pub mod space;
/// Utility functions for integration and benchmark testing
pub mod test_utils;
/// Utility functions and struct
pub mod utils;
/// Wrappers over structures used to configure the VMM.
pub mod vmm_config;
/// Module with virtual state structs.
pub mod vstate;

/// Module with initrd.
pub mod initrd;

use std::collections::HashMap;
use std::io;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use device_manager::DeviceManager;
use event_manager::{EventManager as BaseEventManager, EventOps, Events, MutEventSubscriber};
use snapshot::Persist;
use vm_memory::GuestMemoryBackend;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::terminal::Terminal;
use vstate::vcpu::{self, VcpuSendEventError};

use crate::cpu_config::templates::CpuConfiguration;
use crate::devices::virtio::balloon::device::{HintingStatus, StartHintingCmd};
use crate::devices::virtio::balloon::{
    BALLOON_DEV_ID, Balloon, BalloonConfig, BalloonError, BalloonStats,
};
use crate::devices::virtio::block::BlockError;
use crate::devices::virtio::block::device::Block;
use crate::devices::virtio::block::virtio::device::DISK_ERROR_EVT;
use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceId, VirtioDeviceType};
use crate::devices::virtio::gpu::Gpu;
use crate::devices::virtio::mem::device::VirtioMem;
use crate::devices::virtio::mem::{VIRTIO_MEM_DEV_ID, VirtioMemError, VirtioMemStatus};
use crate::devices::virtio::net::Net;
use crate::devices::virtio::pmem::device::Pmem;
use crate::devices::virtio::rng::Entropy;
use crate::devices::virtio::vsock::{Vsock, VsockUnixBackend};
use crate::logger::{METRICS, MetricsError, log_dev_preview_warning};
use crate::mmds::data_store::Mmds;
use crate::persist::{MicrovmState, MicrovmStateError, VmInfo};
use crate::rate_limiter::BucketUpdate;
use crate::resources::VmmConfig;
use crate::rpc_interface::VmmActionError;
use crate::vmm_config::HotplugDeviceConfig;
use crate::vmm_config::balloon::BalloonDeviceConfig;
use crate::vmm_config::boot_source::BootSourceConfig;
use crate::vmm_config::entropy::EntropyDeviceConfig;
use crate::vmm_config::instance_info::{InstanceInfo, PausedReason, VmState};
use crate::vmm_config::machine_config::MachineConfig;
use crate::vmm_config::memory_hotplug::MemoryHotplugConfig;
use crate::vmm_config::mmds::MmdsConfig;
use crate::vmm_config::net::NetworkInterfaceConfig;
use crate::vmm_config::space::{FillStatus, MemoryRegion, MemoryRegions};
use crate::vmm_config::vsock::VsockDeviceConfig;
pub use crate::vstate::kvm::Kvm;
use crate::vstate::memory::{GuestMemoryMmap, GuestMemoryRegion};
#[cfg(target_arch = "aarch64")]
use crate::vstate::vcpu::VcpuState;
pub use crate::vstate::vcpu::{Vcpu, VcpuConfig, VcpuEvent, VcpuHandle, VcpuResponse};
pub use crate::vstate::vm::{StartVcpusError, Vm};

/// Shorthand type for the EventManager flavour used by Firecracker.
pub type EventManager = BaseEventManager<Arc<Mutex<dyn MutEventSubscriber>>>;

// Since the exit code names e.g. `SIGBUS` are most appropriate yet trigger a test error with the
// clippy lint `upper_case_acronyms` we have disabled this lint for this enum.
/// Vmm exit-code type.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FcExitCode {
    /// Success exit code.
    Ok = 0,
    /// Generic error exit code.
    GenericError = 1,
    /// Generic exit code error; not possible to occur if the program logic is sound.
    UnexpectedError = 2,
    /// Firecracker was shut down after intercepting a restricted system call.
    BadSyscall = 148,
    /// Firecracker was shut down after intercepting `SIGBUS`.
    SIGBUS = 149,
    /// Firecracker was shut down after intercepting `SIGSEGV`.
    SIGSEGV = 150,
    /// Firecracker was shut down after intercepting `SIGXFSZ`.
    SIGXFSZ = 151,
    /// Firecracker was shut down after intercepting `SIGXCPU`.
    SIGXCPU = 154,
    /// Firecracker was shut down after intercepting `SIGPIPE`.
    SIGPIPE = 155,
    /// Firecracker was shut down after intercepting `SIGHUP`.
    SIGHUP = 156,
    /// Firecracker was shut down after intercepting `SIGILL`.
    SIGILL = 157,
    /// Bad configuration for microvm's resources, when using a single json.
    BadConfiguration = 152,
    /// Command line arguments parsing error.
    ArgParsing = 153,
}

/// Timeout used in recv_timeout, when waiting for a vcpu response on
/// Pause/Resume/Save/Restore. A high enough limit that should not be reached during normal usage,
/// used to detect a potential vcpu deadlock.
pub const RECV_TIMEOUT_SEC: Duration = Duration::from_secs(30);

/// Default byte limit of accepted http requests on API and MMDS servers.
pub const HTTP_MAX_PAYLOAD_SIZE: usize = 51200;

/// Errors associated with the VMM internal logic. These errors cannot be generated by direct user
/// input, but can result from bad configuration of the host (for example if Firecracker doesn't
/// have permissions to open the KVM fd).
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VmmError {
    #[cfg(target_arch = "aarch64")]
    /// Invalid command line error.
    Cmdline,
    /// Device manager error: {0}
    DeviceManager(#[from] device_manager::DeviceManagerCreateError),
    /// MMIO Device manager error: {0}
    MmioDeviceManager(device_manager::mmio::MmioError),
    /// Error getting the KVM dirty bitmap. {0}
    DirtyBitmap(kvm_ioctls::Error),
    /// I8042 error: {0}
    I8042Error(devices::legacy::I8042DeviceError),
    #[cfg(target_arch = "x86_64")]
    /// Cannot add devices to the legacy I/O Bus. {0}
    LegacyIOBus(device_manager::legacy::LegacyDeviceError),
    /// Metrics error: {0}
    Metrics(MetricsError),
    /// Cannot add a device to the MMIO Bus. {0}
    RegisterMMIODevice(device_manager::mmio::MmioError),
    /// Error writing to the serial console: {0}
    Serial(io::Error),
    /// Error creating the vcpu: {0}
    VcpuCreate(vstate::vcpu::VcpuError),
    /// Cannot send event to vCPU. {0}
    VcpuEvent(vstate::vcpu::VcpuError),
    /// Cannot create a vCPU handle. {0}
    VcpuHandle(vstate::vcpu::VcpuError),
    /// Failed to start vCPUs
    VcpuStart(StartVcpusError),
    /// Failed to pause the vCPUs.
    VcpuPause,
    /// Failed to exit the vCPUs.
    VcpuExit,
    /// Failed to resume the vCPUs.
    VcpuResume,
    /// Failed to message the vCPUs.
    VcpuMessage,
    /// Operation not supported on {0} VMs.
    NotSupportedOnVmType(&'static str),
    /// Cannot spawn Vcpu thread: {0}
    VcpuSpawn(io::Error),
    /// KvmVm error: {0}
    KvmVm(#[from] vstate::vm::VmError),
    /// Kvm error: {0}
    Kvm(#[from] vstate::kvm::KvmError),
    /// Failed perform action on device: {0}
    FindDeviceError(#[from] device_manager::FindDeviceError),
    /// Block: {0}
    Block(#[from] BlockError),
    /// Balloon: {0}
    Balloon(#[from] BalloonError),
    /// Operation not supported on this VM type
    NotSupported,
    /// Failed to create memory hotplug device: {0}
    VirtioMem(#[from] VirtioMemError),
    /// The resume is refused: {0}
    ResumeRefused(String),
    /// Fill of guest memory: {0}
    Fill(#[from] space::FillError),
}

/// Shorthand type for KVM dirty page bitmap.
pub type DirtyBitmap = HashMap<u32, Vec<u64>>;

/// Returns the size of guest memory, in MiB.
pub(crate) fn mem_size_mib(guest_memory: &GuestMemoryMmap) -> u64 {
    guest_memory.iter().map(|region| region.len()).sum::<u64>() >> 20
}

/// Error type for [`Vmm::dump_cpu_config()`]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DumpCpuConfigError {
    /// Failed to send event to vcpu thread: {0}
    SendEvent(#[from] VcpuSendEventError),
    /// Got unexpected response from vcpu thread.
    UnexpectedResponse,
    /// Failed to dump CPU config: {0}
    DumpCpuConfig(#[from] vcpu::VcpuError),
    /// Operation not allowed: {0}
    NotAllowed(String),
}

/// Contains the state and associated methods required for the Firecracker VMM.
#[derive(Debug)]
pub struct Vmm {
    // The checkpoint loop. First, so that it is dropped (its threads ended) before the guest
    // memory that its sender may read.
    checkpoint: checkpoint::Checkpointer,
    /// The [`InstanceInfo`] state of this [`Vmm`].
    pub instance_info: InstanceInfo,
    /// Machine config
    pub machine_config: MachineConfig,
    boot_source_config: BootSourceConfig,
    shutdown_exit_code: Option<FcExitCode>,

    /// VM object.
    pub vm: Vm,
    // Device manager
    device_manager: DeviceManager,

    // The guest's clock while the guest is stopped: saved when it stopped (a pause request,
    // the end of a lease, a disk error), or taken from the state at a load. It is set again
    // just before the vCPUs run, so that the time for which the guest stands stopped or waits
    // loaded is not time of the guest.
    #[cfg(target_arch = "x86_64")]
    stopped_clock: Option<StoppedClock>,
    // Why a resume is refused, while one is.
    resume_refused: Option<String>,
    // The thread that populates guest memory (`PUT /space/fill`).
    filler: space::Filler,
}

/// The guest's clock of a stopped guest, and whether KVM adds the wall-clock time since it was
/// read when it is set (`clock_realtime` of a load).
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone, Copy)]
pub struct StoppedClock {
    /// The clock.
    pub clock: kvm_bindings::kvm_clock_data,
    /// Whether the time since it was read is added when it is set.
    pub realtime: bool,
}

impl Vmm {
    /// Gets Vmm version.
    pub fn version(&self) -> String {
        self.instance_info.vmm_version.clone()
    }

    /// Gets Vmm instance info.
    pub fn instance_info(&self) -> InstanceInfo {
        self.instance_info.clone()
    }

    /// Gets MMDS reference, if any.
    pub fn get_mmds(&self) -> Option<Arc<Mutex<Mmds>>> {
        let mut mmds = None;
        self.device_manager
            .for_each_virtio_device(|device_type, device| {
                if device_type == VirtioDeviceType::Net
                    && let Some(net) = device.as_any().downcast_ref::<Net>()
                    && let Some(mmds_ns) = &net.mmds_ns
                {
                    mmds = Some(mmds_ns.mmds.clone());
                }
            });

        mmds
    }

    /// Provides the Vmm shutdown exit code if there is one.
    pub fn shutdown_exit_code(&self) -> Option<FcExitCode> {
        self.shutdown_exit_code
    }

    /// Builds a FullVmConfig from the current Vmm state.
    pub fn full_config(&self) -> VmmConfig {
        let mut block = Vec::new();
        let mut net = Vec::new();
        let mut net_with_mmds = Vec::new();
        let mut pmem = Vec::new();
        let mut balloon = None;
        let mut vsock = None;
        let mut entropy = None;
        let mut gpu = None;
        let mut memory_hotplug = None;
        let mut mmds_ipv4_address = None;
        let mut mmds_ref = None;

        self.device_manager
            .for_each_virtio_device(|device_type, device| match device_type {
                VirtioDeviceType::Block => {
                    if let Some(b) = device.as_any().downcast_ref::<Block>() {
                        block.push(b.config());
                    }
                }
                VirtioDeviceType::Net => {
                    if let Some(n) = device.as_any().downcast_ref::<Net>() {
                        net.push(NetworkInterfaceConfig::from(n));
                        if let Some(mmds_ns) = &n.mmds_ns {
                            net_with_mmds.push(n.id.clone());
                            if mmds_ref.is_none() {
                                mmds_ref = Some(mmds_ns.mmds.clone());
                                mmds_ipv4_address = Some(mmds_ns.ipv4_addr());
                            }
                        }
                    }
                }
                VirtioDeviceType::Pmem => {
                    if let Some(p) = device.as_any().downcast_ref::<Pmem>() {
                        pmem.push(p.config.clone());
                    }
                }
                VirtioDeviceType::Balloon => {
                    if let Some(b) = device.as_any().downcast_ref::<Balloon>() {
                        balloon = Some(BalloonDeviceConfig::from(b.config()));
                    }
                }
                VirtioDeviceType::Vsock => {
                    if let Some(v) = device.as_any().downcast_ref::<Vsock<VsockUnixBackend>>() {
                        vsock = Some(VsockDeviceConfig::from(v));
                    }
                }
                VirtioDeviceType::Rng => {
                    if let Some(e) = device.as_any().downcast_ref::<Entropy>() {
                        entropy = Some(EntropyDeviceConfig::from(e));
                    }
                }
                VirtioDeviceType::Mem => {
                    if let Some(m) = device.as_any().downcast_ref::<VirtioMem>() {
                        memory_hotplug = Some(MemoryHotplugConfig::from(m));
                    }
                }
                VirtioDeviceType::Gpu => {
                    if let Some(g) = device.as_any().downcast_ref::<Gpu>() {
                        gpu = Some(g.cfg.clone());
                    }
                }
                // Part of the GPU's configuration (`input`, `sound`).
                VirtioDeviceType::Input | VirtioDeviceType::Sound => {}
            });

        let mmds_config = mmds_ref.map(|mmds| {
            let mmds = mmds.lock().expect("Poisoned lock");
            MmdsConfig {
                version: mmds.version(),
                ipv4_address: mmds_ipv4_address,
                network_interfaces: net_with_mmds,
                imds_compat: mmds.imds_compat(),
            }
        });

        // This must match the From<&VmResources> for VmmConfig implementation
        // in resources.rs which is used to retrieve the config before the VM
        // is started.
        VmmConfig {
            balloon,
            drives: block,
            boot_source: self.boot_source_config.clone(),
            cpu_config: None,
            logger: None,
            machine_config: Some(self.machine_config.clone()),
            metrics: None,
            mmds_config,
            network_interfaces: net,
            vsock,
            entropy,
            gpu,
            pmem_devices: pmem,
            // serial_config is marked serde(skip) so that it doesnt end up in snapshots
            serial_config: None,
            memory_hotplug,
        }
    }

    /// Check if the VM has any devices without snapshot support
    pub fn check_unsnapshottable_devices(&self) -> Result<(), MicrovmStateError> {
        let mut tuples = Vec::new();
        self.device_manager
            .for_each_virtio_device(|device_type, device| {
                if let VirtioDeviceType::Block = device_type
                    && let Some(b) = device.as_any().downcast_ref::<Block>()
                    && b.is_vhost_user()
                {
                    tuples.push(("vhost-user-block", b.id().to_owned()));
                }
            });
        if tuples.is_empty() {
            Ok(())
        } else {
            let msg = tuples
                .iter()
                .map(|(t, id)| format!("{t}(id: {id})"))
                .collect::<Vec<_>>()
                .join(",");
            Err(MicrovmStateError::NotAllowed(format!(
                "Devices without snapshot support are present: {msg}"
            )))
        }
    }

    /// Resumes a stopped guest: the devices are kicked (a drive runs its kept requests again),
    /// the clock of the stop is set, and the vCPUs run. A refused or failed resume leaves the
    /// guest stopped, with its reason.
    pub fn resume_vm(&mut self) -> Result<(), VmmError> {
        // The lease is checked against its clock too: its timer cannot fire while the guest is
        // stopped by a long call.
        self.lease_check();
        let kvm_vm = self
            .vm
            .as_kvm()
            .ok_or_else(|| VmmError::NotSupportedOnVmType(self.vm.type_name()))?;
        if let Some(why) = &self.resume_refused {
            return Err(VmmError::ResumeRefused(why.clone()));
        }
        self.device_manager.kick_virtio_devices();
        #[cfg(target_arch = "x86_64")]
        if let Some(stopped) = &self.stopped_clock {
            kvm_vm
                .set_clock(&stopped.clock, stopped.realtime)
                .map_err(vstate::vm::VmError::Arch)?;
        }
        kvm_vm.resume_vcpus()?;
        #[cfg(target_arch = "x86_64")]
        {
            self.stopped_clock = None;
        }
        self.instance_info.set_running();
        // An armed lease of the checkpoints begins at the resume.
        self.checkpoint_resumed();
        Ok(())
    }

    /// Stops the guest for a pause request of the API. See [`Vmm::stop_vm`].
    pub fn pause_vm(&mut self) -> Result<(), VmmError> {
        self.stop_vm(PausedReason::Api)
    }

    /// Stops the guest for `reason`: the vCPUs stop, the guest's clock is saved, and the
    /// devices end their work in flight (the disk requests of the `Async` engine end). The
    /// loop of the VMM thread then serves only API requests until a resume succeeds, so that no
    /// device writes into guest memory while the guest is stopped.
    ///
    /// A guest that is stopped already keeps the reason of its first stop; the end of a lease
    /// replaces it, because it decides whether a resume is taken.
    pub fn stop_vm(&mut self, reason: PausedReason) -> Result<(), VmmError> {
        let kvm_vm = self
            .vm
            .as_kvm()
            .ok_or_else(|| VmmError::NotSupportedOnVmType(self.vm.type_name()))?;
        if self.instance_info.state == VmState::Paused {
            if reason == PausedReason::Lease {
                self.instance_info.set_paused(reason);
            }
            return Ok(());
        }
        kvm_vm.pause_vcpus()?;
        // The vCPUs are stopped: the stop goes on also when the clock cannot be read (the
        // resume then sets no clock, as before).
        #[cfg(target_arch = "x86_64")]
        if self.stopped_clock.is_none() {
            match kvm_vm.get_clock() {
                Ok(clock) => {
                    self.stopped_clock = Some(StoppedClock {
                        clock,
                        realtime: false,
                    })
                }
                Err(err) => error!("Failed to save the guest's clock at a stop: {}", err),
            }
        }
        self.device_manager.quiesce_virtio_devices();
        info!("The guest stopped: {}", reason.name());
        self.instance_info.set_paused(reason);
        Ok(())
    }

    /// Stops a running guest whose drive failed a request (`paused_reason: disk-error`). A
    /// stopped guest stays as it is: its drive runs the kept requests again at the resume.
    pub fn handle_disk_error(&mut self) {
        if let Some(drive_id) = self.device_manager.take_disk_error()
            && self.instance_info.state == VmState::Running
            && let Err(err) = self.stop_vm(PausedReason::DiskError(drive_id))
        {
            error!("Failed to stop the guest on a disk error: {}", err);
        }
    }

    /// Whether the guest is stopped; the loop of the VMM thread then serves only API requests.
    pub fn is_stopped(&self) -> bool {
        self.instance_info.state == VmState::Paused
    }

    /// Refuses every resume with `why`, or takes resumes again with `None`.
    pub fn refuse_resume(&mut self, why: Option<String>) {
        self.resume_refused = why;
    }

    /// Called at least every 100 ms while the guest is stopped and the loop of the VMM thread
    /// serves only API requests: the place for work that must go on in a stop (the stamp of
    /// the main loop, the events of the checkpoint loop).
    pub fn stopped_tick(&mut self) {
        self.checkpoint_service();
    }

    /// The descriptors that wake the loop of a stopped guest besides an API request: those of
    /// the checkpoint loop.
    pub fn stopped_wait_fds(&self) -> Vec<std::os::fd::RawFd> {
        self.checkpoint.fds()
    }

    /// The state of the checkpoint mode (`GET /space/checkpoint`).
    pub fn checkpoint_info(&self) -> vmm_config::checkpoint::CheckpointInfo {
        self.checkpoint.info()
    }

    /// Whether the checkpoint mode or its tracking runs: a snapshot with memory, which reads
    /// and resets the dirty bitmaps, is refused then.
    pub fn checkpoint_owns_dirty_pages(&self) -> bool {
        self.checkpoint.owns_dirty_pages()
    }

    /// The clock of the stopped guest, if it is stopped.
    #[cfg(target_arch = "x86_64")]
    pub fn stopped_clock(&self) -> Option<&StoppedClock> {
        self.stopped_clock.as_ref()
    }

    /// Sets the clock that the next resume sets (the clock of a loaded state).
    #[cfg(target_arch = "x86_64")]
    pub fn set_stopped_clock(&mut self, clock: Option<StoppedClock>) {
        self.stopped_clock = clock;
    }

    /// The regions of guest memory: where each lies in the process, its size, its guest
    /// address, and its offset in a memory file (the same offsets as a UFFD handler gets).
    pub fn memory_regions(&self) -> MemoryRegions {
        let mut regions = Vec::new();
        if let Some(kvm_vm) = self.vm.as_kvm() {
            let mut offset = 0;
            for region in kvm_vm.guest_memory().iter() {
                let size = region.len();
                regions.push(MemoryRegion {
                    host_addr: region.as_ptr() as u64,
                    size,
                    guest_addr: region.start_addr().0,
                    offset,
                });
                offset += size;
            }
        }
        MemoryRegions { regions }
    }

    /// Starts the fill of every plugged region of guest memory on the fill thread.
    pub fn start_fill(&mut self) -> Result<(), VmmError> {
        let kvm_vm = self
            .vm
            .as_kvm()
            .ok_or_else(|| VmmError::NotSupportedOnVmType(self.vm.type_name()))?;
        let ranges = kvm_vm
            .guest_memory()
            .iter()
            .flat_map(|region| region.plugged_slots())
            .map(|slot| {
                (
                    slot.slice.ptr_guard_mut().as_ptr() as usize,
                    slot.slice.len(),
                )
            })
            .collect();
        self.filler.start(ranges)?;
        Ok(())
    }

    /// What the fill of guest memory is doing.
    pub fn fill_status(&self) -> FillStatus {
        self.filler.status()
    }

    /// Injects CTRL+ALT+DEL keystroke combo in the i8042 device.
    #[cfg(target_arch = "x86_64")]
    pub fn send_ctrl_alt_del(&mut self) -> Result<(), VmmError> {
        self.device_manager
            .legacy_devices
            .as_ref()
            .ok_or(VmmError::NotSupported)?
            .i8042
            .lock()
            .expect("i8042 lock was poisoned")
            .trigger_ctrl_alt_del()
            .map_err(VmmError::I8042Error)
    }

    /// Saves the state of a paused Microvm.
    pub fn save_state(&mut self, vm_info: &VmInfo) -> Result<MicrovmState, MicrovmStateError> {
        self.save_state_with(vm_info, false)
    }

    /// Saves the state of a Microvm whose vCPUs are paused, for a checkpoint: as
    /// [`Vmm::save_state`], but each device is readied by `prepare_checkpoint` in the place of
    /// `prepare_save` (a drive ends its requests in flight with no `fsync`; vsock keeps its
    /// connections). A guest that runs holds the clock of now, one that is stopped the clock of
    /// its stop.
    pub fn save_checkpoint_state(
        &mut self,
        vm_info: &VmInfo,
    ) -> Result<MicrovmState, MicrovmStateError> {
        self.save_state_with(vm_info, true)
    }

    fn save_state_with(
        &mut self,
        vm_info: &VmInfo,
        checkpoint: bool,
    ) -> Result<MicrovmState, MicrovmStateError> {
        self.check_unsnapshottable_devices()?;

        // A snapshot needs a paused guest; a checkpoint is also taken in its own stop of a
        // running guest, whose vCPUs are paused and whose devices are readied by
        // `prepare_checkpoint`.
        if !checkpoint && self.instance_info.state != VmState::Paused {
            return Err(MicrovmStateError::NotAllowed(
                "snapshot requires a paused microVM".into(),
            ));
        }

        // We need to save device state before saving KVM state.
        // Some devices, (at the time of writing this comment block device with async engine)
        // might modify the VirtIO transport and send an interrupt to the guest. If we save KVM
        // state before we save device state, that interrupt will never be delivered to the guest
        // upon resuming from the snapshot.
        let device_states = if checkpoint {
            self.device_manager.save_checkpoint()
        } else {
            self.device_manager.save()
        };
        let kvm_vm = self
            .vm
            .as_kvm()
            .ok_or_else(|| MicrovmStateError::NotAllowed("save_state requires KVM".into()))?;
        let vcpu_states = kvm_vm.save_vcpu_states()?;
        let kvm_state = kvm_vm.kvm().save_state();
        let vm_state = {
            // A stopped guest holds the clock of its stop; a running one the clock of now.
            #[cfg(target_arch = "x86_64")]
            {
                kvm_vm
                    .save_state(self.stopped_clock.as_ref().map(|stopped| &stopped.clock))
                    .map_err(MicrovmStateError::SaveVmState)?
            }
            #[cfg(target_arch = "aarch64")]
            {
                let mpidrs = construct_kvm_mpidrs(&vcpu_states);

                kvm_vm
                    .save_state(&mpidrs)
                    .map_err(MicrovmStateError::SaveVmState)?
            }
        };

        Ok(MicrovmState {
            vm_info: vm_info.clone(),
            kvm_state,
            vm_state,
            vcpu_states,
            device_states,
        })
    }

    /// Dumps CPU configuration.
    pub fn dump_cpu_config(&mut self) -> Result<Vec<CpuConfiguration>, DumpCpuConfigError> {
        let kvm_vm = self
            .vm
            .as_kvm()
            .ok_or_else(|| DumpCpuConfigError::NotAllowed("dump_cpu_config requires KVM".into()))?;
        kvm_vm.dump_cpu_config_states()
    }

    /// Updates the path of the host file backing the emulated block device with id `drive_id`.
    /// We update the disk image on the device and its virtio configuration.
    pub fn update_block_device_path(
        &mut self,
        drive_id: &str,
        path_on_host: String,
    ) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(drive_id, |block: &mut Block| {
                block.update_disk_image(path_on_host)
            })??;
        Ok(())
    }

    /// Updates the rate limiter parameters for block device with `drive_id` id.
    pub fn update_block_rate_limiter(
        &mut self,
        drive_id: &str,
        rl_bytes: BucketUpdate,
        rl_ops: BucketUpdate,
    ) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(drive_id, |block: &mut Block| {
                block.update_rate_limiter(rl_bytes, rl_ops)
            })??;
        Ok(())
    }

    /// Updates the rate limiter parameters for block device with `drive_id` id.
    pub fn update_vhost_user_block_config(&mut self, drive_id: &str) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(drive_id, |block: &mut Block| block.update_config())??;
        Ok(())
    }

    /// Updates the rate limiter parameters for pmem device with `pmem_id` id.
    pub fn update_pmem_rate_limiter(
        &mut self,
        pmem_id: &str,
        rl_bytes: BucketUpdate,
        rl_ops: BucketUpdate,
    ) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(pmem_id, |pmem: &mut Pmem| {
                pmem.update_rate_limiter(rl_bytes, rl_ops)
            })?;
        Ok(())
    }

    /// Updates the rate limiter parameters for net device with `net_id` id.
    pub fn update_net_rate_limiters(
        &mut self,
        net_id: &str,
        rx_bytes: BucketUpdate,
        rx_ops: BucketUpdate,
        tx_bytes: BucketUpdate,
        tx_ops: BucketUpdate,
    ) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(net_id, |net: &mut Net| {
                net.patch_rate_limiters(rx_bytes, rx_ops, tx_bytes, tx_ops)
            })?;
        Ok(())
    }

    /// Returns a reference to the balloon device if present.
    pub fn balloon_config(&self) -> Result<BalloonConfig, VmmError> {
        let config = self
            .device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| dev.config())?;
        Ok(config)
    }

    /// Returns the latest balloon statistics if they are enabled.
    pub fn latest_balloon_stats(&self) -> Result<BalloonStats, VmmError> {
        let stats = self
            .device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| dev.latest_stats())??;
        Ok(stats)
    }

    /// Updates configuration for the balloon device target size.
    pub fn update_balloon_config(&mut self, amount_mib: u32) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| {
                dev.update_size(amount_mib)
            })??;
        Ok(())
    }

    /// Updates configuration for the balloon device as described in `balloon_stats_update`.
    pub fn update_balloon_stats_config(
        &mut self,
        stats_polling_interval_s: u16,
    ) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| {
                dev.update_stats_polling_interval(stats_polling_interval_s)
            })??;
        Ok(())
    }

    /// Returns the current state of the memory hotplug device.
    pub fn memory_hotplug_status(&self) -> Result<VirtioMemStatus, VmmError> {
        self.device_manager
            .with_virtio_device(VIRTIO_MEM_DEV_ID, |dev: &mut VirtioMem| dev.status())
            .map_err(VmmError::FindDeviceError)
    }

    /// Returns the current state of the memory hotplug device.
    pub fn update_memory_hotplug_size(&self, requested_size_mib: u32) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(VIRTIO_MEM_DEV_ID, |dev: &mut VirtioMem| {
                dev.update_requested_size(requested_size_mib)
            })
            .map_err(VmmError::FindDeviceError)??;
        Ok(())
    }

    /// Starts the balloon free page hinting run
    pub fn start_balloon_hinting(&mut self, cmd: StartHintingCmd) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| dev.start_hinting(cmd))??;
        Ok(())
    }

    /// Retrieves the status of the balloon hinting run
    pub fn get_balloon_hinting_status(&mut self) -> Result<HintingStatus, VmmError> {
        let status = self
            .device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| dev.get_hinting_status())??;
        Ok(status)
    }

    /// Stops the balloon free page hinting run
    pub fn stop_balloon_hinting(&mut self) -> Result<(), VmmError> {
        self.device_manager
            .with_virtio_device(BALLOON_DEV_ID, |dev: &mut Balloon| dev.stop_hinting())??;
        Ok(())
    }

    /// Signals Vmm to stop and exit.
    pub fn stop(&mut self, exit_code: FcExitCode) {
        info!("Vmm is stopping.");

        // Break the main event loop, propagating the Vmm exit-code.
        self.shutdown_exit_code = Some(exit_code);
    }

    /// Gets a reference to kvm-ioctls KvmVm
    #[cfg(feature = "gdb")]
    pub fn vm(&self) -> &Vm {
        &self.vm
    }

    /// Attaches a device after VM start
    #[inline]
    pub fn hotplug_device(
        &mut self,
        config: HotplugDeviceConfig,
        event_manager: &mut EventManager,
    ) -> Result<(), VmmActionError> {
        log_dev_preview_warning("PCI device hotplug", None);
        if let HotplugDeviceConfig::Block(block_config) = &config {
            self.machine_config
                .validate_num_queues(&block_config.drive_id, block_config.num_queues)?;
        }
        let kvm_vm = self
            .vm
            .as_kvm()
            .ok_or_else(|| VmmActionError::NotSupported("Operation requires KVM".to_string()))?
            .clone();
        self.device_manager
            .hotplug_device(kvm_vm, config, event_manager)
    }

    /// Detaches a device after VM start
    #[inline]
    pub fn hot_unplug_device(
        &mut self,
        device_id: VirtioDeviceId,
        event_manager: &mut EventManager,
    ) -> Result<(), VmmActionError> {
        log_dev_preview_warning("PCI device hot-unplug", None);
        let kvm_vm = self
            .vm
            .as_kvm()
            .ok_or_else(|| VmmActionError::NotSupported("Operation requires KVM".to_string()))?
            .clone();
        self.device_manager
            .hot_unplug_device(kvm_vm, device_id, event_manager)
    }
}

/// Process the content of the MPIDR_EL1 register in order to be able to pass it to KVM
///
/// The kernel expects to find the four affinity levels of the MPIDR in the first 32 bits of the
/// VGIC register attribute:
/// https://elixir.free-electrons.com/linux/v4.14.203/source/virt/kvm/arm/vgic/vgic-kvm-device.c#L445.
///
/// The format of the MPIDR_EL1 register is:
/// | 39 .... 32 | 31 .... 24 | 23 .... 16 | 15 .... 8 | 7 .... 0 |
/// |    Aff3    |    Other   |    Aff2    |    Aff1   |   Aff0   |
///
/// The KVM mpidr format is:
/// | 63 .... 56 | 55 .... 48 | 47 .... 40 | 39 .... 32 |
/// |    Aff3    |    Aff2    |    Aff1    |    Aff0    |
/// As specified in the linux kernel: Documentation/virt/kvm/devices/arm-vgic-v3.rst
#[cfg(target_arch = "aarch64")]
fn construct_kvm_mpidrs(vcpu_states: &[VcpuState]) -> Vec<u64> {
    vcpu_states
        .iter()
        .map(|state| {
            let cpu_affid = ((state.mpidr & 0xFF_0000_0000) >> 8) | (state.mpidr & 0xFF_FFFF);
            cpu_affid << 32
        })
        .collect()
}

impl Drop for Vmm {
    fn drop(&mut self) {
        if let Some(kvm_vm) = self.vm.as_kvm() {
            info!("Killing vCPU threads");
            kvm_vm.shutdown_vcpus();
        }

        if let Err(err) = std::io::stdin().lock().set_canon_mode() {
            warn!("Cannot set canonical mode for the terminal. {:?}", err);
        }

        // Write the metrics before exiting.
        if let Err(err) = METRICS.write() {
            error!("Failed to write metrics while stopping: {}", err);
        }

        if let Some(kvm_vm) = self.vm.as_kvm()
            && !kvm_vm.vcpus_handles().is_empty()
        {
            error!("Failed to tear down Vmm: the vcpu threads have not finished execution.");
        }
    }
}

impl MutEventSubscriber for Vmm {
    /// Handle a read event (EPOLLIN).
    fn process(&mut self, event: Events, _: &mut EventOps) {
        let source = event.fd();
        let event_set = event.event_set();

        match &self.vm {
            Vm::Kvm(kvm_vm) => {
                if source == kvm_vm.vcpus_exit_evt().as_raw_fd() && event_set == EventSet::IN {
                    // Exit event handling should never do anything more than call 'self.stop()'.
                    let _ = kvm_vm.vcpus_exit_evt().read();

                    let exit_code = 'exit_code: {
                        // Query each vcpu for their exit_code.
                        let handles = kvm_vm.vcpus_handles();
                        for handle in handles.iter() {
                            // Drain all vcpu responses that are pending from this vcpu
                            // until we find an exit status.
                            for response in handle.response_receiver().try_iter() {
                                if let VcpuResponse::Exited(status) = response {
                                    // It could be that some vcpus exited successfully while
                                    // others errored out. Thus make sure that error exits from
                                    // one vcpu always takes precedence over "ok" exits
                                    if status != FcExitCode::Ok {
                                        break 'exit_code status;
                                    }
                                }
                            }
                        }

                        // No CPUs exited with error status code, report "Ok"
                        FcExitCode::Ok
                    };
                    self.stop(exit_code);
                } else if source == DISK_ERROR_EVT.as_raw_fd() && event_set == EventSet::IN {
                    let _ = DISK_ERROR_EVT.read();
                    self.handle_disk_error();
                } else if self.checkpoint.owns(source) {
                    self.checkpoint_service();
                } else {
                    error!("Spurious EventManager event for handler: Vmm");
                }
            }
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        match &self.vm {
            Vm::Kvm(kvm_vm) => {
                if let Err(err) = ops.add(Events::new(kvm_vm.vcpus_exit_evt(), EventSet::IN)) {
                    error!("Failed to register vmm exit event: {}", err);
                }
                if let Err(err) = ops.add(Events::new(&*DISK_ERROR_EVT, EventSet::IN)) {
                    error!("Failed to register the disk error event: {}", err);
                }
                let fds = self.checkpoint.fds();
                for fd in fds
                    .iter()
                    .copied()
                    .chain(std::iter::once(checkpoint::hold::HOLD.wake.as_raw_fd()))
                {
                    if let Err(err) = ops.add(Events::new_raw(fd, EventSet::IN)) {
                        error!(
                            "Failed to register an event of the checkpoint loop: {}",
                            err
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::builder::tests::{
        CustomBlockConfig, default_kernel_cmdline, default_vmm, insert_block_devices,
    };
    use crate::devices::virtio::block::CacheType;
    use crate::utils::u64_to_usize;
    use crate::vmm_config::space::FillState;

    /// A default Vmm that counts as running (it has no vCPU threads, so a pause and a resume
    /// only change the state of the Vmm and of KVM's clock).
    fn running_vmm() -> Vmm {
        let mut vmm = default_vmm();
        vmm.instance_info.state = VmState::Running;
        vmm
    }

    #[cfg(target_arch = "x86_64")]
    fn kvm_clock(vmm: &Vmm) -> u64 {
        vmm.vm.as_kvm().unwrap().get_clock().unwrap().clock
    }

    const MS: u64 = 1_000_000;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_clock_is_saved_at_a_stop_and_set_at_the_resume() {
        let mut vmm = running_vmm();
        let before = kvm_clock(&vmm);
        vmm.pause_vm().unwrap();
        let stopped = vmm.stopped_clock().unwrap().clock.clock;
        assert!(stopped >= before);

        // Nothing sets the clock during the stop: KVM's clock runs on.
        std::thread::sleep(Duration::from_millis(300));
        assert!(kvm_clock(&vmm) >= stopped + 300 * MS);
        // A second pause request keeps the clock of the first stop.
        vmm.pause_vm().unwrap();
        assert_eq!(vmm.stopped_clock().unwrap().clock.clock, stopped);

        // The resume sets the clock of the stop: the guest goes on from it.
        vmm.resume_vm().unwrap();
        let after = kvm_clock(&vmm);
        assert!(
            after >= stopped && after < stopped + 100 * MS,
            "{after} {stopped}"
        );
        assert!(vmm.stopped_clock().is_none());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_state_saved_while_stopped_holds_the_clock_of_the_stop() {
        let mut vmm = running_vmm();
        let vm_info = VmInfo::from(&vmm);
        vmm.pause_vm().unwrap();
        let stopped = vmm.stopped_clock().unwrap().clock.clock;
        std::thread::sleep(Duration::from_millis(200));
        let state = vmm.save_state(&vm_info).unwrap();
        assert_eq!(state.vm_state.clock().clock, stopped);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_state_saved_while_running_reads_the_clock_of_now() {
        let mut vmm = running_vmm();
        let vm_info = VmInfo::from(&vmm);
        // A snapshot needs a paused guest (the worker threads of the drives are paused by it); the
        // state of a running guest is the one of a checkpoint, in its own stop.
        assert!(matches!(
            vmm.save_state(&vm_info),
            Err(MicrovmStateError::NotAllowed(_))
        ));
        let before = kvm_clock(&vmm);
        std::thread::sleep(Duration::from_millis(50));
        let state = vmm.save_checkpoint_state(&vm_info).unwrap();
        let clock = state.vm_state.clock().clock;
        assert!(clock >= before + 50 * MS);
        // Within the check of 50 ms of a checkpoint of a running guest.
        assert!(kvm_clock(&vmm) - clock < 50 * MS);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_checkpoint_state_of_a_running_guest_reads_the_clock_of_now() {
        let mut vmm = running_vmm();
        let vm_info = VmInfo::from(&vmm);
        let before = kvm_clock(&vmm);
        std::thread::sleep(Duration::from_millis(20));
        let state = vmm.save_checkpoint_state(&vm_info).unwrap();
        assert!(state.vm_state.clock().clock >= before + 20 * MS);
        assert!(!vmm.is_stopped());
    }

    #[test]
    fn test_stop_reasons() {
        let mut vmm = running_vmm();
        vmm.stop_vm(PausedReason::DiskError("rootfs".to_string()))
            .unwrap();
        assert!(vmm.is_stopped());
        assert_eq!(
            vmm.instance_info.paused_reason,
            Some(PausedReason::DiskError("rootfs".to_string()))
        );
        assert_eq!(vmm.instance_info.paused_drive_id.as_deref(), Some("rootfs"));
        // A later pause request keeps the reason of the first stop.
        vmm.pause_vm().unwrap();
        assert_eq!(
            vmm.instance_info.paused_reason,
            Some(PausedReason::DiskError("rootfs".to_string()))
        );
        // The end of a lease replaces it.
        vmm.stop_vm(PausedReason::Lease).unwrap();
        assert_eq!(vmm.instance_info.paused_reason, Some(PausedReason::Lease));
        assert!(vmm.instance_info.paused_drive_id.is_none());

        assert!(!vmm.instance_info.ran_since_load);
        vmm.resume_vm().unwrap();
        assert!(!vmm.is_stopped());
        assert!(vmm.instance_info.ran_since_load);
        assert!(vmm.instance_info.paused_reason.is_none());
    }

    #[test]
    fn test_refused_resume_keeps_the_guest_stopped() {
        let mut vmm = running_vmm();
        vmm.pause_vm().unwrap();
        vmm.refuse_resume(Some("the lease is over".to_string()));
        assert!(matches!(
            vmm.resume_vm(),
            Err(VmmError::ResumeRefused(why)) if why == "the lease is over"
        ));
        assert!(vmm.is_stopped());
        assert_eq!(vmm.instance_info.paused_reason, Some(PausedReason::Api));
        #[cfg(target_arch = "x86_64")]
        assert!(vmm.stopped_clock().is_some());

        vmm.refuse_resume(None);
        vmm.resume_vm().unwrap();
        assert!(!vmm.is_stopped());
    }

    #[test]
    fn test_disk_error_stops_the_guest() {
        let mut vmm = running_vmm();
        let mut cmdline = default_kernel_cmdline();
        let mut event_manager = EventManager::new().unwrap();
        let _files = insert_block_devices(
            &mut vmm,
            &mut cmdline,
            &mut event_manager,
            vec![CustomBlockConfig::new(
                "rootfs".to_string(),
                true,
                None,
                false,
                CacheType::Unsafe,
            )],
        );

        // No drive failed: nothing happens.
        vmm.handle_disk_error();
        assert!(!vmm.is_stopped());

        vmm.device_manager
            .with_virtio_device("rootfs", |block: &mut Block| match block {
                Block::Virtio(block) => block
                    .disk_error
                    .store(true, std::sync::atomic::Ordering::SeqCst),
                Block::VhostUser(_) => unreachable!(),
            })
            .unwrap();
        vmm.handle_disk_error();
        assert!(vmm.is_stopped());
        assert_eq!(
            vmm.instance_info.paused_reason,
            Some(PausedReason::DiskError("rootfs".to_string()))
        );
        #[cfg(target_arch = "x86_64")]
        assert!(vmm.stopped_clock().is_some());
    }

    #[test]
    fn test_memory_regions() {
        let vmm = default_vmm();
        let regions = vmm.memory_regions().regions;
        assert!(!regions.is_empty());
        let mut offset = 0;
        for (region, mem) in regions
            .iter()
            .zip(vmm.vm.as_kvm().unwrap().guest_memory().iter())
        {
            assert_eq!(region.offset, offset);
            assert_eq!(region.host_addr, mem.as_ptr() as u64);
            assert_eq!(region.size, mem.len());
            assert_eq!(region.guest_addr, mem.start_addr().0);
            offset += region.size;
        }
        assert_eq!(offset, 128 << 20);
    }

    #[test]
    fn test_fill_populates_guest_memory() {
        let mut vmm = default_vmm();
        assert!(matches!(vmm.start_fill(), Err(VmmError::Fill(_))));
        vmm.filler = space::Filler::spawn(Arc::new(vec![])).unwrap();
        assert_eq!(vmm.fill_status().state, FillState::Idle);
        vmm.start_fill().unwrap();
        let start = Instant::now();
        while vmm.fill_status().state == FillState::Running {
            assert!(start.elapsed() < Duration::from_secs(30));
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(vmm.fill_status().state, FillState::Done);

        for region in vmm.vm.as_kvm().unwrap().guest_memory().iter() {
            let len = u64_to_usize(region.len());
            let mut pages = vec![0u8; len / 4096];
            // SAFETY: the region is guest memory of this Vmm, and `pages` has a byte for each
            // page of it.
            let ret = unsafe { libc::mincore(region.as_ptr().cast(), len, pages.as_mut_ptr()) };
            assert_eq!(ret, 0);
            assert!(pages.iter().all(|page| page & 1 != 0));
        }
    }
}
