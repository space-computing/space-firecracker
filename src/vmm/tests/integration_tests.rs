// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::cast_possible_truncation, clippy::tests_outside_test_module)]

use std::io::{Seek, SeekFrom};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use vmm::builder::build_and_boot_microvm;
use vmm::devices::virtio::block::CacheType;
use vmm::persist::{
    GuestMemoryFromFileError, MicrovmState, MicrovmStateError, RestoreFromSnapshotError,
    RestoreFromSnapshotGuestMemoryError, VirtioDevicesState, VmInfo, snapshot_state_sanity_check,
};
use vmm::resources::VmResources;
use vmm::rpc_interface::{
    LoadSnapshotError, PrebootApiController, RuntimeApiController, VmmAction, VmmActionError,
    VmmData,
};
use vmm::seccomp::get_empty_filters;
use vmm::snapshot::Snapshot;
use vmm::test_utils::mock_resources::{MockVmResources, NOISY_KERNEL_IMAGE};
use vmm::test_utils::{create_vmm, default_vmm, default_vmm_no_boot};
use vmm::vmm_config::balloon::BalloonDeviceConfig;
use vmm::vmm_config::boot_source::BootSourceConfig;
use vmm::vmm_config::drive::BlockDeviceConfig;
use vmm::vmm_config::instance_info::{InstanceInfo, VmState};
use vmm::vmm_config::machine_config::{HugePageConfig, MachineConfig, MachineConfigUpdate};
use vmm::vmm_config::net::NetworkInterfaceConfig;
use vmm::vmm_config::snapshot::{
    CreateSnapshotParams, LoadSnapshotParams, MemBackendConfig, MemBackendType,
    SnapshotLoadHugePageConfig, SnapshotType,
};
use vmm::vmm_config::vsock::VsockDeviceConfig;
use vmm::{DumpCpuConfigError, EventManager, FcExitCode, Vmm};
use vmm_sys_util::tempfile::TempFile;

#[allow(unused_mut, unused_variables)]
fn check_booted_microvm(vmm: Arc<Mutex<Vmm>>, mut evmgr: EventManager) {
    // On x86_64, the vmm should exit once its workload completes and signals the exit event.
    // On aarch64, the test kernel doesn't exit, so the vmm is force-stopped.
    #[cfg(target_arch = "x86_64")]
    evmgr.run_with_timeout(500).unwrap();
    #[cfg(target_arch = "aarch64")]
    vmm.lock().unwrap().stop(FcExitCode::Ok);

    assert_eq!(
        vmm.lock().unwrap().shutdown_exit_code(),
        Some(FcExitCode::Ok)
    );
}

#[test]
fn test_build_and_boot_microvm() {
    // Error case: no boot source configured.
    {
        let resources: VmResources = MockVmResources::new().into();
        let mut event_manager = EventManager::new().unwrap();
        let empty_seccomp_filters = get_empty_filters();

        let vmm_ret = build_and_boot_microvm(
            &InstanceInfo::default(),
            &resources,
            &mut event_manager,
            &empty_seccomp_filters,
        );
        assert_eq!(format!("{:?}", vmm_ret.err()), "Some(MissingKernelConfig)");
    }

    for pci_enabled in [false, true] {
        for memory_hotplug in [false, true] {
            let (vmm, evmgr) = create_vmm(None, false, true, pci_enabled, memory_hotplug);
            check_booted_microvm(vmm, evmgr);
        }
    }
}

#[allow(unused_mut, unused_variables)]
fn check_build_microvm(vmm: Arc<Mutex<Vmm>>, mut evmgr: EventManager) {
    // The built microVM should be in the `VmState::Paused` state here.
    assert_eq!(vmm.lock().unwrap().instance_info().state, VmState::Paused);

    // The microVM should be able to resume and exit successfully.
    // On x86_64, the vmm should exit once its workload completes and signals the exit event.
    // On aarch64, the test kernel doesn't exit, so the vmm is force-stopped.
    vmm.lock().unwrap().resume_vm().unwrap();
    #[cfg(target_arch = "x86_64")]
    evmgr.run_with_timeout(500).unwrap();
    #[cfg(target_arch = "aarch64")]
    vmm.lock().unwrap().stop(FcExitCode::Ok);
    assert_eq!(
        vmm.lock().unwrap().shutdown_exit_code(),
        Some(FcExitCode::Ok)
    );
}

#[test]
fn test_build_microvm() {
    for pci_enabled in [false, true] {
        for memory_hotplug in [false, true] {
            let (vmm, evmgr) = create_vmm(None, false, false, pci_enabled, memory_hotplug);
            check_build_microvm(vmm, evmgr);
        }
    }
}

fn pause_resume_microvm(vmm: Arc<Mutex<Vmm>>) {
    let mut api_controller = RuntimeApiController::new(vmm.clone());
    let mut event_manager = EventManager::new().unwrap();

    // There's a race between this thread and the vcpu thread, but this thread
    // should be able to pause vcpu thread before it finishes running its test-binary.
    api_controller
        .handle_request(VmmAction::Pause, &mut event_manager)
        .unwrap();
    // Pausing again the microVM should not fail (microVM remains in the
    // `Paused` state).
    api_controller
        .handle_request(VmmAction::Pause, &mut event_manager)
        .unwrap();
    api_controller
        .handle_request(VmmAction::Resume, &mut event_manager)
        .unwrap();

    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

#[test]
fn test_pause_resume_microvm() {
    for pci_enabled in [false, true] {
        for memory_hotplug in [false, true] {
            // Tests that pausing and resuming a microVM work as expected.
            let (vmm, _) = create_vmm(None, false, true, pci_enabled, memory_hotplug);

            pause_resume_microvm(vmm);
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_dirty_bitmap_success() {
    let vmms = [
        vmm::test_utils::dirty_tracking_vmm(Some(NOISY_KERNEL_IMAGE)),
        default_vmm(Some(NOISY_KERNEL_IMAGE)),
    ];

    for (vmm, _) in vmms {
        // Let it churn for a while and dirty some pages...
        thread::sleep(Duration::from_millis(100));
        let bitmap = vmm
            .lock()
            .unwrap()
            .vm
            .as_kvm()
            .unwrap()
            .get_dirty_bitmap()
            .unwrap();
        let num_dirty_pages: u32 = bitmap
            .values()
            .map(|bitmap_per_region| {
                // Gently coerce to u32
                let num_dirty_pages_per_region: u32 =
                    bitmap_per_region.iter().map(|n| n.count_ones()).sum();
                num_dirty_pages_per_region
            })
            .sum();
        assert!(num_dirty_pages > 0);
        vmm.lock().unwrap().stop(FcExitCode::Ok);
    }
}

#[test]
fn test_disallow_snapshots_without_pausing() {
    let (vmm, _) = default_vmm(Some(NOISY_KERNEL_IMAGE));
    let vm_info = VmInfo {
        mem_size_mib: 1u64,
        ..Default::default()
    };

    // Verify saving state while running is not allowed.
    assert!(matches!(
        vmm.lock().unwrap().save_state(&vm_info),
        Err(MicrovmStateError::NotAllowed(_))
    ));

    // Pause microVM.
    vmm.lock().unwrap().pause_vm().unwrap();
    // It is now allowed.
    vmm.lock().unwrap().save_state(&vm_info).unwrap();
    // Stop.
    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

#[test]
fn test_disallow_dump_cpu_config_without_pausing() {
    let (vmm, _) = default_vmm_no_boot(Some(NOISY_KERNEL_IMAGE));

    // This call should succeed since the microVM is in the paused state before boot.
    vmm.lock().unwrap().dump_cpu_config().unwrap();

    // Boot the microVM.
    vmm.lock().unwrap().resume_vm().unwrap();

    // Verify this call is not allowed while running.
    assert!(matches!(
        vmm.lock().unwrap().dump_cpu_config(),
        Err(DumpCpuConfigError::NotAllowed(_))
    ));

    // Stop the microVM.
    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

fn verify_create_snapshot(
    is_diff: bool,
    pci_enabled: bool,
    memory_hotplug: bool,
) -> (TempFile, TempFile) {
    let snapshot_file = TempFile::new().unwrap();
    let memory_file = TempFile::new().unwrap();

    let (vmm, _) = create_vmm(
        Some(NOISY_KERNEL_IMAGE),
        is_diff,
        true,
        pci_enabled,
        memory_hotplug,
    );

    let vm_info = VmInfo::from(&*vmm.lock().unwrap());
    let mut controller = RuntimeApiController::new(vmm.clone());
    let mut event_manager = EventManager::new().unwrap();

    // Be sure that the microVM is running.
    thread::sleep(Duration::from_millis(200));

    // Pause microVM.
    controller
        .handle_request(VmmAction::Pause, &mut event_manager)
        .unwrap();

    // Create snapshot.
    let snapshot_type = match is_diff {
        true => SnapshotType::Diff,
        false => SnapshotType::Full,
    };
    let snapshot_params = CreateSnapshotParams {
        snapshot_type,
        snapshot_path: snapshot_file.as_path().to_path_buf(),
        mem_file_path: Some(memory_file.as_path().to_path_buf()),
        sync_snapshot_files: true,
    };

    controller
        .handle_request(
            VmmAction::CreateSnapshot(snapshot_params),
            &mut event_manager,
        )
        .unwrap();

    vmm.lock().unwrap().stop(FcExitCode::Ok);

    // Check that we can deserialize the microVM state from `snapshot_file`.
    let restored_microvm_state: MicrovmState =
        Snapshot::load(&mut snapshot_file.as_file()).unwrap().data;

    assert_eq!(restored_microvm_state.vm_info, vm_info);

    // Verify deserialized data.
    // The default vmm has no devices and one vCPU.
    match &restored_microvm_state.device_states.virtio_state {
        VirtioDevicesState::Mmio(state) => {
            assert!(!pci_enabled);
            assert_eq!(state.block_devices.len(), 0);
            assert_eq!(state.net_devices.len(), 0);
            assert!(state.vsock_device.is_none());
        }
        VirtioDevicesState::Pci(state) => {
            assert!(pci_enabled);
            assert_eq!(state.block_devices.len(), 0);
            assert_eq!(state.net_devices.len(), 0);
            assert!(state.vsock_device.is_none());
        }
    }
    assert_eq!(restored_microvm_state.vcpu_states.len(), 1);

    (snapshot_file, memory_file)
}

fn verify_load_snapshot(
    snapshot_file: TempFile,
    memory_file: TempFile,
    huge_pages: SnapshotLoadHugePageConfig,
) {
    let expected_huge_pages = huge_pages.resolve(HugePageConfig::None);
    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filters = get_empty_filters();
    let mut vm_resources = VmResources::default();

    let mut preboot_api_controller = PrebootApiController::new(
        &empty_seccomp_filters,
        InstanceInfo::default(),
        &mut vm_resources,
        &mut event_manager,
    );

    preboot_api_controller
        .handle_preboot_request(VmmAction::LoadSnapshot(LoadSnapshotParams {
            snapshot_path: snapshot_file.as_path().to_path_buf(),
            mem_backend: MemBackendConfig {
                backend_path: memory_file.as_path().to_path_buf(),
                backend_type: MemBackendType::File,
            },
            track_dirty_pages: false,
            resume_vm: true,
            network_overrides: vec![],
            vsock_override: None,
            clock_realtime: false,
            huge_pages,
        }))
        .unwrap();

    let vmm = preboot_api_controller.built_vmm.take().unwrap();

    {
        let vmm = vmm.lock().unwrap();
        assert_eq!(vmm.instance_info.state, VmState::Running);
        assert_eq!(vmm.machine_config.huge_pages, expected_huge_pages);
    }
    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

#[test]
fn test_create_and_load_snapshot() {
    for diff_snap in [false, true] {
        for pci_enabled in [false, true] {
            for memory_hotplug in [false, true] {
                // Create snapshot.
                let (snapshot_file, memory_file) =
                    verify_create_snapshot(diff_snap, pci_enabled, memory_hotplug);
                // Create a new microVm from snapshot. This only tests code-level logic; it verifies
                // that a microVM can be built with no errors from given snapshot.
                // It does _not_ verify that the guest is actually restored properly. We're using
                // python integration tests for that.
                verify_load_snapshot(
                    snapshot_file,
                    memory_file,
                    SnapshotLoadHugePageConfig::Snapshot,
                );
            }
        }
    }
}

#[test]
fn test_load_snapshot_huge_pages_override() {
    let (snapshot_file, memory_file) = verify_create_snapshot(false, false, false);

    verify_load_snapshot(
        snapshot_file,
        memory_file,
        SnapshotLoadHugePageConfig::Transparent,
    );
}

#[test]
fn test_load_snapshot_rejects_hugetlbfs_with_file_backend() {
    let (snapshot_file, memory_file) = verify_create_snapshot(false, false, false);
    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filters = get_empty_filters();
    let mut vm_resources = VmResources::default();
    let mut preboot_api_controller = PrebootApiController::new(
        &empty_seccomp_filters,
        InstanceInfo::default(),
        &mut vm_resources,
        &mut event_manager,
    );

    let error = preboot_api_controller
        .handle_preboot_request(VmmAction::LoadSnapshot(LoadSnapshotParams {
            snapshot_path: snapshot_file.as_path().to_path_buf(),
            mem_backend: MemBackendConfig {
                backend_path: memory_file.as_path().to_path_buf(),
                backend_type: MemBackendType::File,
            },
            track_dirty_pages: false,
            resume_vm: false,
            network_overrides: vec![],
            vsock_override: None,
            clock_realtime: false,
            huge_pages: SnapshotLoadHugePageConfig::Hugetlbfs2M,
        }))
        .unwrap_err();

    assert!(matches!(
        error,
        VmmActionError::LoadSnapshot(LoadSnapshotError::RestoreFromSnapshot(
            RestoreFromSnapshotError::GuestMemory(RestoreFromSnapshotGuestMemoryError::File(
                GuestMemoryFromFileError::HugetlbfsSnapshot
            ))
        ))
    ));
}

#[test]
fn test_snapshot_load_sanity_checks() {
    let microvm_state = get_microvm_state_from_snapshot(false);
    check_snapshot(microvm_state);
    let microvm_state = get_microvm_state_from_snapshot(true);
    check_snapshot(microvm_state);
}

fn check_snapshot(mut microvm_state: MicrovmState) {
    use vmm::persist::SnapShotStateSanityCheckError;
    snapshot_state_sanity_check(&microvm_state).unwrap();

    // Remove memory regions.
    microvm_state.vm_state.memory.regions.clear();

    // Validate sanity checks fail because there is no mem region in state.
    assert_eq!(
        snapshot_state_sanity_check(&microvm_state),
        Err(SnapShotStateSanityCheckError::NoMemory)
    );
}

fn get_microvm_state_from_snapshot(pci_enabled: bool) -> MicrovmState {
    // Create a diff snapshot
    let (snapshot_file, _) = verify_create_snapshot(true, pci_enabled, false);

    // Deserialize the microVM state.
    snapshot_file.as_file().seek(SeekFrom::Start(0)).unwrap();
    Snapshot::load(&mut snapshot_file.as_file()).unwrap().data
}

fn verify_load_snap_disallowed_after_boot_resources(res: VmmAction, res_name: &str) {
    let (snapshot_file, memory_file) = verify_create_snapshot(false, false, false);

    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filters = get_empty_filters();
    let mut vm_resources = VmResources::default();

    let mut preboot_api_controller = PrebootApiController::new(
        &empty_seccomp_filters,
        InstanceInfo::default(),
        &mut vm_resources,
        &mut event_manager,
    );

    preboot_api_controller.handle_preboot_request(res).unwrap();

    // Load snapshot should no longer be allowed.
    let req = VmmAction::LoadSnapshot(LoadSnapshotParams {
        snapshot_path: snapshot_file.as_path().to_path_buf(),
        mem_backend: MemBackendConfig {
            backend_path: memory_file.as_path().to_path_buf(),
            backend_type: MemBackendType::File,
        },
        track_dirty_pages: false,
        resume_vm: false,
        network_overrides: vec![],
        vsock_override: None,
        clock_realtime: false,
        huge_pages: SnapshotLoadHugePageConfig::Snapshot,
    });
    let err = preboot_api_controller.handle_preboot_request(req);
    assert!(
        matches!(
            err.unwrap_err(),
            VmmActionError::LoadSnapshot(LoadSnapshotError::LoadSnapshotNotAllowed)
        ),
        "LoadSnapshot should be disallowed after {}",
        res_name
    );
}

#[test]
fn test_preboot_load_snap_disallowed_after_boot_resources() {
    let tmp_file = TempFile::new().unwrap();
    let tmp_file = tmp_file.as_path().to_str().unwrap().to_string();
    // Verify LoadSnapshot not allowed after configuring various boot-specific resources.
    let req = VmmAction::ConfigureBootSource(BootSourceConfig {
        kernel_image_path: tmp_file.clone(),
        ..Default::default()
    });
    verify_load_snap_disallowed_after_boot_resources(req, "ConfigureBootSource");

    let config = BlockDeviceConfig {
        drive_id: String::new(),
        partuuid: None,
        is_root_device: false,
        cache_type: CacheType::Unsafe,

        is_read_only: Some(false),
        discard: None,
        path_on_host: Some(tmp_file),
        rate_limiter: None,
        file_engine_type: None,
        blk_size: None,
        topology: None,

        socket: None,
    };

    let req = VmmAction::InsertBlockDevice(config);
    verify_load_snap_disallowed_after_boot_resources(req, "InsertBlockDevice");

    let req = VmmAction::InsertNetworkDevice(NetworkInterfaceConfig {
        iface_id: String::new(),
        host_dev_name: String::new(),
        guest_mac: None,
        mtu: None,
        rx_rate_limiter: None,
        tx_rate_limiter: None,
    });
    verify_load_snap_disallowed_after_boot_resources(req, "InsertNetworkDevice");

    let req = VmmAction::SetBalloonDevice(BalloonDeviceConfig::default());
    verify_load_snap_disallowed_after_boot_resources(req, "SetBalloonDevice");

    let req = VmmAction::SetVsockDevice(VsockDeviceConfig {
        vsock_id: Some(String::new()),
        guest_cid: 0,
        uds_path: String::new(),
    });
    verify_load_snap_disallowed_after_boot_resources(req, "SetVsockDevice");

    let req =
        VmmAction::UpdateMachineConfiguration(MachineConfigUpdate::from(MachineConfig::default()));
    verify_load_snap_disallowed_after_boot_resources(req, "SetVmConfiguration");
}

fn count_dirty_pages(vmm: &Arc<Mutex<Vmm>>) -> u32 {
    vmm.lock()
        .unwrap()
        .vm
        .as_kvm()
        .unwrap()
        .get_dirty_bitmap()
        .unwrap()
        .values()
        .map(|bitmap| bitmap.iter().map(|n| n.count_ones()).sum::<u32>())
        .sum()
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_state_only_snapshot_keeps_the_dirty_bitmap() {
    let (vmm, _) = vmm::test_utils::dirty_tracking_vmm(Some(NOISY_KERNEL_IMAGE));
    let mut controller = RuntimeApiController::new(vmm.clone());
    let mut event_manager = EventManager::new().unwrap();
    thread::sleep(Duration::from_millis(200));
    controller
        .handle_request(VmmAction::Pause, &mut event_manager)
        .unwrap();

    // A snapshot of the state only: the state is written and no dirty bitmap is reset.
    let snapshot_file = TempFile::new().unwrap();
    controller
        .handle_request(
            VmmAction::CreateSnapshot(CreateSnapshotParams {
                snapshot_type: SnapshotType::Diff,
                snapshot_path: snapshot_file.as_path().to_path_buf(),
                mem_file_path: None,
                sync_snapshot_files: false,
            }),
            &mut event_manager,
        )
        .unwrap();
    let state: MicrovmState = Snapshot::load(&mut snapshot_file.as_file()).unwrap().data;
    assert_eq!(state.vcpu_states.len(), 1);
    assert!(count_dirty_pages(&vmm) > 0);

    // A snapshot with memory resets it (the guest is stopped and writes nothing more).
    let memory_file = TempFile::new().unwrap();
    controller
        .handle_request(
            VmmAction::CreateSnapshot(CreateSnapshotParams {
                snapshot_type: SnapshotType::Diff,
                snapshot_path: snapshot_file.as_path().to_path_buf(),
                mem_file_path: Some(memory_file.as_path().to_path_buf()),
                sync_snapshot_files: false,
            }),
            &mut event_manager,
        )
        .unwrap();
    assert_eq!(count_dirty_pages(&vmm), 0);

    // The regions of guest memory, with the offsets of the memory file.
    let regions = match controller
        .handle_request(VmmAction::GetSpaceMemory, &mut event_manager)
        .unwrap()
    {
        VmmData::SpaceMemory(regions) => regions.regions,
        other => panic!("{other:?}"),
    };
    let mut offset = 0;
    for region in &regions {
        assert_eq!(region.offset, offset);
        assert_ne!(region.host_addr, 0);
        offset += region.size;
    }
    assert_eq!(
        offset,
        memory_file.as_file().metadata().unwrap().len(),
        "the regions cover the memory file"
    );

    vmm.lock().unwrap().stop(FcExitCode::Ok);
}

#[test]
#[cfg(target_arch = "x86_64")]
fn test_load_sets_the_clock_at_the_resume() {
    use vmm::vmm_config::instance_info::PausedReason;

    // A guest that ran for a while, so that its clock is well ahead of a new VM's.
    let snapshot_file = TempFile::new().unwrap();
    let memory_file = TempFile::new().unwrap();
    {
        let (vmm, _) = create_vmm(Some(NOISY_KERNEL_IMAGE), false, true, false, false);
        let mut controller = RuntimeApiController::new(vmm.clone());
        let mut event_manager = EventManager::new().unwrap();
        thread::sleep(Duration::from_millis(1000));
        controller
            .handle_request(VmmAction::Pause, &mut event_manager)
            .unwrap();
        controller
            .handle_request(
                VmmAction::CreateSnapshot(CreateSnapshotParams {
                    snapshot_type: SnapshotType::Full,
                    snapshot_path: snapshot_file.as_path().to_path_buf(),
                    mem_file_path: Some(memory_file.as_path().to_path_buf()),
                    sync_snapshot_files: false,
                }),
                &mut event_manager,
            )
            .unwrap();
        vmm.lock().unwrap().stop(FcExitCode::Ok);
    }
    let state: MicrovmState = Snapshot::load(&mut snapshot_file.as_file()).unwrap().data;
    let state_clock = state.vm_state.clock().clock;
    assert!(state_clock >= 1_000_000_000);

    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filters = get_empty_filters();
    let mut vm_resources = VmResources::default();
    let mut preboot_api_controller = PrebootApiController::new(
        &empty_seccomp_filters,
        InstanceInfo::default(),
        &mut vm_resources,
        &mut event_manager,
    );
    preboot_api_controller
        .handle_preboot_request(VmmAction::LoadSnapshot(LoadSnapshotParams {
            snapshot_path: snapshot_file.as_path().to_path_buf(),
            mem_backend: MemBackendConfig {
                backend_path: memory_file.as_path().to_path_buf(),
                backend_type: MemBackendType::File,
            },
            track_dirty_pages: false,
            resume_vm: false,
            network_overrides: vec![],
            vsock_override: None,
            clock_realtime: false,
            huge_pages: SnapshotLoadHugePageConfig::Snapshot,
        }))
        .unwrap();
    let vmm = preboot_api_controller.built_vmm.take().unwrap();
    let kvm_clock = |vmm: &Arc<Mutex<Vmm>>| {
        vmm.lock()
            .unwrap()
            .vm
            .as_kvm()
            .unwrap()
            .get_clock()
            .unwrap()
            .clock
    };

    {
        let locked = vmm.lock().unwrap();
        assert_eq!(locked.instance_info.state, VmState::Paused);
        assert_eq!(locked.instance_info.paused_reason, Some(PausedReason::Load));
        assert!(!locked.instance_info.ran_since_load);
        assert_eq!(locked.stopped_clock().unwrap().clock.clock, state_clock);
    }
    // The load did not set the clock of the state: KVM's clock is a new VM's.
    assert!(kvm_clock(&vmm) < state_clock);
    // The guest waits loaded; that time is not time of the guest.
    thread::sleep(Duration::from_millis(500));

    let mut controller = RuntimeApiController::new(vmm.clone());
    controller
        .handle_request(VmmAction::Resume, &mut event_manager)
        .unwrap();
    let after = kvm_clock(&vmm);
    assert!(
        after >= state_clock && after < state_clock + 100_000_000,
        "{after} {state_clock}"
    );
    {
        let locked = vmm.lock().unwrap();
        assert_eq!(locked.instance_info.state, VmState::Running);
        assert!(locked.instance_info.ran_since_load);
        assert!(locked.stopped_clock().is_none());
    }
    vmm.lock().unwrap().stop(FcExitCode::Ok);
}
