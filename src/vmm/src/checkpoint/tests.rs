// Copyright 2026 Spacebox authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The tests of the checkpoint loop: a VMM of the tests (KVM, guest memory with Firecracker's
//! bitmap, no vCPU thread) against a receiving place in the test, which reads the stream of the
//! plan (2.4) byte by byte, keeps the memory file, and answers when it is let.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend};

use super::stream::{ID_LEN, KIND_DATA, KIND_ZERO, PAGE};
use super::*;
use crate::builder::tests::{
    CustomBlockConfig, default_kernel_cmdline, default_vmm, insert_block_devices, insert_net_device,
};
use crate::devices::virtio::block::CacheType;
use crate::devices::virtio::block::device::Block;
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::net::Net;
use crate::devices::virtio::test_utils::default_interrupt;
use crate::utils::u64_to_usize;
use crate::vmm_config::instance_info::VmState;
use crate::vmm_config::machine_config::HugePageConfig;
use crate::vmm_config::net::NetworkInterfaceConfig;
use crate::vstate::memory::{self, GuestMemoryExtension};
use crate::vstate::vm::Vm;
use crate::{EventManager, Vmm};

const MEM: usize = 32 << 20;

/// The hold and the record of given-back pages are one for the process: each test leaves them
/// as it found them, for the tests of the devices.
struct Reset;

impl Drop for Reset {
    fn drop(&mut self) {
        HOLD.reset_for_test();
        discarded_stop();
    }
}

/// A VMM of the tests that counts as running, with guest memory that has Firecracker's bitmap
/// and the threads of the checkpoint loop (with no seccomp filter).
fn ckpt_vmm() -> Vmm {
    HOLD.reset_for_test();
    let mut vmm = default_vmm();
    let mut vm = crate::vstate::vm::tests::setup_vm();
    let regions = memory::anonymous(
        [(GuestAddress(0), MEM)].into_iter(),
        true,
        HugePageConfig::None,
    )
    .unwrap();
    vm.register_dram_memory_regions(regions).unwrap();
    // (The interrupt controller and the timer come with the vCPUs; no vCPU thread runs.)
    let _ = vm.create_vcpus(1).unwrap();
    vmm.vm = Vm::Kvm(Arc::new(vm));
    vmm.instance_info.state = VmState::Running;
    vmm.checkpoint = Checkpointer::spawn(Arc::new(vec![])).unwrap();
    vmm
}

fn mem(vmm: &Vmm) -> &crate::vstate::memory::GuestMemoryMmap {
    vmm.vm.as_kvm().unwrap().guest_memory()
}

/// The bytes of guest memory, as the memory file has them.
fn memory_bytes(vmm: &Vmm) -> Vec<u8> {
    let mut out = vec![0u8; MEM];
    mem(vmm).read_slice(&mut out, GuestAddress(0)).unwrap();
    out
}

/// A write of the guest (it marks Firecracker's bitmap, as a device does; KVM's log is the
/// live check's).
fn write_page(vmm: &Vmm, page: u64, byte: u8) {
    mem(vmm)
        .write_slice(&[byte; PAGE], GuestAddress(page * PAGE as u64))
        .unwrap();
}

/// A write with no mark, as a device writes its used ring.
fn write_unmarked(vmm: &Vmm, addr: u64, bytes: &[u8]) {
    let host = mem(vmm).get_host_address(GuestAddress(addr)).unwrap();
    // SAFETY: the bytes lie inside guest memory of the VMM of the test.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), host, bytes.len()) };
}

/// Turns the loop of the VMM thread until `done` holds.
fn pump(vmm: &mut Vmm, secs: u64, mut done: impl FnMut(&mut Vmm) -> bool) {
    let start = Instant::now();
    loop {
        vmm.checkpoint_service();
        if done(vmm) {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(secs),
            "the loop did not get there: {:?}",
            vmm.checkpoint_info()
        );
        thread::sleep(Duration::from_millis(1));
    }
}

/// One frame as the place read it.
#[derive(Debug, Clone)]
struct Seen {
    n: u64,
    held: bool,
    /// Offset, pages, data.
    records: Vec<(u64, u64, bool)>,
    state: Vec<u8>,
}

impl Seen {
    fn has_page(&self, page: u64) -> Option<bool> {
        let off = page * PAGE as u64;
        self.records
            .iter()
            .find(|(o, p, _)| *o <= off && off < o + p * PAGE as u64)
            .map(|r| r.2)
    }
}

/// How a stream to the place begins.
#[derive(Clone, Copy)]
enum Begin {
    New,
    Continue(u64, Option<[u8; ID_LEN]>),
}

/// A receiving place in the test.
struct Place {
    addr: SocketAddr,
    image: Arc<Mutex<Vec<u8>>>,
    frames: Arc<Mutex<Vec<Seen>>>,
    /// Frames under this number are answered; a frame waits while it is not.
    answer_below: Arc<AtomicU64>,
    /// The full copy is read once this is true.
    copy_gate: Arc<AtomicBool>,
    /// The head of the stream was read.
    header_seen: Arc<AtomicBool>,
    /// Signals are echoed while this is true.
    echo: Arc<AtomicBool>,
    signals: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

fn read_exact(s: &mut TcpStream, n: usize) -> Option<Vec<u8>> {
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).ok()?;
    Some(b)
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().unwrap())
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().unwrap())
}

/// The page records of a list (offset, pages, data), and the bytes of the list.
type Records = (Vec<(u64, u64, bool)>, usize);

/// Reads one list of page records into the image; returns them.
fn read_records(s: &mut TcpStream, image: &Mutex<Vec<u8>>) -> Option<Records> {
    let mut out = Vec::new();
    let mut len = 0;
    loop {
        let h = read_exact(s, 16)?;
        len += 16;
        let (offset, pages, kind) = (be64(&h), u64::from(be32(&h[8..])), be32(&h[12..]));
        if pages == 0 {
            return Some((out, len));
        }
        let off = u64_to_usize(offset);
        let n = u64_to_usize(pages) * PAGE;
        if kind == KIND_DATA {
            let data = read_exact(s, n)?;
            len += n;
            image.lock().unwrap()[off..off + n].copy_from_slice(&data);
        } else {
            assert_eq!(kind, KIND_ZERO);
            image.lock().unwrap()[off..off + n].fill(0);
        }
        out.push((offset, pages, kind == KIND_DATA));
    }
}

impl Place {
    fn new(begin: Begin) -> Place {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let udp = UdpSocket::bind(addr).unwrap();
        udp.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let p = Place {
            addr,
            image: Arc::new(Mutex::new(vec![0u8; MEM])),
            frames: Arc::new(Mutex::new(Vec::new())),
            answer_below: Arc::new(AtomicU64::new(u64::MAX)),
            copy_gate: Arc::new(AtomicBool::new(true)),
            header_seen: Arc::new(AtomicBool::new(false)),
            echo: Arc::new(AtomicBool::new(true)),
            signals: Arc::new(AtomicU64::new(0)),
            stop: Arc::new(AtomicBool::new(false)),
        };
        let (image, frames, answer_below, gate, header_seen, stop) = (
            p.image.clone(),
            p.frames.clone(),
            p.answer_below.clone(),
            p.copy_gate.clone(),
            p.header_seen.clone(),
            p.stop.clone(),
        );
        thread::spawn(move || {
            let Ok((mut s, _)) = listener.accept() else {
                return;
            };
            let wait = |flag: &AtomicBool| {
                while !flag.load(Ordering::SeqCst) {
                    if stop.load(Ordering::SeqCst) {
                        return false;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                true
            };
            match begin {
                Begin::New => {
                    let h = read_exact(&mut s, 12).unwrap();
                    assert_eq!(&h[..4], b"SBFH");
                    assert_eq!(be32(&h[4..]), 1);
                    let r = be32(&h[8..]) as usize;
                    let regions = read_exact(&mut s, 24 * r).unwrap();
                    assert_eq!(be64(&regions[8..]), MEM as u64);
                    header_seen.store(true, Ordering::SeqCst);
                    if !wait(&gate) {
                        return;
                    }
                    read_records(&mut s, &image).unwrap();
                }
                Begin::Continue(n, id) => {
                    let h = read_exact(&mut s, 12).unwrap();
                    assert_eq!(&h[..4], if id.is_some() { b"SBCI" } else { b"SBCC" });
                    assert_eq!(be64(&h[4..]), n);
                    if let Some(id) = id {
                        assert_eq!(read_exact(&mut s, ID_LEN).unwrap(), id);
                    }
                    header_seen.store(true, Ordering::SeqCst);
                    s.write_all(&n.to_be_bytes()).unwrap();
                }
            }
            loop {
                let Some(h) = read_exact(&mut s, 28) else {
                    return;
                };
                let held = match &h[..4] {
                    b"SBCK" => false,
                    b"SBCH" => true,
                    other => panic!("a frame begins with {other:?}"),
                };
                let n = be64(&h[4..]);
                let (pages_len, state_len) = (be64(&h[12..]), be64(&h[20..]));
                let (records, len) = read_records(&mut s, &image).unwrap();
                assert_eq!(len as u64, pages_len);
                let state = read_exact(&mut s, u64_to_usize(state_len)).unwrap();
                assert_eq!(read_exact(&mut s, 4).unwrap(), b"SBCE");
                frames.lock().unwrap().push(Seen {
                    n,
                    held,
                    records,
                    state,
                });
                while n >= answer_below.load(Ordering::SeqCst) {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                if s.write_all(&n.to_be_bytes()).is_err() {
                    return;
                }
            }
        });
        let (echo, signals, stop) = (p.echo.clone(), p.signals.clone(), p.stop.clone());
        thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let mut m = [0u8; 64];
                if let Ok((len, from)) = udp.recv_from(&mut m)
                    && len == 32
                    && &m[..4] == b"SBSG"
                {
                    signals.fetch_add(1, Ordering::SeqCst);
                    if echo.load(Ordering::SeqCst) {
                        m[..4].copy_from_slice(b"SBSE");
                        let _ = udp.send_to(&m[..32], from);
                    }
                }
            }
        });
        p
    }

    fn uri(&self) -> String {
        format!("tcp:{}", self.addr)
    }

    fn frames(&self) -> Vec<Seen> {
        self.frames.lock().unwrap().clone()
    }

    fn frame(&self, n: u64) -> Option<Seen> {
        self.frames().into_iter().find(|f| f.n == n)
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn set(interval_ms: u32, uri: &str) -> CheckpointSetParams {
    CheckpointSetParams {
        interval_ms,
        uri: Some(uri.to_string()),
        signal_ms: Some(0),
        ..Default::default()
    }
}

fn acked(vmm: &Vmm, n: u64) -> bool {
    vmm.checkpoint_info().acked.is_some_and(|a| a >= n)
}

fn stats_lines(path: &std::path::Path) -> Vec<Vec<String>> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.split(' ').map(str::to_string).collect())
        .collect()
}

fn temp_path(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("ckpt-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn test_full_copy_frame_zero_and_frames() {
    let _reset = Reset;
    let mut vmm = ckpt_vmm();
    // Data before the mode, in more pages than the buffers of the socket hold.
    for page in 0..2048 {
        write_page(&vmm, page, (page % 251) as u8 + 1);
    }
    let place = Place::new(Begin::New);
    place.copy_gate.store(false, Ordering::SeqCst);
    let stats = temp_path("stats-full");
    let mut p = set(50, &place.uri());
    p.stats = Some(stats.to_string_lossy().into());
    vmm.checkpoint_set(&p).unwrap();
    assert!(vmm.checkpoint_info().enabled);
    // The full copy has begun; the guest changes two pages meanwhile.
    pump(&mut vmm, 10, |_| place.header_seen.load(Ordering::SeqCst));
    write_page(&vmm, 5, 0xee);
    write_page(&vmm, 5000, 0xdd);
    place.copy_gate.store(true, Ordering::SeqCst);
    pump(&mut vmm, 10, |v| acked(v, 0));
    // Frame 0 closes the full copy: it has the pages changed during the copy, and the memory
    // file is then the guest.
    let f0 = place.frame(0).unwrap();
    assert!(!f0.held);
    assert_eq!(f0.has_page(5), Some(true));
    assert_eq!(f0.has_page(5000), Some(true));
    assert_eq!(f0.has_page(6), None);
    assert!(*place.image.lock().unwrap() == memory_bytes(&vmm));
    // The state is Firecracker's state file.
    let state: Snapshot<MicrovmState> = Snapshot::load(&mut f0.state.as_slice()).unwrap();
    assert_eq!(
        state.data.vm_state.memory.regions[0].size, MEM,
        "the state of the guest"
    );

    // Frame 1 has what changed since frame 0, and nothing else of the guest.
    write_page(&vmm, 7, 0x77);
    pump(&mut vmm, 10, |v| acked(v, 1));
    let f1 = place.frame(1).unwrap();
    assert_eq!(f1.has_page(7), Some(true));
    assert_eq!(f1.has_page(5), None);
    assert!(*place.image.lock().unwrap() == memory_bytes(&vmm));
    // Frames follow by the clock, also with no page changed.
    pump(&mut vmm, 10, |v| acked(v, 3));
    let info = vmm.checkpoint_info();
    assert!(info.active);
    assert!(info.checkpoints >= 4);
    assert!(!info.lost);
    assert!(info.since_ack_ms.is_some());
    // The line of each answered checkpoint: 15 words, the reason of the mode by the clock.
    let lines = stats_lines(&stats);
    assert!(lines.len() >= 3, "{lines:?}");
    for (i, l) in lines.iter().enumerate() {
        assert_eq!(l.len(), 15, "{l:?}");
        assert_eq!(l[0], i.to_string());
        assert_eq!(l[6], "running");
        assert_eq!(l[7], "interval");
        assert_eq!(l[10], "-1");
        let (begin, read): (i64, i64) = (l[1].parse().unwrap(), l[11].parse().unwrap());
        assert!(read > begin);
    }
    let _ = std::fs::remove_file(stats);
}

#[test]
fn test_used_ring_page_of_a_drive_on_workers_is_in_the_next_checkpoint() {
    // A drive on two worker threads that poll: at each checkpoint of the running guest the
    // workers end their requests and stop, the rings of both queues are marked after the reset,
    // and the workers take their queues again after the stop.
    let _reset = Reset;
    let mut vmm = ckpt_vmm();
    vmm.device_manager.blk_worker_filter = Some(Arc::new(vec![]));
    let mut cmdline = default_kernel_cmdline();
    let mut event_manager = EventManager::new().unwrap();
    let _files = insert_block_devices(
        &mut vmm,
        &mut cmdline,
        &mut event_manager,
        vec![
            CustomBlockConfig::new("root".to_string(), true, None, false, CacheType::Unsafe)
                .with_workers(2, 128),
        ],
    );
    // The guest set up the two queues of the drive: queue q at 0x10000 + 0x4000 * q, its
    // used ring at + 0x2000, with EVENT_IDX.
    let guest_mem = mem(&vmm).clone();
    vmm.device_manager
        .with_virtio_device("root", |block: &mut Block| {
            let Block::Virtio(b) = block else {
                unreachable!()
            };
            b.set_acked_features(b.avail_features());
            for q in 0..2u64 {
                let base = 0x10000 + 0x4000 * q;
                let c = b.queue_config_mut(usize::try_from(q).unwrap()).unwrap();
                c.size = 16;
                c.desc_table_address = GuestAddress(base);
                c.avail_ring_address = GuestAddress(base + 0x1000);
                c.used_ring_address = GuestAddress(base + 0x2000);
                c.ready = true;
            }
            block.activate(guest_mem, default_interrupt()).unwrap();
        })
        .unwrap();
    let place = Place::new(Begin::New);
    vmm.checkpoint_set(&set(30, &place.uri())).unwrap();
    pump(&mut vmm, 10, |v| acked(v, 1));
    // The devices write their used rings, with no mark.
    write_unmarked(&vmm, 0x12000 + 4, &[0xab; 8]);
    write_unmarked(&vmm, 0x16000 + 4, &[0xcd; 8]);
    let n = vmm.checkpoint_info().sent;
    pump(&mut vmm, 10, |v| acked(v, n + 1));
    let f = place.frame(n + 1).unwrap();
    assert_eq!(f.has_page(0x12), Some(true));
    assert_eq!(f.has_page(0x16), Some(true));

    // After the checkpoints the workers serve the guest: a request for the drive's id on each
    // queue (its header at 0x30000 + 0x100 * q, its data at 0x31000 + 0x100 * q, its status at
    // 0x32000 + q), kicked as the guest's driver kicks.
    let gm = mem(&vmm).clone();
    for q in 0..2u64 {
        let base = 0x10000 + 0x4000 * q;
        let (header, data, status) = (0x30000 + 0x100 * q, 0x31000 + 0x100 * q, 0x32000 + q);
        gm.write_obj(
            crate::devices::virtio::block::virtio::RequestHeader::new(
                crate::devices::virtio::block::virtio::VIRTIO_BLK_T_GET_ID,
                0,
            ),
            GuestAddress(header),
        )
        .unwrap();
        gm.write_obj::<u8>(0xff, GuestAddress(status)).unwrap();
        // Three descriptors of 16 bytes: header, data (20 bytes, written by the device),
        // status.
        for (i, (addr, len, flags, next)) in [
            (header, 16u32, 1u16, 1u16),
            (data, 20, 1 | 2, 2),
            (status, 1, 2, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let d = GuestAddress(base + 16 * i as u64);
            gm.write_obj(addr, d).unwrap();
            gm.write_obj(len, GuestAddress(d.0 + 8)).unwrap();
            gm.write_obj(flags, GuestAddress(d.0 + 12)).unwrap();
            gm.write_obj(next, GuestAddress(d.0 + 14)).unwrap();
        }
        let avail = base + 0x1000;
        let old: u16 = gm.read_obj(GuestAddress(avail + 2)).unwrap();
        gm.write_obj(0u16, GuestAddress(avail + 4 + 2 * u64::from(old % 16)))
            .unwrap();
        gm.write_obj(old.wrapping_add(1), GuestAddress(avail + 2))
            .unwrap();
        vmm.device_manager
            .with_virtio_device("root", |block: &mut Block| {
                block
                    .queue_event(usize::try_from(q).unwrap())
                    .unwrap()
                    .write(1)
                    .unwrap();
            })
            .unwrap();
    }
    let start = Instant::now();
    while (0..2u64).any(|q| gm.read_obj::<u8>(GuestAddress(0x32000 + q)).unwrap() != 0) {
        vmm.checkpoint_service();
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the workers did not answer"
        );
        thread::sleep(Duration::from_millis(1));
    }
    for q in 0..2u64 {
        let used: u16 = gm.read_obj(GuestAddress(0x12000 + 0x4000 * q + 2)).unwrap();
        assert_eq!(used, 1);
    }
}

#[test]
fn test_used_ring_page_written_with_no_mark_is_in_the_next_checkpoint() {
    let _reset = Reset;
    let mut vmm = ckpt_vmm();
    let mut cmdline = default_kernel_cmdline();
    let mut event_manager = EventManager::new().unwrap();
    let _files = insert_block_devices(
        &mut vmm,
        &mut cmdline,
        &mut event_manager,
        vec![CustomBlockConfig::new(
            "root".to_string(),
            true,
            None,
            false,
            CacheType::Unsafe,
        )],
    );
    // The guest set up the queue of the drive: its used ring is at 0x12000.
    let guest_mem = mem(&vmm).clone();
    vmm.device_manager
        .with_virtio_device("root", |block: &mut Block| {
            let Block::Virtio(b) = block else {
                unreachable!()
            };
            let q = b.queue_config_mut(0).unwrap();
            q.size = 16;
            q.desc_table_address = GuestAddress(0x10000);
            q.avail_ring_address = GuestAddress(0x11000);
            q.used_ring_address = GuestAddress(0x12000);
            q.ready = true;
            block.activate(guest_mem, default_interrupt()).unwrap();
        })
        .unwrap();
    let place = Place::new(Begin::New);
    vmm.checkpoint_set(&set(30, &place.uri())).unwrap();
    pump(&mut vmm, 10, |v| acked(v, 1));
    // The device writes its used ring, with no mark (as Firecracker's devices do).
    write_unmarked(&vmm, 0x12000 + 4, &[0xab; 8]);
    let n = vmm.checkpoint_info().sent;
    pump(&mut vmm, 10, |v| acked(v, n + 1));
    let f = place.frame(n + 1).unwrap();
    assert_eq!(f.has_page(0x12), Some(true));
    assert!(*place.image.lock().unwrap() == memory_bytes(&vmm));
}

#[test]
fn test_hold_answer_lease_and_release() {
    let _reset = Reset;
    let mut vmm = ckpt_vmm();
    let mut cmdline = default_kernel_cmdline();
    let mut event_manager = EventManager::new().unwrap();
    insert_net_device(
        &mut vmm,
        &mut cmdline,
        &mut event_manager,
        NetworkInterfaceConfig {
            iface_id: "n1".to_string(),
            host_dev_name: "ckpttest%d".to_string(),
            guest_mac: None,
            mtu: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        },
    );
    let hold = |vmm: &Vmm, frame: &[u8]| {
        vmm.device_manager
            .with_virtio_device("n1", |net: &mut Net| net.hold_for_test(frame))
            .unwrap()
    };
    let held = |vmm: &Vmm| {
        vmm.device_manager
            .with_virtio_device("n1", |net: &mut Net| net.held_frames())
            .unwrap()
    };
    let packets = temp_path("packets");
    let place = Place::new(Begin::New);
    let mut p = set(30, &place.uri());
    p.lease_ms = Some(400);
    p.signal_ms = Some(50);
    p.packets = Some(packets.to_string_lossy().into());
    vmm.checkpoint_set(&p).unwrap();
    pump(&mut vmm, 10, |v| acked(v, 0));
    let info = vmm.checkpoint_info();
    assert!(info.holding);
    assert_eq!(info.lease_ms, 400);
    assert!(place.frame(0).unwrap().held);

    // A frame before the stop of checkpoint N waits for the answer to N.
    let mut frame = vec![0u8; 12];
    frame.extend_from_slice(b"frame-one");
    let n = HOLD.open_epoch();
    place.answer_below.store(n, Ordering::SeqCst);
    assert!(hold(&vmm, &frame));
    pump(&mut vmm, 10, |v| v.checkpoint_info().sent >= n);
    assert!(hold(&vmm, &frame));
    assert_eq!(held(&vmm), 2);
    // The lease is kept by the echoes, longer than its time, while no answer comes.
    let wait = Instant::now();
    pump(&mut vmm, 10, |_| {
        wait.elapsed() > Duration::from_millis(700)
    });
    assert!(!vmm.is_stopped());
    assert_eq!(held(&vmm), 2);
    let info = vmm.checkpoint_info();
    assert!(info.lease_left_ms.unwrap() > 0);
    assert!(info.since_echo_ms.unwrap() < 400);
    assert!(info.unanswered_ms.unwrap() >= 600);
    // The answer to N releases the first frame only.
    place.answer_below.store(n + 1, Ordering::SeqCst);
    pump(&mut vmm, 10, |v| acked(v, n));
    assert_eq!(held(&vmm), 1);
    let lines = std::fs::read_to_string(&packets).unwrap();
    let first: Vec<&str> = lines.lines().next().unwrap().split(' ').collect();
    assert_eq!(first[0], "n1");
    assert_eq!(first[3], n.to_string());
    assert_eq!(first[4], "9");

    // No echo: the lease ends 400 ms after the send of the last echoed signal; the guest stops.
    place.answer_below.store(0, Ordering::SeqCst);
    place.echo.store(false, Ordering::SeqCst);
    pump(&mut vmm, 10, |v| v.is_stopped());
    assert_eq!(vmm.instance_info.paused_reason, Some(PausedReason::Lease));
    let info = vmm.checkpoint_info();
    assert!(info.lease_over);
    assert_eq!(info.lease_left_ms, None);
    // A resume is refused, an answer releases nothing, and no checkpoint is taken.
    assert!(matches!(
        vmm.resume_vm(),
        Err(crate::VmmError::ResumeRefused(_))
    ));
    let sent = vmm.checkpoint_info().sent;
    assert!(sent > n);
    place.answer_below.store(u64::MAX, Ordering::SeqCst);
    let wait = Instant::now();
    pump(&mut vmm, 10, |_| {
        wait.elapsed() > Duration::from_millis(300)
    });
    assert_eq!(held(&vmm), 1);
    assert_eq!(vmm.checkpoint_info().sent, sent);
    assert_eq!(vmm.checkpoint_info().acked, Some(n));
    assert!(vmm.checkpoint_info().late >= 1);
    // The release lets the frame go, ends the hold, the lease and the mode, and the guest that
    // the lease stopped continues.
    vmm.checkpoint_release().unwrap();
    assert_eq!(held(&vmm), 0);
    assert!(!vmm.is_stopped());
    let info = vmm.checkpoint_info();
    assert!(!info.holding && !info.lease_over && !info.enabled && !info.active);
    let _ = std::fs::remove_file(packets);
}

#[test]
fn test_lease_checked_at_the_resume() {
    let _reset = Reset;
    let mut vmm = ckpt_vmm();
    let place = Place::new(Begin::New);
    let mut p = set(30, &place.uri());
    p.lease_ms = Some(200);
    p.signal_ms = Some(50);
    vmm.checkpoint_set(&p).unwrap();
    pump(&mut vmm, 10, |v| acked(v, 0));
    // A command stops the guest; its lease goes on (the echoes keep it).
    vmm.pause_vm().unwrap();
    let wait = Instant::now();
    pump(&mut vmm, 10, |_| {
        wait.elapsed() > Duration::from_millis(400)
    });
    assert!(!vmm.checkpoint_info().lease_over);
    // The echoes end, and nothing turns the loop (a long call): the resume itself sees that
    // the lease is over.
    place.echo.store(false, Ordering::SeqCst);
    thread::sleep(Duration::from_millis(500));
    assert!(matches!(
        vmm.resume_vm(),
        Err(crate::VmmError::ResumeRefused(_))
    ));
    assert_eq!(vmm.instance_info.paused_reason, Some(PausedReason::Lease));
    // The release keeps a guest that a command stopped as it was, with its reason.
    vmm.checkpoint_release().unwrap();
    assert!(vmm.is_stopped());
    assert_eq!(vmm.instance_info.paused_reason, Some(PausedReason::Api));
    vmm.resume_vm().unwrap();
}

#[test]
fn test_stopped_guest_keeps_its_checkpoints_and_finish() {
    let _reset = Reset;
    let mut vmm = ckpt_vmm();
    let stats = temp_path("stats-finish");
    let place = Place::new(Begin::New);
    let mut p = set(30, &place.uri());
    p.stats = Some(stats.to_string_lossy().into());
    p.need = Some(true);
    vmm.checkpoint_set(&p).unwrap();
    pump(&mut vmm, 10, |v| acked(v, 0));
    // A guest that a command stopped keeps its checkpoints (by the clock: nothing waits).
    vmm.pause_vm().unwrap();
    write_page(&vmm, 9, 0x99);
    let n = vmm.checkpoint_info().sent;
    pump(&mut vmm, 10, |v| acked(v, n + 1));
    assert!(place.frames().iter().any(|f| f.has_page(9) == Some(true)));
    let lines = stats_lines(&stats);
    let last = lines.last().unwrap();
    assert_eq!(last[6], "paused");
    assert_eq!(last[7], "clock");

    // A finish with no checkpoint on its way.
    write_page(&vmm, 10, 0x10);
    let fin = vmm.checkpoint_finish().unwrap();
    assert!(fin.acked);
    let f = place.frame(fin.epoch).unwrap();
    assert_eq!(f.has_page(10), Some(true));
    assert!(*place.image.lock().unwrap() == memory_bytes(&vmm));
    let info = vmm.checkpoint_info();
    assert_eq!(info.final_epoch, Some(fin.epoch));
    assert!(!info.active && !info.enabled);
    // The hold stays on.
    assert!(info.holding);
    assert_eq!(stats_lines(&stats).last().unwrap()[7], "finish");
    // No mode: no finish.
    vmm.checkpoint_finish().unwrap_err();
    let _ = std::fs::remove_file(stats);
}

#[test]
fn test_finish_with_a_checkpoint_on_its_way() {
    let _reset = Reset;
    let mut vmm = ckpt_vmm();
    let place = Place::new(Begin::New);
    let mut p = set(30, &place.uri());
    p.lost_ms = Some(2000);
    vmm.checkpoint_set(&p).unwrap();
    pump(&mut vmm, 10, |v| acked(v, 0));
    // The guest runs: no finish.
    vmm.checkpoint_finish().unwrap_err();
    let n = vmm.checkpoint_info().sent + 1;
    place.answer_below.store(n, Ordering::SeqCst);
    pump(&mut vmm, 10, |v| v.checkpoint_info().sent >= n);
    vmm.pause_vm().unwrap();
    write_page(&vmm, 11, 0x11);
    // The answer to the checkpoint on its way comes while the finish waits.
    let answer = place.answer_below.clone();
    let t = thread::spawn(move || {
        thread::sleep(Duration::from_millis(300));
        answer.store(u64::MAX, Ordering::SeqCst);
    });
    let fin = vmm.checkpoint_finish().unwrap();
    t.join().unwrap();
    assert_eq!(fin.epoch, n + 1);
    assert_eq!(place.frame(n + 1).unwrap().has_page(11), Some(true));
    assert!(*place.image.lock().unwrap() == memory_bytes(&vmm));
}

#[test]
fn test_finish_with_no_answer_leaves_the_mode() {
    let _reset = Reset;
    let mut vmm = ckpt_vmm();
    let place = Place::new(Begin::New);
    let mut p = set(30, &place.uri());
    p.lost_ms = Some(200);
    vmm.checkpoint_set(&p).unwrap();
    pump(&mut vmm, 10, |v| acked(v, 0));
    vmm.pause_vm().unwrap();
    place.answer_below.store(0, Ordering::SeqCst);
    let start = Instant::now();
    let err = vmm.checkpoint_finish().unwrap_err();
    // Within two times lost-ms and 1 s.
    assert!(start.elapsed() < Duration::from_millis(1600));
    assert!(err.to_string().contains("did not answer"), "{err}");
    // The mode is as it was: it runs, and the late answer counts.
    assert!(vmm.checkpoint_info().active);
    let sent = vmm.checkpoint_info().sent;
    place.answer_below.store(u64::MAX, Ordering::SeqCst);
    pump(&mut vmm, 10, |v| acked(v, sent));
    assert!(!vmm.checkpoint_info().lost);
}

#[test]
fn test_track_and_continue() {
    let _reset = Reset;
    let mut vmm = ckpt_vmm();
    // A guest that arrived: loaded and not resumed.
    vmm.instance_info.set_paused(PausedReason::Load);
    // No continue with no tracking; no tracking of a running guest.
    let id_text = "00112233445566778899aabbccddeeff";
    let place = Place::new(Begin::Continue(7, Some(stream::parse_id(id_text).unwrap())));
    let mut p = set(2000, &place.uri());
    p.cont = Some(true);
    p.epoch = Some(7);
    p.stream_id = Some(id_text.to_string());
    p.need = Some(true);
    p.lease_ms = Some(5000);
    p.signal_ms = Some(500);
    let stats = temp_path("stats-cont");
    p.stats = Some(stats.to_string_lossy().into());
    vmm.checkpoint_set(&p).unwrap_err();
    vmm.checkpoint_track(&CheckpointTrackParams {
        enable: true,
        hold: Some(true),
        lease_ms: Some(5000),
    })
    .unwrap();
    let info = vmm.checkpoint_info();
    assert!(info.tracking && info.holding);
    assert_eq!(info.lease_ms, 5000);
    // The lease begins at the resume.
    assert_eq!(info.lease_left_ms, None);
    // The guest changes a page after the tracking began.
    write_page(&vmm, 12, 0x12);
    vmm.checkpoint_set(&p).unwrap();
    vmm.resume_vm().unwrap();
    assert!(vmm.checkpoint_info().lease_left_ms.unwrap() > 4000);
    // The first checkpoint is taken at once after the answer to the begin: 8.
    pump(&mut vmm, 10, |v| acked(v, 8));
    let f8 = place.frame(8).unwrap();
    assert!(f8.held);
    assert_eq!(f8.has_page(12), Some(true));
    assert_eq!(place.frames()[0].n, 8);
    let line = &stats_lines(&stats)[0];
    assert_eq!(line[0], "8");
    assert_eq!(line[7], "first");
    let info = vmm.checkpoint_info();
    assert_eq!(info.stream_id.as_deref(), Some(id_text));
    assert!(info.tracking);
    // The tracking does not end while the mode runs.
    assert!(
        vmm.checkpoint_track(&CheckpointTrackParams {
            enable: false,
            ..Default::default()
        })
        .is_err()
    );
    let _ = std::fs::remove_file(stats);
}

#[test]
fn test_need_reasons_idle_and_budget() {
    let _reset = Reset;
    let mut vmm = ckpt_vmm();
    let mut cmdline = default_kernel_cmdline();
    let mut event_manager = EventManager::new().unwrap();
    insert_net_device(
        &mut vmm,
        &mut cmdline,
        &mut event_manager,
        NetworkInterfaceConfig {
            iface_id: "n1".to_string(),
            host_dev_name: "ckptneed%d".to_string(),
            guest_mac: None,
            mtu: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        },
    );
    let stats = temp_path("stats-need");
    let place = Place::new(Begin::New);
    let mut p = set(60000, &place.uri());
    p.need = Some(true);
    p.stats = Some(stats.to_string_lossy().into());
    vmm.checkpoint_set(&p).unwrap();
    pump(&mut vmm, 10, |v| acked(v, 0));
    let mut frame = vec![0u8; 12];
    frame.extend_from_slice(b"output");
    // The guest runs (the test VMM has no vCPU to look at: a look cannot tell, so "busy"): a
    // frame that waits gets a checkpoint by the account, busy-us after it.
    vmm.device_manager
        .with_virtio_device("n1", |net: &mut Net| net.hold_for_test(&frame))
        .unwrap();
    pump(&mut vmm, 10, |v| acked(v, 1));
    let line = &stats_lines(&stats)[1];
    assert_eq!(line[7], "budget");
    assert_eq!(line[10], "1");
    assert_eq!(line[9], "1");
    assert!(line[8].parse::<i64>().unwrap() >= 1000);
    // A guest that a command stopped is idle: at once.
    vmm.pause_vm().unwrap();
    vmm.device_manager
        .with_virtio_device("n1", |net: &mut Net| net.hold_for_test(&frame))
        .unwrap();
    pump(&mut vmm, 10, |v| acked(v, 2));
    let line = &stats_lines(&stats)[2];
    assert_eq!(line[7], "idle");
    assert_eq!(line[10], "0");
    // The account in the query.
    assert!(vmm.checkpoint_info().account_us.is_some());
    // No frame waits: nothing before the interval (60 s).
    thread::sleep(Duration::from_millis(100));
    vmm.checkpoint_service();
    assert_eq!(vmm.checkpoint_info().sent, 2);
    let _ = std::fs::remove_file(stats);
}

#[test]
fn test_balloon_pages_are_zeros_and_not_written() {
    let _reset = Reset;
    let mut vmm = ckpt_vmm();
    write_page(&vmm, 20, 0x20);
    write_page(&vmm, 21, 0x21);
    let stats = temp_path("stats-balloon");
    let place = Place::new(Begin::New);
    let mut p = set(30, &place.uri());
    p.stats = Some(stats.to_string_lossy().into());
    vmm.checkpoint_set(&p).unwrap();
    pump(&mut vmm, 10, |v| acked(v, 1));
    assert_eq!(place.image.lock().unwrap()[20 * PAGE], 0x20);
    // The balloon gives two pages back; the guest writes one other.
    mem(&vmm)
        .discard_range(GuestAddress(20 * PAGE as u64), 2 * PAGE)
        .unwrap();
    write_page(&vmm, 22, 0x22);
    let n = vmm.checkpoint_info().sent;
    pump(&mut vmm, 10, |v| acked(v, n + 1));
    let f = place.frame(n + 1).unwrap();
    assert_eq!(f.has_page(20), Some(false));
    assert_eq!(f.has_page(21), Some(false));
    assert_eq!(f.has_page(22), Some(true));
    assert!(*place.image.lock().unwrap() == memory_bytes(&vmm));
    // The pages of the line count all three; the pages written by the guest only one.
    let line = stats_lines(&stats)
        .into_iter()
        .find(|l| l[0] == (n + 1).to_string())
        .unwrap();
    assert_eq!(line[3], "3");
    assert_eq!(line[14], "1");
    let _ = std::fs::remove_file(stats);
}

#[test]
fn test_faults_stale_clock_and_internal_error() {
    for (fault, why) in [
        ("stale-clock", "kvmclock: the saved clock is"),
        ("internal-error", "the guest is in an internal error"),
    ] {
        let _reset = Reset;
        let mut vmm = ckpt_vmm();
        let place = Place::new(Begin::New);
        vmm.checkpoint_set(&set(100, &place.uri())).unwrap();
        pump(&mut vmm, 10, |v| acked(v, 1));
        let mut p = CheckpointSetParams {
            interval_ms: 100,
            fault: Some(fault.to_string()),
            ..Default::default()
        };
        p.uri = None;
        vmm.checkpoint_set(&p).unwrap();
        pump(&mut vmm, 10, |v| v.checkpoint_info().lost);
        let info = vmm.checkpoint_info();
        assert!(info.reason.as_deref().unwrap().contains(why), "{info:?}");
        // No checkpoint goes out after it.
        let frames = place.frames().len();
        let wait = Instant::now();
        pump(&mut vmm, 10, |_| {
            wait.elapsed() > Duration::from_millis(400)
        });
        assert_eq!(place.frames().len(), frames);
        assert!(vmm.checkpoint_info().lost);
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_check_of_the_cpu_registers() {
    let (vm, vcpu) = crate::vstate::vcpu::tests::setup_vcpu(0x10000);
    vcpu.kvm_vcpu
        .fd
        .set_cpuid2(&vm.kvm().supported_cpuid)
        .unwrap();
    let cpu = vcpu.kvm_vcpu.save_state().unwrap();
    let mut state = MicrovmState {
        vcpu_states: vec![cpu],
        ..Default::default()
    };
    verify(&state, false, None).unwrap();
    // What KVM gives when the host has turned virtualization off.
    state.vcpu_states[0].regs.rflags = 0;
    let err = verify(&state, false, None).unwrap_err();
    assert!(err.contains("the registers are not those of a CPU that ran"));
    // The clock of a guest that runs is the clock of now, within 50 ms.
    let clock = vm.get_clock().unwrap().clock;
    let mut state = MicrovmState::default();
    state.vm_state.replace_clock(vm.get_clock().unwrap());
    verify(&state, true, Some(clock + 10_000_000)).unwrap();
    let err = verify(&state, true, Some(clock + 400_000_000)).unwrap_err();
    assert!(err.starts_with("kvmclock: the saved clock is"), "{err}");
    // A guest that a command stopped holds the clock of its stop: no check.
    verify(&state, false, Some(clock + 400_000_000)).unwrap();
}

#[test]
fn test_stop_held_ends_the_signal_and_the_lease() {
    let _reset = Reset;
    let mut vmm = ckpt_vmm();
    let place = Place::new(Begin::New);
    let mut p = set(50, &place.uri());
    p.lease_ms = Some(100);
    p.signal_ms = Some(20);
    vmm.checkpoint_set(&p).unwrap();
    pump(&mut vmm, 10, |v| acked(v, 1));
    vmm.checkpoint_set(&CheckpointSetParams {
        interval_ms: 50,
        fault: Some("stop-held".into()),
        ..Default::default()
    })
    .unwrap();
    // The next stop lasts 2.2 s: the signal stops 100 ms into it, and the lease ends; the guest
    // does not run again.
    let before = place.signals.load(Ordering::SeqCst);
    let start = Instant::now();
    pump(&mut vmm, 10, |v| v.is_stopped());
    assert!(start.elapsed() >= Duration::from_millis(2000));
    let during = place.signals.load(Ordering::SeqCst) - before;
    assert!(during < 20, "{during} signals in a stop of 2.2 s");
    assert_eq!(vmm.instance_info.paused_reason, Some(PausedReason::Lease));
    assert!(vmm.checkpoint_info().lease_over);
}

#[test]
fn test_set_checks_its_members() {
    let _reset = Reset;
    let mut vmm = ckpt_vmm();
    let uri = "tcp:127.0.0.1:1";
    let mut p = set(100, uri);
    p.lease_ms = Some(1000);
    p.signal_ms = Some(500);
    vmm.checkpoint_set(&p).unwrap_err();
    let mut p = set(100, uri);
    p.budget_pct = Some(10);
    vmm.checkpoint_set(&p).unwrap_err();
    let mut p = set(100, uri);
    p.stream_id = Some("0123".into());
    vmm.checkpoint_set(&p).unwrap_err();
    let mut p = set(100, "10.0.0.1:7000");
    p.signal_ms = None;
    vmm.checkpoint_set(&p).unwrap_err();
    let mut p = set(100, uri);
    p.uri = None;
    vmm.checkpoint_set(&p).unwrap_err();
    // A place that does not listen: the new stream never begins and ends, with the reason.
    vmm.checkpoint_set(&set(100, uri)).unwrap();
    pump(&mut vmm, 10, |v| v.checkpoint_info().lost);
    let info = vmm.checkpoint_info();
    assert!(info.reason.unwrap().contains("could not be made"));
    assert!(!info.active && !info.enabled);
    assert!(!vmm.checkpoint.running());
    assert!(!vmm.checkpoint_owns_dirty_pages());
    // The mode starts again, to a place that listens.
    let place = Place::new(Begin::New);
    vmm.checkpoint_set(&set(100, &place.uri())).unwrap();
    pump(&mut vmm, 10, |v| acked(v, 0));
    assert!(!vmm.checkpoint_info().lost);
    // While the mode runs, only the interval and the limit change.
    let mut p = set(100, uri);
    p.uri = None;
    p.hook = Some("/nothing".into());
    vmm.checkpoint_set(&p).unwrap_err();
    vmm.checkpoint_set(&set(100, &place.uri())).unwrap_err();
    let mut p = set(200, uri);
    p.uri = None;
    p.signal_ms = None;
    p.lost_ms = Some(500);
    vmm.checkpoint_set(&p).unwrap();
    assert_eq!(vmm.checkpoint_info().interval_ms, 200);
    // A snapshot with memory is refused while the mode runs.
    assert!(vmm.checkpoint_owns_dirty_pages());
}

/// A hook of a disk program in the test: it answers each line with `ok` and keeps the lines.
fn hook_server(name: &str) -> (std::path::PathBuf, Arc<Mutex<Vec<String>>>) {
    let path = temp_path(name);
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let kept = lines.clone();
    thread::spawn(move || {
        let Ok((s, _)) = listener.accept() else {
            return;
        };
        let mut w = s.try_clone().unwrap();
        for line in std::io::BufRead::lines(std::io::BufReader::new(s)) {
            let Ok(line) = line else {
                break;
            };
            kept.lock().unwrap().push(line);
            if w.write_all(b"ok\n").is_err() {
                break;
            }
        }
        kept.lock().unwrap().push("closed".into());
    });
    (path, lines)
}

#[test]
fn test_hook_lines() {
    let _reset = Reset;
    let mut vmm = ckpt_vmm();
    let (path, lines) = hook_server("hook-release");
    let place = Place::new(Begin::New);
    let mut p = set(30, &place.uri());
    p.hook = Some(path.to_string_lossy().into());
    vmm.checkpoint_set(&p).unwrap();
    pump(&mut vmm, 10, |v| acked(v, 2));
    // "epoch N" in the stop of N (0 is the stop that closes the full copy), "commit N" at its
    // answer, and the next epoch only after it.
    let seen = lines.lock().unwrap().clone();
    assert_eq!(
        &seen[..6],
        &[
            "epoch 0", "commit 0", "epoch 1", "commit 1", "epoch 2", "commit 2"
        ]
    );
    // A release tells the hook "end N".
    vmm.checkpoint_release().unwrap();
    let start = Instant::now();
    while !lines.lock().unwrap().iter().any(|l| l == "closed") {
        assert!(start.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(5));
    }
    let seen = lines.lock().unwrap().clone();
    assert!(seen[seen.len() - 2].starts_with("end "), "{seen:?}");
    let _ = std::fs::remove_file(path);

    // A finish closes the hook with no line after the commit of its last checkpoint.
    let (path, lines) = hook_server("hook-finish");
    let place = Place::new(Begin::New);
    let mut p = set(30, &place.uri());
    p.hook = Some(path.to_string_lossy().into());
    vmm.checkpoint_set(&p).unwrap();
    pump(&mut vmm, 10, |v| acked(v, 1));
    vmm.pause_vm().unwrap();
    let fin = vmm.checkpoint_finish().unwrap();
    let start = Instant::now();
    while !lines.lock().unwrap().iter().any(|l| l == "closed") {
        assert!(start.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(5));
    }
    let seen = lines.lock().unwrap().clone();
    assert_eq!(
        &seen[seen.len() - 3..],
        &[
            format!("epoch {}", fin.epoch),
            format!("commit {}", fin.epoch),
            "closed".to_string()
        ]
    );
    let _ = std::fs::remove_file(path);
}

/// Whether KVM keeps a dirty log for each slot of guest memory: `KVM_GET_DIRTY_LOG` fails on a
/// slot with no log.
fn kvm_logs(vmm: &Vmm) -> Vec<bool> {
    let kvm_vm = vmm.vm.as_kvm().unwrap();
    kvm_vm
        .guest_memory()
        .iter()
        .flat_map(|region| region.plugged_slots())
        .map(|slot| {
            kvm_vm
                .fd()
                .get_dirty_log(slot.slot, slot.slice.len())
                .is_ok()
        })
        .collect()
}

#[test]
fn test_release_ends_the_tracking_with_no_stream() {
    let _reset = Reset;
    for track_from_start in [false, true] {
        let mut vmm = ckpt_vmm();
        vmm.machine_config.track_dirty_pages = track_from_start;
        // A guest that arrived: loaded and not resumed; no stream begins.
        vmm.instance_info.set_paused(PausedReason::Load);
        vmm.checkpoint_track(&CheckpointTrackParams {
            enable: true,
            hold: Some(true),
            lease_ms: Some(5000),
        })
        .unwrap();
        let info = vmm.checkpoint_info();
        assert!(info.tracking && info.holding);
        assert!(vmm.vm.as_kvm().unwrap().log_dirty());
        assert!(kvm_logs(&vmm).iter().all(|on| *on));

        vmm.checkpoint_release().unwrap();
        let info = vmm.checkpoint_info();
        assert!(!info.tracking, "the release left the tracking on");
        assert!(!info.holding);
        // KVM's dirty log goes off, unless the machine tracks dirty pages from its start.
        assert_eq!(vmm.vm.as_kvm().unwrap().log_dirty(), track_from_start);
        assert!(
            kvm_logs(&vmm).iter().all(|on| *on == track_from_start),
            "KVM's dirty log after the release: {:?}",
            kvm_logs(&vmm)
        );
        // The guest that the load stopped stays stopped.
        assert!(vmm.is_stopped());
        assert_eq!(vmm.instance_info.paused_reason, Some(PausedReason::Load));
    }
}

/// The syscalls that the wait of the fault `stop-held` may make, by name and number.
#[cfg(target_arch = "x86_64")]
const WAIT_SYSCALLS: [(&str, i64); 9] = [
    ("poll", libc::SYS_poll),
    ("ppoll", libc::SYS_ppoll),
    ("clock_gettime", libc::SYS_clock_gettime),
    ("nanosleep", libc::SYS_nanosleep),
    ("clock_nanosleep", libc::SYS_clock_nanosleep),
    ("restart_syscall", libc::SYS_restart_syscall),
    ("rt_sigreturn", libc::SYS_rt_sigreturn),
    ("exit", libc::SYS_exit),
    ("exit_group", libc::SYS_exit_group),
];

/// A seccomp filter of the tests: it allows those of `WAIT_SYSCALLS` that the VMM thread's
/// filter of the release (`resources/seccomp/x86_64-unknown-linux-musl.json`, thread `vmm`)
/// allows with no condition on the arguments, and kills the process at any other syscall.
#[cfg(target_arch = "x86_64")]
fn vmm_wait_filter() -> Vec<u64> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../resources/seccomp/x86_64-unknown-linux-musl.json"
    );
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let allowed: Vec<&str> = json["vmm"]["filter"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|rule| rule.get("args").is_none())
        .map(|rule| rule["syscall"].as_str().unwrap())
        .collect();
    assert!(allowed.contains(&"exit_group"));
    // struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }
    let insn = |code: u16, jt: u8, jf: u8, k: u32| {
        u64::from(code) | (u64::from(jt) << 16) | (u64::from(jf) << 24) | (u64::from(k) << 32)
    };
    const LD_W_ABS: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const RET_K: u16 = 0x06;
    const ALLOW: u32 = 0x7fff_0000;
    const KILL_PROCESS: u32 = 0x8000_0000;
    // The syscall's number is the first word of `struct seccomp_data`.
    let mut filter = vec![insn(LD_W_ABS, 0, 0, 0)];
    for (name, nr) in WAIT_SYSCALLS {
        if allowed.contains(&name) {
            filter.push(insn(JEQ_K, 0, 1, u32::try_from(nr).unwrap()));
            filter.push(insn(RET_K, 0, 0, ALLOW));
        }
    }
    filter.push(insn(RET_K, 0, 0, KILL_PROCESS));
    filter
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_stop_held_waits_with_what_the_vmm_filter_allows() {
    // The wait runs in a child process under the filter: a syscall that the VMM thread's filter
    // does not allow ends the child with SIGSYS, as it ends the release binary.
    let filter = vmm_wait_filter();
    let time = Duration::from_millis(300);
    let start = Instant::now();
    // SAFETY: the child sets the filter, waits and ends; it takes no lock and allocates nothing.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        if crate::seccomp::apply_filter(&filter).is_err() {
            // SAFETY: ends the child.
            unsafe { libc::_exit(2) };
        }
        wait_on_vmm_thread(time);
        // SAFETY: ends the child.
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    // SAFETY: waits for the child of this test.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "the wait ended the process: exited {} with {}, signal {}",
        libc::WIFEXITED(status),
        libc::WEXITSTATUS(status),
        if libc::WIFSIGNALED(status) {
            libc::WTERMSIG(status)
        } else {
            0
        }
    );
    assert!(start.elapsed() >= time, "{:?}", start.elapsed());
}
