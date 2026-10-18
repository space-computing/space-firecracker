// Copyright 2026 Spacebox authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The held output: the frames that the guest sends wait until the checkpoint that covers them
//! is answered.
//!
//! Each frame gets the number of the checkpoint that will hold the state from which it was sent:
//! the next one to be taken (the open number). The checkpoint loop puts a mark when it has copied
//! the state of checkpoint N (the guest is stopped), and releases the frames up to that mark when
//! the receiving place has answered N while the lease runs. A guest that continues from
//! checkpoint N on another server then never contradicts a frame that left this one.
//!
//! What is held leaves in two ways only: by the release of an answered checkpoint, and when the
//! hold is turned off (`PUT /space/checkpoint/release`: the management program has the guest for
//! good). Each other end throws it away: the state that those frames came from can be a state
//! that no side continues from.
//!
//! The state here is one for the process (one VMM runs in a process), shared by every network
//! device; each device keeps its own queue ([`HeldQueue`]). Everything that changes a queue runs
//! on the VMM thread. The count of the frames since the last mark is read by the loop, and its
//! first frame writes [`HoldShared::wake`], so that the mode by need does not poll while nothing
//! waits.

use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

use vmm_sys_util::eventfd::EventFd;

/// More than this is not kept for one device: the newest frames are lost.
pub const HELD_MAX_BYTES: usize = 64 * 1024 * 1024;

/// The bytes of a frame that the packet line sums: its first 64 bytes after the virtio header.
const SUM_BYTES: usize = 64;

/// The hold of the process.
pub static HOLD: LazyLock<HoldShared> = LazyLock::new(HoldShared::new);

/// The file of the packet lines (`packets` of `PUT /space/checkpoint`), for checks.
#[derive(Debug)]
struct PacketLog {
    file: std::io::BufWriter<File>,
    seq: u64,
}

/// The state of the hold that every network device shares.
#[derive(Debug)]
pub struct HoldShared {
    holding: AtomicBool,
    open_epoch: AtomicU64,
    // The frames since the last mark, and the time of the first of them (host clock, us).
    n_open: AtomicU64,
    open_first_us: AtomicI64,
    /// Written when the first frame after a mark is held.
    pub wake: EventFd,
    n_held: AtomicU64,
    n_released: AtomicU64,
    n_dropped: AtomicU64,
    n_discarded: AtomicU64,
    log: Mutex<Option<PacketLog>>,
}

/// The counts of the frames since the start of the process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HoldCounts {
    /// Frames that were held.
    pub held: u64,
    /// Frames that left by a release.
    pub released: u64,
    /// Frames that were lost because too many waited.
    pub dropped: u64,
    /// Frames that were thrown away at an end with no release.
    pub discarded: u64,
}

impl HoldShared {
    fn new() -> HoldShared {
        HoldShared {
            holding: AtomicBool::new(false),
            open_epoch: AtomicU64::new(1),
            n_open: AtomicU64::new(0),
            open_first_us: AtomicI64::new(0),
            wake: EventFd::new(libc::EFD_NONBLOCK).expect("Cannot create the wake of the hold"),
            n_held: AtomicU64::new(0),
            n_released: AtomicU64::new(0),
            n_dropped: AtomicU64::new(0),
            n_discarded: AtomicU64::new(0),
            log: Mutex::new(None),
        }
    }

    /// Whether the frames that the guest sends wait now.
    pub fn holding(&self) -> bool {
        self.holding.load(Ordering::Acquire)
    }

    /// Turns the hold on, with `next_epoch` as the number of the frames from now on, or off. The
    /// caller lets the frames that wait go when it turns the hold off.
    pub fn set(&self, on: bool, next_epoch: u64) {
        self.open_epoch.store(next_epoch, Ordering::Release);
        self.holding.store(on, Ordering::Release);
    }

    /// The number that a frame held now gets.
    pub fn open_epoch(&self) -> u64 {
        self.open_epoch.load(Ordering::Acquire)
    }

    /// The mark of checkpoint `epoch`: the frames from now on wait for `epoch + 1`.
    pub fn mark(&self, epoch: u64) {
        self.open_epoch.store(epoch + 1, Ordering::Release);
        self.n_open.store(0, Ordering::Release);
        if let Some(log) = self.log.lock().expect("Poisoned lock").as_mut() {
            let _ = log.file.flush();
        }
    }

    /// The frames that no checkpoint covers, and the time of the first of them (0 with none).
    pub fn waiting(&self) -> (u64, i64) {
        let n = self.n_open.load(Ordering::Acquire);
        let first = if n > 0 {
            self.open_first_us.load(Ordering::Acquire)
        } else {
            0
        };
        (n, first)
    }

    /// The counts.
    pub fn counts(&self) -> HoldCounts {
        HoldCounts {
            held: self.n_held.load(Ordering::Relaxed),
            released: self.n_released.load(Ordering::Relaxed),
            dropped: self.n_dropped.load(Ordering::Relaxed),
            discarded: self.n_discarded.load(Ordering::Relaxed),
        }
    }

    /// Writes one line for each frame that is held from now on to `file`; `None` stops it.
    pub fn set_log(&self, file: Option<File>) {
        let mut log = self.log.lock().expect("Poisoned lock");
        if let Some(old) = log.as_mut() {
            let _ = old.file.flush();
        }
        *log = file.map(|file| PacketLog {
            file: std::io::BufWriter::new(file),
            seq: 0,
        });
    }

    fn took(&self, device: &str, epoch: u64, frame: &[u8], hdr_len: usize, now_us: i64) {
        self.n_held.fetch_add(1, Ordering::Relaxed);
        if let Some(log) = self.log.lock().expect("Poisoned lock").as_mut() {
            log.seq += 1;
            let body = &frame[hdr_len.min(frame.len())..];
            // The line of a packet: the device, a running number, the time (host clock, us), the
            // number of the checkpoint that will cover it, the length of the frame, and a sum
            // (FNV-1a, 32 bits) of its first 64 bytes. The frame is the packet without the virtio
            // header: what a capture on the tap device shows.
            let _ = writeln!(
                log.file,
                "{} {} {} {} {} {:08x}",
                device,
                log.seq,
                now_us,
                epoch,
                body.len(),
                fnv1a(&body[..body.len().min(SUM_BYTES)])
            );
        }
        if self.n_open.fetch_add(1, Ordering::AcqRel) == 0 {
            self.open_first_us.store(now_us, Ordering::Release);
            let _ = self.wake.write(1);
        }
    }

    #[cfg(test)]
    pub(crate) fn reset_for_test(&self) {
        self.set(false, 1);
        self.n_open.store(0, Ordering::Release);
        self.set_log(None);
        let _ = self.wake.read();
    }
}

/// FNV-1a, 32 bits.
pub fn fnv1a(data: &[u8]) -> u32 {
    let mut sum: u32 = 2_166_136_261;
    for byte in data {
        sum = (sum ^ u32::from(*byte)).wrapping_mul(16_777_619);
    }
    sum
}

/// One held frame, with its virtio-net header.
#[derive(Debug)]
struct HeldFrame {
    epoch: u64,
    data: Vec<u8>,
}

/// The frames that one network device holds.
#[derive(Debug, Default)]
pub struct HeldQueue {
    frames: VecDeque<HeldFrame>,
    bytes: usize,
}

impl HeldQueue {
    /// Holds `frame` (the bytes with their virtio-net header of `hdr_len` bytes) when the hold is
    /// on: returns false when the frame is to go out now. A frame over the bound of the device
    /// is lost (it counts as dropped) and true is returned.
    pub fn take(&mut self, device: &str, frame: &[u8], hdr_len: usize, now_us: i64) -> bool {
        let hold = &*HOLD;
        if !hold.holding() {
            return false;
        }
        if self.bytes + frame.len() > HELD_MAX_BYTES {
            hold.n_dropped.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        let epoch = hold.open_epoch();
        self.frames.push_back(HeldFrame {
            epoch,
            data: frame.to_vec(),
        });
        self.bytes += frame.len();
        hold.took(device, epoch, frame, hdr_len, now_us);
        true
    }

    /// Gives each frame up to the mark `upto` to `send`, in their order.
    pub fn release(&mut self, upto: u64, mut send: impl FnMut(&[u8])) {
        while let Some(frame) = self.frames.front() {
            if frame.epoch > upto {
                break;
            }
            let frame = self.frames.pop_front().unwrap();
            self.bytes -= frame.data.len();
            send(&frame.data);
            HOLD.n_released.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Throws away what waits.
    pub fn discard(&mut self) {
        let n = self.frames.len() as u64;
        self.frames.clear();
        self.bytes = 0;
        HOLD.n_discarded.fetch_add(n, Ordering::Relaxed);
    }

    /// The number of frames that wait.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether no frame waits.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1a() {
        assert_eq!(fnv1a(b""), 0x811c_9dc5);
        assert_eq!(fnv1a(b"a"), 0xe40c_292c);
        assert_eq!(fnv1a(b"foobar"), 0xbf9c_f968);
    }

    #[test]
    fn test_hold_mark_release_discard() {
        HOLD.reset_for_test();
        let start = HOLD.counts();
        let mut q = HeldQueue::default();
        // No hold: the frame goes out.
        assert!(!q.take("n1", b"0123456789ab-frame-a", 12, 1));
        HOLD.set(true, 1);
        assert!(q.take("n1", b"0123456789ab-frame-a", 12, 10));
        assert!(q.take("n1", b"0123456789ab-frame-b", 12, 11));
        assert_eq!(HOLD.waiting(), (2, 10));
        assert_eq!(HOLD.wake.read().unwrap(), 1);
        HOLD.mark(1);
        assert_eq!(HOLD.waiting(), (0, 0));
        assert!(q.take("n1", b"0123456789ab-frame-c", 12, 20));
        assert_eq!(HOLD.waiting(), (1, 20));
        // The answer to 1 lets a and b go, not c.
        let mut out = Vec::new();
        q.release(1, |f| out.push(f.to_vec()));
        assert_eq!(
            out,
            vec![
                b"0123456789ab-frame-a".to_vec(),
                b"0123456789ab-frame-b".to_vec()
            ]
        );
        assert_eq!(q.len(), 1);
        // An end with no release throws c away.
        q.discard();
        assert!(q.is_empty());
        let end = HOLD.counts();
        assert_eq!(end.held - start.held, 3);
        assert_eq!(end.released - start.released, 2);
        assert_eq!(end.discarded - start.discarded, 1);
        HOLD.reset_for_test();
    }

    #[test]
    fn test_bound_drops_the_newest() {
        HOLD.reset_for_test();
        HOLD.set(true, 1);
        let start = HOLD.counts();
        let mut q = HeldQueue::default();
        let frame = vec![7u8; 65536];
        for _ in 0..1024 {
            assert!(q.take("n1", &frame, 12, 1));
        }
        assert_eq!(q.len(), 1024);
        // The bound of 64 MiB is reached: the newest is lost, the held ones stay.
        assert!(q.take("n1", &frame, 12, 2));
        assert!(q.take("n1", b"small-frame-also-lost", 12, 2));
        assert_eq!(q.len(), 1024);
        assert_eq!(HOLD.counts().dropped - start.dropped, 2);
        q.discard();
        HOLD.reset_for_test();
    }

    #[test]
    fn test_packet_lines() {
        HOLD.reset_for_test();
        let path = std::env::temp_dir().join(format!("hold-lines-{}", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        HOLD.set_log(Some(file));
        HOLD.set(true, 5);
        let mut q = HeldQueue::default();
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0xabu8; 100]);
        q.take("n1", &frame, 12, 1_234_567);
        HOLD.mark(5);
        q.take("n1", &frame, 12, 1_234_999);
        HOLD.set_log(None);
        let text = std::fs::read_to_string(&path).unwrap();
        let sum = format!("{:08x}", fnv1a(&[0xabu8; 64]));
        assert_eq!(
            text,
            format!("n1 1 1234567 5 100 {sum}\nn1 2 1234999 6 100 {sum}\n")
        );
        std::fs::remove_file(&path).unwrap();
        q.discard();
        HOLD.reset_for_test();
    }
}
