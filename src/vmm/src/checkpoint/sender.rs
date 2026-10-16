// Copyright 2026 Spacebox authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The sender thread of the checkpoint loop, and the hook of the disk.
//!
//! The VMM thread takes each checkpoint in a stop and hands its bytes to this thread; this
//! thread sends them to the receiving place while the guest runs, reads the answer, tells the
//! hook `commit N`, and tells the VMM thread (an event and its eventfd), which releases the held
//! frames. It also sends the full copy of a new stream, reading guest memory while the guest
//! runs (the pages that change meanwhile are tracked, and frame 0 has them), and begins a
//! continued stream. At most one checkpoint is on its way.
//!
//! The thread is started before the seccomp filter of the VMM thread is set (that filter allows
//! no new thread) and sets its own filter, of the thread category `checkpoint`. It waits for
//! work for as long as the VMM lives.

use std::io::{BufWriter, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender as ChannelSender, TryRecvError, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use vmm_sys_util::eventfd::EventFd;

use super::lease::{Lease, host_us, monotonic_ms};
use super::stream::{self, PAGE, RegionDesc};
use crate::logger::info;
use crate::seccomp::BpfProgram;

/// The unix socket of the hook of a disk program: the loop writes a line and waits for `ok`.
#[derive(Debug)]
pub struct Hook {
    stream: UnixStream,
}

/// The hook, shared by the VMM thread (`epoch N` in the stop) and the sender (`commit N`,
/// `end N`); the two never talk to it at the same time.
pub type SharedHook = Arc<Mutex<Option<Hook>>>;

impl Hook {
    /// Connects to the hook.
    pub fn open(path: &str) -> std::io::Result<Hook> {
        Ok(Hook {
            stream: UnixStream::connect(path)?,
        })
    }

    /// The descriptor, for a shutdown while a line waits for its answer.
    pub fn raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    /// Writes `word N` and waits for the line `ok`. False: the hook is gone or said another
    /// thing.
    pub fn tell(&mut self, word: &str, n: u64) -> bool {
        let line = format!("{word} {n}\n");
        if !send_all(self.stream.as_raw_fd(), line.as_bytes()) {
            return false;
        }
        let mut got = Vec::with_capacity(4);
        loop {
            let mut c = 0u8;
            // SAFETY: a read of one byte into `c` from the descriptor of the hook.
            let r = unsafe { libc::read(self.stream.as_raw_fd(), (&raw mut c).cast(), 1) };
            if r < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if r <= 0 {
                return false;
            }
            if c == b'\n' {
                return got == b"ok";
            }
            if got.len() < 4 {
                got.push(c);
            }
        }
    }
}

/// Tells the hook `word N`, if there is one. False: the hook gives no answer.
pub fn hook_tell(hook: &SharedHook, word: &str, n: u64) -> bool {
    match hook.lock().expect("Poisoned lock").as_mut() {
        Some(h) => h.tell(word, n),
        None => true,
    }
}

/// Writes all of `buf` to a socket, with no SIGPIPE when the other side is gone.
fn send_all(fd: RawFd, mut buf: &[u8]) -> bool {
    while !buf.is_empty() {
        // SAFETY: `buf` is valid for its length; the descriptor is a socket.
        let r = unsafe { libc::send(fd, buf.as_ptr().cast(), buf.len(), libc::MSG_NOSIGNAL) };
        if r < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        if r == 0 {
            return false;
        }
        buf = &buf[usize::try_from(r).unwrap()..];
    }
    true
}

/// A writer to the socket of the stream, with no SIGPIPE.
struct SockWriter(RawFd);

impl Write for SockWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            // SAFETY: `buf` is valid for its length; the descriptor is the stream's socket.
            let r =
                unsafe { libc::send(self.0, buf.as_ptr().cast(), buf.len(), libc::MSG_NOSIGNAL) };
            if r >= 0 {
                return Ok(usize::try_from(r).unwrap());
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// One range of guest memory for the full copy: where it lies in the process, its length, and
/// its offset in the memory file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyRange {
    /// The address in the process.
    pub host: usize,
    /// The length.
    pub len: usize,
    /// The offset in the memory file.
    pub offset: u64,
}

/// How a stream begins.
#[derive(Debug)]
pub enum StartKind {
    /// A new stream: the header and the full copy.
    New {
        /// The regions of the header.
        regions: Vec<RegionDesc>,
        /// The plugged memory to copy.
        ranges: Vec<CopyRange>,
    },
    /// A stream that continues from checkpoint `epoch` of another VMM.
    Continue {
        /// The last checkpoint of the other VMM.
        epoch: u64,
        /// The identity of the place.
        id: Option<[u8; stream::ID_LEN]>,
    },
}

/// The work of the sender.
#[derive(Debug)]
pub enum Job {
    /// Connect and begin a stream.
    Start {
        /// The number of this stream; its events carry it.
        generation: u64,
        /// The receiving place.
        addr: SocketAddr,
        /// The limit of an answer.
        lost_ms: u32,
        /// The output is held under a lease: an answer counts only while it runs.
        leased: bool,
        /// How the stream begins.
        kind: StartKind,
    },
    /// Send a frame and wait for its answer.
    Frame {
        /// Its number.
        epoch: u64,
        /// `SBCH`.
        held: bool,
        /// The page records with their end record.
        pages: Vec<u8>,
        /// The state.
        state: Vec<u8>,
    },
    /// The limit of an answer changes.
    LostMs(u32),
    /// The stream ends, and its hook is closed; with `Some(N)` the hook is told `end N` first.
    End {
        /// Tell the hook `end N`.
        tell_end: Option<u64>,
        /// The hook of the stream.
        hook: Option<Hook>,
    },
}

/// What the sender tells the VMM thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The stream is connected.
    Connected {
        /// This end.
        local: SocketAddr,
        /// The receiving place.
        peer: SocketAddr,
    },
    /// The full copy is out.
    FullCopyDone {
        /// Its pages that hold data.
        pages: u64,
        /// Its bytes.
        bytes: u64,
    },
    /// The receiving place answered the begin of a continued stream (host clock, us).
    Continued {
        /// When the answer was read.
        at_us: i64,
    },
    /// A frame is out (host clock, us).
    Sent {
        /// Its number.
        epoch: u64,
        /// When the send ended.
        t_sent_us: i64,
    },
    /// The answer to a frame was read while the lease ran, and the hook was told `commit N`.
    Answer {
        /// Its number.
        epoch: u64,
        /// When it was read (host clock, us).
        at_us: i64,
    },
    /// The answer was read after the lease ended: it releases nothing.
    Late {
        /// Its number.
        epoch: u64,
    },
    /// No answer in the limit (`broken` false: a later answer counts), or the stream or the
    /// hook ended (`broken`: nothing more goes out).
    Lost {
        /// The checkpoint that waits.
        epoch: u64,
        /// What was seen.
        why: String,
        /// Nothing more goes out.
        broken: bool,
    },
    /// The stream ended, and the hook was told what the end asked.
    Ended,
}

#[derive(Debug)]
struct Shared {
    events: ChannelSender<(u64, Event)>,
    evt: EventFd,
    // The descriptor of the stream while it is open; under this lock it is shut down from the
    // VMM thread or forgotten before it is closed, never in between.
    sock: Mutex<RawFd>,
    cancel: AtomicBool,
    spare: Mutex<Option<Vec<u8>>>,
    hook: SharedHook,
}

impl Shared {
    fn tell(&self, generation: u64, event: Event) {
        let _ = self.events.send((generation, event));
        let _ = self.evt.write(1);
    }
}

/// The handle of the sender thread, on the VMM thread.
#[derive(Debug)]
pub struct Sender {
    jobs: Option<ChannelSender<Job>>,
    events: Receiver<(u64, Event)>,
    shared: Arc<Shared>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Sender {
    /// Starts the sender thread; it sets `filter` and waits for work.
    pub fn spawn(
        filter: Arc<BpfProgram>,
        lease: Arc<Lease>,
        hook: SharedHook,
    ) -> std::io::Result<Sender> {
        let (jobs, job_rx) = channel::<Job>();
        let (events_tx, events) = channel();
        let shared = Arc::new(Shared {
            events: events_tx,
            evt: EventFd::new(libc::EFD_NONBLOCK)?,
            sock: Mutex::new(-1),
            cancel: AtomicBool::new(false),
            spare: Mutex::new(None),
            hook,
        });
        let thread_shared = shared.clone();
        let thread = thread::Builder::new()
            .name("fc_ckpt_send".to_owned())
            .spawn(move || {
                if let Err(err) = crate::seccomp::apply_filter(&filter) {
                    panic!("Failed to set the seccomp filter of the checkpoint sender: {err}");
                }
                run(&job_rx, &thread_shared, &lease);
            })?;
        Ok(Sender {
            jobs: Some(jobs),
            events,
            shared,
            thread: Some(thread),
        })
    }

    /// The eventfd that each event writes.
    pub fn evt(&self) -> &EventFd {
        &self.shared.evt
    }

    /// Hands work to the thread.
    pub fn send(&self, job: Job) {
        if let Some(jobs) = &self.jobs {
            let _ = jobs.send(job);
        }
    }

    /// The next event, with the number of its stream, if there is one.
    pub fn try_event(&self) -> Option<(u64, Event)> {
        self.events.try_recv().ok()
    }

    /// The next event, waiting at most `timeout`.
    pub fn wait_event(&self, timeout: Duration) -> Option<(u64, Event)> {
        self.events.recv_timeout(timeout).ok()
    }

    /// Ends what the thread does now: the socket of the stream is shut down (a send or a read
    /// in it ends) and the full copy stops. The caller sends [`Job::End`] after it.
    pub fn cancel(&self) {
        self.shared.cancel.store(true, Ordering::Release);
        let fd = self.shared.sock.lock().expect("Poisoned lock");
        if *fd >= 0 {
            // SAFETY: a shutdown of the socket of the stream, which the thread keeps open until
            // it handles the end; it ends a send or a read in it.
            unsafe { libc::shutdown(*fd, libc::SHUT_RDWR) };
        }
    }

    /// A buffer that a frame used, for the next one.
    pub fn take_spare(&self) -> Option<Vec<u8>> {
        self.shared.spare.lock().expect("Poisoned lock").take()
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        self.cancel();
        if let Some(fd) = self
            .shared
            .hook
            .try_lock()
            .ok()
            .and_then(|h| h.as_ref().map(Hook::raw_fd))
        {
            // SAFETY: a shutdown of the hook's socket, so that a line that waits ends.
            unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
        }
        self.jobs = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A stream that runs.
struct Stream {
    generation: u64,
    sock: TcpStream,
    lost_ms: u32,
    leased: bool,
    broken: bool,
}

fn run(jobs: &Receiver<Job>, shared: &Shared, lease: &Lease) {
    let mut stream: Option<Stream> = None;
    let mut next: Option<Job> = None;
    loop {
        let job = match next.take() {
            Some(job) => job,
            None => match jobs.recv() {
                Ok(job) => job,
                // The VMM, which holds the other end, is gone.
                Err(_) => return,
            },
        };
        match job {
            Job::Start {
                generation,
                addr,
                lost_ms,
                leased,
                kind,
            } => {
                close(&mut stream, shared);
                shared.cancel.store(false, Ordering::Release);
                stream = start(
                    generation, addr, lost_ms, leased, kind, shared, jobs, &mut next,
                );
            }
            Job::Frame {
                epoch,
                held,
                pages,
                state,
            } => {
                if let Some(s) = stream.as_mut().filter(|s| !s.broken) {
                    next = send_frame(s, epoch, held, pages, &state, shared, jobs, lease);
                }
            }
            Job::LostMs(ms) => {
                if let Some(s) = stream.as_mut() {
                    s.lost_ms = ms;
                }
            }
            Job::End { tell_end, hook } => {
                let generation = stream.as_ref().map_or(0, |s| s.generation);
                close(&mut stream, shared);
                if let (Some(n), Some(mut hook)) = (tell_end, hook) {
                    // The mode has ended only when the hook has answered or closed.
                    hook.tell("end", n);
                }
                shared.tell(generation, Event::Ended);
            }
        }
    }
}

fn close(stream: &mut Option<Stream>, shared: &Shared) {
    // The descriptor is forgotten before it is closed, so that a shutdown from the VMM thread
    // never meets a descriptor that the system gave to another file.
    let mut fd = shared.sock.lock().expect("Poisoned lock");
    *fd = -1;
    stream.take();
}

#[allow(clippy::too_many_arguments)]
fn start(
    generation: u64,
    addr: SocketAddr,
    lost_ms: u32,
    leased: bool,
    kind: StartKind,
    shared: &Shared,
    jobs: &Receiver<Job>,
    next: &mut Option<Job>,
) -> Option<Stream> {
    let epoch = match &kind {
        StartKind::New { .. } => 0,
        StartKind::Continue { epoch, .. } => *epoch,
    };
    let lost = |why: String| {
        shared.tell(
            generation,
            Event::Lost {
                epoch,
                why,
                broken: true,
            },
        )
    };
    let limit = Duration::from_millis(u64::from(lost_ms.max(1000)));
    let sock = match TcpStream::connect_timeout(&addr, limit) {
        Ok(sock) => sock,
        Err(err) => {
            lost(format!(
                "the connection to the receiving place could not be made: {err}"
            ));
            return None;
        }
    };
    // A checkpoint goes out in several writes, and the receiving place answers only when it has
    // all of them. With the algorithm of Nagle the kernel keeps a last write that is shorter
    // than a segment until the bytes before it are acknowledged, and the receiving place, which
    // has nothing to send yet, acknowledges them 40 ms later: the answer, and each frame that
    // waits for it, is that late.
    let _ = sock.set_nodelay(true);
    match (sock.local_addr(), sock.peer_addr()) {
        (Ok(local), Ok(peer)) => shared.tell(generation, Event::Connected { local, peer }),
        _ => {
            lost("the connection to the receiving place has ended".into());
            return None;
        }
    }
    *shared.sock.lock().expect("Poisoned lock") = sock.as_raw_fd();
    let mut s = Stream {
        generation,
        sock,
        lost_ms,
        leased,
        broken: false,
    };
    match kind {
        StartKind::New { regions, ranges } => match full_copy(&s, &regions, &ranges, shared) {
            Ok((pages, bytes)) => shared.tell(generation, Event::FullCopyDone { pages, bytes }),
            Err(err) => {
                lost(format!(
                    "the connection to the receiving place has ended: {err}"
                ));
                s.broken = true;
            }
        },
        StartKind::Continue { epoch, id } => {
            let head = stream::continue_head(epoch, id.as_ref());
            if !send_all(s.sock.as_raw_fd(), &head) {
                lost("the connection to the receiving place has ended".into());
                s.broken = true;
                return Some(s);
            }
            // The receiving place says that the checkpoint from which this stream goes on is
            // the newest that it has.
            let t0 = monotonic_ms();
            let mut part = [0u8; 8];
            let mut have = 0;
            loop {
                match read_answer(&s.sock, 20, &mut part, &mut have) {
                    Read::Answer(got) if got == epoch => {
                        shared.tell(generation, Event::Continued { at_us: host_us() });
                        break;
                    }
                    Read::Answer(_) => {
                        lost(
                            "the receiving place answered another checkpoint to the continue"
                                .into(),
                        );
                        s.broken = true;
                        break;
                    }
                    Read::Closed => {
                        lost(
                            "the receiving place does not continue from this checkpoint: it \
                             closed the connection"
                                .into(),
                        );
                        s.broken = true;
                        break;
                    }
                    Read::Nothing => {}
                }
                if shared.cancel.load(Ordering::Acquire) {
                    break;
                }
                if let Some(job) = control(jobs, &mut s) {
                    *next = Some(job);
                    break;
                }
                if monotonic_ms() - t0 > i64::from(s.lost_ms) {
                    lost("no answer to the continue in the set time".into());
                    s.broken = true;
                    break;
                }
            }
        }
    }
    Some(s)
}

/// The header and the full copy of a new stream: each page of the plugged memory as it is now,
/// pages of zeros as records of zeros. The guest runs meanwhile; frame 0 has what it changes.
fn full_copy(
    s: &Stream,
    regions: &[RegionDesc],
    ranges: &[CopyRange],
    shared: &Shared,
) -> std::io::Result<(u64, u64)> {
    const RUN: usize = 4096;
    let mut w = BufWriter::with_capacity(1 << 20, SockWriter(s.sock.as_raw_fd()));
    let mut bytes = 0u64;
    let mut data_pages = 0u64;
    let head = stream::header(regions);
    w.write_all(&head)?;
    bytes += head.len() as u64;
    let mut rec = Vec::with_capacity(16);
    for range in ranges {
        let pages = range.len / PAGE;
        let mut i = 0;
        while i < pages {
            if shared.cancel.load(Ordering::Acquire) {
                return Err(std::io::Error::other("the mode ended"));
            }
            // SAFETY: the range is plugged guest memory, which stays mapped while the VMM lives;
            // the guest may write it meanwhile, and such a page is sent again in frame 0.
            let page = |k: usize| unsafe {
                std::slice::from_raw_parts((range.host + k * PAGE) as *const u8, PAGE)
            };
            let zero = stream::page_is_zero(page(i));
            let mut n = 1;
            while i + n < pages && n < RUN && stream::page_is_zero(page(i + n)) == zero {
                n += 1;
            }
            rec.clear();
            stream::record_head(
                &mut rec,
                range.offset + (i * PAGE) as u64,
                u32::try_from(n).unwrap(),
                if zero {
                    stream::KIND_ZERO
                } else {
                    stream::KIND_DATA
                },
            );
            w.write_all(&rec)?;
            bytes += 16;
            if !zero {
                // SAFETY: as above, for the `n` pages of this record.
                let data = unsafe {
                    std::slice::from_raw_parts((range.host + i * PAGE) as *const u8, n * PAGE)
                };
                w.write_all(data)?;
                bytes += (n * PAGE) as u64;
                data_pages += n as u64;
            }
            i += n;
        }
    }
    rec.clear();
    stream::end_record(&mut rec);
    w.write_all(&rec)?;
    w.flush()?;
    bytes += 16;
    info!(
        "The full copy of the checkpoints is out: {} pages, {} bytes",
        data_pages, bytes
    );
    Ok((data_pages, bytes))
}

enum Read {
    Answer(u64),
    Nothing,
    Closed,
}

/// Waits up to `timeout_ms` for (a part of) the answer.
fn read_answer(sock: &TcpStream, timeout_ms: i32, part: &mut [u8; 8], have: &mut usize) -> Read {
    let mut p = libc::pollfd {
        fd: sock.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd.
    let r = unsafe { libc::poll(&mut p, 1, timeout_ms) };
    if r <= 0 {
        return Read::Nothing;
    }
    // SAFETY: a read into the part of `part` that is not filled yet.
    let n = unsafe {
        libc::read(
            sock.as_raw_fd(),
            part[*have..].as_mut_ptr().cast(),
            8 - *have,
        )
    };
    if n < 0 {
        return match std::io::Error::last_os_error().kind() {
            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock => Read::Nothing,
            _ => Read::Closed,
        };
    }
    if n == 0 {
        return Read::Closed;
    }
    *have += usize::try_from(n).unwrap();
    if *have < 8 {
        return Read::Nothing;
    }
    *have = 0;
    Read::Answer(u64::from_be_bytes(*part))
}

/// A job that changes the stream while it waits; another job ends the wait and is handled next.
fn control(jobs: &Receiver<Job>, s: &mut Stream) -> Option<Job> {
    loop {
        match jobs.try_recv() {
            Ok(Job::LostMs(ms)) => s.lost_ms = ms,
            Ok(job) => return Some(job),
            Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => return None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn send_frame(
    s: &mut Stream,
    epoch: u64,
    held: bool,
    pages: Vec<u8>,
    state: &[u8],
    shared: &Shared,
    jobs: &Receiver<Job>,
    lease: &Lease,
) -> Option<Job> {
    let generation = s.generation;
    let head = stream::frame_head(epoch, held, pages.len() as u64, state.len() as u64);
    let fd = s.sock.as_raw_fd();
    let ok = send_all(fd, &head)
        && send_all(fd, &pages)
        && send_all(fd, state)
        && send_all(fd, stream::FRAME_END);
    {
        let mut spare = shared.spare.lock().expect("Poisoned lock");
        let mut pages = pages;
        pages.clear();
        *spare = Some(pages);
    }
    if !ok {
        s.broken = true;
        shared.tell(
            generation,
            Event::Lost {
                epoch,
                why: "the connection to the receiving place has ended".into(),
                broken: true,
            },
        );
        return None;
    }
    let t_sent = host_us();
    shared.tell(
        generation,
        Event::Sent {
            epoch,
            t_sent_us: t_sent,
        },
    );
    let mut part = [0u8; 8];
    let mut have = 0;
    let mut told = false;
    loop {
        match read_answer(&s.sock, 20, &mut part, &mut have) {
            Read::Answer(got) if got == epoch => {
                let at = host_us();
                if s.leased && lease.passed(lease.now()) {
                    // The answer was read after the lease time was over: it releases nothing.
                    lease.count_late();
                    shared.tell(generation, Event::Late { epoch });
                    return None;
                }
                if !hook_tell(&shared.hook, "commit", epoch) {
                    s.broken = true;
                    shared.tell(
                        generation,
                        Event::Lost {
                            epoch,
                            why: "the hook gives no answer".into(),
                            broken: true,
                        },
                    );
                    return None;
                }
                shared.tell(generation, Event::Answer { epoch, at_us: at });
                return None;
            }
            Read::Answer(_) | Read::Nothing => {}
            Read::Closed => {
                s.broken = true;
                shared.tell(
                    generation,
                    Event::Lost {
                        epoch,
                        why: "the connection to the receiving place has ended".into(),
                        broken: true,
                    },
                );
                return None;
            }
        }
        if !told && host_us() - t_sent > i64::from(s.lost_ms) * 1000 {
            told = true;
            shared.tell(
                generation,
                Event::Lost {
                    epoch,
                    why: "no answer in the set time".into(),
                    broken: false,
                },
            );
        }
        if shared.cancel.load(Ordering::Acquire) {
            return None;
        }
        if let Some(job) = control(jobs, s) {
            return Some(job);
        }
    }
}
