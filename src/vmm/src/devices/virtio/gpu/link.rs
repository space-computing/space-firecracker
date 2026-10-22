// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The connection to the renderer (the "sink" of the Spacebox QEMU fork's remote GPU).
//!
//! The device's state lives on the screen's thread (`fc_screen`, [`super::device`]); this module holds what the
//! two I/O threads share with it:
//!
//! - The resend queue ([`TxQueue`]): reliable messages stay in it until the peer acknowledges
//!   them, so that a new connection can continue where the old one stopped (as `tx_queue` of
//!   the QEMU source).
//! - A writer thread (`fc_gpu_tx`) that takes the next message of the queue, compresses it when
//!   the connection is compressed, and writes it.
//! - A reader thread (`fc_gpu_rx`) that reads, takes the peer's HELLO out first, uncompresses,
//!   cuts the stream into messages and hands them to the device's thread through a channel and an
//!   eventfd.
//!
//! The device's thread connects (a unix socket connects at once or fails), writes its HELLO, and
//! decides about everything that arrives. The link of the renderer inside the guest listens
//! instead ([`Link::listen`]): that renderer connects out through vsock, and the device takes its
//! connection when it wants that renderer. Both threads apply Firecracker's `vmm` seccomp filter
//! before anything else and never start other threads; they block only on the socket and on a
//! condition variable.

use std::collections::VecDeque;
use std::fs::File;
use std::io::ErrorKind;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;

use gpu_journal::Blob;
use vmm_sys_util::eventfd::EventFd;

use super::protocol::{Filter, HDR_LEN, Hdr, SP_F_ZSTD, SP_HELLO, ZPacker, ZUnpacker};
use crate::logger::error;
use crate::seccomp::BpfProgram;

/// Monotonic clock in microseconds (`g_get_monotonic_time`).
pub(crate) fn now_us() -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes into the timespec we own.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec * 1_000_000 + ts.tv_nsec / 1000
}

/// Counts of delays over 12, 25 and 50 ms and the longest (`struct SpDelayStat`).
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct DelayStat {
    pub n: u32,
    pub over12: u32,
    pub over25: u32,
    pub over50: u32,
    pub max: i64,
}

impl DelayStat {
    pub(crate) fn add(&mut self, d: i64) {
        self.n += 1;
        self.over12 += u32::from(d > 12_000);
        self.over25 += u32::from(d > 25_000);
        self.over50 += u32::from(d > 50_000);
        self.max = self.max.max(d);
    }
}

/// One message as it goes on the wire before compression: header, a, b. Its bytes are shared
/// with the snapshots and checkpoints that hold it as not acknowledged.
#[derive(Debug)]
pub(crate) struct TxBuf {
    pub data: Blob,
    pub t_us: i64,
    pub filter: Option<Filter>,
}

#[derive(Debug)]
struct TxEntry {
    buf: Arc<TxBuf>,
    /// 0 = not resent.
    id: u64,
    writing: bool,
}

/// The resend queue (`tx_queue`, `tx_next`, `tx_backlog`, `tx_unacked`, `tx_id` of the QEMU
/// source). `next` is the index of the first entry not yet written to the current connection.
#[derive(Debug, Default)]
pub(crate) struct TxQueue {
    entries: VecDeque<TxEntry>,
    next: usize,
    /// The peer's HELLO has been answered: the writer may send.
    pub enabled: bool,
    /// Bytes not yet written.
    pub backlog: usize,
    /// Bytes written or not, not yet acknowledged.
    pub unacked: usize,
    /// The last reliable id given out.
    pub tx_id: u64,
}

impl TxQueue {
    /// Queue a message; a reliable one gets the next id, written into its header together with
    /// the acknowledgement `ack`.
    pub(crate) fn push(
        &mut self,
        mut data: Vec<u8>,
        reliable: bool,
        ack: u64,
        t_us: i64,
        filter: Option<Filter>,
    ) -> u64 {
        let id = if reliable {
            self.tx_id += 1;
            self.tx_id
        } else {
            0
        };
        data[8..16].copy_from_slice(&id.to_le_bytes());
        data[16..24].copy_from_slice(&ack.to_le_bytes());
        self.backlog += data.len();
        self.unacked += data.len();
        self.entries.push_back(TxEntry {
            buf: Arc::new(TxBuf {
                data: Arc::new(data),
                t_us,
                filter,
            }),
            id,
            writing: false,
        });
        id
    }

    /// The next message to write, marked as being written.
    pub(crate) fn take(&mut self) -> Option<Arc<TxBuf>> {
        if !self.enabled || self.next >= self.entries.len() {
            return None;
        }
        let e = &mut self.entries[self.next];
        self.next += 1;
        e.writing = true;
        Some(e.buf.clone())
    }

    fn remove(&mut self, i: usize) {
        let e = self.entries.remove(i).unwrap();
        if i < self.next {
            self.next -= 1;
        }
        self.unacked -= self.unacked.min(e.buf.data.len());
    }

    /// The writer is done with `buf` (written, or the write failed).
    pub(crate) fn written(&mut self, buf: &Arc<TxBuf>) {
        self.backlog -= self.backlog.min(buf.data.len());
        if let Some(i) = self.entries.iter().position(|e| Arc::ptr_eq(&e.buf, buf)) {
            self.entries[i].writing = false;
            if self.entries[i].id == 0 {
                // not resent: forget it once written (or once the write failed)
                self.remove(i);
            }
        }
    }

    /// The peer has everything up to `id`: drop it (`sp_acked`).
    pub(crate) fn acked(&mut self, id: u64) {
        let mut i = 0;
        while i < self.next && i < self.entries.len() {
            let e = &self.entries[i];
            if e.id != 0 && e.id <= id && !e.writing {
                self.remove(i);
            } else if e.id > id {
                break;
            } else {
                i += 1;
            }
        }
    }

    /// Open the queue: everything the peer does not have yet goes out again (`sp_tx_start`).
    pub(crate) fn start(&mut self, peer_has: u64) {
        self.acked(peer_has);
        let mut i = 0;
        let mut unsent = 0;
        while i < self.entries.len() {
            let e = &self.entries[i];
            if e.id == 0 && !e.writing {
                // one-shot messages of the old connection are stale
                self.remove(i);
            } else {
                unsent += e.buf.data.len();
                i += 1;
            }
        }
        self.next = 0;
        self.backlog = unsent;
        self.enabled = true;
    }

    /// The reliable messages the peer has not acknowledged, with their ids (for a snapshot).
    pub(crate) fn unacked_messages(&self) -> Vec<(u64, Blob)> {
        self.entries
            .iter()
            .filter(|e| e.id != 0)
            .map(|e| (e.id, e.buf.data.clone()))
            .collect()
    }

    /// The queue of a snapshot: the last id given out and the messages not acknowledged. The
    /// queue stays closed until the peer's HELLO.
    pub(crate) fn restore(&mut self, tx_id: u64, unacked: &[(u64, Blob)], t_us: i64) {
        self.forget();
        for (id, data) in unacked {
            self.backlog += data.len();
            self.unacked += data.len();
            self.entries.push_back(TxEntry {
                buf: Arc::new(TxBuf {
                    data: data.clone(),
                    t_us,
                    filter: None,
                }),
                id: *id,
                writing: false,
            });
        }
        self.next = 0;
        self.tx_id = tx_id;
    }

    /// Start empty with a new peer (`sp_tx_forget`).
    pub(crate) fn forget(&mut self) {
        let mut i = 0;
        while i < self.entries.len() {
            if self.entries[i].writing {
                self.entries[i].id = 0; // the writer frees it
                i += 1;
            } else {
                self.entries.remove(i);
            }
        }
        self.next = self.entries.len();
        self.backlog = 0;
        self.unacked = 0;
        self.tx_id = 0;
    }

    #[cfg(test)]
    fn ids(&self) -> Vec<u64> {
        self.entries.iter().map(|e| e.id).collect()
    }

    /// The queued messages: (header, a, b).
    #[cfg(test)]
    pub(crate) fn messages(&self) -> Vec<(Hdr, Vec<u8>, Vec<u8>)> {
        self.entries
            .iter()
            .map(|e| {
                let h = Hdr::decode(&e.buf.data).unwrap();
                let a_end = HDR_LEN + h.a_len as usize;
                (
                    h,
                    e.buf.data[HDR_LEN..a_end].to_vec(),
                    e.buf.data[a_end..].to_vec(),
                )
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn last_filter(&self) -> Option<Filter> {
        self.entries.back().and_then(|e| e.buf.filter)
    }
}

/// What the reader thread hands to the device's thread.
#[derive(Debug)]
pub(crate) enum RxEvent {
    /// A whole message of connection `cgen`.
    Msg {
        cgen: u64,
        hdr: Hdr,
        a: Vec<u8>,
        b: Vec<u8>,
    },
    /// Connection `cgen` ended; `reason` if the reader closed it because of bad data.
    Closed { cgen: u64, reason: Option<String> },
}

#[derive(Debug)]
pub(crate) struct LinkState {
    conn: Option<Arc<UnixStream>>,
    /// Counts connections; each starts new zstd streams.
    cgen: u64,
    pub q: TxQueue,
    /// Both ends offered compression (set with the peer's HELLO).
    pub z_on: bool,
    /// Bytes written to the socket.
    pub wire_tx: u64,
    /// Time from queueing a message to having written it.
    pub txd: DelayStat,
}

#[derive(Debug)]
struct Shared {
    st: Mutex<LinkState>,
    /// Wakes the writer.
    tx_cond: Condvar,
    /// Wakes the reader: a new connection.
    rx_cond: Condvar,
    /// Bytes read from the socket, and after uncompressing.
    wire_rx: AtomicU64,
    rx_bytes: AtomicU64,
    /// Bytes read from the socket since the link was made (never reset).
    rx_total: AtomicU64,
    z_level: i32,
}

/// The device's end of the connection.
#[derive(Debug)]
pub(crate) struct Link {
    shared: Arc<Shared>,
    rx: Receiver<RxEvent>,
    /// Readable when events wait in the channel.
    pub(crate) rx_event: EventFd,
    path: String,
    /// A link that listens: its socket, and the newest connection that came and is not taken
    /// yet (the device takes it when it wants that renderer).
    listener: Option<UnixListener>,
    held: Option<UnixStream>,
    /// The current connection, if any, and its number.
    stream: Option<Arc<UnixStream>>,
    pub(crate) cgen: u64,
    /// Events taken out of the channel by [`Link::wait`], handed out first.
    stash: VecDeque<RxEvent>,
}

fn shutdown(s: &UnixStream) {
    // SAFETY: shutdown on an fd we own; it only changes the socket's state.
    unsafe { libc::shutdown(s.as_raw_fd(), libc::SHUT_RDWR) };
}

/// Starts a thread that applies `filter` first and reports whether it could.
fn spawn_filtered<F>(name: &str, filter: Arc<BpfProgram>, f: F) -> std::io::Result<()>
where
    F: FnOnce() + Send + 'static,
{
    let (ok_tx, ok_rx) = mpsc::channel();
    thread::Builder::new().name(name.into()).spawn(move || {
        if let Err(err) = crate::seccomp::apply_filter(&filter) {
            let _ = ok_tx.send(Err(err.to_string()));
            return;
        }
        let _ = ok_tx.send(Ok(()));
        f();
    })?;
    match ok_rx.recv() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(std::io::Error::other(format!(
            "{name}: seccomp filter: {e}"
        ))),
        Err(_) => Err(std::io::Error::other(format!("{name}: thread ended"))),
    }
}

impl Link {
    /// The connection to the sink at `path` (not connected yet), with its two threads
    /// (`<name>_tx`, `<name>_rx`), which run under `filter`. `z_level` 0 = compression not
    /// offered. `dump`: a copy of every message written, before compression.
    pub(crate) fn new(
        name: &str,
        path: String,
        z_level: i32,
        filter: Arc<BpfProgram>,
        dump: Option<File>,
    ) -> std::io::Result<Self> {
        let shared = Arc::new(Shared {
            st: Mutex::new(LinkState {
                conn: None,
                cgen: 0,
                q: TxQueue::default(),
                z_on: false,
                wire_tx: 0,
                txd: DelayStat::default(),
            }),
            tx_cond: Condvar::new(),
            rx_cond: Condvar::new(),
            wire_rx: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            rx_total: AtomicU64::new(0),
            z_level,
        });
        let (in_tx, rx) = mpsc::channel();
        let rx_event = EventFd::new(libc::EFD_NONBLOCK)?;
        let ev = rx_event.try_clone()?;
        let s = shared.clone();
        spawn_filtered(&format!("{name}_tx"), filter.clone(), move || {
            writer(&s, dump)
        })?;
        let s = shared.clone();
        spawn_filtered(&format!("{name}_rx"), filter, move || {
            reader(&s, &in_tx, &ev)
        })?;
        Ok(Link {
            shared,
            rx,
            rx_event,
            path,
            listener: None,
            held: None,
            stream: None,
            cgen: 0,
            stash: VecDeque::new(),
        })
    }

    /// A link whose renderer connects to it: the device listens on `path` (a stale socket file
    /// is removed), takes each connection that comes ([`Self::accept`]), and pairs the newest
    /// one when it wants that renderer ([`Self::connect`]).
    pub(crate) fn listen(
        name: &str,
        path: String,
        z_level: i32,
        filter: Arc<BpfProgram>,
        dump: Option<File>,
    ) -> std::io::Result<Self> {
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        let mut link = Self::new(name, path, z_level, filter, dump)?;
        link.listener = Some(listener);
        Ok(link)
    }

    /// The listening socket of a link that listens.
    pub(crate) fn listener(&self) -> Option<&UnixListener> {
        self.listener.as_ref()
    }

    /// Takes the connections that wait on the listening socket; the newest is held, the older
    /// ones are closed. True if one came.
    pub(crate) fn accept(&mut self) -> bool {
        let Some(l) = self.listener.as_ref() else {
            return false;
        };
        let mut came = false;
        while let Ok((s, _)) = l.accept() {
            // the threads block on the socket
            if s.set_nonblocking(false).is_ok() {
                self.held = Some(s);
                came = true;
            }
        }
        came
    }

    /// Whether the renderer can be paired now: connected, or (a link that listens) holding a
    /// connection of the renderer, or (a link that connects) worth a try.
    pub(crate) fn reachable(&self) -> bool {
        self.stream.is_some() || self.listener.is_none() || self.held.is_some()
    }

    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn z_level(&self) -> i32 {
        self.shared.z_level
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, LinkState> {
        self.shared.st.lock().unwrap()
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    pub(crate) fn try_recv(&mut self) -> Option<RxEvent> {
        self.stash.pop_front().or_else(|| self.rx.try_recv().ok())
    }

    /// Wait at most `d` for the reader to pass something on (for the device when it must
    /// not return to the event loop: the drain before a snapshot). True if something waits.
    pub(crate) fn wait(&mut self, d: std::time::Duration) -> bool {
        if !self.stash.is_empty() {
            return true;
        }
        match self.rx.recv_timeout(d) {
            Ok(ev) => {
                self.stash.push_back(ev);
                true
            }
            Err(_) => false,
        }
    }

    /// Bytes read from the socket and bytes after uncompressing, since the last call.
    pub(crate) fn take_rx_counts(&self) -> (u64, u64) {
        (
            self.shared.wire_rx.swap(0, Ordering::Relaxed),
            self.shared.rx_bytes.swap(0, Ordering::Relaxed),
        )
    }

    /// Bytes read from the socket since the link was made: it changes while the peer sends.
    pub(crate) fn rx_total(&self) -> u64 {
        self.shared.rx_total.load(Ordering::Relaxed)
    }

    /// Try to connect (a link that listens takes the connection it holds); on success write
    /// `hello` (the queue stays closed until the peer answers).
    pub(crate) fn connect(&mut self, hello: &Hdr) -> bool {
        let s = if self.listener.is_some() {
            self.accept();
            match self.held.take() {
                Some(s) => s,
                None => return false,
            }
        } else {
            let Ok(s) = UnixStream::connect(&self.path) else {
                return false;
            };
            s
        };
        let s = Arc::new(s);
        self.cgen = {
            let mut st = self.shared.st.lock().unwrap();
            st.conn = Some(s.clone());
            st.cgen += 1;
            st.q.enabled = false;
            st.z_on = false;
            st.cgen
        };
        self.stream = Some(s.clone());
        self.shared.rx_cond.notify_all();
        // HELLO goes out directly, outside the queue, never compressed. 80 bytes into a new
        // socket do not block.
        let _ = (&*s).write_all(&hello.encode());
        true
    }

    /// Drop the current connection (the reader and the writer see it end).
    pub(crate) fn disconnect(&mut self) {
        if let Some(s) = self.stream.take() {
            {
                let mut st = self.lock();
                st.conn = None;
                st.q.enabled = false;
            }
            shutdown(&s);
        }
    }

    /// Set whether the current connection is compressed and open the queue (`sp_tx_start`).
    pub(crate) fn start(&self, z_on: bool, peer_has: u64) {
        let mut st = self.lock();
        st.z_on = z_on;
        st.q.start(peer_has);
        drop(st);
        self.shared.tx_cond.notify_one();
    }

    pub(crate) fn set_z_on(&self, z_on: bool) {
        self.lock().z_on = z_on;
    }

    pub(crate) fn forget(&self) {
        self.lock().q.forget();
    }

    pub(crate) fn acked(&self, id: u64) {
        self.lock().q.acked(id);
    }

    pub(crate) fn backlog(&self) -> usize {
        self.lock().q.backlog
    }

    /// Queue a message (see [`TxQueue::push`]).
    pub(crate) fn push(
        &self,
        data: Vec<u8>,
        reliable: bool,
        ack: u64,
        t_us: i64,
        filter: Option<Filter>,
    ) {
        self.lock().q.push(data, reliable, ack, t_us, filter);
        self.shared.tx_cond.notify_one();
    }
}

fn writer(sh: &Shared, mut dump: Option<File>) {
    let mut z = ZPacker::new();
    let mut zgen = 0u64;
    loop {
        let (buf, stream, compress, cgen) = {
            let mut st = sh.st.lock().unwrap();
            loop {
                if st.conn.is_some()
                    && let Some(b) = st.q.take()
                {
                    break (b, st.conn.clone().unwrap(), st.z_on, st.cgen);
                }
                st = sh.tx_cond.wait(st).unwrap();
            }
        };
        if let Some(d) = dump.as_mut() {
            let _ = d.write_all(&buf.data);
        }
        let mut wire: &[u8] = &buf.data;
        if compress {
            if cgen != zgen {
                zgen = cgen;
                z.restart(sh.z_level);
            }
            match z.pack(&buf.data, buf.filter) {
                Some(w) => wire = w,
                None => {
                    // cannot happen with a sane library; drop the connection so that both
                    // streams start again
                    error!("spacebox remote gpu: compression failed");
                    shutdown(&stream);
                    zgen = 0;
                    wire = &[];
                }
            }
        }
        let mut done = 0usize;
        while done < wire.len() {
            match (&*stream).write(&wire[done..]) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break, // the reader notices the closed connection
            }
        }
        let mut st = sh.st.lock().unwrap();
        st.wire_tx += done as u64;
        st.txd.add(now_us() - buf.t_us);
        st.q.written(&buf);
    }
}

fn reader(sh: &Shared, out: &Sender<RxEvent>, ev: &EventFd) {
    let mut z = ZUnpacker::new();
    let mut seen = 0u64;
    let mut tmp = vec![0u8; 1 << 18];
    let mut rxw: Vec<u8> = Vec::new();
    let mut rx: Vec<u8> = Vec::new();
    loop {
        let (stream, cgen) = {
            let mut st = sh.st.lock().unwrap();
            loop {
                if let Some(c) = st.conn.as_ref()
                    && st.cgen != seen
                {
                    break (c.clone(), st.cgen);
                }
                st = sh.rx_cond.wait(st).unwrap();
            }
        };
        seen = cgen;
        z.restart();
        rxw.clear();
        rx.clear();
        let mut hello_in = false;
        let mut z_on = false;
        let reason: Option<String> = 'conn: loop {
            let n = match (&*stream).read(&mut tmp) {
                Ok(0) => break None,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break None,
            };
            sh.wire_rx.fetch_add(n as u64, Ordering::Relaxed);
            sh.rx_total.fetch_add(n as u64, Ordering::Relaxed);
            rxw.extend_from_slice(&tmp[..n]);
            loop {
                let had = rx.len();
                // The first message of a connection is the peer's HELLO, never compressed; it
                // decides how the rest is to be read.
                let moved = if !hello_in {
                    if rxw.len() >= HDR_LEN {
                        rx.extend_from_slice(&rxw[..HDR_LEN]);
                        rxw.drain(..HDR_LEN);
                        hello_in = true;
                        if let Some(h) = Hdr::decode(&rx[had..]) {
                            z_on = h.typ == SP_HELLO && sh.z_level != 0 && h.flags & SP_F_ZSTD != 0;
                        }
                        true
                    } else {
                        false
                    }
                } else if z_on {
                    match z.unpack(&mut rxw, &mut rx) {
                        Ok(m) => m,
                        Err(()) => break 'conn Some("bad compressed data".to_string()),
                    }
                } else if !rxw.is_empty() {
                    rx.append(&mut rxw);
                    true
                } else {
                    false
                };
                sh.rx_bytes
                    .fetch_add((rx.len() - had) as u64, Ordering::Relaxed);
                let mut off = 0usize;
                while rx.len() - off >= HDR_LEN {
                    let Some(hdr) = Hdr::decode(&rx[off..]) else {
                        break 'conn Some("bad frame".to_string());
                    };
                    let total = hdr.total();
                    if rx.len() - off < total {
                        break;
                    }
                    let a_end = off + HDR_LEN + hdr.a_len as usize;
                    let msg = RxEvent::Msg {
                        cgen,
                        hdr,
                        a: rx[off + HDR_LEN..a_end].to_vec(),
                        b: rx[a_end..off + total].to_vec(),
                    };
                    if out.send(msg).is_err() {
                        return;
                    }
                    off += total;
                }
                rx.drain(..off);
                if !moved {
                    break;
                }
            }
            let _ = ev.write(1);
        };
        if reason.is_some() {
            shutdown(&stream);
        }
        drop(stream);
        if out.send(RxEvent::Closed { cgen, reason }).is_err() {
            return;
        }
        let _ = ev.write(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(n: usize) -> Vec<u8> {
        vec![0u8; HDR_LEN + n]
    }

    #[test]
    fn ids_acks_and_bytes() {
        let mut q = TxQueue::default();
        assert_eq!(q.push(msg(20), true, 5, 0, None), 1);
        assert_eq!(q.push(msg(0), false, 5, 0, None), 0);
        assert_eq!(q.push(msg(10), true, 6, 0, None), 2);
        assert_eq!(q.ids(), vec![1, 0, 2]);
        assert_eq!(q.backlog, 270);
        assert_eq!(q.unacked, 270);
        // the id and the ack are written into the header
        let b = q.entries[2].buf.clone();
        assert_eq!(u64::from_le_bytes(b.data[8..16].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(b.data[16..24].try_into().unwrap()), 6);
        // closed until started
        assert!(q.take().is_none());
        q.start(0);
        // the unreliable message of before the start is stale
        assert_eq!(q.ids(), vec![1, 2]);
        assert_eq!(q.backlog, 190);
        assert_eq!(q.unacked, 190);
        let a = q.take().unwrap();
        let c = q.take().unwrap();
        assert!(q.take().is_none());
        q.written(&a);
        q.written(&c);
        assert_eq!(q.backlog, 0);
        // written but not acknowledged: kept
        assert_eq!(q.ids(), vec![1, 2]);
        q.acked(1);
        assert_eq!(q.ids(), vec![2]);
        assert_eq!(q.unacked, 90);
        q.acked(2);
        assert!(q.ids().is_empty());
        assert_eq!(q.unacked, 0);
    }

    #[test]
    fn unreliable_messages_go_once() {
        let mut q = TxQueue::default();
        q.start(0);
        q.push(msg(0), false, 0, 0, None);
        q.push(msg(0), true, 0, 0, None);
        let a = q.take().unwrap();
        q.written(&a);
        assert_eq!(q.ids(), vec![1]);
        // the next one to write is still the reliable one
        let b = q.take().unwrap();
        assert_eq!(u64::from_le_bytes(b.data[8..16].try_into().unwrap()), 1);
    }

    #[test]
    fn resume_resends_what_the_peer_lacks() {
        let mut q = TxQueue::default();
        q.start(0);
        for _ in 0..5 {
            q.push(msg(1), true, 0, 0, None);
        }
        // all five written on the old connection, the peer had 2 of them when it ended
        for _ in 0..5 {
            let b = q.take().unwrap();
            q.written(&b);
        }
        q.acked(1);
        assert_eq!(q.ids(), vec![2, 3, 4, 5]);
        q.enabled = false; // connection lost
        q.push(msg(1), true, 0, 0, None); // queued while disconnected
        assert!(q.take().is_none());
        // the peer's HELLO says it has 2
        q.start(2);
        assert_eq!(q.ids(), vec![3, 4, 5, 6]);
        assert_eq!(q.backlog, 4 * 81);
        let got: Vec<u64> = std::iter::from_fn(|| q.take())
            .map(|b| u64::from_le_bytes(b.data[8..16].try_into().unwrap()))
            .collect();
        assert_eq!(got, vec![3, 4, 5, 6]);
    }

    #[test]
    fn a_message_being_written_survives_acks_and_a_forget() {
        let mut q = TxQueue::default();
        q.start(0);
        q.push(msg(0), true, 0, 0, None);
        q.push(msg(0), true, 0, 0, None);
        let a = q.take().unwrap();
        // acked while still being written: not freed under the writer
        q.acked(2);
        assert_eq!(q.ids(), vec![1, 2]);
        // a new peer: everything is forgotten; the one being written goes when it is done
        q.forget();
        assert_eq!(q.ids(), vec![0]);
        assert_eq!(q.tx_id, 0);
        assert!(q.take().is_none());
        q.written(&a);
        assert!(q.ids().is_empty());
        q.start(0);
        assert_eq!(q.push(msg(0), true, 0, 0, None), 1);
        assert!(q.take().is_some());
    }

    #[test]
    fn acked_stops_at_the_first_newer_id() {
        let mut q = TxQueue::default();
        q.start(0);
        for _ in 0..3 {
            q.push(msg(0), true, 0, 0, None);
        }
        let bufs: Vec<_> = std::iter::from_fn(|| q.take()).collect();
        for b in &bufs {
            q.written(b);
        }
        // not past `next`: an entry not yet written to this connection is not dropped
        q.enabled = false;
        q.start(0);
        let first = q.take().unwrap();
        q.written(&first);
        q.acked(3);
        assert_eq!(q.ids(), vec![2, 3]);
    }
}
