// Copyright 2026 Spacebox authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The sign of life of the checkpoints: a signal of its own, apart from the stream.
//!
//! A thread of its own sends a datagram (UDP) each `signal-ms` to the address and the port of
//! the stream, from the address of the stream. The receiving place echoes it when it has this
//! stream open, has answered its begin, has not begun its seal, and has the identity that the
//! signal names. The thread keeps the time on the lease clock at which it sent each signal,
//! taken before the send. When it reads the echo of signal k, it tells the lease the send time
//! of k. Nothing of an echo but its number is used. An echo releases nothing.
//!
//! The thread takes no lock of the VMM: it sends during the stop of a checkpoint and while the
//! sender waits in a send. A signal also says that the main loop of the VMM thread turns: the
//! VMM thread ends the lease and takes the checkpoints, so a VMM whose main loop stands must not
//! look alive. The VMM thread writes the time each 100 ms, also while the guest is stopped, and
//! this thread sends only when that time is not older than five times `signal-ms`. A stop of a
//! checkpoint that is longer than that pauses the signal until it ends.
//!
//! ```text
//! the signal:  "SBSG" | u8 1 | u8 1 or 0 (it names an identity) | be16 the port of this end of
//!              the stream | 16 bytes: the identity, or zeros | be64 its number
//! the echo:    the same bytes with "SBSE" in the place of "SBSG"
//! ```

use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::thread;

use vmm_sys_util::eventfd::EventFd;

use super::lease::{Lease, monotonic_ms};
use super::stream::ID_LEN;
use crate::logger::{error, info};
use crate::seccomp::BpfProgram;

const SIGNAL: &[u8; 4] = b"SBSG";
const ECHO: &[u8; 4] = b"SBSE";
const SIGNAL_LEN: usize = 32;
/// The send times of the newest signals.
const KEPT: usize = 64;
/// The main loop turned this many signal times ago at the latest.
pub const BEAT_SIGNALS: i64 = 5;

/// What the signal thread is told.
#[derive(Debug)]
enum Command {
    Start {
        local: SocketAddr,
        peer: SocketAddr,
        signal_ms: u32,
        id: Option<[u8; ID_LEN]>,
    },
    Stop,
}

/// The handle of the signal thread, on the VMM thread.
#[derive(Debug)]
pub struct Signal {
    commands: Option<Sender<Command>>,
    wake: EventFd,
    running: bool,
    thread: Option<thread::JoinHandle<()>>,
}

/// The bytes of the signal before its number.
pub fn signal_head(port: u16, id: Option<&[u8; ID_LEN]>) -> [u8; SIGNAL_LEN - 8] {
    let mut head = [0u8; SIGNAL_LEN - 8];
    head[..4].copy_from_slice(SIGNAL);
    head[4] = 1;
    head[5] = u8::from(id.is_some());
    head[6..8].copy_from_slice(&port.to_be_bytes());
    if let Some(id) = id {
        head[8..24].copy_from_slice(id);
    }
    head
}

impl Signal {
    /// Starts the signal thread; it sets `filter` and waits.
    pub fn spawn(filter: Arc<BpfProgram>, lease: Arc<Lease>) -> std::io::Result<Signal> {
        let (commands, rx) = channel();
        let wake = EventFd::new(libc::EFD_NONBLOCK)?;
        let thread_wake = wake.try_clone()?;
        let thread = thread::Builder::new()
            .name("fc_ckpt_signal".to_owned())
            .spawn(move || {
                if let Err(err) = crate::seccomp::apply_filter(&filter) {
                    panic!("Failed to set the seccomp filter of the checkpoint signal: {err}");
                }
                while let Ok(command) = rx.recv() {
                    if let Command::Start {
                        local,
                        peer,
                        signal_ms,
                        id,
                    } = command
                    {
                        run(local, peer, signal_ms, id, &rx, &thread_wake, &lease);
                    }
                }
            })?;
        Ok(Signal {
            commands: Some(commands),
            wake,
            running: false,
            thread: Some(thread),
        })
    }

    /// The signal goes from `local` (the address of this end of the stream) to `peer` each
    /// `signal_ms`, naming `id`.
    pub fn start(
        &mut self,
        local: SocketAddr,
        peer: SocketAddr,
        signal_ms: u32,
        id: Option<[u8; ID_LEN]>,
    ) {
        self.stop();
        if let Some(c) = &self.commands {
            let _ = c.send(Command::Start {
                local,
                peer,
                signal_ms,
                id,
            });
            self.running = true;
        }
    }

    /// No further signal is sent.
    pub fn stop(&mut self) {
        if self.running {
            if let Some(c) = &self.commands {
                let _ = c.send(Command::Stop);
            }
            let _ = self.wake.write(1);
            self.running = false;
        }
    }

    /// Whether the signal runs.
    pub fn running(&self) -> bool {
        self.running
    }
}

impl Drop for Signal {
    fn drop(&mut self) {
        self.stop();
        self.commands = None;
        let _ = self.wake.write(1);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run(
    local: SocketAddr,
    peer: SocketAddr,
    signal_ms: u32,
    id: Option<[u8; ID_LEN]>,
    rx: &Receiver<Command>,
    wake: &EventFd,
    lease: &Lease,
) {
    let mut from = local;
    from.set_port(0);
    let sock = match UdpSocket::bind(from).and_then(|s| s.connect(peer).map(|()| s)) {
        Ok(sock) => sock,
        Err(err) => {
            error!("The socket of the signal of the checkpoints: {}", err);
            return;
        }
    };
    info!(
        "The signal of the checkpoints goes to {} each {} ms",
        peer, signal_ms
    );
    lease.forget_echoes();
    let head = signal_head(local.port(), id.as_ref());
    let mut kept = [(0u64, 0i64); KEPT];
    let mut number = 0u64;
    let period = i64::from(signal_ms.max(1));
    let mut next = monotonic_ms();
    loop {
        let now = monotonic_ms();
        if now >= next {
            // The main loop of the VMM thread stands: this VMM gives no sign of life.
            if now - lease.last_beat() <= BEAT_SIGNALS * period {
                // The send time is taken before the send, and kept. A VMM whose lease time is
                // over gives no further sign of life.
                let sent = lease.now();
                if !lease.passed(sent) {
                    number += 1;
                    kept[usize::try_from(number % KEPT as u64).unwrap()] = (number, sent);
                    let mut m = [0u8; SIGNAL_LEN];
                    m[..SIGNAL_LEN - 8].copy_from_slice(&head);
                    m[SIGNAL_LEN - 8..].copy_from_slice(&number.to_be_bytes());
                    // A signal that is lost costs nothing: the next one follows.
                    // SAFETY: `m` is valid for its length; the socket is connected.
                    unsafe {
                        libc::send(
                            sock.as_raw_fd(),
                            m.as_ptr().cast(),
                            SIGNAL_LEN,
                            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                        )
                    };
                }
            }
            next += period;
            if next <= now {
                // This thread stood still: no signals in a row for it.
                next = now + period;
            }
        }
        let mut fds = [
            libc::pollfd {
                fd: sock.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let timeout = i32::try_from((next - monotonic_ms()).clamp(1, 1000)).unwrap();
        // SAFETY: two valid pollfds.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) };
        if r > 0 && fds[0].revents != 0 {
            read_echoes(&sock, &head, &kept, lease);
        }
        if r > 0 && fds[1].revents != 0 {
            let _ = wake.read();
        }
        match rx.try_recv() {
            Ok(Command::Stop) | Err(TryRecvError::Disconnected) => return,
            Ok(Command::Start { .. }) => {
                error!("The signal of the checkpoints was started twice");
                return;
            }
            Err(TryRecvError::Empty) => {}
        }
    }
}

fn read_echoes(
    sock: &UdpSocket,
    head: &[u8; SIGNAL_LEN - 8],
    kept: &[(u64, i64); KEPT],
    lease: &Lease,
) {
    loop {
        let mut m = [0u8; SIGNAL_LEN + 1];
        // SAFETY: a read into `m`.
        let n = unsafe {
            libc::recv(
                sock.as_raw_fd(),
                m.as_mut_ptr().cast(),
                m.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            match std::io::Error::last_os_error().raw_os_error() {
                // (also the word of the kernel that no one listens there)
                Some(libc::EINTR) | Some(libc::ECONNREFUSED) => continue,
                _ => return,
            }
        }
        if usize::try_from(n).unwrap() != SIGNAL_LEN || &m[..4] != ECHO || m[4..24] != head[4..24] {
            continue;
        }
        let number = u64::from_be_bytes(m[24..32].try_into().unwrap());
        let (kept_number, sent) = kept[usize::try_from(number % KEPT as u64).unwrap()];
        if number == 0 || kept_number != number {
            continue;
        }
        lease.echo(sent);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// A place that echoes each signal it gets, while `echo` says so; returns the signals.
    fn place(
        sock: UdpSocket,
        echo: Arc<std::sync::atomic::AtomicBool>,
        n: usize,
    ) -> thread::JoinHandle<Vec<Vec<u8>>> {
        thread::spawn(move || {
            let mut got = Vec::new();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            while got.len() < n {
                let mut m = [0u8; 64];
                let Ok((len, from)) = sock.recv_from(&mut m) else {
                    break;
                };
                let m = m[..len].to_vec();
                if echo.load(std::sync::atomic::Ordering::SeqCst) {
                    let mut e = m.clone();
                    e[..4].copy_from_slice(b"SBSE");
                    sock.send_to(&e, from).unwrap();
                }
                got.push(m);
            }
            got
        })
    }

    #[test]
    fn test_signal_and_echo_keep_the_lease() {
        let lease = Lease::new();
        lease.stamp();
        let place_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = place_sock.local_addr().unwrap();
        let echo = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let got = place(place_sock, echo.clone(), 6);
        let mut signal = Signal::spawn(Arc::new(vec![]), lease.clone()).unwrap();
        let begin = lease.now();
        lease.begin(begin, 200);
        let id = [7u8; ID_LEN];
        signal.start("127.0.0.1:4321".parse().unwrap(), peer, 50, Some(id));
        // The lease of 200 ms is kept by the echoes for longer than its time.
        for _ in 0..6 {
            lease.stamp();
            std::thread::sleep(Duration::from_millis(60));
        }
        assert!(!lease.passed(lease.now()));
        assert!(lease.info().since_echo_ms.unwrap() < 200);
        signal.stop();
        let got = got.join().unwrap();
        assert_eq!(got.len(), 6);
        for (k, m) in got.iter().enumerate() {
            assert_eq!(m.len(), 32);
            assert_eq!(&m[..4], b"SBSG");
            assert_eq!(m[4], 1);
            assert_eq!(m[5], 1);
            assert_eq!(u16::from_be_bytes([m[6], m[7]]), 4321);
            assert_eq!(&m[8..24], &id);
            assert_eq!(
                u64::from_be_bytes(m[24..32].try_into().unwrap()),
                k as u64 + 1
            );
        }
        // With no signal and no echo the lease ends.
        std::thread::sleep(Duration::from_millis(260));
        assert!(lease.passed(lease.now()));
    }

    #[test]
    fn test_no_signal_while_the_main_loop_stands() {
        let lease = Lease::new();
        let place_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        place_sock
            .set_read_timeout(Some(Duration::from_millis(400)))
            .unwrap();
        let peer = place_sock.local_addr().unwrap();
        let mut signal = Signal::spawn(Arc::new(vec![]), lease.clone()).unwrap();
        // The main loop turned 300 ms ago: older than 5 times 20 ms.
        lease.stamp();
        std::thread::sleep(Duration::from_millis(300));
        signal.start("127.0.0.1:1".parse().unwrap(), peer, 20, None);
        let mut m = [0u8; 64];
        place_sock.recv_from(&mut m).unwrap_err();
        // It turns again: the signals go out, naming no identity.
        lease.stamp();
        let (len, _) = place_sock.recv_from(&mut m).unwrap();
        assert_eq!(len, 32);
        assert_eq!(m[5], 0);
        assert_eq!(&m[8..24], &[0u8; 16]);
        signal.stop();
    }

    #[test]
    fn test_no_signal_after_the_lease() {
        let lease = Lease::new();
        lease.stamp();
        let place_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        place_sock
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let peer = place_sock.local_addr().unwrap();
        lease.begin(lease.now() - 1000, 100);
        let mut signal = Signal::spawn(Arc::new(vec![]), lease.clone()).unwrap();
        signal.start("127.0.0.1:1".parse().unwrap(), peer, 20, None);
        let mut m = [0u8; 64];
        place_sock.recv_from(&mut m).unwrap_err();
        signal.stop();
    }
}
