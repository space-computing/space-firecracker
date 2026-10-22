// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The channel to the guest agent (`guest/scroll-agent.py` of spacebox): text lines between the
//! sink and a program in the guest, carried in the GPU device's connection (`SP_SCROLL`).
//!
//! Firecracker has no virtio-serial. The agent connects through vsock to the host's port 5000,
//! and Firecracker's vsock device connects that to the unix socket `<vsock uds>_5000`; the GPU
//! device listens there. The sink's precise scroll events and its `PING` go to the agent, the
//! agent's answers (`READY`) back to the sink, which counts the channel ready on them. A new
//! connection of the agent replaces the old one (all vsock connections end at a snapshot, and
//! the agent connects again). Everything here is nonblocking and runs on the screen's thread
//! (`fc_screen`).

use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};

/// Bytes kept for the agent while its socket is full; beyond that, lines are dropped (the
/// sink's own scroll socket keeps as much).
const TX_MAX: usize = 64 << 10;
/// The longest line taken from the agent.
const LINE_MAX: usize = 4096;

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct AgentCounters {
    pub connections: u64,
    pub lines_in: u64,
    pub lines_out: u64,
    pub dropped: u64,
}

#[derive(Debug)]
pub(crate) struct Agent {
    path: String,
    pub(crate) listener: UnixListener,
    pub(crate) conn: Option<UnixStream>,
    /// Bytes for the agent not written yet.
    tx: Vec<u8>,
    /// The part of a line from the agent not complete yet.
    rx: Vec<u8>,
    pub(crate) counters: AgentCounters,
}

/// What a read of the agent's connection found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AgentRead {
    /// Complete lines (each ending in `\n`) for the sink; may be empty.
    Lines(Vec<u8>),
    /// The connection ended; it must be taken out of the event loop and dropped.
    Closed,
}

impl Agent {
    /// Listen on `path` (a stale socket file is removed). Called at build time.
    pub(crate) fn new(path: &str) -> std::io::Result<Self> {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let listener = UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        Ok(Agent {
            path: path.to_owned(),
            listener,
            conn: None,
            tx: Vec::new(),
            rx: Vec::new(),
            counters: AgentCounters::default(),
        })
    }

    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn is_connected(&self) -> bool {
        self.conn.is_some()
    }

    /// Take a waiting connection. Returns it to be registered, and the old one (if any) to be
    /// taken out of the event loop and dropped.
    pub(crate) fn accept(&mut self) -> Option<(i32, Option<UnixStream>)> {
        let (s, _) = self.listener.accept().ok()?;
        if s.set_nonblocking(true).is_err() {
            return None;
        }
        let fd = s.as_raw_fd();
        let old = self.conn.replace(s);
        self.tx.clear();
        self.rx.clear();
        self.counters.connections += 1;
        Some((fd, old))
    }

    /// Take the connection away (it ended).
    pub(crate) fn take_conn(&mut self) -> Option<UnixStream> {
        self.tx.clear();
        self.rx.clear();
        self.conn.take()
    }

    /// Lines from the sink for the agent; dropped when no agent is connected or too much waits.
    pub(crate) fn send(&mut self, data: &[u8]) {
        let lines = data.iter().filter(|&&b| b == b'\n').count() as u64;
        if self.conn.is_none() || self.tx.len() + data.len() > TX_MAX {
            self.counters.dropped += lines;
            return;
        }
        self.counters.lines_out += lines;
        self.tx.extend_from_slice(data);
        self.flush();
    }

    /// Write what waits, as far as the socket takes it. A write error leaves the connection to
    /// the next read, which finds it ended.
    pub(crate) fn flush(&mut self) {
        let Some(c) = self.conn.as_mut() else {
            return;
        };
        while !self.tx.is_empty() {
            match c.write(&self.tx) {
                Ok(0) => break,
                Ok(n) => {
                    self.tx.drain(..n);
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    }

    /// Read what the agent sent.
    pub(crate) fn read(&mut self) -> AgentRead {
        let Some(c) = self.conn.as_mut() else {
            return AgentRead::Lines(Vec::new());
        };
        let mut buf = [0u8; 4096];
        loop {
            match c.read(&mut buf) {
                Ok(0) => return AgentRead::Closed,
                Ok(n) => {
                    self.rx.extend_from_slice(&buf[..n]);
                    if n < buf.len() {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(_) => return AgentRead::Closed,
            }
        }
        let end = self
            .rx
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1);
        let lines: Vec<u8> = self.rx.drain(..end).collect();
        if self.rx.len() > LINE_MAX {
            // A line too long: not the agent's protocol.
            self.rx.clear();
            self.counters.dropped += 1;
        }
        self.counters.lines_in += lines.iter().filter(|&&b| b == b'\n').count() as u64;
        AgentRead::Lines(lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(name: &str) -> String {
        let p =
            std::env::temp_dir().join(format!("fc-gpu-agent-{name}-{}.sock", std::process::id()));
        p.to_str().unwrap().to_owned()
    }

    #[test]
    fn test_agent_channel() {
        let p = path("a");
        std::fs::write(&p, b"stale").unwrap(); // a stale file is replaced
        let mut a = Agent::new(&p).unwrap();
        assert!(!a.is_connected());
        assert!(a.accept().is_none());
        // Nothing connected: lines from the sink are dropped.
        a.send(b"PING\n");
        assert_eq!(a.counters.dropped, 1);

        let mut g = UnixStream::connect(&p).unwrap();
        let (_, old) = a.accept().unwrap();
        assert!(old.is_none() && a.is_connected());
        a.send(b"PING\n1 2 0.5 -3 1 4 0\n");
        let mut got = [0u8; 22];
        g.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"PING\n1 2 0.5 -3 1 4 0\n");
        assert_eq!(a.counters.lines_out, 2);

        // The agent's lines come back whole; a part of a line waits for the rest.
        g.write_all(b"READY\nREA").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(a.read(), AgentRead::Lines(b"READY\n".to_vec()));
        assert_eq!(a.read(), AgentRead::Lines(Vec::new()));
        g.write_all(b"DY\n").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(a.read(), AgentRead::Lines(b"READY\n".to_vec()));
        assert_eq!(a.counters.lines_in, 2);

        // A new connection replaces the old one (the agent after a snapshot).
        let mut g2 = UnixStream::connect(&p).unwrap();
        let (_, old) = a.accept().unwrap();
        assert!(old.is_some());
        assert_eq!(a.counters.connections, 2);
        a.send(b"PING\n");
        let mut got = [0u8; 5];
        g2.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"PING\n");

        // The agent ends its connection: the read says so, and the channel is free.
        drop(g2);
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(a.read(), AgentRead::Closed);
        assert!(a.take_conn().is_some());
        assert!(!a.is_connected());
        drop(g);

        // Too much waiting for a full socket: the rest is dropped, not kept.
        let _g3 = UnixStream::connect(&p).unwrap();
        a.accept().unwrap();
        let line = [b'x'; 1023];
        let mut big = line.to_vec();
        big.push(b'\n');
        for _ in 0..1024 {
            a.send(&big);
        }
        assert!(a.counters.dropped > 1);
        std::fs::remove_file(&p).unwrap();
    }
}
