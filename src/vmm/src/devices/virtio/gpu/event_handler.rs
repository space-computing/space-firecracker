// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::epoll::EventSet;

use super::agent::AgentRead;
use super::device::{GUEST, USER};
use super::{CTRL_QUEUE, CURSOR_QUEUE, Gpu};
use crate::devices::virtio::device::VirtioDevice;
use crate::logger::{error, warn};

impl Gpu {
    const PROCESS_ACTIVATE: u32 = 0;
    const PROCESS_CTRL_QUEUE: u32 = 1;
    const PROCESS_CURSOR_QUEUE: u32 = 2;
    const PROCESS_REMOTE: u32 = 3;
    const PROCESS_RETRY: u32 = 4;
    const PROCESS_ACK: u32 = 5;
    const PROCESS_STATS: u32 = 6;
    const PROCESS_AGENT_LISTEN: u32 = 7;
    const PROCESS_AGENT_CONN: u32 = 8;
    const PROCESS_REMOTE_GUEST: u32 = 9;
    const PROCESS_GUEST_LISTEN: u32 = 10;

    fn add(ops: &mut EventOps, fd: &impl std::os::fd::AsRawFd, data: u32) {
        if let Err(err) = ops.add(Events::with_data(fd, data, EventSet::IN)) {
            error!("gpu: failed to register an event: {err}");
        }
    }

    /// The connection and the timers work whether the guest's driver is up or not.
    fn register_connection_events(&self, ops: &mut EventOps) {
        Self::add(ops, &self.conns[USER].link.rx_event, Self::PROCESS_REMOTE);
        if let Some(c) = self.conns.get(GUEST) {
            Self::add(ops, &c.link.rx_event, Self::PROCESS_REMOTE_GUEST);
            if let Some(l) = c.link.listener() {
                Self::add(ops, l, Self::PROCESS_GUEST_LISTEN);
            }
        }
        Self::add(ops, &self.retry_timer, Self::PROCESS_RETRY);
        Self::add(ops, &self.ack_timer, Self::PROCESS_ACK);
        Self::add(ops, &self.stats_timer, Self::PROCESS_STATS);
        if let Some(ag) = &self.agent {
            Self::add(ops, &ag.listener, Self::PROCESS_AGENT_LISTEN);
            if let Some(c) = &ag.conn {
                Self::add(ops, c, Self::PROCESS_AGENT_CONN);
            }
        }
    }

    /// A connection of the in-guest renderer: it is held, and paired at once when that renderer
    /// is wanted (a newer one replaces one that is held).
    fn process_guest_listen(&mut self) {
        if !self.conns[GUEST].link.accept() {
            return;
        }
        let c = &self.conns[GUEST];
        let msg = format!(
            "spacebox remote gpu: the in-guest renderer connected on {}{}",
            c.link.path(),
            if c.wanted && !c.link.is_connected() {
                ""
            } else {
                " (held until it is wanted)"
            }
        );
        self.log_info_line(&msg);
        let c = &self.conns[GUEST];
        if c.wanted && !c.link.is_connected() {
            self.retry_timer
                .arm(std::time::Duration::from_millis(1), None);
        }
    }

    /// A connection of the agent: it replaces the one before.
    fn process_agent_listen(&mut self, ops: &mut EventOps) {
        let Some(ag) = self.agent.as_mut() else {
            return;
        };
        let Some((_, old)) = ag.accept() else {
            return;
        };
        if let Some(old) = old
            && let Err(err) = ops.remove(Events::new(&old, EventSet::IN))
        {
            error!("gpu: failed to unregister the agent's old connection: {err}");
        }
        let msg = format!(
            "spacebox remote gpu: the guest agent connected on {}",
            ag.path()
        );
        if let Some(c) = &ag.conn {
            Self::add(ops, c, Self::PROCESS_AGENT_CONN);
        }
        self.log_info_line(&msg);
        self.agent_connected();
        self.notify_used();
    }

    fn process_agent_conn(&mut self, ops: &mut EventOps) {
        let Some(ag) = self.agent.as_mut() else {
            return;
        };
        match ag.read() {
            AgentRead::Lines(lines) => self.agent_lines(&lines),
            AgentRead::Closed => {
                if let Some(c) = ag.take_conn()
                    && let Err(err) = ops.remove(Events::new(&c, EventSet::IN))
                {
                    error!("gpu: failed to unregister the agent's connection: {err}");
                }
                self.log_info_line("spacebox remote gpu: the guest agent's connection ended");
            }
        }
        self.notify_used();
    }

    fn register_queue_events(&mut self, ops: &mut EventOps) {
        if self.runtime_events_registered {
            return;
        }
        Self::add(
            ops,
            self.queue_event(CTRL_QUEUE)
                .expect("an event of each queue"),
            Self::PROCESS_CTRL_QUEUE,
        );
        Self::add(
            ops,
            self.queue_event(CURSOR_QUEUE)
                .expect("an event of each queue"),
            Self::PROCESS_CURSOR_QUEUE,
        );
        self.runtime_events_registered = true;
    }

    fn process_activate_event(&mut self, ops: &mut EventOps) {
        if let Err(err) = self.activate_event().read() {
            error!("gpu: failed to consume the activate event: {err}");
        }
        self.register_queue_events(ops);
        // What the sinks sent before the driver was up waits in the channels.
        for ci in 0..self.conns.len() {
            self.process_remote(ci);
        }
        self.process_queues();
    }

    fn process_queues(&mut self) {
        if let Err(err) = self.process_ctrl_queue() {
            error!("gpu: control queue: {err}");
        }
        if let Err(err) = self.process_cursor_queue() {
            error!("gpu: cursor queue: {err}");
        }
        self.notify_used();
    }
}

impl MutEventSubscriber for Gpu {
    fn init(&mut self, ops: &mut EventOps) {
        self.register_connection_events(ops);
        Self::add(ops, self.activate_event(), Self::PROCESS_ACTIVATE);
        if self.is_activated() {
            self.register_queue_events(ops);
        }
    }

    fn process(&mut self, events: Events, ops: &mut EventOps) {
        let event_set = events.event_set();
        let source = events.data();
        if source == Self::PROCESS_AGENT_CONN {
            // Data, or the end of the connection (which comes without IN).
            self.process_agent_conn(ops);
            return;
        }
        if !event_set.contains(EventSet::IN) {
            warn!("gpu: unknown event {event_set:?} from source {source}");
            return;
        }
        match source {
            Self::PROCESS_ACTIVATE => self.process_activate_event(ops),
            Self::PROCESS_REMOTE => self.process_remote(USER),
            Self::PROCESS_REMOTE_GUEST => self.process_remote(GUEST),
            Self::PROCESS_RETRY => self.process_retry(),
            Self::PROCESS_ACK => self.process_ack_timer(),
            Self::PROCESS_STATS => self.process_stats_timer(),
            Self::PROCESS_AGENT_LISTEN => self.process_agent_listen(ops),
            Self::PROCESS_GUEST_LISTEN => self.process_guest_listen(),
            Self::PROCESS_CTRL_QUEUE | Self::PROCESS_CURSOR_QUEUE => {
                let q = if source == Self::PROCESS_CTRL_QUEUE {
                    CTRL_QUEUE
                } else {
                    CURSOR_QUEUE
                };
                if let Err(err) = self.queue_event(q).expect("an event of each queue").read() {
                    error!("gpu: failed to read a queue event: {err}");
                }
                if self.is_activated() {
                    self.process_queues();
                }
            }
            _ => warn!("gpu: unknown event source {source}"),
        }
    }
}
