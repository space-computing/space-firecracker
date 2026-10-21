// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests of the device's rules against the QEMU source's: the answers given ahead of the sink,
//! the reads of query buffers, the answers from the sink's information, the scan of command
//! streams, and the connection (HELLO, compression, resume) with a sink played by the test.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Instant;

use super::*;
use crate::devices::virtio::gpu::input::{BTN_LEFT, EV_KEY, event as input_event};
use crate::devices::virtio::gpu::keymap::QCODE_TO_LINUX;
use crate::devices::virtio::gpu::protocol::EXPECT_LEN;
use crate::devices::virtio::gpu::protocol::{Hdr, ZPacker, ZUnpacker};
use crate::devices::virtio::gpu::spec::tests::{spec as test_spec, text as spec_text};
use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt};
use crate::snapshot::Persist;
use crate::test_utils::single_region_mem;
use crate::vstate::memory::Address;
use gpu_journal::{CMD_CTX_ATTACH_RESOURCE, CMD_SET_SCANOUT};

const RESP_AT: u64 = 0x10000;
const BACKING_AT: u64 = 0x40000;
const BACKING_LEN: u32 = 0x10000;

struct Rig<'a> {
    mem: &'a GuestMemoryMmap,
    ctrl: VirtQueue<'a>,
    gpu: Gpu,
    next_head: u16,
    /// Where the answer of each command given goes, by the order of the commands.
    resp_addrs: Vec<u64>,
}

fn cfg(socket: &str) -> GpuConfig {
    GpuConfig {
        socket_path: socket.into(),
        spec_path: "/the-spec-of-the-test".into(),
        ..Default::default()
    }
}

fn rig_with(mem: &GuestMemoryMmap, cfg: GpuConfig) -> Rig<'_> {
    // queues of the size the device makes (a restore checks it)
    let ctrl = VirtQueue::new(GuestAddress(0), mem, FIRECRACKER_MAX_QUEUE_SIZE);
    let cursor = VirtQueue::new(
        ctrl.end().unchecked_align_up(16),
        mem,
        FIRECRACKER_MAX_QUEUE_SIZE,
    );
    let mut gpu = Gpu::with_spec(cfg, test_spec(), Arc::new(Vec::new())).unwrap();
    gpu.queues = vec![ctrl.create_queue(), cursor.create_queue()];
    gpu.activate(mem.clone(), default_interrupt()).unwrap();
    Rig {
        mem,
        ctrl,
        gpu,
        next_head: 0,
        resp_addrs: Vec::new(),
    }
}

fn hdr(typ: u32, fence: Option<u64>, ctx: u32) -> Vec<u8> {
    let mut r = vec![0u8; 24];
    r[0..4].copy_from_slice(&typ.to_le_bytes());
    if let Some(f) = fence {
        r[4..8].copy_from_slice(&FLAG_FENCE.to_le_bytes());
        r[8..16].copy_from_slice(&f.to_le_bytes());
    }
    r[16..20].copy_from_slice(&ctx.to_le_bytes());
    r
}

fn put32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn put64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn submit(fence: Option<u64>, ctx: u32, stream: &[u32]) -> Vec<u8> {
    let mut r = hdr(CMD_SUBMIT_3D, fence, ctx);
    put32(&mut r, u32::try_from(stream.len() * 4).unwrap());
    put32(&mut r, 0);
    for w in stream {
        put32(&mut r, *w);
    }
    r
}

fn create_3d(id: u32, target: u32, format: u32, bind: u32, w: u32, h: u32) -> Vec<u8> {
    let mut r = hdr(CMD_RESOURCE_CREATE_3D, None, 0);
    for x in [id, target, format, bind, w, h, 1, 1, 0, 0, 0, 0] {
        put32(&mut r, x);
    }
    r
}

fn attach(id: u32, addr: u64, len: u32) -> Vec<u8> {
    let mut r = hdr(CMD_RESOURCE_ATTACH_BACKING, None, 0);
    put32(&mut r, id);
    put32(&mut r, 1);
    put64(&mut r, addr);
    put32(&mut r, len);
    put32(&mut r, 0);
    r
}

#[allow(clippy::too_many_arguments)]
fn transfer_3d(
    typ: u32,
    fence: Option<u64>,
    id: u32,
    bx: [u32; 6],
    offset: u64,
    level: u32,
    stride: u32,
) -> Vec<u8> {
    let mut r = hdr(typ, fence, 0);
    for x in bx {
        put32(&mut r, x);
    }
    put64(&mut r, offset);
    for x in [id, level, stride, 0] {
        put32(&mut r, x);
    }
    r
}

impl Rig<'_> {
    /// Give the device one command, as if popped from the control queue.
    fn give(&mut self, req: Vec<u8>) -> usize {
        let n = self.resp_addrs.len();
        let at = RESP_AT + (n as u64) * 0x1000;
        self.mem.write_slice(&[0xee; 64], GuestAddress(at)).unwrap();
        self.resp_addrs.push(at);
        let cmd = Cmd {
            head: self.next_head % 16,
            writable: vec![(GuestAddress(at), 0x1000)],
        };
        self.next_head += 1;
        self.gpu.source_one(self.mem, cmd, req);
        self.gpu.notify_used();
        n
    }

    /// The answer of command `n`, if it has one (its first 24 bytes changed).
    fn answer_of(&self, n: usize) -> Option<Vec<u8>> {
        let mut b = vec![0u8; 64];
        self.mem
            .read_slice(&mut b, GuestAddress(self.resp_addrs[n]))
            .unwrap();
        (b[..24] != [0xee; 24]).then_some(b)
    }

    fn used(&self) -> u16 {
        self.ctrl.used.idx.get()
    }

    /// The messages queued for the sink: (header, a, b).
    fn sent(&self) -> Vec<(Hdr, Vec<u8>, Vec<u8>)> {
        self.gpu.conns[USER].link.lock().q.messages()
    }

    fn sent_types(&self) -> Vec<u32> {
        self.sent().iter().map(|m| m.0.typ).collect()
    }

    fn sink_says(&mut self, typ: u32, seq: u64, a: &[u8], b: &[u8], args: [u64; 3]) {
        let h = Hdr {
            typ,
            seq,
            a_len: u32::try_from(a.len()).unwrap(),
            b_len: u32::try_from(b.len()).unwrap(),
            arg0: args[0],
            arg1: args[1],
            arg2: args[2],
            ..Default::default()
        };
        self.gpu.dispatch(USER, &h, a, b);
        self.gpu.notify_used();
    }

    /// A resource with a backing of [`BACKING_LEN`] bytes at `addr`.
    #[allow(clippy::too_many_arguments)]
    fn resource(
        &mut self,
        id: u32,
        target: u32,
        format: u32,
        bind: u32,
        w: u32,
        h: u32,
        addr: u64,
    ) {
        self.give(create_3d(id, target, format, bind, w, h));
        self.give(attach(id, addr, BACKING_LEN));
    }
}

fn resp_type(a: &[u8]) -> u32 {
    u32_at(a, 0)
}

#[test]
fn fenced_commands_are_answered_ahead_within_the_window() {
    let mem = single_region_mem(0x100000);
    let mut r = rig_with(&mem, cfg("/nonexistent"));
    for f in 1..=10u64 {
        r.give(submit(Some(f), 1, &[]));
    }
    // The first 8 (the window) are answered at once, with their fences.
    for n in 0..8 {
        let a = r.answer_of(n).unwrap();
        assert_eq!(resp_type(&a), RESP_OK_NODATA);
        assert_eq!(u32_at(&a, 4), FLAG_FENCE);
        assert_eq!(u64_at(&a, 8), n as u64 + 1);
        assert_eq!(u32_at(&a, 16), 1);
    }
    assert!(r.answer_of(8).is_none());
    assert!(r.answer_of(9).is_none());
    assert_eq!(r.used(), 8);
    assert_eq!((r.gpu.fence_out, r.gpu.wait_out, r.gpu.hard_out), (8, 2, 0));
    // Every command went to the sink, numbered, in order.
    let seqs: Vec<u64> = r.sent().iter().map(|m| m.0.seq).collect();
    assert_eq!(seqs, (1..=10).collect::<Vec<_>>());
    assert!(r.sent().iter().all(|m| m.0.typ == SP_CTRL));
    // The sink's answer to an early one is dropped (the guest has it).
    r.sink_says(SP_RESP, 1, &hdr(RESP_OK_NODATA, Some(1), 1), &[], [0; 3]);
    assert_eq!(r.used(), 8);
    assert_eq!(r.gpu.fence_out, 7);
    // The sink's answer to a waiting one goes to the guest as it is.
    let mut a9 = hdr(RESP_OK_NODATA, Some(9), 1);
    a9[20] = 0x5a;
    r.sink_says(SP_RESP, 9, &a9, &[], [0; 3]);
    assert_eq!(r.used(), 9);
    assert_eq!(&r.answer_of(8).unwrap()[..24], &a9[..]);
    assert_eq!(r.gpu.wait_out, 1);
    // An unknown sequence number (dropped by a reset) is ignored.
    r.sink_says(SP_RESP, 77, &a9, &[], [0; 3]);
    assert_eq!(r.used(), 9);
}

#[test]
fn unfenced_commands_are_answered_here_and_sent_with_seq_0() {
    let mem = single_region_mem(0x100000);
    let mut r = rig_with(&mem, cfg("/nonexistent"));
    r.give(hdr(CMD_RESOURCE_FLUSH, None, 0));
    let a = r.answer_of(0).unwrap();
    assert_eq!(resp_type(&a), RESP_OK_NODATA);
    assert_eq!(u32_at(&a, 4), 0);
    let s = r.sent();
    assert_eq!(s.len(), 1);
    assert_eq!((s[0].0.typ, s[0].0.seq), (SP_CTRL, 0));
    assert!(r.gpu.pending.is_empty());
    assert_eq!(r.gpu.seq, 1);
    // A response capacity of the guest's buffer goes as arg0.
    assert_eq!(s[0].0.arg0, 0x1000);
}

#[test]
fn window_0_waits_for_the_sink() {
    let mem = single_region_mem(0x100000);
    let mut c = cfg("/nonexistent");
    c.fence_window = Some(0);
    let mut r = rig_with(&mem, c);
    r.give(hdr(CMD_RESOURCE_FLUSH, None, 0));
    r.give(submit(Some(1), 1, &[]));
    assert!(r.answer_of(0).is_none());
    assert!(r.answer_of(1).is_none());
    assert_eq!(r.gpu.pending.len(), 2);
}

#[test]
fn no_later_fence_ahead_while_one_waits_for_data() {
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg("/nonexistent"));
    // B8G8R8A8 (format 1), 64x64 texture.
    r.resource(5, 2, 1, 0, 64, 64, BACKING_AT);
    let base = r.used();
    // A fenced read back waits for its data; the fenced command after it may not be answered.
    let n0 = r.give(transfer_3d(
        CMD_TRANSFER_FROM_HOST_3D,
        Some(1),
        5,
        [0, 0, 0, 4, 2, 1],
        0,
        0,
        0,
    ));
    let n1 = r.give(submit(Some(2), 1, &[]));
    assert!(r.answer_of(n0).is_none());
    assert!(r.answer_of(n1).is_none());
    assert_eq!((r.gpu.hard_out, r.gpu.wait_out, r.gpu.fence_out), (1, 2, 0));
    // The read back range goes as arg1/arg2: 2 rows of 64 pixels, 4 pixels of the second.
    let s = r.sent();
    let last = &s[s.len() - 2].0;
    assert_eq!((last.arg1, last.arg2), (0, 256 + 16));
    // The sink's answer writes the data into the backing and answers the guest.
    let data: Vec<u8> = (0..272u32).map(|i| (i % 251) as u8).collect();
    let seq = last.seq;
    r.sink_says(
        SP_RESP,
        seq,
        &hdr(RESP_OK_NODATA, Some(1), 0),
        &data,
        [0; 3],
    );
    let mut got = vec![0u8; 272];
    mem.read_slice(&mut got, GuestAddress(BACKING_AT)).unwrap();
    assert_eq!(got, data);
    assert!(r.answer_of(n0).is_some());
    assert_eq!(r.used(), base + 1);
    assert_eq!(r.gpu.hard_out, 0);
    // The next fenced command is answered ahead again.
    let n2 = r.give(submit(Some(3), 1, &[]));
    assert!(r.answer_of(n2).is_some());
}

#[test]
fn beyond_the_window_by_age_only() {
    let mem = single_region_mem(0x100000);
    let mut c = cfg("/nonexistent");
    c.fence_window = Some(2);
    c.fence_age_ms = Some(20);
    let mut r = rig_with(&mem, c);
    r.give(submit(Some(1), 1, &[]));
    r.give(submit(Some(2), 1, &[]));
    // No round trip measured yet: the third waits.
    r.give(submit(Some(3), 1, &[]));
    assert!(r.answer_of(2).is_none());
    // With a round trip of 1 ms, the oldest unanswered command being young: ahead.
    r.gpu.rtt_min_cur = 1000;
    r.give(submit(Some(4), 1, &[]));
    assert!(r.answer_of(3).is_some());
    assert_eq!(r.gpu.counters.n_ahead, 1);
    // The oldest one is 100 ms old: no more.
    let head = r.gpu.fq_head;
    r.gpu.fq[head] = now_us() - 100_000;
    r.give(submit(Some(5), 1, &[]));
    assert!(r.answer_of(4).is_none());
}

#[test]
fn beyond_the_window_a_longer_age_while_the_guest_decodes_video() {
    let mem = single_region_mem(0x100000);
    let mut c = cfg("/nonexistent");
    c.fence_window = Some(2);
    c.fence_age_ms = Some(20);
    // fence_age_video_ms: the default, 100
    let mut r = rig_with(&mem, c);
    r.gpu.rtt_min_cur = 1000;
    r.give(submit(Some(1), 1, &[]));
    r.give(submit(Some(2), 1, &[]));
    // The oldest unanswered command is 50 ms old, and no video: the third waits.
    let head = r.gpu.fq_head;
    r.gpu.fq[head] = now_us() - 50_000;
    r.give(submit(Some(3), 1, &[]));
    assert!(r.answer_of(2).is_none());
    // A decode command (DECODE_BITSTREAM, 59): video for the next second.
    r.give(submit(None, 1, &[59]));
    assert!(r.gpu.video_until > now_us() + 900_000);
    let n = r.give(submit(Some(4), 1, &[]));
    assert!(r.answer_of(n).is_some());
    assert_eq!(r.gpu.counters.n_ahead, 1);
    assert_eq!(r.gpu.counters.n_ahead_video, 1);
    // The fence of a decode command is answered by the same rule.
    let n = r.give(submit(Some(5), 1, &[59]));
    assert!(r.answer_of(n).is_some());
    assert_eq!(r.gpu.counters.n_ahead_video, 2);
    // Over 100 ms (and two round trips): no more, even with video.
    r.gpu.fq[head] = now_us() - 150_000;
    let n = r.give(submit(Some(6), 1, &[59]));
    assert!(r.answer_of(n).is_none());
    // A second after the last decode the short age is back.
    r.gpu.fq[head] = now_us() - 50_000;
    r.gpu.video_until = now_us() - 1;
    let n = r.give(submit(Some(7), 1, &[]));
    assert!(r.answer_of(n).is_none());
    assert_eq!(r.gpu.counters.n_ahead, 2);
}

#[test]
fn beyond_the_window_no_age_of_video_with_0() {
    let mem = single_region_mem(0x100000);
    let mut c = cfg("/nonexistent");
    c.fence_window = Some(2);
    c.fence_age_video_ms = Some(0);
    let mut r = rig_with(&mem, c);
    r.gpu.rtt_min_cur = 1000;
    r.give(submit(Some(1), 1, &[]));
    r.give(submit(Some(2), 1, &[]));
    // Video, and the oldest command just sent: with an age of 0 nothing beyond the window.
    let n = r.give(submit(Some(3), 1, &[59]));
    assert!(r.answer_of(n).is_none());
    assert_eq!(r.gpu.counters.n_ahead, 0);
}

#[test]
fn query_buffer_reads_are_answered_here_and_parked() {
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg("/nonexistent"));
    // A query buffer (a PIPE_BUFFER), and a query object of context 3 that writes into it.
    r.resource(9, 0, 1, 0, 16, 1, BACKING_AT);
    // VIRGL_CCMD_CREATE_OBJECT (1), VIRGL_OBJECT_QUERY (9), 4 dwords: handle 42, type, offset,
    // result resource 9
    r.give(submit(Some(1), 3, &[(4 << 16) | (9 << 8) | 1, 42, 0, 0, 9]));
    assert!(r.gpu.query_bufs.contains(&9));
    // VIRGL_CCMD_GET_QUERY_RESULT (21) of handle 42: the 16 bytes go to the sink to be watched.
    r.give(submit(None, 3, &[(2 << 16) | 21, 42, 0]));
    let s = r.sent();
    let mw = s.iter().find(|m| m.0.typ == SP_MEMWRITE).unwrap();
    assert_eq!((mw.0.arg0, mw.0.arg1, mw.0.arg2, mw.1.len()), (9, 0, 1, 16));
    // Its state is "ready": the read is answered at once, nothing sent, no seq used.
    mem.write_slice(&1u32.to_le_bytes(), GuestAddress(BACKING_AT))
        .unwrap();
    let seq = r.gpu.seq;
    let n_sent = r.sent().len();
    let n = r.give(transfer_3d(
        CMD_TRANSFER_FROM_HOST_3D,
        Some(7),
        9,
        [0, 0, 0, 16, 1, 1],
        0,
        0,
        0,
    ));
    let a = r.answer_of(n).unwrap();
    assert_eq!(
        (resp_type(&a), u32_at(&a, 4), u64_at(&a, 8), u32_at(&a, 16)),
        (RESP_OK_NODATA, FLAG_FENCE, 7, 0)
    );
    assert_eq!(r.gpu.seq, seq);
    assert_eq!(r.sent().len(), n_sent);
    assert_eq!(r.gpu.ctx_qpoll[0], 1);
    // "Waiting for the host": parked until the sink writes the result.
    mem.write_slice(
        &QUERY_STATE_WAIT_HOST.to_le_bytes(),
        GuestAddress(BACKING_AT),
    )
    .unwrap();
    let n = r.give(transfer_3d(
        CMD_TRANSFER_FROM_HOST_3D,
        None,
        9,
        [0, 0, 0, 16, 1, 1],
        0,
        0,
        0,
    ));
    assert!(r.answer_of(n).is_none());
    assert_eq!(r.gpu.parked.len(), 1);
    let mut result = vec![0u8; 16];
    result[0] = 1;
    result[8] = 0x33;
    r.sink_says(SP_MEMWRITE, 0, &result, &[], [9, 0, 0]);
    assert!(r.answer_of(n).is_some());
    assert!(r.gpu.parked.is_empty());
    let mut got = [0u8; 16];
    mem.read_slice(&mut got, GuestAddress(BACKING_AT)).unwrap();
    assert_eq!(&got[..], &result[..]);
    // Parked longer than 200 ms: answered by the timer.
    mem.write_slice(
        &QUERY_STATE_WAIT_HOST.to_le_bytes(),
        GuestAddress(BACKING_AT),
    )
    .unwrap();
    let n = r.give(transfer_3d(
        CMD_TRANSFER_FROM_HOST_3D,
        None,
        9,
        [0, 0, 0, 16, 1, 1],
        0,
        0,
        0,
    ));
    r.gpu.unpark(&mem, 0, 200_000);
    r.gpu.notify_used();
    assert!(r.answer_of(n).is_none());
    r.gpu.parked[0].t0 -= 300_000;
    r.gpu.unpark(&mem, 0, 200_000);
    r.gpu.notify_used();
    assert!(r.answer_of(n).is_some());
}

#[test]
fn query_reads_are_forwarded_while_a_fence_waits_for_data() {
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg("/nonexistent"));
    r.resource(9, 0, 1, 0, 16, 1, BACKING_AT);
    r.resource(5, 2, 1, 0, 64, 64, BACKING_AT + 0x20000);
    r.give(submit(Some(1), 3, &[(4 << 16) | (9 << 8) | 1, 42, 0, 0, 9]));
    r.give(transfer_3d(
        CMD_TRANSFER_FROM_HOST_3D,
        Some(2),
        5,
        [0, 0, 0, 4, 2, 1],
        0,
        0,
        0,
    ));
    assert_eq!(r.gpu.hard_out, 1);
    let seq = r.gpu.seq;
    let n = r.give(transfer_3d(
        CMD_TRANSFER_FROM_HOST_3D,
        None,
        9,
        [0, 0, 0, 16, 1, 1],
        0,
        0,
        0,
    ));
    assert!(r.answer_of(n).is_none());
    assert_eq!(r.gpu.seq, seq + 1);
}

fn capset_info(index: u32) -> Vec<u8> {
    let mut r = hdr(CMD_GET_CAPSET_INFO, None, 0);
    put32(&mut r, index);
    put32(&mut r, 0);
    r
}

fn capset(id: u32, ver: u32) -> Vec<u8> {
    let mut r = hdr(CMD_GET_CAPSET, None, 0);
    put32(&mut r, id);
    put32(&mut r, ver);
    r
}

fn get_edid(scanout: u32) -> Vec<u8> {
    let mut r = hdr(CMD_GET_EDID, None, 0);
    put32(&mut r, scanout);
    put32(&mut r, 0);
    r
}

#[test]
fn queries_are_answered_from_the_spec_and_the_sinks_information() {
    let mem = single_region_mem(0x100000);
    let mut r = rig_with(&mem, cfg("/nonexistent"));
    assert_eq!(r.gpu.config_word(3), 2);
    assert_eq!(r.gpu.config_word(2), 1);
    // The capsets are the spec's, with no renderer: capset 1 (version 1, 8 bytes) and 2
    // (version 2, 12 bytes).
    let n = r.give(capset_info(1));
    let a = r.answer_of(n).unwrap();
    assert_eq!(
        (
            resp_type(&a),
            u32_at(&a, 24),
            u32_at(&a, 28),
            u32_at(&a, 32)
        ),
        (RESP_OK_CAPSET_INFO, 2, 2, 12)
    );
    let n = r.give(capset(1, 0));
    let a = r.answer_of(n).unwrap();
    assert_eq!(resp_type(&a), RESP_OK_CAPSET);
    assert_eq!(&a[24..32], &(1..=8).collect::<Vec<u8>>()[..]);
    // A renderer's capsets are not taken: the guest keeps the spec's.
    r.sink_says(SP_INFO, 0, &[7; 8], &[], [1, 1, (1 << 32) | 8]);
    let n = r.give(capset(1, 0));
    assert_eq!(
        &r.answer_of(n).unwrap()[24..32],
        &(1..=8).collect::<Vec<u8>>()[..]
    );
    // Before the display information: forwarded.
    let n = r.give(hdr(CMD_GET_DISPLAY_INFO, None, 0));
    assert!(r.answer_of(n).is_none());
    assert_eq!(r.gpu.counters.queries.forwarded_after_info, 1);
    let mut dinfo = hdr(0x1101, None, 0);
    dinfo.resize(408, 0);
    dinfo[24..28].copy_from_slice(&2560u32.to_le_bytes());
    r.sink_says(SP_INFO, 0, &dinfo, &[], [2, 0, 0]);
    let edid = vec![0x11u8; 40];
    r.sink_says(SP_INFO, 0, &edid, &[], [3, 0, 0]);

    // A version above the spec's: forwarded.
    let n = r.give(capset(1, 2));
    assert!(r.answer_of(n).is_none());
    let n = r.give(hdr(CMD_GET_DISPLAY_INFO, None, 0));
    let a = r.answer_of(n).unwrap();
    assert_eq!(u32_at(&a, 24), 2560);
    let n = r.give(get_edid(0));
    assert_eq!(&r.answer_of(n).unwrap()[..40], &edid[..]);
    // Scanout 1 and capset index 2 (the device has 2): forwarded.
    let n = r.give(get_edid(1));
    assert!(r.answer_of(n).is_none());
    let n = r.give(capset_info(2));
    assert!(r.answer_of(n).is_none());
    let q = r.gpu.counters.queries;
    assert_eq!(
        (q.capset_info, q.capset, q.display_info, q.edid),
        (1, 2, 1, 1)
    );
    assert_eq!((q.forwarded_before_info, q.forwarded_after_info), (0, 4));
    // Local answers use no sequence number.
    assert_eq!(r.gpu.seq, 4);
}

#[test]
fn display_events_set_the_config() {
    let mem = single_region_mem(0x100000);
    let mut r = rig_with(&mem, cfg("/nonexistent"));
    r.sink_says(SP_DISPLAY, 0, &[], &[], [1, 0, 0]);
    assert_eq!(r.gpu.config_word(0), 1);
    r.gpu.write_config(4, &1u32.to_le_bytes());
    assert_eq!(r.gpu.config_word(0), 0);
}

#[test]
fn a_display_the_guest_has_not_been_shown_raises_a_display_event() {
    let mem = single_region_mem(0x100000);
    let mut r = rig_with(&mem, cfg("/nonexistent"));
    let d1 = [1u8; 24];
    r.sink_says(SP_INFO, 0, &d1, &[], [2, 0, 0]);
    assert_eq!(r.gpu.config_word(0), 1);
    r.gpu.write_config(4, &1u32.to_le_bytes());
    // the same display again (a new pairing of the same renderer): no event
    r.sink_says(SP_INFO, 0, &d1, &[], [2, 0, 0]);
    assert_eq!(r.gpu.config_word(0), 0);
    // another display: the guest reads it again
    r.sink_says(SP_INFO, 0, &[2u8; 24], &[], [2, 0, 0]);
    assert_eq!(r.gpu.config_word(0), 1);
}

#[test]
fn transfers_send_their_bytes_and_hint_the_filter() {
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg("/nonexistent"));
    // R8G8B8A8 (format 67), 256x256.
    r.resource(5, 2, 67, 0, 256, 256, BACKING_AT);
    let pix: Vec<u8> = (0..BACKING_LEN).map(|i| (i % 253) as u8).collect();
    mem.write_slice(&pix, GuestAddress(BACKING_AT)).unwrap();
    // 16 rows of the whole width at row 2: 16 KiB from offset 2048.
    r.give(transfer_3d(
        CMD_TRANSFER_TO_HOST_3D,
        None,
        5,
        [0, 2, 0, 256, 16, 1],
        2048,
        0,
        0,
    ));
    let s = r.sent();
    let m = s.last().unwrap();
    assert_eq!((m.0.typ, m.0.arg1, m.0.arg2), (SP_CTRL, 2048, 16384));
    assert_eq!(&m.2[..], &pix[2048..2048 + 16384]);
    let f = r.gpu.conns[USER].link.lock().q.last_filter();
    assert_eq!(
        f,
        Some(Filter {
            off: 80 + 72,
            bpp: 4,
            stride: 1024
        })
    );
    assert_eq!(r.gpu.counters.xfer_bytes, 16384);
}

#[test]
fn the_stream_scan_pushes_and_expects() {
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg("/nonexistent"));
    r.resource(5, 2, 67, 0, 64, 64, BACKING_AT);
    // A staging buffer.
    r.resource(6, 0, 64, 0, 0x10000, 1, BACKING_AT + 0x10000);
    // A buffer that lives only in the renderer (VIRGL_BIND_CUSTOM), as video bitstreams.
    r.resource(7, 0, 64, 1 << 17, 0x10000, 1, BACKING_AT + 0x20000);
    let before = r.sent().len();
    let box2 = [0u32, 0, 0, 64, 2, 1];
    let mut st = Vec::new();
    // TRANSFER3D (43) to the renderer: 2 rows of 256 bytes from offset 0.
    st.extend_from_slice(&[(13 << 16) | 43, 5, 0, 0, 0, 0]);
    st.extend_from_slice(&box2);
    st.extend_from_slice(&[0, 1]);
    // TRANSFER3D from the renderer: expected back.
    st.extend_from_slice(&[(13 << 16) | 43, 5, 0, 0, 0, 0]);
    st.extend_from_slice(&box2);
    st.extend_from_slice(&[512, 2]);
    // COPY_TRANSFER3D (45) from staging 6 at 4096 into the texture, and back.
    st.extend_from_slice(&[(14 << 16) | 45, 5, 0, 0, 0, 0]);
    st.extend_from_slice(&box2);
    st.extend_from_slice(&[6, 4096, 0]);
    st.extend_from_slice(&[(14 << 16) | 45, 5, 0, 0, 0, 0]);
    st.extend_from_slice(&box2);
    st.extend_from_slice(&[6, 8192, 2]);
    // GET_MEMORY_INFO (50) into 6.
    st.extend_from_slice(&[(1 << 16) | 50, 6]);
    // TRANSFER3D of 8 KiB into the custom buffer: not sent.
    st.extend_from_slice(&[(13 << 16) | 43, 7, 0, 0, 0, 0, 0, 0, 0, 8192, 1, 1, 0, 1]);
    // DECODE_BITSTREAM (59): description buffer 6 (its width), bitstream 7 (300 bytes).
    st.extend_from_slice(&[(5 << 16) | 59, 1, 2, 6, 7, 300]);
    let n = r.give(submit(Some(1), 1, &st));
    // Waits for the sink: it has expectations.
    assert!(r.answer_of(n).is_none());
    assert_eq!(r.gpu.hard_out, 1);
    let s: Vec<_> = r.sent().into_iter().skip(before).collect();
    let types: Vec<u32> = s.iter().map(|m| m.0.typ).collect();
    assert_eq!(
        types,
        vec![
            SP_MEMWRITE,
            SP_MEMWRITE,
            SP_MEMWRITE,
            SP_MEMWRITE,
            SP_EXPECT,
            SP_WMARK,
            SP_CTRL
        ]
    );
    // The uploads into 5, and the one into 7 that was not sent, are the write marks; the
    // journal keeps the second upload into 5, which covers the first, with the bytes of the
    // staging buffer that were pushed.
    assert_eq!(s[5].1, [5u32.to_le_bytes(), 7u32.to_le_bytes()].concat());
    let up = r.gpu.journal.uploads_of(5);
    assert_eq!(up.len(), 1);
    assert_eq!(up[0].1, &s[1].1[..]);
    assert_eq!((s[0].0.arg0, s[0].0.arg1, s[0].1.len()), (5, 0, 512));
    assert_eq!((s[1].0.arg0, s[1].0.arg1, s[1].1.len()), (6, 4096, 512));
    // The decode command pushes the description (as wide as its resource, 64 KiB, here all of
    // its backing) and 300 bytes of the bitstream; the deferred upload was not sent.
    assert_eq!((s[2].0.arg0, s[2].1.len()), (6, 0x10000));
    assert_eq!((s[3].0.arg0, s[3].1.len()), (7, 300));
    assert_eq!(r.gpu.counters.n_defer, 1);
    assert_eq!(r.gpu.counters.defer_bytes, 8192);
    // Expectations: the read back of 5, the copy back into 6, the memory info of 6.
    let e = &s[4].1;
    assert_eq!(e.len(), 3 * EXPECT_LEN);
    let ex = |k: usize| {
        (
            u32_at(e, k * 24),
            u64_at(e, k * 24 + 8),
            u64_at(e, k * 24 + 16),
        )
    };
    assert_eq!(ex(0), (5, 512, 512));
    assert_eq!(ex(1), (6, 8192, 512));
    assert_eq!(ex(2), (6, 0, 64));
    // While video is decoded, every message carries the video flag.
    assert!(s[4..].iter().all(|m| m.0.flags & SP_F_VIDEO != 0));
}

#[test]
fn a_resource_is_marked_once_until_the_next_mark_point() {
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg("/nonexistent"));
    r.resource(5, 2, 67, 0, 64, 64, BACKING_AT);
    // TRANSFER3D (43) of 2 rows into 5, to the renderer: an upload, which writes 5.
    let mut st = vec![(13 << 16) | 43, 5, 0, 0, 0, 0];
    st.extend_from_slice(&[0, 0, 0, 64, 2, 1, 0, 1]);
    let marks = |r: &Rig<'_>, from: usize| -> Vec<Vec<u8>> {
        r.sent()
            .into_iter()
            .skip(from)
            .filter(|m| m.0.typ == SP_WMARK)
            .map(|m| m.1)
            .collect()
    };
    let n0 = r.sent().len();
    r.give(submit(None, 1, &st));
    assert_eq!(marks(&r, n0), [5u32.to_le_bytes().to_vec()]);
    // Written again before a mark point: the renderer's `written` of 5 is already newer than
    // every point, so no mark is sent.
    let n1 = r.sent().len();
    r.give(submit(None, 1, &st));
    assert!(marks(&r, n1).is_empty());
    assert_eq!(
        (
            r.gpu.counters.n_wmark,
            r.gpu.counters.wmark_ids,
            r.gpu.counters.wmark_skipped
        ),
        (1, 1, 1)
    );
    // A mark point (what a new pairing and a state reset do): marked again at the next write.
    r.gpu.conns[USER].marked.clear();
    let n2 = r.sent().len();
    r.give(submit(None, 1, &st));
    assert_eq!(marks(&r, n2), [5u32.to_le_bytes().to_vec()]);
}

#[test]
fn reset_drops_what_waits() {
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg("/nonexistent"));
    r.resource(5, 2, 1, 0, 64, 64, BACKING_AT);
    r.give(transfer_3d(
        CMD_TRANSFER_FROM_HOST_3D,
        Some(1),
        5,
        [0, 0, 0, 4, 2, 1],
        0,
        0,
        0,
    ));
    assert_eq!(r.gpu.pending.len(), 1);
    assert!(r.gpu._reset());
    assert!(r.gpu.pending.is_empty());
    assert!(r.gpu.resources.is_empty());
    assert_eq!((r.gpu.hard_out, r.gpu.wait_out, r.gpu.fq_len), (0, 0, 0));
    assert_eq!(*r.sent_types().last().unwrap(), SP_RESET);
}

#[test]
fn transfer_range_matches_the_qemu_source() {
    // B8G8R8A8_UNORM (format 1, 4 bytes), a 100x50 texture, a 10x2 box at (0,0).
    let (off, len) = transfer_range(1, 100, 50, 0, 0, 0, [0, 0, 0, 10, 2, 1], 0, 20000);
    assert_eq!((off, len), (0, 400 + 40));
    // Unknown format: everything from the offset.
    assert_eq!(
        transfer_range(0, 1, 1, 0, 0, 0, [0; 6], 100, 1000),
        (100, 900)
    );
    // Clamped to the backing.
    assert_eq!(
        transfer_range(1, 100, 50, 0, 0, 0, [0, 0, 0, 100, 50, 1], 0, 1000).1,
        1000
    );
    // A level: the width halves; a given stride wins; depth uses the layer stride.
    assert_eq!(
        transfer_range(1, 100, 50, 1, 0, 0, [0, 0, 0, 10, 2, 1], 0, 1 << 20).1,
        200 + 40
    );
    assert_eq!(
        transfer_range(1, 100, 50, 0, 512, 0, [0, 0, 0, 10, 2, 1], 0, 1 << 20).1,
        512 + 40
    );
    assert_eq!(
        transfer_range(1, 100, 50, 0, 0, 30000, [0, 0, 0, 10, 2, 3], 0, 1 << 20).1,
        60000 + 400 + 40
    );
    // An offset beyond the backing: nothing.
    assert_eq!(
        transfer_range(1, 100, 50, 0, 0, 0, [0, 0, 0, 10, 2, 1], 5000, 5000),
        (5000, 0)
    );
}

// ---- the connection, with the test as the sink ----------------------------------------------

struct Sink {
    s: std::os::unix::net::UnixStream,
    z: ZUnpacker,
    zw: ZPacker,
    rxw: Vec<u8>,
    rx: Vec<u8>,
    compressed: bool,
    /// The device's HELLO, once read.
    last_hello: Option<Hdr>,
    /// The specs the device sent (`SP_SPEC`), which `next` passes over.
    specs: Vec<Vec<u8>>,
}

impl Sink {
    /// The device closed the connection (with nothing sent on it).
    fn closed(&mut self) -> bool {
        let mut b = [0u8; 1];
        matches!(self.s.read(&mut b), Ok(0))
    }

    fn read_hello(&mut self) -> Hdr {
        let mut h = [0u8; 80];
        self.s.read_exact(&mut h).unwrap();
        let h = Hdr::decode(&h).unwrap();
        self.last_hello = Some(h);
        h
    }

    /// The sink's HELLO, and at once its yes to the spec that the device sends at a new pairing
    /// (the device takes it after the HELLO; at a resumed pairing it is ignored).
    fn hello(&mut self, session: u64, peer: u64, has: u64, zstd: bool) {
        self.hello_only(session, peer, has, zstd);
        self.spec_reply(true, "");
    }

    /// The sink's answer to the spec.
    fn spec_reply(&mut self, yes: bool, why: &str) {
        let h = Hdr {
            typ: SP_SPEC_REPLY,
            a_len: u32::try_from(why.len()).unwrap(),
            arg0: u64::from(yes),
            ..Default::default()
        };
        self.send(h, why.as_bytes());
    }

    fn hello_only(&mut self, session: u64, peer: u64, has: u64, zstd: bool) {
        let h = Hdr {
            typ: SP_HELLO,
            arg0: session,
            arg1: peer,
            arg2: has,
            flags: if zstd { SP_F_ZSTD } else { 0 },
            ..Default::default()
        };
        self.s.write_all(&h.encode()).unwrap();
        self.compressed = zstd;
        self.zw.restart(1);
        self.z.restart();
        self.rxw.clear();
        self.rx.clear();
    }

    fn send(&mut self, h: Hdr, a: &[u8]) {
        let mut m = h.encode().to_vec();
        m.extend_from_slice(a);
        if self.compressed {
            let w = self.zw.pack(&m, None).unwrap().to_vec();
            self.s.write_all(&w).unwrap();
        } else {
            self.s.write_all(&m).unwrap();
        }
    }

    /// The next message from the device but the spec (kept in `specs`).
    fn next(&mut self) -> (Hdr, Vec<u8>) {
        loop {
            let (h, a) = self.next_any();
            if h.typ != SP_SPEC {
                return (h, a);
            }
            self.specs.push(a);
        }
    }

    /// The next message from the device.
    fn next_any(&mut self) -> (Hdr, Vec<u8>) {
        let mut tmp = [0u8; 65536];
        loop {
            if self.compressed {
                self.z.unpack(&mut self.rxw, &mut self.rx).unwrap();
            } else {
                self.rx.append(&mut self.rxw);
            }
            if let Some(h) = Hdr::decode(&self.rx)
                && self.rx.len() >= h.total()
            {
                let a = self.rx[80..80 + h.a_len as usize].to_vec();
                self.rx.drain(..h.total());
                return (h, a);
            }
            let n = self.s.read(&mut tmp).unwrap();
            assert!(n > 0, "the device closed the connection");
            self.rxw.extend_from_slice(&tmp[..n]);
        }
    }
}

/// Run the device's event handlers until `done` holds (at most 5 s).
fn pump(gpu: &mut Gpu, mut done: impl FnMut(&Gpu) -> bool) {
    let t = Instant::now();
    while !done(gpu) {
        assert!(t.elapsed() < Duration::from_secs(5), "timed out");
        gpu.process_remote(USER);
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn hello_compression_resume_and_a_new_sink() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x100000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    r.gpu.process_retry();
    assert!(r.gpu.conns[USER].link.is_connected());
    let (s, _) = listener.accept().unwrap();
    let mut sink = Sink {
        s,
        z: ZUnpacker::new(),
        zw: ZPacker::new(),
        rxw: Vec::new(),
        rx: Vec::new(),
        compressed: false,
        last_hello: None,
        specs: Vec::new(),
    };
    let h = sink.read_hello();
    assert_eq!(
        (h.typ, h.arg1, h.arg2, h.flags),
        (SP_HELLO, 0, 0, SP_F_SPEC | SP_F_ZSTD)
    );
    let session = h.arg0;
    assert_ne!(session, 0);
    sink.hello(0xabc, session, 0, true);
    pump(&mut r.gpu, |g| g.conns[USER].up());
    r.give(hdr(CMD_RESOURCE_FLUSH, None, 0));
    r.give(submit(Some(1), 1, &[]));
    // The queue is open, compressed: the two commands, ids 1 and 2.
    let (m1, _) = sink.next();
    let (m2, _) = sink.next();
    assert_eq!((m1.typ, m1.id, m1.seq), (SP_CTRL, 1, 0));
    assert_eq!((m2.typ, m2.id, m2.seq), (SP_CTRL, 2, 2));
    assert!(r.gpu.conns[USER].link.lock().z_on);
    // The sink answers seq 2 (id 1 of its direction) and acknowledges id 1.
    sink.send(
        Hdr {
            typ: SP_RESP,
            id: 1,
            ack: 1,
            seq: 2,
            a_len: 24,
            ..Default::default()
        },
        &hdr(RESP_OK_NODATA, Some(1), 1),
    );
    pump(&mut r.gpu, |g| g.conns[USER].rx_id == 1);
    assert_eq!(r.gpu.conns[USER].link.lock().q.messages().len(), 1); // id 2 not acknowledged yet

    // The connection is lost; the guest goes on; the device reconnects and the sink, which
    // has id 1 only, gets id 2 again and the new one.
    drop(sink);
    pump(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    r.give(hdr(CMD_RESOURCE_FLUSH, None, 0));
    r.gpu.process_retry();
    let (s, _) = listener.accept().unwrap();
    let mut sink = Sink {
        s,
        z: ZUnpacker::new(),
        zw: ZPacker::new(),
        rxw: Vec::new(),
        rx: Vec::new(),
        compressed: false,
        last_hello: None,
        specs: Vec::new(),
    };
    let h = sink.read_hello();
    assert_eq!((h.arg0, h.arg1, h.arg2), (session, 0xabc, 1));
    sink.hello(0xabc, session, 1, true);
    pump(&mut r.gpu, |g| g.conns[USER].up());
    assert_eq!(r.gpu.counters.n_reconnect, 1);
    let (a, _) = sink.next();
    let (b, _) = sink.next();
    assert_eq!((a.id, a.seq, b.id), (2, 2, 3));
    // A message out of order closes the connection.
    sink.send(
        Hdr {
            typ: SP_ACK,
            id: 5,
            ack: 3,
            ..Default::default()
        },
        &[],
    );
    pump(&mut r.gpu, |g| !g.conns[USER].link.is_connected());

    // A different sink (it restarted) after commands went out: it is built again from the
    // journal (a context and a texture), and the guest's commands go on.
    r.give(ctx_create(1));
    r.give(create_3d(5, 2, 67, 2, 8, 8));
    r.gpu.process_retry();
    let (s, _) = listener.accept().unwrap();
    let mut sink = Sink {
        s,
        z: ZUnpacker::new(),
        zw: ZPacker::new(),
        rxw: Vec::new(),
        rx: Vec::new(),
        compressed: false,
        last_hello: None,
        specs: Vec::new(),
    };
    sink.read_hello();
    sink.hello(0xdef, 0, 0, false);
    pump(&mut r.gpu, |g| g.conns[USER].up());
    assert!(r.gpu.switch.is_some());
    let (m, _) = sink.next();
    assert_eq!((m.typ, m.id, m.arg0), (SP_STATE_RESET, 1, 0));
    sink.send(
        Hdr {
            typ: SP_STATE_KEPT,
            id: 1,
            ack: 1,
            ..Default::default()
        },
        &[],
    );
    pump(&mut r.gpu, |g| g.switch.is_none());
    assert_eq!(r.gpu.n_switch, 1);
    let mut got = Vec::new();
    for _ in 0..3 {
        let (m, a) = sink.next();
        got.push((m.typ, u32_at(&a, 0)));
    }
    assert_eq!(
        got,
        [
            (SP_CTRL, CMD_CTX_CREATE),
            (SP_CTRL, CMD_RESOURCE_CREATE_3D),
            (SP_CTRL, CMD_SUBMIT_3D)
        ]
    );
    // the guest's commands go to the rebuilt sink
    r.give(hdr(CMD_RESOURCE_FLUSH, None, 0));
    let (m, a) = sink.next();
    assert_eq!((m.typ, u32_at(&a, 0)), (SP_CTRL, CMD_RESOURCE_FLUSH));
}

fn ctx_create(id: u32) -> Vec<u8> {
    let mut r = hdr(CMD_CTX_CREATE, None, id);
    r.resize(96, 0);
    r
}

/// An input device of the test, with an event queue that has no buffers yet.
fn input_dev(mem: &GuestMemoryMmap, at: u64, kind: InputKind) -> Arc<Mutex<Input>> {
    let ev = VirtQueue::new(GuestAddress(at), mem, 16);
    let st = VirtQueue::new(ev.end().unchecked_align_up(16), mem, 16);
    let mut d = Input::new(kind).unwrap();
    d.queues = vec![ev.create_queue(), st.create_queue()];
    d.activate(mem.clone(), default_interrupt()).unwrap();
    Arc::new(Mutex::new(d))
}

#[test]
fn input_scroll_and_sound_go_through_the_connection() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let agent_path = dir.as_path().join("vsock.sock_5000");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x100000);
    let mut c = cfg(path.to_str().unwrap());
    c.agent_socket_path = Some(agent_path.to_str().unwrap().into());
    let mut r = rig_with(&mem, c);
    let kbd = input_dev(&mem, 0x80000, InputKind::Keyboard);
    let tab = input_dev(&mem, 0x90000, InputKind::Tablet);
    r.gpu.set_inputs(kbd.clone(), tab.clone());

    r.gpu.process_retry();
    let (s, _) = listener.accept().unwrap();
    let mut sink = Sink {
        s,
        z: ZUnpacker::new(),
        zw: ZPacker::new(),
        rxw: Vec::new(),
        rx: Vec::new(),
        compressed: false,
        last_hello: None,
        specs: Vec::new(),
    };
    // With an agent's channel the HELLO says that the scroll goes in the stream.
    let h = sink.read_hello();
    assert_eq!(h.flags, SP_F_SPEC | SP_F_ZSTD | SP_F_SCROLL);
    sink.hello(0xabc, h.arg0, 0, false);
    pump(&mut r.gpu, |g| g.conns[USER].up());

    // The sink's input: a key (with its sync), then a pointer move and a click and a sync.
    let mut id = 0;
    let mut say = |sink: &mut Sink, typ: u32, a: &[u8]| {
        id += 1;
        sink.send(
            Hdr {
                typ,
                id,
                a_len: u32::try_from(a.len()).unwrap(),
                ..Default::default()
            },
            a,
        );
        id
    };
    let inp = |kind: u32, a: u32, b: i32| -> Vec<u8> {
        let mut v = Vec::new();
        put32(&mut v, kind);
        put32(&mut v, a);
        v.extend_from_slice(&b.to_le_bytes());
        v
    };
    let qa = u32::try_from(QCODE_TO_LINUX.iter().position(|&k| k == 30).unwrap()).unwrap();
    say(&mut sink, SP_INPUT, &inp(1, qa, 1));
    say(&mut sink, SP_INPUT, &inp(0, 0, 0));
    say(&mut sink, SP_INPUT, &inp(4, 0, 0x100));
    say(&mut sink, SP_INPUT, &inp(4, 1, 0x200));
    say(&mut sink, SP_INPUT, &inp(2, 0, 1));
    let last = say(&mut sink, SP_INPUT, &inp(0, 0, 0));
    pump(&mut r.gpu, |g| g.conns[USER].rx_id == last);
    // No buffers in the guest yet: the reports wait (the key and its sync; three and a sync).
    assert_eq!(kbd.lock().unwrap().pending_len(), 2);
    assert_eq!(tab.lock().unwrap().pending_len(), 4);
    assert_eq!(r.gpu.counters.n_input, 6);
    assert_eq!(r.gpu.counters.n_input_dropped, 0);

    // The scroll channel: the sink's PING reaches the agent, the agent's READY the sink.
    let mut guest = UnixStream::connect(&agent_path).unwrap();
    r.gpu.agent.as_mut().unwrap().accept().unwrap();
    let last = say(&mut sink, SP_SCROLL, b"PING\n1 2 0 -3.5 1 4 0\n");
    pump(&mut r.gpu, |g| g.conns[USER].rx_id == last);
    let mut got = [0u8; 22];
    guest.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"PING\n1 2 0 -3.5 1 4 0\n");
    guest.write_all(b"READY\n").unwrap();
    std::thread::sleep(Duration::from_millis(20));
    let crate::devices::virtio::gpu::agent::AgentRead::Lines(lines) =
        r.gpu.agent.as_mut().unwrap().read()
    else {
        panic!("the agent's connection ended");
    };
    r.gpu.agent_lines(&lines);
    let (m, a) = sink.next();
    assert_eq!((m.typ, a.as_slice()), (SP_SCROLL, &b"READY\n"[..]));
    assert_ne!(m.id, 0);

    // Sound: one unreliable message with the rate and the channels.
    r.gpu.send_audio(48_000, 2, &[1, 2, 3, 4], 0);
    let (m, a) = sink.next();
    assert_eq!(
        (m.typ, m.id, m.arg0, m.arg1, a),
        (SP_AUDIO, 0, 48_000, 2, vec![1, 2, 3, 4])
    );
    assert_eq!(r.gpu.counters.sound.messages, 1);
    // With no sink, played samples are not kept.
    drop(sink);
    pump(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    r.gpu.send_audio(48_000, 2, &[0; 960], 960);
    assert_eq!(
        (
            r.gpu.counters.sound.not_sent,
            r.gpu.counters.sound.short_bytes
        ),
        (960, 960)
    );
}

fn sink_on(listener: &UnixListener) -> Sink {
    let (s, _) = listener.accept().unwrap();
    sink_from(s)
}

/// The in-guest renderer of a test connects to the device's socket; the device takes the
/// connection as its event does ([`Link::accept`]), and pairs it when it wants that renderer.
fn guest_connects(path: &std::path::Path, gpu: &mut Gpu) -> UnixStream {
    let s = UnixStream::connect(path).unwrap();
    assert!(gpu.conns[GUEST].link.accept());
    s
}

/// A connection that the device has not paired (no HELLO is read).
fn sink_from_no_hello(s: UnixStream) -> Sink {
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    Sink {
        s,
        z: ZUnpacker::new(),
        zw: ZPacker::new(),
        rxw: Vec::new(),
        rx: Vec::new(),
        compressed: false,
        last_hello: None,
        specs: Vec::new(),
    }
}

fn sink_from(s: UnixStream) -> Sink {
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut sink = Sink {
        s,
        z: ZUnpacker::new(),
        zw: ZPacker::new(),
        rxw: Vec::new(),
        rx: Vec::new(),
        compressed: false,
        last_hello: None,
        specs: Vec::new(),
    };
    sink.read_hello();
    sink
}

/// Run both connections' handlers until `done` holds.
fn pump2(gpu: &mut Gpu, mut done: impl FnMut(&Gpu) -> bool) {
    let t = Instant::now();
    while !done(gpu) {
        assert!(t.elapsed() < Duration::from_secs(5), "timed out");
        gpu.process_remote(USER);
        gpu.process_remote(GUEST);
        std::thread::sleep(Duration::from_millis(2));
    }
}

impl Sink {
    /// The next messages from the device, as (type, the first word of a).
    fn take(&mut self, n: usize) -> Vec<(u32, u32)> {
        (0..n)
            .map(|_| {
                let (h, a) = self.next();
                (h.typ, u32_at(&a, 0))
            })
            .collect()
    }

    fn say(&mut self, id: u64, typ: u32, a: &[u8], b: &[u8], arg0: u64) {
        self.say_args(id, typ, a, b, [arg0, 0, 0]);
    }

    fn say_args(&mut self, id: u64, typ: u32, a: &[u8], b: &[u8], args: [u64; 3]) {
        let mut m = a.to_vec();
        m.extend_from_slice(b);
        self.send(export_hdr(id, typ, a, b, args), &m);
    }

    /// The reply of export `req` with one piece of resource `res` (64 bytes of `fill`):
    /// `SP_EXPORT_DATA` with message id `id`, then `SP_EXPORT_DONE` with `id + 1`.
    fn export_answer(&mut self, id: u64, req: u64, res: u32, fill: u8) {
        let mut x = vec![0u8; 48];
        x[..4].copy_from_slice(&res.to_le_bytes());
        self.say_args(id, SP_EXPORT_DATA, &x, &[fill; 64], [0, 0, req]);
        self.say_args(id + 1, SP_EXPORT_DONE, &[], &[], [1, 64, req]);
    }

    /// Acknowledge everything up to `id`.
    fn ack_to(&mut self, id: u64) {
        self.send(
            Hdr {
                typ: SP_ACK,
                ack: id,
                ..Default::default()
            },
            &[],
        );
    }
}

fn export_hdr(id: u64, typ: u32, a: &[u8], b: &[u8], args: [u64; 3]) -> Hdr {
    Hdr {
        typ,
        id,
        a_len: u32::try_from(a.len()).unwrap(),
        b_len: u32::try_from(b.len()).unwrap(),
        arg0: args[0],
        arg1: args[1],
        arg2: args[2],
        ..Default::default()
    }
}

#[test]
fn switches_between_the_users_renderer_and_the_in_guest_renderer() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let (up, cp) = (
        dir.as_path().join("u.sock"),
        dir.as_path().join("v.sock_5001"),
    );
    let ul = UnixListener::bind(&up).unwrap();
    let mem = single_region_mem(0x200000);
    let mut c = cfg(up.to_str().unwrap());
    c.guest_renderer_socket_path = Some(cp.to_str().unwrap().into());
    let mut r = rig_with(&mem, c);
    r.gpu.process_retry();
    let mut user = sink_on(&ul);
    user.hello(0x111, r.gpu.session, 0, false);
    pump2(&mut r.gpu, |g| g.conns[USER].up());
    // A context with a texture 5 that the GPU draws into, shown on the scanout.
    r.give(ctx_create(1));
    r.resource(5, 2, 67, 2, 64, 64, BACKING_AT);
    let mut at = hdr(CMD_CTX_ATTACH_RESOURCE, None, 1);
    put32(&mut at, 5);
    put32(&mut at, 0);
    r.give(at);
    r.give(submit(
        None,
        1,
        &[
            (5 << 16) | (8 << 8) | 1,
            40,
            5,
            67,
            0,
            0,
            (3 << 16) | 5,
            1,
            0,
            40,
            (8 << 16) | 7,
            4,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    ));
    let mut so = hdr(CMD_SET_SCANOUT, None, 0);
    for x in [0, 0, 64, 64, 0, 5] {
        put32(&mut so, x);
    }
    r.give(so);
    assert_eq!(r.gpu.journal.gpu_written(), [5]);
    assert_eq!(
        user.take(7).iter().map(|m| m.0).collect::<Vec<_>>(),
        [
            SP_CTRL, SP_CTRL, SP_CTRL, SP_CTRL, SP_WMARK, SP_CTRL, SP_CTRL
        ]
    );

    // The in-guest renderer has connected; it is held, not paired, while the user's renderer
    // runs the guest.
    let gs = guest_connects(&cp, &mut r.gpu);
    r.gpu.process_retry();
    assert!(!r.gpu.conns[GUEST].link.is_connected());
    // The user's renderer detaches: the in-guest renderer is paired, reset, gets the scanout's
    // resource and its contents first, then the rest; the old one is told it may go.
    user.say(1, SP_DETACH, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.switch.is_some());
    r.gpu.process_retry();
    let mut cpu = sink_from(gs);
    cpu.hello(0x222, 0, 0, false);
    pump2(&mut r.gpu, |g| {
        g.switch.as_ref().unwrap().phase == Phase::Reset
    });
    assert_eq!(cpu.take(1), [(SP_STATE_RESET, 0)]);
    cpu.say(1, SP_STATE_KEPT, &[], &[], 0);
    pump2(&mut r.gpu, |g| {
        g.switch.as_ref().unwrap().phase == Phase::Scanout
    });
    let (e, a) = user.next();
    assert_eq!((e.typ, u32_at(&a, 0)), (SP_EXPORT, 5));
    assert_ne!(e.arg0, 0);
    let x = gpu_journal::xfer(5, 1, 0, 0, 0, 2, [0, 0, 0, 64, 64, 1]);
    // a reply of another export is dropped: it does not reach the new renderer
    user.say_args(2, SP_EXPORT_DATA, &x, &[7; 100], [0, 0, e.arg0 + 1]);
    user.say_args(3, SP_EXPORT_DATA, &x, &[9; 100], [0, 0, e.arg0]);
    user.say_args(4, SP_EXPORT_DONE, &[], &[], [1, 100, e.arg0]);
    pump2(&mut r.gpu, |g| g.switch.is_none());
    assert_eq!(r.gpu.counters.export_stale, 1);
    assert_eq!(r.gpu.active, GUEST);
    assert_eq!(
        cpu.take(8),
        [
            (SP_CTRL, CMD_RESOURCE_CREATE_3D),
            (SP_CTRL, CMD_RESOURCE_ATTACH_BACKING),
            (SP_IMPORT, 5),
            (SP_CTRL, CMD_SET_SCANOUT),
            (SP_CTRL, CMD_CTX_CREATE),
            (SP_CTRL, CMD_CTX_ATTACH_RESOURCE),
            (SP_CTRL, CMD_SUBMIT_3D),
            (SP_CTRL, CMD_SET_SCANOUT),
        ]
    );
    assert_eq!(user.take(1), [(SP_BYE, 0)]);
    r.give(hdr(CMD_RESOURCE_FLUSH, None, 0));
    assert_eq!(cpu.take(1), [(SP_CTRL, CMD_RESOURCE_FLUSH)]);

    // The user's renderer, started again, connects: a planned switch back, the in-guest renderer
    // exporting.
    drop(user);
    pump2(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    r.gpu.process_retry();
    let mut user = sink_on(&ul);
    user.hello(0x333, 0, 0, false);
    pump2(&mut r.gpu, |g| {
        g.switch.as_ref().is_some_and(|s| s.phase == Phase::Reset)
    });
    assert_eq!(user.take(1), [(SP_STATE_RESET, 0)]);
    user.say(1, SP_STATE_KEPT, &[], &[], 0);
    pump2(&mut r.gpu, |g| {
        g.switch.as_ref().unwrap().phase == Phase::Scanout
    });
    let (e2, a) = cpu.next();
    assert_eq!((e2.typ, u32_at(&a, 0)), (SP_EXPORT, 5));
    // each export has its own request id
    assert_ne!(e2.arg0, e.arg0);
    cpu.say_args(2, SP_EXPORT_DATA, &x, &[8; 100], [0, 0, e2.arg0]);
    cpu.say_args(3, SP_EXPORT_DONE, &[], &[], [1, 100, e2.arg0]);
    pump2(&mut r.gpu, |g| g.switch.is_none());
    assert_eq!(r.gpu.active, USER);
    assert!(!r.gpu.conns[GUEST].link.is_connected());
    let got = user.take(8);
    assert_eq!(got[2], (SP_IMPORT, 5));
    assert_eq!(r.gpu.n_switch, 2);

    // The user's renderer is gone for 10 s: the in-guest renderer takes over from the journal. A
    // forward with no renderer behind it (a connection closed before its HELLO) does not
    // count as being back.
    drop(user);
    pump2(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    let lost = r.gpu.conns[USER].lost_at;
    r.gpu.process_retry();
    drop(ul.accept().unwrap());
    pump2(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    assert_eq!(r.gpu.conns[USER].lost_at, lost);
    r.gpu.process_ack_timer();
    assert!(r.gpu.switch.is_none());
    r.gpu.conns[USER].lost_at -= TAKEOVER_US + 1;
    r.gpu.process_ack_timer();
    assert_eq!(r.gpu.switch.as_ref().unwrap().from, None);
    let gs = guest_connects(&cp, &mut r.gpu);
    r.gpu.process_retry();
    let mut cpu = sink_from(gs);
    cpu.hello(0x444, 0, 0, false);
    pump2(&mut r.gpu, |g| {
        g.switch.as_ref().unwrap().phase == Phase::Reset
    });
    assert_eq!(cpu.take(1), [(SP_STATE_RESET, 0)]);
    cpu.say(1, SP_STATE_KEPT, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.switch.is_none());
    assert_eq!(r.gpu.active, GUEST);
    assert_eq!(
        cpu.take(6),
        [
            (SP_CTRL, CMD_CTX_CREATE),
            (SP_CTRL, CMD_RESOURCE_CREATE_3D),
            (SP_CTRL, CMD_RESOURCE_ATTACH_BACKING),
            (SP_CTRL, CMD_CTX_ATTACH_RESOURCE),
            (SP_CTRL, CMD_SUBMIT_3D),
            (SP_CTRL, CMD_SET_SCANOUT),
        ]
    );
    assert_eq!(r.gpu.n_switch, 3);
}

/// A device paired with a test sink, with a context and a texture 5 that a draw writes; the
/// sink has acknowledged everything. Returns the sink and the last id the device gave out.
fn paired_with_a_drawn_texture(r: &mut Rig<'_>, listener: &UnixListener) -> (Sink, u64) {
    r.gpu.process_retry();
    let mut sink = sink_on(listener);
    sink.hello(0xabc, r.gpu.session, 0, false);
    pump(&mut r.gpu, |g| g.conns[USER].up());
    r.give(ctx_create(1));
    r.resource(5, 2, 67, 2, 64, 64, BACKING_AT);
    let mut at = hdr(CMD_CTX_ATTACH_RESOURCE, None, 1);
    put32(&mut at, 5);
    put32(&mut at, 0);
    r.give(at);
    r.give(submit(None, 1, &draw_into(5)));
    let tx_id = r.gpu.conns[USER].link.lock().q.tx_id;
    let got: Vec<u32> = (0..tx_id).map(|_| sink.next().0.typ).collect();
    assert_eq!(got.iter().filter(|&&t| t == SP_WMARK).count(), 1);
    sink.send(
        Hdr {
            typ: SP_ACK,
            ack: tx_id,
            ..Default::default()
        },
        &[],
    );
    pump(&mut r.gpu, |g| g.conns[USER].link.lock().q.unacked == 0);
    (sink, tx_id)
}

/// A command stream that makes a surface of resource `id` and draws with it bound as the
/// framebuffer (the stream of the switch test).
fn draw_into(id: u32) -> Vec<u32> {
    vec![
        (5 << 16) | (8 << 8) | 1,
        40,
        id,
        67,
        0,
        0,
        (3 << 16) | 5,
        1,
        0,
        40,
        (8 << 16) | 7,
        4,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
}

/// The device's state through what a snapshot keeps: the state file's bitcode and the side
/// file's bytes.
fn through_a_snapshot(gpu: &Gpu) -> GpuState {
    let mut st = gpu.save();
    let side = st.side.take().unwrap();
    let mut bytes = Vec::new();
    side.write_to(&mut bytes).unwrap();
    let mut st: GpuState = bitcode::deserialize(&bitcode::serialize(&st).unwrap()).unwrap();
    assert!(st.side.is_none());
    st.side = Some(Arc::new(
        GpuSideState::read_from(&mut bytes.as_slice())
            .unwrap()
            .unwrap(),
    ));
    st
}

fn restored(mem: &GuestMemoryMmap, st: &GpuState) -> Gpu {
    let mut g = Gpu::restore(
        GpuConstructorArgs {
            mem: mem.clone(),
            filter: Arc::new(Vec::new()),
        },
        st,
    )
    .unwrap();
    g.activate(mem.clone(), default_interrupt()).unwrap();
    g
}

#[test]
fn a_snapshot_drains_closes_and_is_a_mark_point() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    let (mut sink, tx_id) = paired_with_a_drawn_texture(&mut r, &listener);
    assert!(r.gpu.conns[USER].marked.contains(&5));
    // A fenced command that the sink answers while the device waits.
    r.gpu.fence_window = 0;
    r.give(submit(Some(7), 1, &[]));
    assert_eq!(r.gpu.pending.len(), 1);
    let answer = std::thread::spawn(move || {
        let (m, _) = sink.next();
        sink.send(
            Hdr {
                typ: SP_RESP,
                id: 1,
                ack: m.id,
                seq: m.seq,
                a_len: 24,
                ..Default::default()
            },
            &hdr(RESP_OK_NODATA, Some(7), 1),
        );
        sink
    });
    let t = Instant::now();
    r.gpu.prepare_save();
    assert!(t.elapsed() < Duration::from_secs(2));
    let _sink = answer.join().unwrap();
    // answered, acknowledged, closed; the snapshot is a mark point; no command is taken
    assert!(r.gpu.pending.is_empty());
    assert_eq!(r.answer_of(5).map(|a| resp_type(&a)), Some(RESP_OK_NODATA));
    assert!(!r.gpu.conns[USER].link.is_connected());
    assert!(r.gpu.conns[USER].marked.is_empty());
    assert!(!r.gpu.conns[USER].wanted);
    let st = through_a_snapshot(&r.gpu);
    assert_eq!(st.conns[USER].tx_id, tx_id + 1);
    assert_eq!(st.conns[USER].rx_id, 1);
    assert!(st.conns[USER].wanted);
    assert_eq!(st.side.as_ref().unwrap().pending, []);
    // A renderer that is gone is waited for at most 2 s, and what it has not answered is kept.
    r.gpu.kick();
    assert!(r.gpu.conns[USER].wanted);
    r.gpu.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello(0xabc, r.gpu.session, tx_id + 1, false);
    pump(&mut r.gpu, |g| g.conns[USER].up());
    r.give(submit(Some(8), 1, &[]));
    drop(sink);
    let t = Instant::now();
    r.gpu.prepare_save();
    let waited = t.elapsed();
    assert!(waited >= Duration::from_millis(1900) && waited < Duration::from_secs(3));
    let st = through_a_snapshot(&r.gpu);
    let side = st.side.as_ref().unwrap();
    assert_eq!(side.pending.len(), 1);
    assert_eq!(side.pending[0].fence_id, 8);
    assert_eq!(side.unacked[USER].len(), 1);
}

#[test]
fn a_restored_device_resumes_the_renderer_of_the_snapshot() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    let (sink, tx_id) = paired_with_a_drawn_texture(&mut r, &listener);
    r.gpu.prepare_save();
    let st = through_a_snapshot(&r.gpu);
    drop(r);
    drop(sink);

    // On another server: the same session, ids, resources and journal.
    let mut g = restored(&mem, &st);
    assert_eq!(g.session, st.session);
    assert_eq!(g.resources.len(), 1);
    assert_eq!(g.journal.stats().resources, 1);
    assert_eq!(g.journal.gpu_written(), [5]);
    assert_eq!(g.conns[USER].link.lock().q.tx_id, tx_id);
    g.process_retry();
    let mut sink = sink_on(&listener);
    // the HELLO says the device was restored, and up to which id it had sent
    let h = sink.last_hello.unwrap();
    assert_eq!(
        (h.arg0, h.arg1, h.arg2, h.seq, h.flags & SP_F_RESTORED),
        (st.session, 0xabc, 0, tx_id, SP_F_RESTORED)
    );
    // The renderer has exactly that: a resume, no reset, no rebuild.
    sink.hello(0xabc, st.session, tx_id, false);
    pump(&mut g, |g| g.conns[USER].up());
    assert!(g.switch.is_none());
    assert_eq!(g.counters.n_reconnect, 1);
    assert!(!g.conns[USER].restored);
    let cmd = Cmd {
        head: 0,
        writable: vec![(GuestAddress(RESP_AT), 0x1000)],
    };
    g.source_one(&mem, cmd, hdr(CMD_RESOURCE_FLUSH, None, 0));
    let (m, a) = sink.next();
    assert_eq!(
        (m.typ, m.id, u32_at(&a, 0)),
        (SP_CTRL, tx_id + 1, CMD_RESOURCE_FLUSH)
    );
}

#[test]
fn a_restored_device_resets_a_renderer_that_ran_on_and_rebuilds() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    let (sink, n) = paired_with_a_drawn_texture(&mut r, &listener);
    r.gpu.prepare_save();
    let st = through_a_snapshot(&r.gpu);
    drop(sink);

    // The VM runs on after the snapshot: the same renderer resumes, and texture 5 is drawn
    // into again; it is marked again, since the snapshot was a mark point.
    r.gpu.kick();
    r.gpu.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello(0xabc, r.gpu.session, n, false);
    pump(&mut r.gpu, |g| g.conns[USER].up());
    r.give(submit(None, 1, &draw_into(5)));
    let after: Vec<(u32, u32, u64)> = (0..2)
        .map(|_| {
            let (m, a) = sink.next();
            (m.typ, u32_at(&a, 0), m.id)
        })
        .collect();
    assert_eq!(
        after,
        [(SP_WMARK, 5, n + 1), (SP_CTRL, CMD_SUBMIT_3D, n + 2)]
    );
    drop(r);
    drop(sink);

    // Rolled back: the renderer has 2 more of the device's messages than the snapshot. It
    // is reset to the snapshot's last id and gets what it does not keep from the journal.
    let mut g = restored(&mem, &st);
    g.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello(0xabc, st.session, n + 2, false);
    pump(&mut g, |g| g.conns[USER].up());
    assert!(g.switch.is_some());
    let (m, _) = sink.next();
    assert_eq!((m.typ, m.id, m.arg0), (SP_STATE_RESET, n + 1, n));
    // texture 5 changed after the snapshot: the renderer does not keep it
    sink.say(1, SP_STATE_KEPT, &[], &[], n);
    pump(&mut g, |g| g.switch.is_none());
    assert_eq!(
        sink.take(5),
        [
            (SP_CTRL, CMD_CTX_CREATE),
            (SP_CTRL, CMD_RESOURCE_CREATE_3D),
            (SP_CTRL, CMD_RESOURCE_ATTACH_BACKING),
            (SP_CTRL, CMD_CTX_ATTACH_RESOURCE),
            (SP_CTRL, CMD_SUBMIT_3D),
        ]
    );
    assert_eq!(g.n_switch, st.n_switch + 1);
    // The redraw after a rollback waits for the resume, then 2 s (the user's choice).
    assert!(g.redraw_after_resume);
    assert_eq!(g.redraw_at, None);
    // a snapshot before the resume keeps it as a redraw to do
    assert!(g.save().redraw_pending);
    let t = now_us();
    g.kick();
    assert!(!g.redraw_after_resume);
    let at = g.redraw_at.unwrap();
    assert!(at >= t + 2_000_000 && at < now_us() + 2_000_000 + 1);
    g.process_ack_timer();
    assert_eq!(g.redraw_at, Some(at));
    // when it is due the ack timer asks for it (no agent here: nothing is pending after)
    g.redraw_at = Some(now_us() - 1);
    g.process_ack_timer();
    assert_eq!(g.redraw_at, None);
}

#[test]
fn a_restored_device_rebuilds_a_renderer_that_does_not_know_it() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    let (sink, _) = paired_with_a_drawn_texture(&mut r, &listener);
    r.gpu.prepare_save();
    let st = through_a_snapshot(&r.gpu);
    drop(r);
    drop(sink);
    let mut g = restored(&mem, &st);
    g.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello(0x999, 0, 0, false);
    pump(&mut g, |g| g.conns[USER].up());
    let (m, _) = sink.next();
    assert_eq!((m.typ, m.id, m.arg0), (SP_STATE_RESET, 1, 0));
    sink.say(1, SP_STATE_KEPT, &[], &[], 0);
    pump(&mut g, |g| g.switch.is_none());
    assert_eq!(sink.take(1), [(SP_CTRL, CMD_CTX_CREATE)]);
}

#[test]
fn a_checkpoint_waits_for_nothing_keeps_the_connection_and_is_a_mark_point() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    let (mut sink, tx_id) = paired_with_a_drawn_texture(&mut r, &listener);
    assert!(r.gpu.conns[USER].marked.contains(&5));
    // a fenced command that waits for the sink, not acknowledged
    r.gpu.fence_window = 0;
    r.give(submit(Some(7), 1, &[]));
    assert_eq!(r.gpu.pending.len(), 1);
    let t = Instant::now();
    r.gpu.prepare_checkpoint();
    assert!(t.elapsed() < Duration::from_millis(100));
    // nothing answered here, nothing closed; a mark point
    assert_eq!(r.gpu.pending.len(), 1);
    assert!(r.gpu.conns[USER].link.is_connected());
    assert!(r.gpu.conns[USER].hello_done);
    assert!(r.gpu.conns[USER].wanted);
    assert!(r.gpu.conns[USER].marked.is_empty());
    // the side state has the command and the message, and no export
    let st = through_a_snapshot(&r.gpu);
    let side = st.side.as_ref().unwrap();
    assert_eq!(side.pending.len(), 1);
    assert_eq!(side.pending[0].fence_id, 7);
    assert_eq!(
        side.unacked[USER].iter().map(|m| m.0).collect::<Vec<_>>(),
        [tx_id + 1]
    );
    assert!(side.scanout_saved.is_empty());
    assert_eq!(st.conns[USER].tx_id, tx_id + 1);
    // the guest goes on: the texture drawn again is marked again
    r.give(submit(None, 1, &draw_into(5)));
    let got: Vec<(u32, u32)> = (0..3)
        .map(|_| {
            let (m, a) = sink.next();
            (m.typ, u32_at(&a, 0))
        })
        .collect();
    assert_eq!(
        got,
        [
            (SP_CTRL, CMD_SUBMIT_3D),
            (SP_WMARK, 5),
            (SP_CTRL, CMD_SUBMIT_3D)
        ]
    );
}

#[test]
fn the_stop_of_a_move_waits_for_nothing_and_the_destination_resumes_what_was_not_answered() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    let (sink, tx_id) = paired_with_a_drawn_texture(&mut r, &listener);
    r.gpu.fence_window = 0;
    r.give(submit(Some(7), 1, &[]));
    assert_eq!(r.gpu.pending.len(), 1);
    let t = Instant::now();
    r.gpu.prepare_move();
    assert!(t.elapsed() < Duration::from_millis(100));
    // closed, a mark point, the command still waits
    assert!(!r.gpu.conns[USER].link.is_connected());
    assert!(r.gpu.conns[USER].marked.is_empty());
    assert!(!r.gpu.conns[USER].wanted);
    assert_eq!(r.gpu.pending.len(), 1);
    let st = through_a_snapshot(&r.gpu);
    let side = st.side.as_ref().unwrap();
    assert_eq!(side.pending.len(), 1);
    assert_eq!(side.unacked[USER].len(), 1);
    assert!(side.scanout_saved.is_empty());
    assert!(st.conns[USER].wanted);
    drop(sink);

    // The destination resumes the same renderer, which lacks the command: it is sent again,
    // and its answer completes the guest's command there.
    let mut g = restored(&mem, &st);
    g.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello(0xabc, st.session, tx_id, false);
    pump(&mut g, |g| g.conns[USER].up());
    assert!(g.switch.is_none());
    let (m, a) = sink.next();
    assert_eq!(
        (m.typ, m.id, u32_at(&a, 0)),
        (SP_CTRL, tx_id + 1, CMD_SUBMIT_3D)
    );
    sink.send(
        Hdr {
            typ: SP_RESP,
            id: 1,
            ack: m.id,
            seq: m.seq,
            a_len: 24,
            ..Default::default()
        },
        &hdr(RESP_OK_NODATA, Some(7), 1),
    );
    pump(&mut g, |g| g.pending.is_empty());
    drop(g);
    drop(sink);

    // The way back: the source goes on, and says that it was restored at its stop, so that a
    // renderer that the destination ran on goes back to it.
    r.gpu.kick();
    r.gpu.process_retry();
    let sink = sink_on(&listener);
    let h = sink.last_hello.unwrap();
    assert_eq!((h.seq, h.flags & SP_F_RESTORED), (tx_id + 1, SP_F_RESTORED));
}

#[test]
fn a_device_whose_large_state_is_lost_is_restored_without_it() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    let (sink, tx_id) = paired_with_a_drawn_texture(&mut r, &listener);
    r.gpu.prepare_checkpoint();
    let mut st = through_a_snapshot(&r.gpu);
    drop(r);
    drop(sink);
    // the side file that says so
    assert!(
        GpuSideState::read_from(&mut SIDE_LOST.as_slice())
            .unwrap()
            .is_none()
    );
    st.side = None;
    st.side_lost = true;
    let mut g = restored(&mem, &st);
    assert_eq!(g.session, st.session);
    assert!(g.resources.is_empty());
    assert_eq!(g.journal.stats().resources, 0);
    assert!(g.pending.is_empty());
    assert_eq!(g.conns[USER].link.lock().q.tx_id, tx_id);
    // it names no session of a renderer: the renderer starts empty, and gets the (empty)
    // journal
    g.process_retry();
    let mut sink = sink_on(&listener);
    assert_eq!(sink.last_hello.unwrap().arg1, 0);
    sink.hello(0xabc, st.session, tx_id, false);
    pump(&mut g, |g| g.conns[USER].up());
    let (m, _) = sink.next();
    assert_eq!((m.typ, m.arg0), (SP_STATE_RESET, 0));
    sink.say(1, SP_STATE_KEPT, &[], &[], 0);
    pump(&mut g, |g| g.switch.is_none());
    // with no large state and no word that it is lost, the restore is refused
    st.side_lost = false;
    assert!(matches!(
        Gpu::restore(
            GpuConstructorArgs {
                mem: mem.clone(),
                filter: Arc::new(Vec::new()),
            },
            &st
        ),
        Err(GpuPersistError::NoSide)
    ));
}

#[test]
fn a_restore_needs_the_side_file_of_its_snapshot() {
    let mem = single_region_mem(0x100000);
    let r = rig_with(&mem, cfg("/nonexistent"));
    let mut st = r.gpu.save();
    let side = st.side.take().unwrap();
    let args = || GpuConstructorArgs {
        mem: mem.clone(),
        filter: Arc::new(Vec::new()),
    };
    assert!(matches!(
        Gpu::restore(args(), &st),
        Err(GpuPersistError::NoSide)
    ));
    let mut other = (*side).clone();
    other.side_id ^= 1;
    st.side = Some(Arc::new(other));
    assert!(matches!(
        Gpu::restore(args(), &st),
        Err(GpuPersistError::OtherSide)
    ));
    // a damaged side file is refused
    let mut bytes = Vec::new();
    side.write_to(&mut bytes).unwrap();
    let k = bytes.len() / 2;
    bytes[k] ^= 0xff;
    GpuSideState::read_from(&mut bytes.as_slice()).unwrap_err();
    st.side = Some(side);
    Gpu::restore(args(), &st).unwrap();
}

#[test]
fn a_rollback_gets_the_shown_resources_as_they_were_at_the_snapshot() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    let (mut sink, _) = paired_with_a_drawn_texture(&mut r, &listener);
    // texture 6 is drawn by the GPU too, and not shown (as the cached pictures of a shell's panel)
    r.resource(6, 2, 67, 2, 64, 64, BACKING_AT + 0x10000);
    let mut at = hdr(CMD_CTX_ATTACH_RESOURCE, None, 1);
    put32(&mut at, 6);
    put32(&mut at, 0);
    r.give(at);
    r.give(submit(None, 1, &draw_into(6)));
    // texture 5 (drawn by the GPU) is shown
    let mut sc = hdr(0x0103, None, 0);
    for v in [0, 0, 64, 64, 0, 5] {
        put32(&mut sc, v);
    }
    r.give(sc);
    assert_eq!(r.gpu.scanned, [5]);
    let mut last = 0;
    loop {
        let (m, a) = sink.next();
        last = m.id.max(last);
        if (m.typ, u32_at(&a, 0)) == (SP_CTRL, 0x0103) {
            break;
        }
    }
    // At the snapshot, after the drain, the device asks for what the GPU drew: the shown
    // texture first, then the other one.
    let answer = std::thread::spawn(move || {
        sink.send(
            Hdr {
                typ: SP_ACK,
                ack: last,
                ..Default::default()
            },
            &[],
        );
        for (k, res, fill) in [(1, 5u32, 5u8), (3, 6u32, 6u8)] {
            let (e, a) = sink.next();
            assert_eq!((e.typ, a.len(), u32_at(&a, 0)), (SP_EXPORT, 4, res));
            // a sink's messages carry its acknowledgement
            sink.ack_to(e.id);
            sink.export_answer(k, e.arg0, res, fill);
        }
        sink
    });
    r.gpu.prepare_save();
    let sink = answer.join().unwrap();
    assert_eq!(r.gpu.scanout_saved.len(), 2);
    assert_eq!(u32_at(&r.gpu.scanout_saved[0].0, 0), 5);
    assert!(r.gpu.saved_missing.is_empty());
    let st = through_a_snapshot(&r.gpu);
    assert_eq!(st.side.as_ref().unwrap().scanout_saved.len(), 2);
    assert!(st.side.as_ref().unwrap().scanout_missing.is_empty());
    drop(r);
    drop(sink);

    // Rolled back: the renderer ran on and keeps nothing of the snapshot. After the rebuild it
    // gets textures 5 and 6 as they were at the snapshot, and the scanout is shown again.
    let mut g = restored(&mem, &st);
    assert_eq!(g.scanout_saved.len(), 2);
    g.process_retry();
    let mut sink = sink_on(&listener);
    let n = st.conns[USER].tx_id;
    sink.hello(0xabc, st.session, n + 5, false);
    pump(&mut g, |g| g.conns[USER].up());
    let (m, _) = sink.next();
    assert_eq!((m.typ, m.arg0), (SP_STATE_RESET, n));
    sink.say(5, SP_STATE_KEPT, &[], &[], n);
    pump(&mut g, |g| g.switch.is_none());
    let mut seen = Vec::new();
    loop {
        let (h, a) = sink.next();
        seen.push((h.typ, u32_at(&a, 0), h.b_len));
        if h.typ == SP_CTRL && u32_at(&a, 0) == 0x0103 && seen.iter().any(|s| s.0 == SP_IMPORT) {
            break;
        }
        assert!(seen.len() < 40, "{seen:?}");
    }
    assert!(seen.contains(&(SP_IMPORT, 5, 64)), "{seen:?}");
    assert!(seen.contains(&(SP_IMPORT, 6, 64)), "{seen:?}");
    assert!(g.scanout_saved.is_empty());
}

// ---- a snapshot's export that is slow, stalled or answered late (V4 of validation r2) ------

/// A device paired with a test sink, with texture 5 drawn by the GPU and shown, and with
/// `other` texture 6 drawn too and not shown. Returns the sink and the last id the device
/// gave out (not acknowledged yet).
fn shown_texture(r: &mut Rig<'_>, listener: &UnixListener, other: bool) -> (Sink, u64) {
    let (mut sink, _) = paired_with_a_drawn_texture(r, listener);
    if other {
        r.resource(6, 2, 67, 2, 64, 64, BACKING_AT + 0x10000);
        let mut at = hdr(CMD_CTX_ATTACH_RESOURCE, None, 1);
        put32(&mut at, 6);
        put32(&mut at, 0);
        r.give(at);
        r.give(submit(None, 1, &draw_into(6)));
    }
    let mut sc = hdr(0x0103, None, 0);
    for v in [0, 0, 64, 64, 0, 5] {
        put32(&mut sc, v);
    }
    r.give(sc);
    let mut last = 0;
    loop {
        let (m, a) = sink.next();
        last = m.id.max(last);
        if (m.typ, u32_at(&a, 0)) == (SP_CTRL, 0x0103) {
            break;
        }
    }
    (sink, last)
}

/// Read the device's next `SP_EXPORT` and acknowledge it: (its request id, the resources).
fn export_asked(sink: &mut Sink) -> (u64, Vec<u32>) {
    let (e, a) = sink.next();
    assert_eq!(e.typ, SP_EXPORT);
    sink.ack_to(e.id);
    (e.arg0, a.chunks_exact(4).map(|c| u32_at(c, 0)).collect())
}

#[test]
fn a_slow_snapshot_export_that_keeps_sending_completes_after_more_than_2_s() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    let (mut sink, last) = shown_texture(&mut r, &listener, false);
    // A slow link: the piece of texture 5 arrives in 7 parts 500 ms apart (3 s in all, never
    // 2 s with nothing).
    let answer = std::thread::spawn(move || {
        sink.ack_to(last);
        let (req, ids) = export_asked(&mut sink);
        assert_eq!(ids, [5]);
        let mut x = vec![0u8; 48];
        x[..4].copy_from_slice(&5u32.to_le_bytes());
        let b = [5u8; 4096];
        let mut m = export_hdr(1, SP_EXPORT_DATA, &x, &b, [0, 0, req])
            .encode()
            .to_vec();
        m.extend_from_slice(&x);
        m.extend_from_slice(&b);
        for part in m.chunks(m.len().div_ceil(7)) {
            sink.s.write_all(part).unwrap();
            std::thread::sleep(Duration::from_millis(500));
        }
        sink.say_args(2, SP_EXPORT_DONE, &[], &[], [1, 4096, req]);
        sink
    });
    let t = Instant::now();
    r.gpu.prepare_save();
    let waited = t.elapsed();
    let _sink = answer.join().unwrap();
    assert!(waited > Duration::from_millis(2900), "{waited:?}");
    assert_eq!(r.gpu.scanout_saved.len(), 1);
    assert_eq!(r.gpu.scanout_saved[0].1, [5u8; 4096]);
    assert!(r.gpu.saved_missing.is_empty());
    let st = through_a_snapshot(&r.gpu);
    assert!(st.side.as_ref().unwrap().scanout_missing.is_empty());
}

#[test]
fn a_stalled_snapshot_export_ends_after_2_s_of_silence_and_is_recorded() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    let (mut sink, last) = shown_texture(&mut r, &listener, false);
    // The renderer takes the export and then sends nothing (stopped).
    let answer = std::thread::spawn(move || {
        sink.ack_to(last);
        let (_, ids) = export_asked(&mut sink);
        assert_eq!(ids, [5]);
        (sink, Instant::now())
    });
    r.gpu.prepare_save();
    let (_sink, asked) = answer.join().unwrap();
    let silent = asked.elapsed();
    assert!(
        silent >= Duration::from_millis(1990) && silent < Duration::from_millis(2600),
        "{silent:?}"
    );
    // the snapshot is taken, without the content, which is recorded as missing
    assert!(!r.gpu.conns[USER].link.is_connected());
    assert!(r.gpu.scanout_saved.is_empty());
    assert_eq!(r.gpu.saved_missing, [5]);
    let st = through_a_snapshot(&r.gpu);
    assert_eq!(st.side.as_ref().unwrap().scanout_missing, [5]);
}

#[test]
fn a_late_reply_of_a_first_export_does_not_complete_the_second() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    let (mut sink, last) = shown_texture(&mut r, &listener, true);
    // The renderer stalls on the first export (texture 5) past its 2 s of silence; the device
    // asks for the second (texture 6); then the renderer answers the first, late, and 500 ms
    // later the second.
    let answer = std::thread::spawn(move || {
        sink.ack_to(last);
        let (req1, ids1) = export_asked(&mut sink);
        let (req2, ids2) = export_asked(&mut sink);
        assert_eq!((ids1.as_slice(), ids2.as_slice()), (&[5][..], &[6][..]));
        assert_ne!(req1, req2);
        sink.export_answer(1, req1, 5, 5);
        std::thread::sleep(Duration::from_millis(500));
        let t = Instant::now();
        sink.export_answer(3, req2, 6, 6);
        (sink, t)
    });
    r.gpu.prepare_save();
    let ended = Instant::now();
    let (_sink, second) = answer.join().unwrap();
    // it waited for the second export's own reply
    assert!(ended > second);
    assert_eq!(r.gpu.scanout_saved.len(), 1);
    assert_eq!(u32_at(&r.gpu.scanout_saved[0].0, 0), 6);
    assert_eq!(r.gpu.scanout_saved[0].1, [6u8; 64]);
    assert_eq!(r.gpu.saved_missing, [5]);
    assert_eq!(r.gpu.counters.export_stale, 2);
}

#[test]
fn the_side_files_record_of_missing_content_round_trips() {
    let mem = single_region_mem(0x100000);
    let mut r = rig_with(&mem, cfg("/nonexistent"));
    r.gpu.saved_missing = vec![5, 1110, 7];
    let st = through_a_snapshot(&r.gpu);
    assert_eq!(st.side.as_ref().unwrap().scanout_missing, [5, 1110, 7]);
    let g = Gpu::restore(
        GpuConstructorArgs {
            mem: mem.clone(),
            filter: Arc::new(Vec::new()),
        },
        &st,
    )
    .unwrap();
    assert_eq!(g.saved_missing, [5, 1110, 7]);
    // a side file of the form before the record is refused
    let mut bytes = Vec::new();
    st.side.as_ref().unwrap().write_to(&mut bytes).unwrap();
    bytes[..8].copy_from_slice(b"SPGPU001");
    GpuSideState::read_from(&mut bytes.as_slice()).unwrap_err();
}

/// Put command `req` on the guest's control queue at slot `i` (the request and a writable
/// answer); returns the address of the answer.
fn guest_put(r: &Rig<'_>, i: u16, req: &[u8]) -> u64 {
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    let req_at = 0x60000 + u64::from(i) * 0x2000;
    let resp_at = req_at + 0x1000;
    r.mem.write_slice(req, GuestAddress(req_at)).unwrap();
    r.mem
        .write_slice(&[0xee; 64], GuestAddress(resp_at))
        .unwrap();
    r.ctrl.dtable[usize::from(2 * i)].set(
        req_at,
        u32::try_from(req.len()).unwrap(),
        VIRTQ_DESC_F_NEXT,
        2 * i + 1,
    );
    r.ctrl.dtable[usize::from(2 * i + 1)].set(resp_at, 0x1000, VIRTQ_DESC_F_WRITE, 0);
    r.ctrl.avail.ring[usize::from(i)].set(2 * i);
    r.ctrl.avail.idx.set(i + 1);
    resp_at
}

fn answered(r: &Rig<'_>, at: u64) -> Option<u32> {
    let mut b = [0u8; 24];
    r.mem.read_slice(&mut b, GuestAddress(at)).unwrap();
    (b != [0xee; 24]).then(|| resp_type(&b))
}

#[test]
fn a_guest_whose_renderer_never_came_is_served_by_the_device_after_the_first_wait() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    // No renderer yet, within the first wait: a fenced command waits in the guest's queue.
    let a1 = guest_put(&r, 0, &submit(Some(7), 1, &[]));
    r.gpu.process_ctrl_queue().unwrap();
    assert_eq!(answered(&r, a1), None);
    assert!(!r.gpu.alone());
    // The first wait is over: the device takes the command and answers it, keeps it in its
    // journal (the context), and queues nothing for a renderer.
    r.gpu.made_at -= FIRST_WAIT_US + 1;
    let a2 = guest_put(&r, 1, &ctx_create(3));
    r.gpu.process_ack_timer();
    assert_eq!(answered(&r, a1), Some(RESP_OK_NODATA));
    assert_eq!(answered(&r, a2), Some(RESP_OK_NODATA));
    assert_eq!(r.used(), 2);
    assert!(r.gpu.pending.is_empty());
    assert_eq!(r.gpu.journal.stats().contexts, 1);
    assert_eq!(r.gpu.conns[USER].link.lock().q.unacked, 0);
    assert!(r.gpu.alone_said);
    // A renderer that comes then starts empty and gets the state from the journal.
    let listener = UnixListener::bind(&path).unwrap();
    r.gpu.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello(0xabc, r.gpu.session, 0, false);
    pump(&mut r.gpu, |g| g.conns[USER].up());
    let (m, _) = sink.next();
    assert_eq!((m.typ, m.arg0), (SP_STATE_RESET, 0));
    sink.say(1, SP_STATE_KEPT, &[], &[], 0);
    pump(&mut r.gpu, |g| g.switch.is_none());
    assert_eq!(sink.take(1), [(SP_CTRL, CMD_CTX_CREATE)]);
    assert!(!r.gpu.alone());
}

#[test]
fn a_lost_renderer_is_waited_for_and_then_let_go_when_there_is_no_in_guest_renderer() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    let (sink, _) = paired_with_a_drawn_texture(&mut r, &listener);
    drop(sink);
    pump(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    // lost: the guest's commands wait for it (it may come back and resume)
    let a1 = guest_put(&r, 0, &submit(Some(9), 1, &[]));
    r.gpu.process_ack_timer();
    assert_eq!(answered(&r, a1), None);
    assert_ne!(r.gpu.conns[USER].peer_session, 0);
    // lost for longer than the wait: let go, and the device serves the guest
    r.gpu.conns[USER].lost_at -= LOST_WAIT_US + 1;
    r.gpu.process_ack_timer();
    assert_eq!(r.gpu.conns[USER].peer_session, 0);
    assert_eq!(answered(&r, a1), Some(RESP_OK_NODATA));
}

#[test]
fn a_new_pairing_and_a_restore_release_the_keys_that_the_guest_holds() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    let kbd = input_dev(&mem, 0x180000, InputKind::Keyboard);
    let tab = input_dev(&mem, 0x190000, InputKind::Tablet);
    r.gpu.set_inputs(kbd.clone(), tab.clone());
    // a key and a button held, a key pressed and released
    kbd.lock()
        .unwrap()
        .queue_events_of_report(&[input_event(EV_KEY, 30, 1)]);
    kbd.lock()
        .unwrap()
        .queue_events_of_report(&[input_event(EV_KEY, 31, 1)]);
    kbd.lock()
        .unwrap()
        .queue_events_of_report(&[input_event(EV_KEY, 31, 0)]);
    kbd.lock().unwrap().sync();
    tab.lock()
        .unwrap()
        .queue_events_of_report(&[input_event(EV_KEY, BTN_LEFT, 1)]);
    tab.lock().unwrap().sync();
    assert_eq!(kbd.lock().unwrap().held(), [30]);
    assert_eq!(tab.lock().unwrap().held(), [BTN_LEFT]);
    let (k0, t0) = (
        kbd.lock().unwrap().pending_len(),
        tab.lock().unwrap().pending_len(),
    );
    // a renderer pairs: both are released, in a report each
    r.gpu.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello(0xabc, r.gpu.session, 0, false);
    pump(&mut r.gpu, |g| g.conns[USER].up());
    assert!(kbd.lock().unwrap().held().is_empty());
    assert!(tab.lock().unwrap().held().is_empty());
    assert_eq!(kbd.lock().unwrap().pending_len(), k0 + 2);
    assert_eq!(tab.lock().unwrap().pending_len(), t0 + 2);
    // nothing held: a pairing adds nothing
    drop(sink);
    pump(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    r.gpu.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello(
        0xabc,
        r.gpu.session,
        r.gpu.conns[USER].link.lock().q.tx_id,
        false,
    );
    pump(&mut r.gpu, |g| g.conns[USER].up());
    assert_eq!(kbd.lock().unwrap().pending_len(), k0 + 2);
    // the held keys go with the input device's state; a restored device releases at the resume
    kbd.lock()
        .unwrap()
        .queue_events_of_report(&[input_event(EV_KEY, 48, 1)]);
    kbd.lock().unwrap().sync();
    let st = kbd.lock().unwrap().save();
    assert_eq!(st.held, [48]);
    let gst = through_a_snapshot(&r.gpu);
    drop(sink);
    let mut g = restored(&mem, &gst);
    assert!(g.release_at_kick);
    // (the restore of an input device keeps what it holds: input.rs, test_persistence)
    let k2 = input_dev(&mem, 0x1a0000, InputKind::Keyboard);
    {
        let mut k = k2.lock().unwrap();
        k.queue_events_of_report(&[input_event(EV_KEY, 48, 1)]);
        k.sync();
    }
    g.set_inputs(k2.clone(), input_dev(&mem, 0x1b0000, InputKind::Tablet));
    let before = k2.lock().unwrap().pending_len();
    g.kick();
    assert!(!g.release_at_kick);
    assert!(k2.lock().unwrap().held().is_empty());
    assert_eq!(k2.lock().unwrap().pending_len(), before + 2);
}

#[test]
fn a_redraw_waits_until_the_renderer_is_paired() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let agent_path = dir.as_path().join("vsock.sock_5000");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut c = cfg(path.to_str().unwrap());
    c.agent_socket_path = Some(agent_path.to_str().unwrap().into());
    let mut r = rig_with(&mem, c);
    let mut guest = UnixStream::connect(&agent_path).unwrap();
    r.gpu.agent.as_mut().unwrap().accept().unwrap();
    r.gpu.agent_connected();
    guest
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    // no renderer: the compositor could not answer the agent's change of scale; it waits
    r.gpu.redraw();
    assert!(r.gpu.redraw_pending);
    let mut got = [0u8; 7];
    guest.read_exact(&mut got).unwrap_err();
    // the renderer is paired: the redraw is asked for then
    r.gpu.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello(0xabc, r.gpu.session, 0, false);
    pump(&mut r.gpu, |g| g.conns[USER].up());
    guest
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    guest.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"REDRAW\n");
    assert!(!r.gpu.redraw_pending);
}

#[test]
fn a_rollback_to_an_incomplete_snapshot_logs_the_lack_and_redraws_2_s_after_the_resume() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let agent_path = dir.as_path().join("vsock.sock_5000");
    let log = dir.as_path().join("gpu.log");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut c = cfg(path.to_str().unwrap());
    c.agent_socket_path = Some(agent_path.to_str().unwrap().into());
    c.stats_path = Some(log.to_str().unwrap().into());
    let mut r = rig_with(&mem, c);
    let (mut sink, last) = shown_texture(&mut r, &listener, false);
    let answer = std::thread::spawn(move || {
        sink.ack_to(last);
        export_asked(&mut sink);
        sink
    });
    r.gpu.prepare_save();
    let sink = answer.join().unwrap();
    assert_eq!(r.gpu.saved_missing, [5]);
    let st = through_a_snapshot(&r.gpu);
    drop(r);
    drop(sink);
    let n = st.conns[USER].tx_id;
    let lack = "the snapshot's GPU content was incomplete: the resources [5] were not saved";

    // Rolled back, and the renderer does not keep texture 5 (it changed after the snapshot):
    // the lack is logged, and the redraw comes 2 s after the resume, as after every rollback
    // (the user's choice), not before.
    let mut g = restored(&mem, &st);
    assert_eq!(g.saved_missing, [5]);
    g.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello(0xabc, st.session, n + 5, false);
    pump(&mut g, |g| g.conns[USER].up());
    let (m, _) = sink.next();
    assert_eq!((m.typ, m.arg0), (SP_STATE_RESET, n));
    sink.say(1, SP_STATE_KEPT, &[], &[], n);
    pump(&mut g, |g| g.switch.is_none());
    assert!(std::fs::read_to_string(&log).unwrap().contains(lack));
    assert!(g.redraw_after_resume);
    assert_eq!(g.redraw_at, None);
    assert!(!g.redraw_pending);
    assert!(g.saved_missing.is_empty());
    let t = now_us();
    g.kick();
    let at = g.redraw_at.unwrap();
    assert!(at >= t + 2_000_000 && at < now_us() + 2_000_000 + 1);
    // the agent connects after the resume: it is not asked before the 2 s are over
    let mut guest = UnixStream::connect(&agent_path).unwrap();
    g.agent.as_mut().unwrap().accept().unwrap();
    g.agent_connected();
    let mut got = [0u8; 7];
    guest
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    while now_us() < at - 150_000 {
        g.process_ack_timer();
        guest.read_exact(&mut got).unwrap_err();
    }
    assert_eq!(g.redraw_at, Some(at));
    assert!(
        !std::fs::read_to_string(&log)
            .unwrap()
            .contains("asked the guest agent to redraw")
    );
    // when it is due the ack timer asks for it
    std::thread::sleep(Duration::from_micros(
        u64::try_from(at - now_us()).unwrap_or(0) + 1000,
    ));
    g.process_ack_timer();
    assert_eq!(g.redraw_at, None);
    guest
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    guest.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"REDRAW\n");
    assert!(now_us() >= t + 2_000_000);
    drop(g);
    drop(sink);
    drop(guest);

    // The same snapshot, and a renderer that kept texture 5: nothing it needs is missing,
    // nothing is logged as lacking, and the redraw comes 2 s after the resume as well.
    std::fs::write(&log, b"").unwrap();
    let mut g = restored(&mem, &st);
    g.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello(0xabc, st.session, n + 5, false);
    pump(&mut g, |g| g.conns[USER].up());
    let (m, _) = sink.next();
    assert_eq!((m.typ, m.arg0), (SP_STATE_RESET, n));
    sink.say(1, SP_STATE_KEPT, &5u32.to_le_bytes(), &[], n);
    pump(&mut g, |g| g.switch.is_none());
    assert!(!std::fs::read_to_string(&log).unwrap().contains(lack));
    assert!(g.redraw_after_resume);
    assert!(!g.redraw_pending);
}

// ---- the spec at the pairing -----------------------------------------------------------------

#[test]
fn the_capsets_come_from_the_spec_before_any_renderer_and_in_order() {
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg("/nonexistent"));
    // Within the first wait, with no renderer: the kernel's probe reads the capsets, answered
    // here; the command after them waits for a renderer, and so does what comes after it.
    let a0 = guest_put(&r, 0, &capset_info(0));
    let a1 = guest_put(&r, 1, &capset(2, 0));
    let a2 = guest_put(&r, 2, &submit(Some(7), 1, &[]));
    let a3 = guest_put(&r, 3, &capset_info(1));
    r.gpu.process_ctrl_queue().unwrap();
    r.gpu.notify_used();
    assert_eq!(answered(&r, a0), Some(RESP_OK_CAPSET_INFO));
    assert_eq!(answered(&r, a1), Some(RESP_OK_CAPSET));
    let mut c2 = vec![0u8; 12];
    mem.read_slice(&mut c2, GuestAddress(a1 + 24)).unwrap();
    assert_eq!(c2, test_spec().capset(2).unwrap().data);
    assert_eq!((answered(&r, a2), answered(&r, a3)), (None, None));
    assert_eq!(r.used(), 2);
    assert_eq!(r.gpu.seq, 0);
    assert!(r.gpu.conns[USER].link.lock().q.messages().is_empty());
    let q = r.gpu.counters.queries;
    assert_eq!((q.forwarded_before_info, q.forwarded_after_info), (0, 0));
}

#[test]
fn a_new_pairing_gets_the_spec_and_runs_nothing_before_its_yes() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    r.gpu.process_retry();
    let mut sink = sink_on(&listener);
    // the HELLO says that the device holds a spec
    assert_ne!(sink.last_hello.unwrap().flags & SP_F_SPEC, 0);
    sink.hello_only(0xabc, r.gpu.session, 0, false);
    pump(&mut r.gpu, |g| g.conns[USER].hello_done);
    // the spec is the first message, the file as it is, not resent
    let (h, a) = sink.next_any();
    assert_eq!((h.typ, h.id), (SP_SPEC, 0));
    assert_eq!(a, spec_text().into_bytes());
    // before the yes the renderer is not paired: the guest's command waits, and what the
    // renderer sends is not taken
    assert!(!r.gpu.conns[USER].up());
    let a0 = guest_put(&r, 0, &submit(Some(7), 1, &[]));
    r.gpu.process_ctrl_queue().unwrap();
    assert_eq!(answered(&r, a0), None);
    let mut dinfo = hdr(0x1101, None, 0);
    dinfo.resize(408, 0);
    sink.say(1, SP_INFO, &dinfo, &[], 2);
    sink.spec_reply(true, "");
    pump(&mut r.gpu, |g| g.conns[USER].up());
    assert!(r.gpu.dinfo.is_none());
    assert!(r.gpu.paired_once);
    // after the yes the command goes to the renderer
    assert_eq!(sink.take(1), [(SP_CTRL, CMD_SUBMIT_3D)]);
    assert!(sink.specs.is_empty());

    // A pairing that resumes is not sent the spec again.
    drop(sink);
    pump(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    r.gpu.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello_only(0xabc, r.gpu.session, 1, false);
    pump(&mut r.gpu, |g| g.conns[USER].up());
    assert_eq!(r.gpu.counters.n_reconnect, 1);
    r.give(hdr(CMD_RESOURCE_FLUSH, None, 0));
    let (m, a) = sink.next_any();
    assert_eq!((m.typ, u32_at(&a, 0)), (SP_CTRL, CMD_RESOURCE_FLUSH));

    // A pairing lost before its yes starts again: the next HELLO is a new pairing.
    drop(sink);
    pump(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    r.gpu.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello_only(0xdef, r.gpu.session, 0, false);
    pump(&mut r.gpu, |g| g.conns[USER].hello_done);
    assert_eq!(sink.next_any().0.typ, SP_SPEC);
    drop(sink);
    pump(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    assert_eq!(r.gpu.conns[USER].peer_session, 0);
    r.gpu.process_retry();
    let sink = sink_on(&listener);
    assert_eq!(sink.last_hello.unwrap().arg1, 0);
}

#[test]
fn a_renderer_that_cannot_do_the_spec_is_not_paired_and_is_tried_again_later() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    r.gpu.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello_only(0xabc, r.gpu.session, 0, false);
    pump(&mut r.gpu, |g| g.conns[USER].hello_done);
    assert_eq!(sink.next_any().0.typ, SP_SPEC);
    sink.spec_reply(
        false,
        " capset 1 max_tbo_size[0]: 134217728 here, profile 268435456 (ge);",
    );
    // the device closes the connection; the renderer is not paired
    pump(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    let c = &r.gpu.conns[USER];
    assert!(c.refused && !c.spec_ok);
    assert_eq!((c.peer_session, c.n_refused), (0, 1));
    assert!(!r.gpu.paired_once);
    // not tried again within 5 s
    r.gpu.process_retry();
    assert!(!r.gpu.conns[USER].link.is_connected());
    // after the first wait the guest is served alone
    r.gpu.made_at -= FIRST_WAIT_US + 1;
    let a0 = guest_put(&r, 0, &submit(Some(3), 1, &[]));
    r.gpu.process_ack_timer();
    assert_eq!(answered(&r, a0), Some(RESP_OK_NODATA));
    // tried again after 5 s; one that can do the spec is paired and built from the journal
    r.gpu.conns[USER].refused_at -= SPEC_RETRY_US + 1;
    r.gpu.process_retry();
    assert!(r.gpu.conns[USER].link.is_connected());
    let mut sink = sink_on(&listener);
    sink.hello(0xdef, 0, 0, false);
    pump(&mut r.gpu, |g| g.conns[USER].up());
    assert!(!r.gpu.conns[USER].refused);
    let _ = sink;
}

#[test]
fn a_switch_to_an_in_guest_renderer_that_cannot_do_the_spec_is_given_up() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let (up, cp) = (
        dir.as_path().join("u.sock"),
        dir.as_path().join("v.sock_5001"),
    );
    let ul = UnixListener::bind(&up).unwrap();
    let mem = single_region_mem(0x200000);
    let mut c = cfg(up.to_str().unwrap());
    c.guest_renderer_socket_path = Some(cp.to_str().unwrap().into());
    let mut r = rig_with(&mem, c);
    r.gpu.process_retry();
    let mut user = sink_on(&ul);
    user.hello(0x111, r.gpu.session, 0, false);
    pump2(&mut r.gpu, |g| g.conns[USER].up());
    r.give(ctx_create(1));
    assert_eq!(user.take(1), [(SP_CTRL, CMD_CTX_CREATE)]);
    // The user's renderer detaches; the in-guest renderer cannot do the spec: the switch is given
    // up, the user's renderer is let go, and the guest is served alone.
    let gs = guest_connects(&cp, &mut r.gpu);
    user.say(1, SP_DETACH, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.switch.is_some());
    r.gpu.process_retry();
    let mut cpu = sink_from(gs);
    cpu.hello_only(0x222, 0, 0, false);
    pump2(&mut r.gpu, |g| g.conns[GUEST].hello_done);
    assert_eq!(cpu.next_any().0.typ, SP_SPEC);
    cpu.spec_reply(
        false,
        " capset 2 min_aliased_point_size[0]: 1 here, profile 0 (fle);",
    );
    pump2(&mut r.gpu, |g| g.switch.is_none());
    assert!(r.gpu.conns[GUEST].refused && !r.gpu.conns[GUEST].wanted);
    assert!(!r.gpu.conns[GUEST].link.is_connected());
    assert_eq!(r.gpu.active, USER);
    assert_eq!(r.gpu.conns[USER].peer_session, 0);
    assert_eq!(user.take(1), [(SP_BYE, 0)]);
    drop(user);
    pump2(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    let a0 = guest_put(&r, 0, &submit(Some(5), 1, &[]));
    r.gpu.process_ack_timer();
    assert_eq!(answered(&r, a0), Some(RESP_OK_NODATA));
    // no takeover by an in-guest renderer that cannot do the spec
    r.gpu.conns[USER].lost_at -= TAKEOVER_US + 1;
    r.gpu.process_ack_timer();
    assert!(r.gpu.switch.is_none());
    assert!(!r.gpu.conns[GUEST].wanted);
}

/// A device with the in-guest renderer's socket at `<dir>/v.sock_5001`, and a user's renderer
/// paired that has run a context; returns the user's sink and the socket path.
fn with_user_and_guest_socket<'a>(
    mem: &'a GuestMemoryMmap,
    dir: &std::path::Path,
) -> (Rig<'a>, Sink, std::path::PathBuf, UnixListener) {
    let (up, cp) = (dir.join("u.sock"), dir.join("v.sock_5001"));
    let ul = UnixListener::bind(&up).unwrap();
    let mut c = cfg(up.to_str().unwrap());
    c.guest_renderer_socket_path = Some(cp.to_str().unwrap().into());
    let mut r = rig_with(mem, c);
    r.gpu.process_retry();
    let mut user = sink_on(&ul);
    user.hello(0x111, r.gpu.session, 0, false);
    pump2(&mut r.gpu, |g| g.conns[USER].up());
    r.give(ctx_create(1));
    assert_eq!(user.take(1), [(SP_CTRL, CMD_CTX_CREATE)]);
    (r, user, cp, ul)
}

#[test]
fn a_detach_with_no_in_guest_renderer_connected_ends_at_once() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let mem = single_region_mem(0x200000);
    let (mut r, mut user, _, _ul) = with_user_and_guest_socket(&mem, dir.as_path());
    // nothing to hand the state to: the renderer may go, and the guest is served alone
    user.say(1, SP_DETACH, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.conns[USER].peer_session == 0);
    assert_eq!(user.take(1), [(SP_BYE, 0)]);
    assert!(r.gpu.switch.is_none());
    assert_eq!(r.gpu.conns[USER].peer_session, 0);
    drop(user);
    pump2(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    let a0 = guest_put(&r, 0, &submit(Some(5), 1, &[]));
    r.gpu.process_ack_timer();
    assert_eq!(answered(&r, a0), Some(RESP_OK_NODATA));
}

#[test]
fn a_takeover_serves_the_guest_alone_until_the_in_guest_renderer_connects() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let mem = single_region_mem(0x200000);
    let (mut r, user, cp, _ul) = with_user_and_guest_socket(&mem, dir.as_path());
    drop(user);
    pump2(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    r.gpu.conns[USER].lost_at -= TAKEOVER_US + 1;
    r.gpu.process_ack_timer();
    // the takeover has begun, and no in-guest renderer is there: the guest does not wait
    assert_eq!(
        r.gpu.switch.as_ref().map(|s| (s.from, s.to)),
        Some((None, GUEST))
    );
    let a0 = guest_put(&r, 0, &submit(Some(5), 1, &[]));
    r.gpu.process_ack_timer();
    assert_eq!(answered(&r, a0), Some(RESP_OK_NODATA));
    // the in-guest renderer connects (a newer connection replaces a held one): it is paired at
    // once, built from the journal, and runs the guest
    let old = guest_connects(&cp, &mut r.gpu);
    let gs = guest_connects(&cp, &mut r.gpu);
    let mut old = sink_from_no_hello(old);
    r.gpu.process_retry();
    let mut g = sink_from(gs);
    g.hello(0x222, 0, 0, false);
    pump2(&mut r.gpu, |g| {
        g.switch.as_ref().is_some_and(|s| s.phase == Phase::Reset)
    });
    assert_eq!(g.take(1), [(SP_STATE_RESET, 0)]);
    g.say(1, SP_STATE_KEPT, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.switch.is_none());
    assert_eq!(r.gpu.active, GUEST);
    assert_eq!(
        g.take(2),
        [(SP_CTRL, CMD_CTX_CREATE), (SP_CTRL, CMD_SUBMIT_3D)]
    );
    // the older connection was closed with nothing sent
    assert!(old.closed());
}

#[test]
fn the_users_renderer_back_first_takes_the_guest_from_a_takeover_that_waits() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let mem = single_region_mem(0x200000);
    let (mut r, user, _cp, ul) = with_user_and_guest_socket(&mem, dir.as_path());
    drop(user);
    pump2(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    r.gpu.conns[USER].lost_at -= TAKEOVER_US + 1;
    r.gpu.process_ack_timer();
    assert!(r.gpu.switch.is_some());
    // the user's renderer starts again before any in-guest renderer has come
    r.gpu.process_retry();
    let mut user = sink_on(&ul);
    user.hello(0x333, 0, 0, false);
    pump2(&mut r.gpu, |g| {
        g.switch
            .as_ref()
            .is_some_and(|s| s.to == USER && s.phase == Phase::Reset)
    });
    assert!(!r.gpu.conns[GUEST].wanted);
    assert_eq!(user.take(1), [(SP_STATE_RESET, 0)]);
    user.say(1, SP_STATE_KEPT, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.switch.is_none());
    assert_eq!(r.gpu.active, USER);
    assert_eq!(user.take(1), [(SP_CTRL, CMD_CTX_CREATE)]);
}

#[test]
fn a_snapshot_while_the_in_guest_renderer_runs_waits_for_nothing_and_it_resumes_after_the_restore()
{
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let mem = single_region_mem(0x200000);
    let (mut r, user, cp, _ul) = with_user_and_guest_socket(&mem, dir.as_path());
    // the in-guest renderer runs the guest (a planned switch)
    let gs = guest_connects(&cp, &mut r.gpu);
    let mut user = user;
    user.say(1, SP_DETACH, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.switch.is_some());
    r.gpu.process_retry();
    let mut g = sink_from(gs);
    g.hello(0x222, 0, 0, false);
    pump2(&mut r.gpu, |g| {
        g.switch.as_ref().is_some_and(|s| s.phase == Phase::Reset)
    });
    assert_eq!(g.take(1), [(SP_STATE_RESET, 0)]);
    g.say(1, SP_STATE_KEPT, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.switch.is_none());
    assert_eq!(r.gpu.active, GUEST);
    assert_eq!(g.take(1), [(SP_CTRL, CMD_CTX_CREATE)]);
    assert_eq!(user.take(1), [(SP_BYE, 0)]);
    // a fenced command that the renderer has not answered
    r.gpu.fence_window = 0;
    r.give(submit(Some(7), 1, &[]));
    let (m, _) = g.next();
    assert_eq!((m.typ, r.gpu.pending.len()), (SP_CTRL, 1));
    // the snapshot does not wait for it (its state is in the guest's memory) and exports nothing
    let t = Instant::now();
    r.gpu.prepare_save();
    assert!(t.elapsed() < Duration::from_millis(200));
    assert!(!r.gpu.conns[GUEST].link.is_connected());
    let st = through_a_snapshot(&r.gpu);
    let side = st.side.as_ref().unwrap();
    assert_eq!(side.pending.len(), 1);
    assert!(side.scanout_saved.is_empty() && side.scanout_missing.is_empty());
    assert_eq!(st.active, GUEST);
    // a checkpoint and the stop of a move record nothing as missing either
    r.gpu.kick();
    r.gpu.prepare_checkpoint();
    let ck = through_a_snapshot(&r.gpu);
    assert!(ck.side.as_ref().unwrap().scanout_missing.is_empty());
    drop(r);
    drop(g);

    // Restored: the in-guest renderer, restored with the guest's memory of the same instant,
    // connects again and resumes; the command it had not answered comes again with its id.
    let mut d = restored(&mem, &st);
    let gs = guest_connects(&cp, &mut d);
    d.process_retry();
    let mut g = sink_from(gs);
    let h = g.last_hello.unwrap();
    assert_eq!((h.arg1, h.flags & SP_F_RESTORED), (0x222, SP_F_RESTORED));
    g.hello(0x222, st.session, m.id - 1, false);
    pump2(&mut d, |d| d.conns[GUEST].up());
    assert!(d.switch.is_none());
    assert_eq!(d.counters.n_reconnect, 1);
    // what it had not acknowledged comes again with the same ids (a sink drops the ids it has), the command it had
    // not received among them
    let mut ids = Vec::new();
    let (m2, a) = loop {
        let (x, a) = g.next();
        if x.id >= m.id {
            break (x, a);
        }
        ids.push(x.id);
    };
    assert!(
        ids.iter().enumerate().all(|(i, id)| *id == i as u64 + 1),
        "{ids:?}"
    );
    assert_eq!(
        (m2.typ, m2.id, u32_at(&a, 0)),
        (SP_CTRL, m.id, CMD_SUBMIT_3D)
    );
}

/// The in-guest renderer runs the guest (a takeover from the journal); returns its sink.
fn guest_runs_it(r: &mut Rig<'_>, cp: &std::path::Path) -> Sink {
    r.gpu.conns[USER].lost_at -= TAKEOVER_US + 1;
    r.gpu.process_ack_timer();
    let gs = guest_connects(cp, &mut r.gpu);
    r.gpu.process_retry();
    let mut g = sink_from(gs);
    g.hello(0x222, 0, 0, false);
    pump2(&mut r.gpu, |g| {
        g.switch.as_ref().is_some_and(|s| s.phase == Phase::Reset)
    });
    assert_eq!(g.take(1), [(SP_STATE_RESET, 0)]);
    g.say(1, SP_STATE_KEPT, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.switch.is_none());
    assert_eq!(r.gpu.active, GUEST);
    g
}

#[test]
fn a_lost_in_guest_renderer_that_runs_the_guest_is_let_go_after_5_s() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let mem = single_region_mem(0x200000);
    let (mut r, user, cp, _ul) = with_user_and_guest_socket(&mem, dir.as_path());
    drop(user);
    pump2(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    let g = guest_runs_it(&mut r, &cp);
    // it goes (the guest's shutdown stops it): the guest's commands wait for it a while
    drop(g);
    pump2(&mut r.gpu, |g| !g.conns[GUEST].link.is_connected());
    let a0 = guest_put(&r, 0, &submit(Some(5), 1, &[]));
    r.gpu.process_ack_timer();
    assert_eq!(answered(&r, a0), None);
    // then it is let go: the device answers them, and the renderer starts empty when it comes back
    r.gpu.conns[GUEST].lost_at -= GUEST_LOST_WAIT_US + 1;
    r.gpu.process_ack_timer();
    assert_eq!(answered(&r, a0), Some(RESP_OK_NODATA));
    assert_eq!(r.gpu.conns[GUEST].peer_session, 0);
    // the user's renderer that comes now is built from the journal: nothing is asked of the lost one
    r.gpu.process_retry();
    let mut user = sink_on(&_ul);
    user.hello(0x333, 0, 0, false);
    pump2(&mut r.gpu, |g| {
        g.switch.as_ref().is_some_and(|s| s.phase == Phase::Reset)
    });
    assert_eq!(r.gpu.switch.as_ref().unwrap().from, None);
    assert_eq!(user.take(1), [(SP_STATE_RESET, 0)]);
    user.say(1, SP_STATE_KEPT, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.switch.is_none());
    assert_eq!(r.gpu.active, USER);
}

#[test]
fn the_wait_for_a_renderer_counts_from_the_resume() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let mem = single_region_mem(0x200000);
    let (mut r, user, _cp, _ul) = with_user_and_guest_socket(&mem, dir.as_path());
    drop(user);
    pump2(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    r.gpu.conns[USER].lost_at -= TAKEOVER_US + 1;
    // the VM resumes (after a restore, a pause): the 10 s count from now
    r.gpu.kick();
    r.gpu.process_ack_timer();
    assert!(r.gpu.switch.is_none());
}

#[test]
fn the_snapshot_keeps_the_spec_and_a_pairing_without_its_yes_starts_again() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    let (sink, _) = paired_with_a_drawn_texture(&mut r, &listener);
    r.gpu.prepare_checkpoint();
    let st = through_a_snapshot(&r.gpu);
    assert_eq!(st.spec, spec_text().into_bytes());
    assert_ne!(st.conns[USER].peer_session, 0);
    // the restored device has the snapshot's spec (its spec_path is not read again), and its
    // pairing had the renderer's yes
    let g = restored(&mem, &st);
    assert_eq!(g.spec, test_spec());
    assert!(g.conns[USER].spec_ok);
    // a state whose spec is not well formed is refused
    let mut bad = st.clone();
    bad.spec = b"not a spec".to_vec();
    Gpu::restore(
        GpuConstructorArgs {
            mem: mem.clone(),
            filter: Arc::new(Vec::new()),
        },
        &bad,
    )
    .unwrap_err();
    // a pairing that waits for the renderer's answer is in the state as no pairing
    drop(sink);
    pump(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    r.gpu.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello_only(0x999, r.gpu.session, 0, false);
    pump(&mut r.gpu, |g| g.conns[USER].hello_done);
    assert!(!r.gpu.conns[USER].spec_ok);
    r.gpu.prepare_checkpoint();
    let st = through_a_snapshot(&r.gpu);
    assert_eq!(st.conns[USER].peer_session, 0);
    let g = restored(&mem, &st);
    assert!(!g.conns[USER].spec_ok);
    let _ = sink.next_any();
}

#[test]
fn a_renderer_that_pairs_after_a_long_loss_gets_its_reset_with_a_new_id() {
    // G4's F4: the user's renderer lost for longer than the wait, with no in-guest renderer, and
    // a renderer that refused the spec meanwhile; then one that can do it. The device let the new
    // pairing go while it waited for the yes, served the guest alone onto its open link (the
    // renderer dropped those messages but counted their ids), forgot the queue, and sent the
    // reset with an id that the renderer had had: the switch waited for ever.
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let path = dir.as_path().join("gpu.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mem = single_region_mem(0x200000);
    let mut r = rig_with(&mem, cfg(path.to_str().unwrap()));
    let (sink, _) = paired_with_a_drawn_texture(&mut r, &listener);
    drop(sink);
    pump(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    r.gpu.conns[USER].lost_at -= LOST_WAIT_US + 1;
    r.gpu.process_ack_timer();
    assert_eq!(r.gpu.conns[USER].peer_session, 0);
    // a renderer that cannot do the spec
    r.gpu.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello_only(0xbad, 0, 0, false);
    pump(&mut r.gpu, |g| g.conns[USER].hello_done);
    assert_eq!(sink.next_any().0.typ, SP_SPEC);
    sink.spec_reply(false, " capset 1 max_tbo_size[0]: 1 here, profile 2 (ge);");
    pump(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    // one that can: the guest's command comes while it answers the spec
    r.gpu.conns[USER].refused_at -= SPEC_RETRY_US + 1;
    r.gpu.process_retry();
    let mut sink = sink_on(&listener);
    sink.hello_only(0xdef, 0, 0, false);
    pump(&mut r.gpu, |g| g.conns[USER].hello_done);
    assert_eq!(sink.next_any().0.typ, SP_SPEC);
    let a0 = guest_put(&r, 0, &submit(Some(5), 1, &[]));
    r.gpu.process_ack_timer();
    r.gpu.process_ctrl_queue().unwrap();
    // the pairing under way is not let go, and nothing is queued for it
    assert_eq!(r.gpu.conns[USER].peer_session, 0xdef);
    assert_eq!(r.gpu.conns[USER].link.lock().q.tx_id, 0);
    sink.spec_reply(true, "");
    pump(&mut r.gpu, |g| {
        g.switch.as_ref().is_some_and(|s| s.phase == Phase::Reset)
    });
    // the reset is the first message after the spec, with the pairing's first id
    let (m, _) = sink.next();
    assert_eq!((m.typ, m.id, m.arg0), (SP_STATE_RESET, 1, 0));
    sink.say(1, SP_STATE_KEPT, &[], &[], 0);
    pump(&mut r.gpu, |g| g.switch.is_none());
    // the state from the journal, then the guest's command, every id one more than the last
    let mut ids = vec![m.id];
    let mut types = Vec::new();
    loop {
        let (h, a) = sink.next();
        if h.id != 0 {
            ids.push(h.id);
        }
        types.push((h.typ, u32_at(&a, 0)));
        if (h.typ, u32_at(&a, 0)) == (SP_CTRL, CMD_SUBMIT_3D) && h.seq != 0 {
            break;
        }
    }
    assert!(ids.windows(2).all(|w| w[1] == w[0] + 1), "{ids:?}");
    assert!(types.contains(&(SP_CTRL, CMD_CTX_CREATE)));
    assert_eq!(answered(&r, a0), Some(RESP_OK_NODATA));
}

#[test]
fn a_users_renderer_back_during_a_takeover_that_waits_gets_nothing_before_its_yes() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let mem = single_region_mem(0x200000);
    let (mut r, user, _cp, ul) = with_user_and_guest_socket(&mem, dir.as_path());
    drop(user);
    pump2(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    r.gpu.conns[USER].lost_at -= TAKEOVER_US + 1;
    r.gpu.process_ack_timer();
    assert!(r.gpu.switch.is_some());
    // the user's renderer starts again; while it answers the spec the guest is served alone
    r.gpu.process_retry();
    let mut user = sink_on(&ul);
    user.hello_only(0x333, 0, 0, false);
    pump2(&mut r.gpu, |g| g.conns[USER].hello_done);
    assert_eq!(user.next_any().0.typ, SP_SPEC);
    // a command taken, and time for the link's writer to send what was queued, before the run of
    // the control queue ends (where the device forgets what it queued for a renderer not there)
    r.give(submit(None, 1, &[]));
    std::thread::sleep(Duration::from_millis(20));
    let a0 = guest_put(&r, 0, &submit(Some(5), 1, &[]));
    r.gpu.process_ack_timer();
    assert_eq!(answered(&r, a0), Some(RESP_OK_NODATA));
    assert_eq!(r.gpu.conns[USER].link.lock().q.tx_id, 0);
    user.spec_reply(true, "");
    pump2(&mut r.gpu, |g| {
        g.switch
            .as_ref()
            .is_some_and(|s| s.to == USER && s.phase == Phase::Reset)
    });
    let (m, _) = user.next();
    assert_eq!((m.typ, m.id), (SP_STATE_RESET, 1));
    user.say(1, SP_STATE_KEPT, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.switch.is_none());
    assert_eq!(r.gpu.active, USER);
    assert_eq!(
        user.take(2),
        [(SP_CTRL, CMD_CTX_CREATE), (SP_CTRL, CMD_SUBMIT_3D)]
    );
}

#[test]
fn the_commands_answered_with_no_renderer_are_logged_at_most_once_a_second() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let log = dir.as_path().join("stats.log");
    let mem = single_region_mem(0x200000);
    let mut c = cfg(dir.as_path().join("gpu.sock").to_str().unwrap());
    c.stats_path = Some(log.to_str().unwrap().into());
    let mut r = rig_with(&mem, c);
    r.gpu.made_at -= FIRST_WAIT_US + 1;
    let lines = || {
        std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .filter(|l| l.contains("were answered here"))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    // the first one at once; three more within the second: no line, counted
    for i in 0..4 {
        guest_put(&r, i, &submit(Some(u64::from(i) + 1), 1, &[]));
        r.gpu.process_ack_timer();
    }
    assert_eq!(
        lines(),
        ["spacebox remote gpu: 1 commands of the lost renderer were answered here"]
    );
    // a second later, the count of those
    r.gpu.answered_lost_said -= 1_000_000;
    r.gpu.process_ack_timer();
    assert_eq!(
        lines()[1],
        "spacebox remote gpu: 3 commands of the lost renderer were answered here"
    );
    assert_eq!(lines().len(), 2);
}

/// The next message from `sink` of type `typ`; the ones before it are returned too.
fn until(sink: &mut Sink, typ: u32) -> (Hdr, Vec<u8>, Vec<(u32, u32)>) {
    let mut before = Vec::new();
    loop {
        let (h, a) = sink.next();
        if h.typ == typ {
            return (h, a, before);
        }
        before.push((h.typ, u32_at(&a, 0)));
    }
}

/// `struct virtio_gpu_update_cursor` of resource `res` (0x0300) or a move (0x0301).
fn cursor_req(typ: u32, res: u32) -> Vec<u8> {
    let mut r = hdr(typ, None, 0);
    for x in [0, 10, 20, 0, res, 1, 1, 0] {
        put32(&mut r, x);
    }
    r
}

/// The user's renderer runs the guest; the in-guest renderer has connected. The user turns the
/// GPU off: the planned switch to the in-guest renderer, the user's link kept; returns the
/// in-guest renderer's sink, which has been asked for pictures.
fn toggled_off(r: &mut Rig<'_>, user: &mut Sink, cp: &std::path::Path, id: u64) -> Sink {
    let gs = guest_connects(cp, &mut r.gpu);
    r.gpu.process_retry();
    user.say(id, SP_GPU, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.switch.is_some());
    assert_eq!(r.gpu.switch.as_ref().unwrap().from, Some(USER));
    r.gpu.process_retry();
    let mut g = sink_from(gs);
    g.hello(0x222, 0, 0, false);
    pump2(&mut r.gpu, |g| {
        g.switch.as_ref().is_some_and(|s| s.phase == Phase::Reset)
    });
    assert_eq!(g.take(1), [(SP_STATE_RESET, 0)]);
    g.say(1, SP_STATE_KEPT, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.switch.is_none());
    assert_eq!(r.gpu.active, GUEST);
    // the in-guest renderer is built from the journal, then asked for pictures
    let (h, _, rebuilt) = until(&mut g, SP_STREAM);
    assert!(rebuilt.contains(&(SP_CTRL, CMD_CTX_CREATE)));
    assert_eq!(h.arg0, 1);
    assert!(r.gpu.stream_on);
    g
}

#[test]
fn the_users_toggle_switches_to_the_in_guest_renderer_and_back_with_the_users_link_kept() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let mem = single_region_mem(0x200000);
    let (mut r, mut user, cp, _ul) = with_user_and_guest_socket(&mem, dir.as_path());
    // a cursor's resource: 64 x 64 of 4 bytes, its pixels in guest memory
    r.resource(9, 2, 1, 0, 64, 64, BACKING_AT);
    mem.write_slice(&[0x5a; 16384], GuestAddress(BACKING_AT))
        .unwrap();
    assert_eq!(
        user.take(2),
        [
            (SP_CTRL, CMD_RESOURCE_CREATE_3D),
            (SP_CTRL, CMD_RESOURCE_ATTACH_BACKING)
        ]
    );
    let mut g = toggled_off(&mut r, &mut user, &cp, 1);
    // the user's link stays up, and its renderer is told that the toggle is off
    assert!(r.gpu.conns[USER].up() && r.gpu.gpu_off);
    let (h, _, _) = until(&mut user, SP_GPU_STATE);
    assert_eq!((h.arg0, h.arg1), (0, 0));
    // the guest's commands go to the in-guest renderer
    r.give(hdr(CMD_RESOURCE_FLUSH, None, 0));
    assert_eq!(g.take(1), [(SP_CTRL, CMD_RESOURCE_FLUSH)]);
    // its pictures go to the user's renderer as they are
    let jpg = [0xff, 0xd8, 0x11, 0x22, 0xff, 0xd9];
    g.say_args(0, SP_PICTURE, &jpg, &[], [2560, 1600, 7]);
    pump2(&mut r.gpu, |g| g.counters.n_picture == 1);
    let (h, a) = user.next();
    assert_eq!((h.typ, h.id, a.as_slice()), (SP_PICTURE, 0, &jpg[..]));
    assert_eq!((h.arg0, h.arg1, h.arg2), (2560, 1600, 7));
    // the sound goes to the user's renderer, and a new cursor with its pixels
    r.gpu.send_audio(48000, 2, &[1; 64], 0);
    assert_eq!(user.next().0.typ, SP_AUDIO);
    let px = r.gpu.cursor_pixels(&mem, &cursor_req(CMD_UPDATE_CURSOR, 9));
    assert_eq!(px, vec![0x5a; 16384]);
    assert!(r.gpu.cursor_pixels(&mem, &cursor_req(0x0301, 9)).is_empty());
    assert!(
        r.gpu
            .cursor_pixels(&mem, &cursor_req(CMD_UPDATE_CURSOR, 1))
            .is_empty()
    );

    // On: the pictures stop, and the planned switch back makes the user's renderer a new attach
    user.say(2, SP_GPU, &[], &[], 1);
    pump2(&mut r.gpu, |g| {
        g.switch
            .as_ref()
            .is_some_and(|s| s.to == USER && s.phase == Phase::Reset)
    });
    assert_eq!(r.gpu.switch.as_ref().unwrap().from, Some(GUEST));
    let (h, _, _) = until(&mut g, SP_STREAM);
    assert_eq!(h.arg0, 0);
    let (h, _, _) = until(&mut user, SP_STATE_RESET);
    assert_eq!(h.arg0, 0);
    user.say(3, SP_STATE_KEPT, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.switch.is_none());
    assert_eq!(r.gpu.active, USER);
    assert!(!r.gpu.gpu_off);
    assert!(!r.gpu.conns[GUEST].link.is_connected());
    let (h, _, rebuilt) = until(&mut user, SP_GPU_STATE);
    assert_eq!(h.arg0, 1);
    assert!(rebuilt.contains(&(SP_CTRL, CMD_CTX_CREATE)));
    // a picture that comes after the stream stopped is not passed on
    let late = export_hdr(0, SP_PICTURE, &jpg, &[], [2560, 1600, 8]);
    r.gpu.picture(&late, &jpg);
    assert_eq!(
        (r.gpu.counters.n_picture, r.gpu.counters.pictures_late),
        (1, 1)
    );
    drop(g);
}

#[test]
fn a_sudden_loss_with_the_toggle_off_stops_the_pictures_and_the_renderer_back_starts_on() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let mem = single_region_mem(0x200000);
    let (mut r, mut user, cp, ul) = with_user_and_guest_socket(&mem, dir.as_path());
    let mut g = toggled_off(&mut r, &mut user, &cp, 1);
    drop(user);
    pump2(&mut r.gpu, |g| !g.conns[USER].link.is_connected());
    // the in-guest renderer runs the guest on, with no pictures
    assert_eq!(r.gpu.active, GUEST);
    assert!(!r.gpu.gpu_off && !r.gpu.stream_on);
    let (h, _, _) = until(&mut g, SP_STREAM);
    assert_eq!(h.arg0, 0);
    assert_eq!(r.gpu.conns[USER].peer_session, 0);
    // the user's renderer that comes back is a new pairing: the planned switch to it
    r.gpu.process_retry();
    let mut user = sink_on(&ul);
    user.hello(0x333, 0, 0, false);
    pump2(&mut r.gpu, |g| {
        g.switch
            .as_ref()
            .is_some_and(|s| s.to == USER && s.phase == Phase::Reset)
    });
    assert_eq!(r.gpu.switch.as_ref().unwrap().from, Some(GUEST));
    assert_eq!(user.take(1), [(SP_STATE_RESET, 0)]);
    user.say(1, SP_STATE_KEPT, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.switch.is_none());
    assert_eq!(r.gpu.active, USER);
    // a renderer that has not used its toggle is told nothing of it
    assert_eq!(r.gpu.gpu_state_said, None);
}

#[test]
fn the_toggle_off_waits_5_s_for_the_in_guest_renderer_and_then_stays_on() {
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let mem = single_region_mem(0x200000);
    let (mut r, mut user, cp, _ul) = with_user_and_guest_socket(&mem, dir.as_path());
    // no in-guest renderer connected: the toggle waits for it
    user.say(1, SP_GPU, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.gpu_off);
    r.gpu.process_ack_timer();
    assert!(r.gpu.switch.is_none() && r.gpu.gpu_state_said.is_none());
    // it connects within the wait: the planned switch to it begins
    let _gs = guest_connects(&cp, &mut r.gpu);
    r.gpu.process_ack_timer();
    assert_eq!(
        r.gpu.switch.as_ref().map(|s| (s.from, s.to)),
        Some((Some(USER), GUEST))
    );

    // another device whose in-guest renderer does not come in 5 s: the toggle stays on
    let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
    let (mut r, mut user, _cp, _ul) = with_user_and_guest_socket(&mem, dir.as_path());
    user.say(1, SP_GPU, &[], &[], 0);
    pump2(&mut r.gpu, |g| g.gpu_off);
    r.gpu.gpu_off_at -= OFF_WAIT_US + 1;
    r.gpu.process_ack_timer();
    assert!(r.gpu.switch.is_none() && !r.gpu.gpu_off);
    assert_eq!(r.gpu.active, USER);
    let (h, _, _) = until(&mut user, SP_GPU_STATE);
    assert_eq!((h.arg0, h.arg1), (1, 1));
}
