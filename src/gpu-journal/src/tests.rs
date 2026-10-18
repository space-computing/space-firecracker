// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::cast_possible_truncation, clippy::vec_init_then_push)]

use super::*;

fn req(typ: u32, ctx: u32, body: &[u32]) -> Vec<u8> {
    let mut r = hdr(typ, ctx, HDR);
    r[4..8].copy_from_slice(&1u32.to_le_bytes()); // fenced: the rebuild must clear it
    r[8..16].copy_from_slice(&77u64.to_le_bytes());
    r.extend(body.iter().flat_map(|w| w.to_le_bytes()));
    r
}

fn submit(ctx: u32, cmds: &[Vec<u32>]) -> Vec<u8> {
    let words: Vec<u32> = cmds.iter().flatten().copied().collect();
    let mut body = vec![(words.len() * 4) as u32, 0];
    body.extend(words);
    req(CMD_SUBMIT_3D, ctx, &body)
}

fn c(cmd: u32, obj: u32, args: &[u32]) -> Vec<u32> {
    let mut v = vec![cmd_word(cmd, obj, args.len())];
    v.extend_from_slice(args);
    v
}

fn none(_: u32, _: u64, _: u64) -> Option<Vec<u8>> {
    None
}

/// A context 1 with a 64x64 RGBA texture 5 (backing 16384 bytes) attached.
fn base() -> Journal {
    let mut j = Journal::new();
    j.ctrl(&req(CMD_CTX_CREATE, 1, &[4, 0]), &[], &mut none);
    // id, target 2D, format R8G8B8A8_UNORM (67), bind render target | sampler view, 64x64
    j.ctrl(
        &req(
            CMD_RESOURCE_CREATE_3D,
            0,
            &[5, 2, 67, 0xa, 64, 64, 1, 1, 0, 0, 0, 0],
        ),
        &[],
        &mut none,
    );
    j.ctrl(
        &req(CMD_RESOURCE_ATTACH_BACKING, 0, &[5, 1, 0x1000, 0, 16384, 0]),
        &[],
        &mut none,
    );
    j.ctrl(&req(CMD_CTX_ATTACH_RESOURCE, 1, &[5, 0]), &[], &mut none);
    j
}

fn rebuilt(j: &Journal, kept: &BTreeSet<u32>) -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    j.rebuild(kept, &mut |m| match m {
        Msg::Ctrl(r) => v.push((format!("ctrl {:#x}", u32_at(&r, 0)), r)),
        Msg::Import(h, d) => {
            let mut b = h.to_vec();
            b.extend_from_slice(d);
            v.push(("import".into(), b));
        }
        Msg::Cursor(c) => v.push(("cursor".into(), c.to_vec())),
    });
    v
}

/// The command words of the rebuilt submits of a context.
fn rebuilt_words(j: &Journal) -> Vec<u32> {
    rebuilt(j, &BTreeSet::new())
        .into_iter()
        .filter(|(k, _)| k == "ctrl 0x207")
        .flat_map(|(_, r)| {
            r[32..]
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn rebuild_order_and_no_fences() {
    let mut j = base();
    j.ctrl(
        &req(CMD_SET_SCANOUT, 0, &[0, 0, 64, 64, 0, 5]),
        &[],
        &mut none,
    );
    j.ctrl(
        &req(CMD_RESOURCE_FLUSH, 0, &[0, 0, 64, 64, 5, 0]),
        &[],
        &mut none,
    );
    let mut cur = req(CMD_UPDATE_CURSOR, 0, &[0, 10, 20, 0, 5, 1, 1, 0]);
    j.cursor(&cur);
    cur[0..4].copy_from_slice(&CMD_MOVE_CURSOR.to_le_bytes());
    cur[28..32].copy_from_slice(&30u32.to_le_bytes());
    j.cursor(&cur);
    let m = rebuilt(&j, &BTreeSet::new());
    let kinds: Vec<&str> = m.iter().map(|x| x.0.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "ctrl 0x200",
            "ctrl 0x204",
            "ctrl 0x106",
            "ctrl 0x202",
            "ctrl 0x207",
            "ctrl 0x103",
            "ctrl 0x104",
            "cursor"
        ]
    );
    for (k, r) in &m {
        if k.starts_with("ctrl") {
            assert_eq!(u32_at(r, 4), 0, "{k} keeps a fence flag");
            assert_eq!(u64_at(r, 8), 0);
        }
    }
    // the cursor moved after its update
    assert_eq!(u32_at(&m[7].1, 28), 30);
    assert_eq!(u32_at(&m[7].1, 0), CMD_UPDATE_CURSOR);
    // a kept resource is not made again, but still attached
    let kept: BTreeSet<u32> = [5].into();
    let kinds: Vec<String> = rebuilt(&j, &kept).into_iter().map(|x| x.0).collect();
    assert_eq!(kinds[..3], ["ctrl 0x200", "ctrl 0x202", "ctrl 0x207"]);
}

#[test]
fn uploads_kept_and_covered() {
    let mut j = base();
    let up = |j: &mut Journal, x: u32, w: u32, h: u32, v: u8| {
        let data = vec![v; ((h - 1) * 256 + w * 4) as usize];
        // box x, 0, 0, w, h, 1; offset; res 5, level 0, stride 256, layer 0
        j.ctrl(
            &req(
                CMD_TRANSFER_TO_HOST_3D,
                1,
                &[x, 0, 0, w, h, 1, x * 4, 0, 5, 0, 256, 0],
            ),
            &data,
            &mut none,
        );
    };
    up(&mut j, 8, 4, 2, 1);
    up(&mut j, 0, 16, 2, 2); // covers the first
    up(&mut j, 32, 8, 2, 3);
    assert_eq!(j.uploads_of(5).len(), 2);
    assert_eq!(j.stats().upload_bytes, 256 + 64 + 256 + 32);
    // uploads that add up to more than the level become one upload of the level
    up(&mut j, 1, 40, 60, 4);
    up(&mut j, 2, 40, 61, 5);
    let u = j.uploads_of(5);
    assert_eq!(u.len(), 1);
    assert_eq!(u[0].1.len(), 64 * 64 * 4);
    let at = |x: usize, y: usize| u[0].1[y * 256 + x * 4];
    assert_eq!(at(0, 0), 2);
    assert_eq!(at(1, 0), 4);
    assert_eq!(at(2, 60), 5);
    assert_eq!(at(1, 60), 0); // never uploaded there
    assert_eq!(at(41, 59), 5);
    assert_eq!(at(42, 0), 0); // the third upload (32..40) is covered by the later ones
    assert_eq!(at(45, 0), 0);
    assert_eq!(j.stats().upload_bytes, 64 * 64 * 4);
    // an unref drops the uploads
    j.ctrl(&req(CMD_RESOURCE_UNREF, 0, &[5, 0]), &[], &mut none);
    assert_eq!(j.stats().upload_bytes, 0);
}

#[test]
fn blobs_split_and_put_back() {
    let mut j = base();
    let up = |j: &mut Journal, x: u32, v: u8| {
        j.ctrl(
            &req(
                CMD_TRANSFER_TO_HOST_3D,
                1,
                &[x, 0, 0, 4, 1, 1, x * 4, 0, 5, 0, 256, 0],
            ),
            &[v; 16],
            &mut none,
        );
    };
    up(&mut j, 0, 1);
    up(&mut j, 8, 2);
    let blobs = j.blobs();
    assert_eq!(blobs.len(), 2);
    assert_eq!(j.blob_count(), 2);
    // a copy shares the bytes: the same allocation, not a copy
    let copy = j.clone();
    assert!(Arc::ptr_eq(&copy.blobs()[0], &blobs[0]));
    // the structure holds no bytes; put back, it rebuilds the same as the journal
    let mut bare = j.without_blobs();
    assert!(bare.blobs().iter().all(|b| b.is_empty()));
    let bytes = bitcode_free_len(&bare);
    assert!(bytes < 16);
    let mut it = blobs.clone().into_iter();
    bare.put_blobs(&mut it).unwrap();
    assert!(it.next().is_none());
    let all = BTreeSet::new();
    assert_eq!(rebuilt(&bare, &all), rebuilt(&j, &all));
    // fewer bytes than uploads
    let mut short = j.without_blobs();
    short
        .put_blobs(&mut blobs[..1].iter().cloned())
        .unwrap_err();
    // a later upload is new bytes; the one it does not cover keeps its allocation
    up(&mut j, 16, 3);
    let after = j.blobs();
    assert_eq!(after.len(), 3);
    assert!(Arc::ptr_eq(&after[0], &blobs[0]));
    assert!(Arc::ptr_eq(&after[1], &blobs[1]));
}

/// The bytes of the uploads that a journal holds.
fn bitcode_free_len(j: &Journal) -> usize {
    j.blobs().iter().map(|b| b.len()).sum()
}

#[test]
fn in_stream_uploads() {
    let mut j = base();
    // a staging buffer 6 with backing
    j.ctrl(
        &req(
            CMD_RESOURCE_CREATE_3D,
            0,
            &[6, 0, 64, 0x8000, 4096, 1, 1, 1, 0, 0, 0, 0],
        ),
        &[],
        &mut none,
    );
    j.ctrl(
        &req(CMD_RESOURCE_ATTACH_BACKING, 0, &[6, 1, 0x9000, 0, 4096, 0]),
        &[],
        &mut none,
    );
    let mut asked = Vec::new();
    let mut fetch = |res: u32, off: u64, len: u64| {
        asked.push((res, off, len));
        Some(vec![7u8; len as usize])
    };
    // COPY_TRANSFER3D: texture 5 level 0, box 0,0,0 4x4x1 from staging 6 at 128, stride 16
    let ct = c(
        C_COPY_TRANSFER3D,
        0,
        &[5, 0, 0, 16, 0, 0, 0, 0, 4, 4, 1, 6, 128, 0],
    );
    // RESOURCE_INLINE_WRITE into 5, box 8,8 1x1: one pixel
    let iw = c(
        C_RESOURCE_INLINE_WRITE,
        0,
        &[5, 0, 0, 0, 0, 8, 8, 0, 1, 1, 1, 0xaabbccdd],
    );
    let marks = j.ctrl(&submit(1, &[ct, iw]), &[], &mut fetch);
    assert_eq!(asked, [(6, 128, 3 * 16 + 16)]);
    assert_eq!(marks, [5]);
    let u = j.uploads_of(5);
    assert_eq!(u.len(), 2);
    assert_eq!(u[1].1, [0xdd, 0xcc, 0xbb, 0xaa]);
    // an upload is not a GPU write
    assert!(j.gpu_written().is_empty());
}

#[test]
fn bound_state_compaction() {
    let mut j = base();
    let mut cmds = Vec::new();
    // blend states 10 and 11; 10 bound, then destroyed while bound; handle 10 used again for
    // another blend state, which is not bound
    cmds.push(c(C_CREATE_OBJECT, 1, &[10, 0, 0, 0xaaaa]));
    cmds.push(c(C_CREATE_OBJECT, 1, &[11, 0, 0, 0xbbbb]));
    cmds.push(c(C_BIND_OBJECT, 1, &[10]));
    cmds.push(c(C_DESTROY_OBJECT, 1, &[10]));
    cmds.push(c(C_CREATE_OBJECT, 1, &[10, 0, 0, 0xcccc]));
    // viewports set again and again: only the last stays
    for k in 0..300 {
        cmds.push(c(C_SET_VIEWPORT_STATE, 0, &[0, k, 0, 0, 0, 0, 0]));
    }
    // 11 destroyed while not bound: it goes
    cmds.push(c(C_DESTROY_OBJECT, 1, &[11]));
    for k in 0..300 {
        cmds.push(c(C_SET_VIEWPORT_STATE, 0, &[0, 1000 + k, 0, 0, 0, 0, 0]));
    }
    j.ctrl(&submit(1, &cmds), &[], &mut none);
    let w = rebuilt_words(&j);
    let expect: Vec<u32> = [
        c(C_SET_SUB_CTX, 0, &[0]),
        c(C_CREATE_OBJECT, 1, &[10, 0, 0, 0xaaaa]),
        c(C_BIND_OBJECT, 1, &[10]),
        c(C_DESTROY_OBJECT, 1, &[10]),
        c(C_CREATE_OBJECT, 1, &[10, 0, 0, 0xcccc]),
        c(C_SET_VIEWPORT_STATE, 0, &[0, 1299, 0, 0, 0, 0, 0]),
        c(C_SET_SUB_CTX, 0, &[0]),
    ]
    .concat();
    assert_eq!(w, expect);
    // once another blend state is bound, the destroyed one is not needed any more
    let mut more = vec![c(C_BIND_OBJECT, 1, &[10])];
    for k in 0..600 {
        more.push(c(C_SET_SCISSOR_STATE, 0, &[0, k, k]));
    }
    j.ctrl(&submit(1, &more), &[], &mut none);
    let w = rebuilt_words(&j);
    let expect: Vec<u32> = [
        c(C_SET_SUB_CTX, 0, &[0]),
        c(C_CREATE_OBJECT, 1, &[10, 0, 0, 0xcccc]),
        c(C_SET_VIEWPORT_STATE, 0, &[0, 1299, 0, 0, 0, 0, 0]),
        c(C_BIND_OBJECT, 1, &[10]),
        c(C_SET_SCISSOR_STATE, 0, &[0, 599, 599]),
        c(C_SET_SUB_CTX, 0, &[0]),
    ]
    .concat();
    assert_eq!(w, expect);
}

#[test]
fn slots_of_a_command() {
    let mut j = base();
    let mut cmds = vec![
        // sampler views of the fragment stage (1), slots 0..3, then slot 1 alone
        c(C_CREATE_OBJECT, O_SAMPLER_VIEW, &[20, 5, 67, 0, 0, 0]),
        c(C_SET_SAMPLER_VIEWS, 0, &[1, 0, 20, 20, 20]),
        c(C_SET_SAMPLER_VIEWS, 0, &[1, 1, 20]),
        // the same slots of the vertex stage do not cover the fragment stage's
        c(C_SET_SAMPLER_VIEWS, 0, &[0, 0, 20, 20, 20]),
    ];
    for k in 0..300 {
        cmds.push(c(C_SET_STENCIL_REF, 0, &[k]));
    }
    j.ctrl(&submit(1, &cmds), &[], &mut none);
    let w = rebuilt_words(&j);
    let expect: Vec<u32> = [
        c(C_SET_SUB_CTX, 0, &[0]),
        c(C_CREATE_OBJECT, O_SAMPLER_VIEW, &[20, 5, 67, 0, 0, 0]),
        c(C_SET_SAMPLER_VIEWS, 0, &[1, 0, 20, 20, 20]),
        c(C_SET_SAMPLER_VIEWS, 0, &[1, 1, 20]),
        c(C_SET_SAMPLER_VIEWS, 0, &[0, 0, 20, 20, 20]),
        c(C_SET_STENCIL_REF, 0, &[299]),
        c(C_SET_SUB_CTX, 0, &[0]),
    ]
    .concat();
    assert_eq!(w, expect);
}

#[test]
fn sub_contexts_and_long_shaders() {
    let mut j = base();
    let cmds = vec![
        c(C_CREATE_SUB_CTX, 0, &[3]),
        c(C_SET_SUB_CTX, 0, &[3]),
        // a shader in two parts
        c(C_CREATE_OBJECT, O_SHADER, &[30, 1, 100, 8, 0, 0x1111]),
        c(C_CREATE_OBJECT, O_SHADER, &[30, 1, SHADER_CONT | 4, 0x2222]),
        c(C_BIND_SHADER, 0, &[30, 1]),
        c(C_SET_SUB_CTX, 0, &[0]),
        c(C_SET_STENCIL_REF, 0, &[9]),
        c(C_SET_SUB_CTX, 0, &[3]),
    ];
    j.ctrl(&submit(1, &cmds), &[], &mut none);
    let w = rebuilt_words(&j);
    let expect: Vec<u32> = [
        c(C_SET_SUB_CTX, 0, &[0]),
        c(C_SET_STENCIL_REF, 0, &[9]),
        c(C_CREATE_SUB_CTX, 0, &[3]),
        c(C_SET_SUB_CTX, 0, &[3]),
        c(C_CREATE_OBJECT, O_SHADER, &[30, 1, 100, 8, 0, 0x1111]),
        c(C_CREATE_OBJECT, O_SHADER, &[30, 1, SHADER_CONT | 4, 0x2222]),
        c(C_BIND_SHADER, 0, &[30, 1]),
        c(C_SET_SUB_CTX, 0, &[3]),
    ]
    .concat();
    assert_eq!(w, expect);
    // a destroyed sub-context leaves nothing
    j.ctrl(&submit(1, &[c(C_DESTROY_SUB_CTX, 0, &[3])]), &[], &mut none);
    let w = rebuilt_words(&j);
    let expect: Vec<u32> = [
        c(C_SET_SUB_CTX, 0, &[0]),
        c(C_SET_STENCIL_REF, 0, &[9]),
        c(C_SET_SUB_CTX, 0, &[0]),
    ]
    .concat();
    assert_eq!(w, expect);
}

#[test]
fn write_marks_and_gone_resources() {
    let mut j = base();
    // a vertex buffer 7, and the texture 5 as the color buffer
    j.ctrl(
        &req(
            CMD_RESOURCE_CREATE_3D,
            0,
            &[7, 0, 64, 0x10, 1024, 1, 1, 1, 0, 0, 0, 0],
        ),
        &[],
        &mut none,
    );
    j.ctrl(&req(CMD_CTX_ATTACH_RESOURCE, 1, &[7, 0]), &[], &mut none);
    let cmds = vec![
        c(C_CREATE_OBJECT, O_SURFACE, &[40, 5, 67, 0, 0]),
        c(C_SET_FRAMEBUFFER_STATE, 0, &[1, 0, 40]),
        c(C_SET_VERTEX_BUFFERS, 0, &[16, 0, 7]),
        c(C_DRAW_VBO, 0, &[0; 12]),
    ];
    let marks = j.ctrl(&submit(1, &cmds), &[], &mut none);
    assert_eq!(marks, [5]);
    assert_eq!(j.gpu_written(), [5]);
    assert!(j.stats().gpu_written_bytes >= 64 * 64 * 4);
    // the vertex buffer goes (the guest's later commands do not use it) and its id comes back
    // as another resource: the kept binding names nothing
    j.ctrl(&req(CMD_RESOURCE_UNREF, 0, &[7, 0]), &[], &mut none);
    j.ctrl(
        &req(
            CMD_RESOURCE_CREATE_3D,
            0,
            &[7, 0, 64, 0x10, 2048, 1, 1, 1, 0, 0, 0, 0],
        ),
        &[],
        &mut none,
    );
    let w = rebuilt_words(&j);
    let expect: Vec<u32> = [
        c(C_SET_SUB_CTX, 0, &[0]),
        c(C_CREATE_OBJECT, O_SURFACE, &[40, 5, 67, 0, 0]),
        c(C_SET_FRAMEBUFFER_STATE, 0, &[1, 0, 40]),
        c(C_SET_VERTEX_BUFFERS, 0, &[16, 0, 0]),
        c(C_SET_SUB_CTX, 0, &[0]),
    ]
    .concat();
    assert_eq!(w, expect);
    // the texture goes: its surface is not made again and the framebuffer names nothing
    j.ctrl(&req(CMD_RESOURCE_UNREF, 0, &[5, 0]), &[], &mut none);
    let w = rebuilt_words(&j);
    let expect: Vec<u32> = [
        c(C_SET_SUB_CTX, 0, &[0]),
        c(C_SET_FRAMEBUFFER_STATE, 0, &[1, 0, 0]),
        c(C_SET_VERTEX_BUFFERS, 0, &[16, 0, 0]),
        c(C_SET_SUB_CTX, 0, &[0]),
    ]
    .concat();
    assert_eq!(w, expect);
}

#[test]
fn detached_but_bound_is_attached_for_the_rebuild() {
    let mut j = base();
    let cmds = vec![
        c(C_CREATE_OBJECT, O_SAMPLER_VIEW, &[20, 5, 67, 0, 0, 0]),
        c(C_SET_SAMPLER_VIEWS, 0, &[1, 0, 20]),
    ];
    j.ctrl(&submit(1, &cmds), &[], &mut none);
    j.ctrl(&req(CMD_CTX_DETACH_RESOURCE, 1, &[5, 0]), &[], &mut none);
    let kinds: Vec<String> = rebuilt(&j, &BTreeSet::new())
        .into_iter()
        .map(|x| x.0)
        .collect();
    assert_eq!(
        kinds,
        [
            "ctrl 0x200",
            "ctrl 0x204",
            "ctrl 0x106",
            "ctrl 0x202",
            "ctrl 0x207",
            "ctrl 0x203"
        ]
    );
}

#[test]
fn transfer_range_matches_vrend() {
    // RGBA8 64x64, box 2,3 4x5 at stride 256: 4 rows of 256 and 16 bytes
    assert_eq!(
        transfer_range(67, 64, 64, 0, 256, 0, [2, 3, 0, 4, 5, 1], 100, 1 << 20),
        (100, 4 * 256 + 16)
    );
    // clipped to the backing; an unknown format takes everything from the offset
    assert_eq!(
        transfer_range(67, 64, 64, 0, 256, 0, [0, 0, 0, 64, 64, 1], 0, 1000),
        (0, 1000)
    );
    assert_eq!(
        transfer_range(0, 64, 64, 0, 0, 0, [0; 6], 10, 1000),
        (10, 990)
    );
}
