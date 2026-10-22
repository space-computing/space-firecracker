// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The GPU spec: what the guest is shown of the GPU (the two virgl capsets), the same whichever
//! renderer runs the guest's commands. The guest's kernel reads the capsets once, at its probe,
//! and Mesa keeps using what they offer; so the device answers them from the spec from the first
//! moment, with no renderer, and every renderer checks at its pairing that it can do all of it
//! (`SP_SPEC`, [`super::device`]). The spec comes from `spec_path` of the configuration and is
//! kept in the device's snapshot state.
//!
//! The file is text, in the format of `screen/tools/capset-profile.py` of the spacebox
//! repository (which makes it) and of the sink's check (`sp_profile_load` in
//! `hw/display/virtio-gpu-remote.c` of `space-qemu`):
//!
//! ```text
//! spacebox-capset-profile 1
//! capset ID VERSION SIZE HEX             the bytes of capset ID
//! check ID OFFSET COUNT RULE NAME [ARG]  how a renderer checks COUNT 4-byte values at OFFSET
//! ```
//!
//! and comment lines (`#`). The device reads the capsets only; it checks that the spec has
//! exactly the capsets it advertises, and that the check lines cover each 4-byte word of each
//! capset once, so that a renderer that passes the checks can do all of the spec.

use std::fmt::Write as _;

/// The first line of a spec.
const MAGIC: &str = "spacebox-capset-profile 1";
/// The largest spec file taken.
const MAX_LEN: usize = 1 << 20;
/// The rules of a check line (the sink knows each of them).
const RULES: [&str; 10] = [
    "bits", "ge", "le", "fge", "fle", "ige", "ile", "align", "video", "none",
];
/// The longest rule and name of a check line (the sink keeps them in `char[8]` and `char[48]`).
const MAX_RULE: usize = 7;
const MAX_NAME: usize = 47;

/// One capset of the spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Capset {
    pub(crate) id: u32,
    pub(crate) ver: u32,
    pub(crate) data: Vec<u8>,
}

/// A spec, as read from its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Spec {
    /// The file as it is: what is sent to a renderer and kept in a snapshot.
    text: Vec<u8>,
    capsets: Vec<Capset>,
    /// The first 16 hex digits of the file's SHA-256 (the sink logs the same).
    digest: String,
}

fn num(s: &str, what: &str, line: usize) -> Result<u32, String> {
    s.parse::<u32>()
        .map_err(|_| format!("line {line}: {what} {s:?} is not a number"))
}

impl Spec {
    /// The spec of a file's text; `ids`: the capsets it must have, exactly.
    pub(crate) fn parse(text: Vec<u8>, ids: &[u32]) -> Result<Spec, String> {
        if text.len() > MAX_LEN {
            return Err(format!("{} bytes, more than {MAX_LEN}", text.len()));
        }
        let s = std::str::from_utf8(&text).map_err(|_| "not text".to_string())?;
        let mut lines = s.split('\n').enumerate().map(|(i, l)| (i + 1, l));
        if lines.next().map(|l| l.1) != Some(MAGIC) {
            return Err(format!("the first line is not {MAGIC:?}"));
        }
        let mut capsets: Vec<Capset> = Vec::new();
        // (capset, offset, count, line) of each check line
        let mut checks: Vec<(u32, u32, u32, usize)> = Vec::new();
        // (capset, the offset of the count of video entries, line) of each video check
        let mut video: Vec<(u32, u32, usize)> = Vec::new();
        for (n, line) in lines {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let f: Vec<&str> = line.split(' ').collect();
            match (f[0], f.len()) {
                ("capset", 5) => {
                    let id = num(f[1], "the capset id", n)?;
                    let ver = num(f[2], "the version", n)?;
                    let size = num(f[3], "the size", n)? as usize;
                    if size == 0 || f[4].len() != 2 * size {
                        return Err(format!(
                            "line {n}: capset {id} has {} hex digits for {size} bytes",
                            f[4].len()
                        ));
                    }
                    if !f[4].bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(format!("line {n}: bad hex"));
                    }
                    let data = (0..size)
                        .map(|i| u8::from_str_radix(&f[4][2 * i..2 * i + 2], 16))
                        .collect::<Result<Vec<u8>, _>>()
                        .map_err(|_| format!("line {n}: bad hex"))?;
                    if capsets.iter().any(|c| c.id == id) {
                        return Err(format!("line {n}: capset {id} again"));
                    }
                    capsets.push(Capset { id, ver, data });
                }
                ("check", 6 | 7) => {
                    let id = num(f[1], "the capset id", n)?;
                    let off = num(f[2], "the offset", n)?;
                    let count = num(f[3], "the count", n)?;
                    let (rule, name) = (f[4], f[5]);
                    if !RULES.contains(&rule) || rule.len() > MAX_RULE {
                        return Err(format!("line {n}: unknown rule {rule:?}"));
                    }
                    if name.is_empty() || name.len() > MAX_NAME {
                        return Err(format!("line {n}: a name of {} bytes", name.len()));
                    }
                    if rule == "video" {
                        let Some(arg) = f.get(6) else {
                            return Err(format!(
                                "line {n}: a video check with no offset of its count"
                            ));
                        };
                        video.push((id, num(arg, "the offset", n)?, n));
                    }
                    checks.push((id, off, count, n));
                }
                _ => return Err(format!("line {n}: not understood")),
            }
        }
        let mut have: Vec<u32> = capsets.iter().map(|c| c.id).collect();
        have.sort_unstable();
        let mut want = ids.to_vec();
        want.sort_unstable();
        if have != want {
            return Err(format!("the capsets {have:?}, not {want:?}"));
        }
        for c in &capsets {
            if c.data.len() % 4 != 0 {
                return Err(format!(
                    "capset {} has {} bytes, not a multiple of 4",
                    c.id,
                    c.data.len()
                ));
            }
        }
        let index = |id: u32, n: usize| {
            capsets.iter().position(|c| c.id == id).ok_or_else(|| {
                format!("line {n}: a check of capset {id}, which the spec does not have")
            })
        };
        // each 4-byte word of each capset in exactly one check line
        let mut words: Vec<Vec<u32>> = capsets.iter().map(|c| vec![0; c.data.len() / 4]).collect();
        for &(id, off, count, n) in &checks {
            let i = index(id, n)?;
            if off % 4 != 0 || u64::from(off) + 4 * u64::from(count) > capsets[i].data.len() as u64
            {
                return Err(format!("line {n}: a check outside capset {id}"));
            }
            for w in (off / 4)..(off / 4 + count) {
                words[i][w as usize] += 1;
            }
        }
        // the count of the video entries has a check line of its own
        for &(id, off, n) in &video {
            if u64::from(off) + 4 > capsets[index(id, n)?].data.len() as u64 {
                return Err(format!(
                    "line {n}: the count of the video entries is outside capset {id}"
                ));
            }
        }
        for (c, w) in capsets.iter().zip(&words) {
            if let Some(at) = w.iter().position(|&k| k != 1) {
                return Err(format!(
                    "capset {}: the word at byte {} is in {} check lines, not 1",
                    c.id,
                    at * 4,
                    w[at]
                ));
            }
        }
        let sum = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &text);
        let mut digest = String::new();
        for b in &sum.as_ref()[..8] {
            let _ = write!(digest, "{b:02x}");
        }
        Ok(Spec {
            text,
            capsets,
            digest,
        })
    }

    /// The spec of the file `path`.
    pub(crate) fn load(path: &str, ids: &[u32]) -> std::io::Result<Spec> {
        let text = std::fs::read(path)
            .map_err(|e| std::io::Error::new(e.kind(), format!("the GPU spec {path}: {e}")))?;
        Spec::parse(text, ids).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("the GPU spec {path}: {e}"),
            )
        })
    }

    pub(crate) fn text(&self) -> &[u8] {
        &self.text
    }

    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }

    pub(crate) fn capset(&self, id: u32) -> Option<&Capset> {
        self.capsets.iter().find(|c| c.id == id)
    }

    /// The capsets in words, for the log.
    pub(crate) fn describe(&self) -> String {
        self.capsets
            .iter()
            .map(|c| format!("capset {} version {} ({} bytes)", c.id, c.ver, c.data.len()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A spec of the test: capset 1 (version 1, 8 bytes) and capset 2 (version 2, 12 bytes).
    pub(crate) fn text() -> String {
        [
            MAGIC,
            "# a spec of the device's tests",
            "capset 1 1 8 0102030405060708",
            "capset 2 2 12 090909090a0a0a0a00000000",
            "check 1 0 1 bits bset",
            "check 1 4 1 ge max_tbo_size",
            "check 2 0 1 none renderer",
            "check 2 4 1 fle min_point",
            "check 2 8 1 none num_video_caps",
            "",
        ]
        .join("\n")
    }

    pub(crate) fn spec() -> Spec {
        Spec::parse(text().into_bytes(), &[1, 2]).unwrap()
    }

    fn bad(t: &str) -> String {
        Spec::parse(t.as_bytes().to_vec(), &[1, 2]).unwrap_err()
    }

    #[test]
    fn a_spec_is_read_with_its_capsets_and_checked_lines() {
        let s = spec();
        assert_eq!(s.capset(1).unwrap().data, (1..=8).collect::<Vec<u8>>());
        assert_eq!(
            (s.capset(2).unwrap().ver, s.capset(2).unwrap().data.len()),
            (2, 12)
        );
        assert!(s.capset(3).is_none());
        assert_eq!(s.text(), text().as_bytes());
        assert_eq!(s.digest().len(), 16);
        assert_eq!(
            s.describe(),
            "capset 1 version 1 (8 bytes), capset 2 version 2 (12 bytes)"
        );
        // the same file, the same digest; another file, another
        assert_eq!(spec().digest(), s.digest());
        let other = text().replace("0102030405060708", "0102030405060709");
        assert_ne!(
            Spec::parse(other.into_bytes(), &[1, 2]).unwrap().digest(),
            s.digest()
        );
        // a video check names the offset of the count of its entries
        let v = text().replace(
            "check 2 8 1 none num_video_caps",
            "check 2 8 1 video video_caps 8",
        );
        Spec::parse(v.into_bytes(), &[1, 2]).unwrap();
    }

    #[test]
    fn a_spec_that_is_not_complete_or_not_well_formed_is_refused() {
        let t = text();
        assert!(bad("").contains("first line"));
        assert!(bad(&t.replacen(MAGIC, "spacebox-capset-profile 2", 1)).contains("first line"));
        assert!(
            bad(&t.replace("capset 2 2 12 090909090a0a0a0a00000000\n", ""))
                .contains("the capsets [1]")
        );
        assert!(bad(&t.replace("0102030405060708", "01020304050607")).contains("hex digits"));
        assert!(bad(&t.replace("0102030405060708", "01020304050607zz")).contains("bad hex"));
        assert!(bad(&t.replace("check 1 4 1 ge", "check 1 4 1 gt")).contains("unknown rule"));
        // a word with no check line, and a word in two
        assert!(bad(&t.replace("check 1 4 1 ge max_tbo_size\n", "")).contains("in 0 check lines"));
        assert!(bad(&t.replace("check 1 4 1 ge", "check 1 0 2 ge")).contains("in 2 check lines"));
        assert!(bad(&t.replace("check 1 4 1 ge", "check 1 4 2 ge")).contains("outside"));
        assert!(bad(&t.replace("check 1 4 1 ge", "check 3 4 1 ge")).contains("does not have"));
        assert!(
            bad(&t.replace("check 1 4 1 ge max_tbo_size", "check 1 4 1 ge"))
                .contains("not understood")
        );
        assert!(
            bad(&t.replace(
                "check 2 8 1 none num_video_caps",
                "check 2 8 1 video video_caps"
            ))
            .contains("no offset")
        );
        assert!(bad(&format!("{t}capset 1 1 4 00000000\n")).contains("again"));
        assert!(bad(&t.replace("check 1 0 1", "check  1 0 1")).contains("not a number"));
    }
}
