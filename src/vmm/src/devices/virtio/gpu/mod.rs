// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The screen: a virtio-gpu device whose commands are rendered on the user's device (see
//! [`device`]), and beside it the devices whose input and output go through the same renderer:
//! a virtio-input keyboard and tablet ([`input`]), a virtio-snd device ([`sound`]), and the
//! channel to the guest agent ([`agent`]).

mod agent;
pub mod device;
mod event_handler;
pub mod input;
mod keymap;
mod link;
mod protocol;
pub mod sound;

pub use self::device::{
    GPU_DEV_ID, Gpu, GpuConstructorArgs, GpuPersistError, GpuSideState, GpuState, SIDE_LOST,
    SideParts, side_path,
};
pub use self::input::{
    Input, InputConstructorArgs, InputKind, InputPersistError, InputState, KEYBOARD_DEV_ID,
    TABLET_DEV_ID,
};
pub use self::sound::{
    GpuAudioOut, SOUND_DEV_ID, Sound, SoundConstructorArgs, SoundPersistError, SoundState,
};

pub(crate) const GPU_NUM_QUEUES: usize = 2;
pub(crate) const CTRL_QUEUE: usize = 0;
pub(crate) const CURSOR_QUEUE: usize = 1;
