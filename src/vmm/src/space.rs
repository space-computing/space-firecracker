// Copyright 2026 Spacebox authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The fill of guest memory (`PUT /space/fill`).
//!
//! A fill populates every page of the plugged guest memory for writing
//! (`madvise(MADV_POPULATE_WRITE)`), so that afterwards no page of the guest is a page of the
//! page cache of the host or a page that is not there. It runs on a thread of its own while the
//! guest runs on: on the VMM thread it would stop every device for seconds for each GiB. The
//! thread is started before the seccomp filter of the VMM thread is set (that filter allows no
//! new thread) and sets its own filter, of the thread category `fill`.

use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::logger::{error, info};
use crate::seccomp::BpfProgram;
use crate::vmm_config::space::{FillState, FillStatus};

/// `MADV_POPULATE_WRITE` of Linux 5.14.
const MADV_POPULATE_WRITE: libc::c_int = 23;

/// One range of guest memory in the address space of the process: its address and its length.
pub type HostRange = (usize, usize);

/// Errors of a fill.
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum FillError {
    /// A fill is already running.
    AlreadyRunning,
    /// The fill thread is not running.
    NoThread,
}

/// The handle of the fill thread.
#[derive(Debug, Default)]
pub struct Filler {
    jobs: Option<Sender<Vec<HostRange>>>,
    status: Arc<Mutex<FillStatus>>,
}

impl Filler {
    /// Starts the fill thread. It sets `filter` and waits for a fill.
    pub fn spawn(filter: Arc<BpfProgram>) -> std::io::Result<Filler> {
        let (jobs, receiver) = channel::<Vec<HostRange>>();
        let status = Arc::new(Mutex::new(FillStatus::default()));
        let thread_status = status.clone();
        thread::Builder::new()
            .name("fc_fill".to_owned())
            .spawn(move || {
                if let Err(err) = crate::seccomp::apply_filter(&filter) {
                    panic!("Failed to set the seccomp filter of the fill thread: {err}");
                }
                // The thread ends when the Vmm, which holds the sender, is dropped.
                while let Ok(ranges) = receiver.recv() {
                    let result = populate_write(&ranges);
                    let mut status = thread_status.lock().expect("Poisoned lock");
                    *status = match result {
                        Ok(()) => {
                            info!("The fill of guest memory is done.");
                            FillStatus {
                                state: FillState::Done,
                                error: None,
                            }
                        }
                        Err(err) => {
                            error!("The fill of guest memory failed: {err}");
                            FillStatus {
                                state: FillState::Failed,
                                error: Some(err.to_string()),
                            }
                        }
                    };
                }
            })?;
        Ok(Filler {
            jobs: Some(jobs),
            status,
        })
    }

    /// Starts a fill of `ranges`. A fill that runs is not started again.
    pub fn start(&self, ranges: Vec<HostRange>) -> Result<(), FillError> {
        let jobs = self.jobs.as_ref().ok_or(FillError::NoThread)?;
        let mut status = self.status.lock().expect("Poisoned lock");
        if status.state == FillState::Running {
            return Err(FillError::AlreadyRunning);
        }
        // The thread writes the end of the fill under the same lock, so the state that is set
        // here is never written after that end.
        jobs.send(ranges).map_err(|_| FillError::NoThread)?;
        *status = FillStatus {
            state: FillState::Running,
            error: None,
        };
        drop(status);
        Ok(())
    }

    /// What the fill is doing.
    pub fn status(&self) -> FillStatus {
        self.status.lock().expect("Poisoned lock").clone()
    }
}

/// Populates each range for writing. A page that is there keeps its bytes; a page of a private
/// file mapping gets a copy of its own; a page that is not there becomes a zero page, or is asked
/// for from the UFFD handler of a range that one serves.
fn populate_write(ranges: &[HostRange]) -> std::io::Result<()> {
    for &(addr, len) in ranges {
        loop {
            // SAFETY: the range is guest memory that the process mapped and keeps mapped while
            // the Vmm lives; the advice changes no byte of it.
            let ret = unsafe { libc::madvise(addr as *mut libc::c_void, len, MADV_POPULATE_WRITE) };
            if ret == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
                _ => return Err(err),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    fn wait_done(filler: &Filler) -> FillStatus {
        let start = Instant::now();
        loop {
            let status = filler.status();
            if status.state != FillState::Running {
                return status;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "fill did not end"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// The number of pages of `[addr, addr + len)` that are in memory.
    fn resident_pages(addr: usize, len: usize) -> usize {
        let pages = len / 4096;
        let mut vec = vec![0u8; pages];
        // SAFETY: the range is a mapping of this test and `vec` has a byte for each page.
        let ret = unsafe { libc::mincore(addr as *mut libc::c_void, len, vec.as_mut_ptr()) };
        assert_eq!(ret, 0);
        vec.iter().filter(|b| **b & 1 != 0).count()
    }

    #[test]
    fn test_fill_populates_every_page() {
        let len = 64 * 4096;
        // SAFETY: an anonymous private mapping of this test.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(addr, libc::MAP_FAILED);
        let addr = addr as usize;
        // One page holds data before the fill and keeps it.
        // SAFETY: the address is in the mapping above.
        unsafe { *((addr + 4096) as *mut u8) = 0x5a };
        assert_eq!(resident_pages(addr, len), 1);

        let filler = Filler::spawn(Arc::new(vec![])).unwrap();
        assert_eq!(filler.status().state, FillState::Idle);
        filler.start(vec![(addr, len)]).unwrap();
        let status = wait_done(&filler);
        assert_eq!(status.state, FillState::Done, "{:?}", status.error);
        assert_eq!(resident_pages(addr, len), 64);
        // SAFETY: the address is in the mapping above.
        assert_eq!(unsafe { *((addr + 4096) as *const u8) }, 0x5a);

        // A fill can run again after one ended.
        filler.start(vec![(addr, len)]).unwrap();
        assert_eq!(wait_done(&filler).state, FillState::Done);

        // SAFETY: the mapping of this test.
        unsafe { libc::munmap(addr as *mut libc::c_void, len) };
    }

    #[test]
    fn test_fill_failure_is_reported() {
        let len = 4 * 4096;
        // SAFETY: an anonymous mapping of this test with no access, which cannot be populated.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(addr, libc::MAP_FAILED);
        let filler = Filler::spawn(Arc::new(vec![])).unwrap();
        filler.start(vec![(addr as usize, len)]).unwrap();
        let status = wait_done(&filler);
        assert_eq!(status.state, FillState::Failed);
        assert!(status.error.is_some());
        // SAFETY: the mapping of this test.
        unsafe { libc::munmap(addr, len) };
    }

    #[test]
    fn test_fill_with_no_thread() {
        let filler = Filler::default();
        assert_eq!(filler.start(vec![]), Err(FillError::NoThread));
    }
}
