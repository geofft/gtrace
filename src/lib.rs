extern crate serde;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate gtrace_derive;

extern crate libc;
extern crate nix;

use nix::unistd::Pid;
use nix::sys::wait::WaitStatus;
use nix::sys::ptrace;
use nix::Result;

pub mod arch;
pub mod decode;
pub mod syscall;

pub fn traceme() -> std::io::Result<()> {
    match ptrace::traceme() {
        Ok(()) => Ok(()),
        Err(::nix::Error::Sys(errno)) => Err(std::io::Error::from_raw_os_error(errno as i32)),
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

pub enum TraceEvent {
    SysEnter,
    SysExit,
    Signal(u8),
    Exit(i32),
}

enum State {
    Userspace,
    Kernelspace,
}

pub struct Tracee {
    pid: Pid,
    state: State,
}

impl Tracee {
    pub fn new(pid: Pid) -> Tracee {
        ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD |
                                ptrace::Options::PTRACE_O_TRACEEXEC).unwrap();
        Tracee {
            pid: pid,
            state: State::Userspace,
        }
    }

    pub fn step(&mut self, status: WaitStatus) -> TraceEvent {
        match status {
            WaitStatus::PtraceSyscall(_) => {
                match self.state {
                    State::Userspace => {
                        self.state = State::Kernelspace;
                        TraceEvent::SysEnter
                    },
                    State::Kernelspace => {
                        self.state = State::Userspace;
                        TraceEvent::SysExit
                    },
                }
            }
            WaitStatus::Exited(_, status) => TraceEvent::Exit(status),
            WaitStatus::Stopped(_, sig) => TraceEvent::Signal(sig as u8),
            _ => panic!("unexpected status {:?}", status)
        }
    }

    pub fn run(&mut self) -> Result<()> {
        ptrace::syscall(self.pid)
    }

    pub fn get_syscall(&mut self) -> Result<u64> {
        unsafe { ptrace::ptrace(ptrace::Request::PTRACE_PEEKUSER, self.pid,
                                arch::x86_64::ORIG_RAX as *mut _, 0 as *mut _).map(|x| x as u64) }
    }

    pub fn get_arg(&mut self, reg: u8) -> Result<u64> {
        let offset = match reg {
            0 => arch::x86_64::RDI,
            1 => arch::x86_64::RSI,
            2 => arch::x86_64::RDX,
            3 => arch::x86_64::R10,
            4 => arch::x86_64::R8,
            5 => arch::x86_64::R9,
            _ => panic!("there aren't that many registers")
        };
        unsafe { ptrace::ptrace(ptrace::Request::PTRACE_PEEKUSER, self.pid,
                                offset as *mut _, 0 as *mut _).map(|x| x as u64) }
    }

    pub fn get_return(&mut self) -> Result<i64> {
        unsafe { ptrace::ptrace(ptrace::Request::PTRACE_PEEKUSER, self.pid,
                                arch::x86_64::RAX as *mut _, 0 as *mut _) }
    }

    /// Read len bytes from addr. May return fewer than len bytes if
    /// part of the range is unmapped, or an error if addr itself is
    /// unmapped.
    pub fn copy_from(&mut self, addr: usize, len: usize) -> Result<Vec<u8>> {
        use nix::sys::uio::*;

        let mut res = Vec::with_capacity(len);
        unsafe {
            res.set_len(len);
            let target: Vec<_> = PageIter::new(addr, len, arch::x86_64::PAGE_SIZE)
                                 .map(|(a, l)| RemoteIoVec { base: a, len: l })
                                 .collect();
            let n = {
                try!(process_vm_readv(self.pid,
                                      &mut [IoVec::from_mut_slice(&mut res)],
                                      &target[..]))
            };
            res.set_len(n);
        }
        Ok(res)
    }

    /// Read a NUL-terminated C string of up to len bytes from addr.
    /// Returns an error if none of the string could be read,
    /// Ok(vec, false) if some of the string could be read but we ran into an unmapped page, or
    /// Ok(vec, true) if all of the string could be read, up to either len or
    /// the terminating NUL. As with strncpy, if there is no terminating NUL in
    /// the first len bytes, no terminating NUL will be in the output.
    pub fn strncpy_from(&mut self, addr: usize, len: usize) -> Result<(Vec<u8>, bool)> {
        use nix::sys::uio::*;
        use nix::Error::Sys;
        use nix::errno::Errno::EFAULT;

        let mut remote_pages = PageIter::new(addr, len, arch::x86_64::PAGE_SIZE);

        let mut res = Vec::with_capacity(len);

        // Read the first chunk, returning an error if it didn't work
        match remote_pages.next() {
            None => { return Ok((Vec::new(), true)); }
            Some((chunkaddr, chunklen)) => unsafe {
                res.set_len(chunklen);
                let n = {
                    try!(process_vm_readv(self.pid,
                                          &mut [IoVec::from_mut_slice(&mut res)],
                                          &[RemoteIoVec { base: chunkaddr, len: chunklen }]))
                };
                res.set_len(n);
            }
        }

        let mut oldlen = 0;

        loop {
            // Try to find a terminating NUL
            if let Some(nul) = res[oldlen..].iter().position(|&b| b == 0) {
                res.truncate(oldlen + nul + 1);
                return Ok((res, true));
            }
            oldlen = res.len();

            // If not, read the next page, but don't error on EFAULT,
            // just report the partial read. Report all other errors as
            // errors.
            match remote_pages.next() {
                None => { return Ok((res, true)); }
                Some((chunkaddr, chunklen)) => unsafe {
                    res.set_len(oldlen + chunklen);
                    match { process_vm_readv(self.pid,
                            &mut [IoVec::from_mut_slice(&mut res[oldlen..])],
                            &[RemoteIoVec { base: chunkaddr, len: chunklen }]) } {
                        Ok(n) => { res.set_len(n); }
                        Err(Sys(EFAULT)) => { return Ok((res, false)); }
                        Err(e) => { return Err(e); }
                    }
                }
            }
        }
    }
}

struct PageIter {
    addr: usize,
    max_addr: usize,
    page_size: usize,
}

impl PageIter {
    fn new(addr: usize, len: usize, page_size: usize) -> PageIter {
        PageIter { addr: addr, max_addr: addr + len, page_size: page_size }
    }
}

impl Iterator for PageIter {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<(usize, usize)> {
        if self.addr == self.max_addr {
            return None;
        }
        let mut len = self.page_size - (self.addr % self.page_size);
        if self.addr + len > self.max_addr {
            len = self.max_addr - self.addr;
        }
        let ret = Some((self.addr, len));
        self.addr += len;
        ret
    }
}

#[test]
fn test_page_iter() {
    fn check(addr: usize, len: usize, v: Vec<(usize, usize)>) {
        let iov: Vec<(usize, usize)> = PageIter::new(addr, len, 10).collect();
        assert_eq!(iov, v);
    }

    check(3, 5,   vec![(3, 5)]);
    check(3, 21,  vec![(3, 7), (10, 10), (20, 4)]);
    check(10, 10, vec![(10, 10)]);
    check(10, 11, vec![(10, 10), (20, 1)]);
    check(10, 0,  vec![]);
}
