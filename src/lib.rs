//extern crate libc;
extern crate nix;

use nix::libc;

use libc::pid_t;
use nix::sys::wait::WaitStatus;
use nix::sys::ptrace::*;
use nix::sys::ptrace::ptrace::*;
use nix::Result;

pub mod arch;

pub fn traceme() -> std::io::Result<()> {
    match ptrace(PTRACE_TRACEME, 0, 0 as *mut _, 0 as *mut _) {
        Ok(_) => Ok(()),
        Err(e) => Err(std::io::Error::from(e))
    }
}

pub enum TraceEvent {
    SysEnter,
    SysExit,
    Signal(u8),
    Exit(i8),
}

enum State {
    Userspace,
    Kernelspace,
}

pub struct Tracee {
    pid: pid_t,
    state: State,
}

impl Tracee {
    pub fn new(pid: pid_t) -> Tracee {
        ptrace_setoptions(pid, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC).unwrap();
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
        ptrace(PTRACE_SYSCALL, self.pid, 0 as *mut _, 0 as *mut _).map(drop)
    }

    pub fn get_syscall(&mut self) -> Result<i64> {
        ptrace(PTRACE_PEEKUSER, self.pid, arch::x86_64::ORIG_RAX as *mut _, 0 as *mut _)
    }

    pub fn get_arg(&mut self, reg: u8) -> Result<i64> {
        let offset = match reg {
            0 => arch::x86_64::RDI,
            1 => arch::x86_64::RSI,
            2 => arch::x86_64::RDX,
            3 => arch::x86_64::R10,
            4 => arch::x86_64::R8,
            5 => arch::x86_64::R9,
            _ => panic!("there aren't that many registers")
        };
        ptrace(PTRACE_PEEKUSER, self.pid, offset as *mut _, 0 as *mut _)
    }

    pub fn get_return(&mut self) -> Result<i64> {
        ptrace(PTRACE_PEEKUSER, self.pid, arch::x86_64::RAX as *mut _, 0 as *mut _)
    }

    pub fn copy_from(&mut self, addr: usize, len: usize) -> Result<Vec<u8>> {
        use nix::sys::uio::*;

        let mut res = Vec::with_capacity(len);
        unsafe {
            res.set_len(len);
            let n = {
                try!(process_vm_readv(self.pid,
                                      &mut [IoVec::from_mut_slice(&mut res)],
                                      &[IoVec::from_slice(std::slice::from_raw_parts(addr as *const u8, len))]))
            };
            res.set_len(n);
        }
        Ok(res)
    }
}
