use libc::PATH_MAX;
use nix::Result;

use Tracee;
use syscall::{Buffer, Syscall};

fn parse_read(tracee: &mut Tracee) -> Result<Syscall> {
    let fd = tracee.get_arg(0)?;
    let buf = Buffer { addr: tracee.get_arg(1)?,
                       data: None };
    let count = tracee.get_arg(2)?;
    Ok(Syscall::Read { fd: fd, buf: buf, count: count })
}

fn parse_write(tracee: &mut Tracee) -> Result<Syscall> {
    let fd = tracee.get_arg(0)?;
    let addr = tracee.get_arg(1)?;
    let count = tracee.get_arg(2)?;
    let data = tracee.copy_from(addr as usize, count as usize)?;
    let buf = Buffer { addr: addr,
                       data: Some(data) };
    Ok(Syscall::Write { fd: fd, buf: buf, count: count })
}

fn parse_open(tracee: &mut Tracee) -> Result<Syscall> {
    let addr = tracee.get_arg(0)?;
    let data = tracee.strncpy_from(addr as usize, PATH_MAX as usize)?.0;
    let pathname = Buffer { addr: addr,
                            data: Some(data) };
    let flags = tracee.get_arg(1)?;
    let mode = if flags & (::libc::O_CREAT as u64) != 0 { tracee.get_arg(2)? } else { 0 };
    Ok(Syscall::Open { pathname: pathname, flags: flags, mode: mode })
}

fn parse_close(tracee: &mut Tracee) -> Result<Syscall> {
    Ok(Syscall::Close { fd: tracee.get_arg(0)? })
}

fn parse_stat(tracee: &mut Tracee) -> Result<Syscall> {
    let addr = tracee.get_arg(0)?;
    let data = tracee.strncpy_from(addr as usize, PATH_MAX as usize)?.0;
    let pathname = Buffer { addr : addr,
                            data: Some(data) };
    let buf = tracee.get_arg(1)?;
    Ok(Syscall::Stat { pathname: pathname, buf: buf })
}

fn parse_fstat(tracee: &mut Tracee) -> Result<Syscall> {
    let fd = tracee.get_arg(0)?;
    let buf = tracee.get_arg(1)?;
    Ok(Syscall::Fstat { fd: fd, buf: buf })
}

fn parse_lstat(tracee: &mut Tracee) -> Result<Syscall> {
    let addr = tracee.get_arg(0)?;
    let data = tracee.strncpy_from(addr as usize, PATH_MAX as usize)?.0;
    let pathname = Buffer { addr : addr,
                            data: Some(data) };
    let buf = tracee.get_arg(1)?;
    Ok(Syscall::Lstat { pathname: pathname, buf: buf })
}

fn parse_unknown(tracee: &mut Tracee, nr: u64) -> Result<Syscall> {
    Ok(Syscall::Unknown {
        nr: nr,
        a: tracee.get_arg(0)?,
        b: tracee.get_arg(1)?,
        c: tracee.get_arg(2)?,
        d: tracee.get_arg(3)?,
        e: tracee.get_arg(4)?,
        f: tracee.get_arg(5)?,
    })
}

// TODO following need to move to arch

/// Decode a syscall on entry.
pub fn decode(tracee: &mut Tracee) -> Result<Syscall> {
    match tracee.get_syscall()? {
        0 => parse_read(tracee),
        1 => parse_write(tracee),
        2 => parse_open(tracee),
        3 => parse_close(tracee),
        4 => parse_stat(tracee),
        5 => parse_fstat(tracee),
        6 => parse_lstat(tracee),
        /*
        8 => parse_lseek(tracee),
        9 => parse_mmap(tracee),
        10 => parse_mprotect(tracee),
        */
        other => parse_unknown(tracee, other)
    }
}

/// Fill in the remainder of a syscall on exit.
pub fn fixup(syscall: Syscall) -> Syscall {
    syscall
}
