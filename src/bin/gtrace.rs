extern crate libc;
extern crate gtrace;
extern crate nix;

use std::os::unix::process::CommandExt;
use std::process::Command;
use nix::sys::wait::waitpid;

use gtrace::TraceEvent;

fn print_syscall(tracee: &mut gtrace::Tracee) -> nix::Result<()> {
    let arg0 = tracee.get_arg(0)?;
    let arg1 = tracee.get_arg(1)?;
    let arg2 = tracee.get_arg(2)?;
    match tracee.get_syscall()? {
        0 => print!("read({}, {:x}, {})", arg0, arg1, arg2),
        1 => print!("write({}, {:?}, {})",
                    arg0,
                    String::from_utf8_lossy(&tracee.copy_from(arg1 as usize, arg2 as usize)?[..]),
                    arg2),
        2 => print!("open({:?}, {})",
                    String::from_utf8_lossy(&tracee.strncpy_from(arg0 as usize, libc::PATH_MAX as usize)?.0[..]),
                    arg1),
        nr => print!("sys_{}(...)", nr)
    }
    Ok(())
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let mut cmd = Command::new(args.next().expect("usage: gtrace cmd [args...]"));
    for arg in args {
        cmd.arg(arg);
    }
    cmd.before_exec(gtrace::traceme);
    let mut child = cmd.spawn().expect("child process failed");
    let pid: libc::pid_t = child.id() as libc::pid_t;
    let mut tracee = gtrace::Tracee::new(pid);
    loop {
        match tracee.step(waitpid(pid, None).unwrap()) {
            TraceEvent::SysEnter => print_syscall(&mut tracee).unwrap(),
            TraceEvent::SysExit => println!(" = {}", tracee.get_return().unwrap()),
            TraceEvent::Signal(sig) => println!("** signal {:?}", sig),
            TraceEvent::Exit(_) => { break; }
        }
        tracee.run().unwrap();
    }
    //child.wait().unwrap();
}
