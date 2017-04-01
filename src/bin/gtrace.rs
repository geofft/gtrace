extern crate libc;
extern crate gtrace;
extern crate nix;

use std::os::unix::process::CommandExt;
use std::process::Command;
use nix::sys::wait::waitpid;

use gtrace::TraceEvent;

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
            TraceEvent::SysEnter => print!("{}", gtrace::decode::decode(&mut tracee).unwrap()),
            TraceEvent::SysExit => println!(" = {}", tracee.get_return().unwrap()),
            TraceEvent::Signal(sig) => println!("** signal {:?}", sig),
            TraceEvent::Exit(_) => { break; }
        }
        tracee.run().unwrap();
    }
    //child.wait().unwrap();
}
