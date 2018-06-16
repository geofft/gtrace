extern crate libc;
extern crate gtrace;
extern crate nix;

use std::os::unix::process::CommandExt;
use std::process;
use std::process::Command;
use nix::sys::wait::waitpid;

use gtrace::TraceEvent;

enum App {
    Run(String, Vec<String>),
    Attach(libc::pid_t),
}

fn parse_args(args: &Vec<String>) -> Option<App> {
    let pos = args.iter().position(|ref x| x == &"-p");

    if let Some(pos) = pos {
        let pid = args.iter().nth(pos + 1).expect("Can't find PID");
        let pid = pid.parse::<libc::pid_t>().expect("Can't parse PID");
        return Some(App::Attach(pid));
    } else {
        let name = args.first();
        let args = args.iter().skip(1).cloned().collect();
        return name.map(|x| App::Run(x.to_string(), args));
    }
}

fn get_tracee(app: App) -> (Option<process::Child>, nix::unistd::Pid, gtrace::Tracee) {
    match app {
        App::Run(name, args) => {
            let mut cmd = Command::new(name);
            for arg in args {
                cmd.arg(arg);
            }
            cmd.before_exec(gtrace::traceme);
            let child = cmd.spawn().expect("child process failed");
            let pid = nix::unistd::Pid::from_raw(child.id() as libc::pid_t);
            (Some(child), pid, gtrace::Tracee::new(pid))
        }
        App::Attach(pid) => {
            let pid = nix::unistd::Pid::from_raw(pid);
            (None, pid, gtrace::Tracee::attach(pid))
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let app = parse_args(&args);

    if let None = app {
        println!("gtrace: must have PROG [ARGS] or -p PID");
        process::exit(0)
    }

    let app = app.unwrap();
    let (_, pid, mut tracee) = get_tracee(app);
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
