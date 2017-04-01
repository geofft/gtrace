#[derive(Serialize, Deserialize)]
pub struct Buffer {
    pub addr: u64,
    pub data: Option<Vec<u8>>,
}

impl ::std::fmt::Display for Buffer {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        if let Some(ref data) = self.data {
            write!(f, "{:?}", String::from_utf8_lossy(data))
        } else {
            write!(f, "{:x}", self.addr)
        }
    }
}

#[derive(Serialize, Deserialize, Syscall)]
pub enum Syscall {
    Read { fd: u64, buf: Buffer, count: u64 },
    Write { fd: u64, buf: Buffer, count: u64 },
    Open { pathname: Buffer, flags: u64, mode: u64 }, // XXX Option
    Close { fd: u64 },
    // XXX add support for printing nr
    Unknown { nr: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64 }
}

#[derive(Serialize, Deserialize)]
pub struct SyscallRecord {
    // time
    pub pid: u64,
    pub call: Syscall,
    pub result: u64,
    // XXX decode errno
}
