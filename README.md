gtrace
===

gtrace is a library for implementing strace-like behavior, and a
reference client that works like strace.

Thanks
===

The following sources were very helpful in learning how to do this:

 * Nelson Elhage's [Write yourself an strace in 70 lines of code](https://blog.nelhage.com/2010/08/write-yourself-an-strace-in-70-lines-of-code/)
 * Joe Kain's [Loading and ptrac'ing a process in Rust](http://system.joekain.com/2015/07/15/rust-load-and-ptrace.html) and related blog posts
 * the [ptrace(2) man page](http://man7.org/linux/man-pages/man2/ptrace.2.html), in particular the extended description [written by Denys Vlasenko](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/commit/?id=4d12a715f2780abaecb4001e50be3ac6e915cbba)
