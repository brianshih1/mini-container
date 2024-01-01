# Limit Syscalls

### Goal

Restrict the number of system calls that the running process can make to protect the host system.

### Theory

Certain system calls may pose security risks or impact the host system. [Seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html) (Secure Computing Mode) is a Linux feature that allows developers to filter system calls to the kernel. Seccomp operates in two modes:

- Strict: a minimal set of syscalls is allowed
- Filter: allows developers to define custom policies for which syscalls are permitted

Seccomp filters are expressed as Berkeley Packet Filters (BPF) programs. These filters can be used to allow or deny system calls, as well as conditionally filter on system call arguments.

For this project, we will be using the following seccomp system calls

- [seccomp_init](https://man7.org/linux/man-pages/man3/seccomp_init.3.html): initializes the seccomp filter
- [seccomp_rule_add](https://man7.org/linux/man-pages/man3/seccomp_rule_add.3.html): add a new filter rule to the current seccomp filter
- [seccomp_load](https://man7.org/linux/man-pages/man3/seccomp_load.3.html): load the current seccomp filter into the kernel

Each filter in the seccomp filter returns an action, that can be one of:

- SCMP_ACT_KILL: kill the thread
- SCMP_ACT_KILL_PROCESS: kill the process
- SCMP_ACT_TRAP: throw a SIGSYS signal
- SCMP_ACT_ERRNO: return value with the specified error code:
- SCMP_ACT_TRACE: notify the tracer
- SCMP_ACT_LOG: logged
- SCMP_ACT_ALLOW: allowed
- SCMP_ACT_NOTIFY: notify the monitoring process

In short, Seccomp allows us to set rules that determine what happens when certain system calls are invoked. Seccomp is a powerful tool. But knowing which system calls to filter out is the tricky part. In this blog, I will focus only on the mechanism of filtering system calls and not discuss which system calls are dangerous. For an explanation of that, I suggest [Lizzie’s blog](https://blog.lizzie.io/linux-containers-in-500-loc.html#org8504d16) or [Docker’s documentation](https://github.com/docker/docs/blob/1253f14f6dd83df2cf9965182de118e5886c1b9e/content/engine/security/seccomp.md).

### Demo

For this project, we will be using the [syscallz crate](https://docs.rs/syscallz/latest/syscallz/), a seccomp library for Rust.

In the following example, we will try and limit the `getpid` system call. In the library, `Context::init_with_action`, `ctx.set_action_for_syscall` and `ctx.load()` are wrappers around `seccomp_init`, `seccomp_rule_add`, and `seccomp_load`.

```rust
use libc::getpid;
use syscallz::{Action, Context, Syscall};

fn main() {
    println!("pid (first attempt):, {}", unsafe { getpid() });

    match Context::init_with_action(Action::Allow) {
        Ok(mut ctx) => {
            ctx.set_action_for_syscall(Action::Errno(100), Syscall::getpid)
                .unwrap();
            ctx.load().unwrap();
        }
        Err(e) => {
            println!("Failed to init with action: {:?}", e);
        }
    }

    println!("pid (second attempt):, {}", unsafe { getpid() });
}
```

Compiling and executing the code above yields the following, where `-100` is the corresponding error code.

```docker
pid (first attempt):, 6613
pid (second attempt):, -100
```

### Implementation

For my project, I disabled the same set of syscalls that [Lizzie’s implementation](https://blog.lizzie.io/linux-containers-in-500-loc.html#org8504d16) of container disables. Here is the implementation:

```rust
const DISABLED_SYSCALLS: [Syscall; 9] = [
    Syscall::keyctl,
    Syscall::add_key,
    Syscall::request_key,
    Syscall::ptrace,
    Syscall::mbind,
    Syscall::migrate_pages,
    Syscall::set_mempolicy,
    Syscall::userfaultfd,
    Syscall::perf_event_open,
];

fn syscalls() -> ContainerResult {
    let s_isuid: u64 = Mode::S_ISUID.bits().into();
    let s_isgid: u64 = Mode::S_ISGID.bits().into();
    let clone_newuser = CloneFlags::CLONE_NEWUSER.bits() as u64;

    // Each tuple: (SysCall, argument_idx, value). 0 would be the first argument index.
    let conditional_syscalls = [
        (Syscall::fchmod, 1, s_isuid),
        (Syscall::fchmod, 1, s_isgid),
        (Syscall::fchmodat, 2, s_isuid),
        (Syscall::fchmodat, 2, s_isgid),
        (Syscall::unshare, 0, clone_newuser),
        (Syscall::clone, 0, clone_newuser),
        // TODO: ioctl causes an error when running /bin/ash somehow...
        // (Syscall::ioctl, 1, TIOCSTI),
    ];
    match Context::init_with_action(Action::Allow) {
        Ok(mut ctx) => {
            for syscall in DISABLED_SYSCALLS {
                if let Err(err) = ctx.set_action_for_syscall(Action::Errno(0), syscall) {
                    return Err(ContainerError::DisableSyscall);
                };
            }

            for (syscall, arg_idx, bit) in conditional_syscalls {
                if let Err(err) = ctx.set_rule_for_syscall(
                    Action::Errno(1000),
                    syscall,
                    &[Comparator::new(arg_idx, Cmp::MaskedEq, bit, Some(bit))],
                ) {
                    return Err(ContainerError::DisableSyscall);
                }
            }

            if let Err(err) = ctx.load() {
                return Err(ContainerError::DisableSyscall);
            };
        }
        Err(err) => {
            return Err(ContainerError::DisableSyscall);
        }
    }
    Ok(())
}
```

`seccomp_rule_add_array` allows developers to filter a syscall based on specific argument values by providing a comparator. Here is the code I used to perform conditional filters:

```rust
ctx.set_rule_for_syscall(
    Action::Errno(1000),
    syscall,
    &[Comparator::new(arg_idx, Cmp::MaskedEq, bit, Some(bit))],
)
```

For example, to error our when `unshare` is invoked when it contains the `clone_newuser` bit, we can provide a `Comparator` to `set_rule_for_syscall` like this:

```rust
let clone_newuser = CloneFlags::CLONE_NEWUSER.bits() as u64;
ctx.set_rule_for_syscall(
    Action::Errno(1000),
    Syscall::unshare,
    &[Comparator::new(0, Cmp::MaskedEq, clone_newuser, Some(clone_newuser))],
);
```

### Testing the Implementation

Now, let’s test whether our implementation works. In this test, we will confirm that performing `unshare` works without the `CLONE_NEWUSER` flag but fails with the `CLONE_NEWUSER` flag.

First, let’s confirm that `unshare` works when there are no flags set. Here is the `unshare_test` program:

```rust
use nix::sched::{unshare, CloneFlags};

fn main() {
    match unshare(CloneFlags::empty()) {
        Ok(_) => println!("Unshared success!"),
        Err(e) => println!("Error: {:?}", e),
    }
}
```

After compiling the binary for `unshare_test`, we need to copy the executable into the `alpine` directory before running the program in the container.

```bash
# inside the unshare_test repo
RUSTFLAGS="-C target-feature=+crt-static" cargo build --target="aarch64-unknown-linux-gnu"
cp target/aarch64-unknown-linux-gnu/debug/unshare_test /home/brianshih/alpine

# navigate to mini-container repo
sudo target/debug/mini-container /unshare_test /home/brianshih/alpine
# Unshared Success!
```

Based on the output of running the executable in the container environment, we’ve confirmed that `unshare` works when there are no flags set.

Now, let’s see what will happen if performing `unshare` with the `CLONE_NEWUSER` flag works with the following code:

```rust
use nix::sched::{unshare, CloneFlags};

fn main() {
    match unshare(CloneFlags::CLONE_NEWUSER) {
        Ok(_) => println!("Unshared success!"),
        Err(e) => println!("Error: {:?}", e),
    }
}
```

After compiling and copying the executable to the target root filesystem, I ran the executable in the container environment:

```bash
sudo target/debug/mini-container /unshare_test /home/brianshih/alpine
# Error: UnknownErrno
```

Based on the output, we have confirmed that it works.

To check which `Seccomp` mode and how many `seccomp filters` there are, you can perform `grep Seccomp /proc/{pid}/status` like follows:

```bash
sudo target/debug/mini-container /bin/ash /home/brianshih/alpine
# ...
# Child pid: Pid(6381)

# Host system
grep Seccomp /proc/6381/status
# Seccomp:	2
# Seccomp_filters:	1
```

Here, we can see that `Seccomp` is in the filter mode and there is one filter since our code only initializes and loads one filter.

### Additional Resources

[Intro to Seccomp and Seccomp-bpf](https://wiki.mozilla.org/Security/Sandbox/Seccomp)

[Mozilla wiki - Seccomp](https://wiki.mozilla.org/Security/Sandbox/Seccomp)
