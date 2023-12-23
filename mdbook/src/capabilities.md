# Capabilities

### Goal

We want to granularly control and limit the privileges of processes within a container.

### Theory

Traditionally, processes run with either a full set of privileges granted by the root user or with a limited set of privileges granted by the process’s user and groups.

However, sometimes a program needs to be run by an unprivileged user but be able to make privileged calls. In that case, the [suid bit](https://www.redhat.com/sysadmin/suid-sgid-sticky-bit) would be set on the file, which will cause the file to be executed by the user who owns the file. This makes the program susceptible to privilege escalation attacks.

Linux Capabilities are introduced as a mechanism that allows a process to perform privileged operations without being granted superuser access. Rather than a single privilege, the superuser privilege is divided into distinct units known as capabilities.

**Rules of Capabilities**

In Linux, both processes and files (executables) can have capabilities. So what capabilities are granted when a file is executed by a process? For that, we need to first introduce the concept of capabilities set.

Each process stores 5 different sets of capabilities (based on the [“Thread capability sets” section in the Linux doc](https://www.notion.so/Capabilities-04f91e967ee9426eb354611b98364ede?pvs=21)):

- **Effective**: The kernel will run permission checks against effective capabilities. If the capability for a privileged operation is not set, a permission error will be thrown.
- **Permitted**: superset for the effective capabilities. The process can transition it to the effective set dynamically.
- **Inheritable**: capabilities inside the inheritable set will be added to the permitted set when a program is executed via the `execve` syscall
- **Bounding**: the superset of all the capabilities. If a capability is not inside the bounded set, it is not allowed
- **Ambient**: a set of capabilities preserved across an execve call that is not privileged. No capability can be ambient if it is not both permitted and inheritable.

Here is a screenshot from the Linux [doc](https://man7.org/linux/man-pages/man7/capabilities.7.html) about how the different Linux capabilities will transform across `execve` calls:

![Screenshot 2023-12-20 at 1.32.44 AM.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/552ab37c-e9e7-4e4e-b079-a27f36afc8b3/c39cf7c4-dd28-402d-a64d-fbbc98ebfcfa/Screenshot_2023-12-20_at_1.32.44_AM.png)

If a user wants to execute a file that needs capability `X`, the user needs X to be inside `P'(effective)`. In the 2 demos below, we will demonstrate how we can achieve that for different types of files.

### Demo

**Demo 1: Gaining Capabilities from Executables**

One of the Linux Capabilities is `CAP_NET_BIND_SERVICE`, which determines whether a process can bind a socket to a Internet domain privileged ports (port number less than 1024).

To start off, I’ve created a Rust project with the following code. All this code snippet does is that it tries to create a `TcpListener` and bind it to a privileged address (80).

```rust
use std::net::TcpListener;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:80").unwrap();
	  println!("TcpListner bound to 127.0.0.1:80. Accepting incoming connection"):
		listener.accept();
}
```

When we run this code, we will get this error:

```rust
Error: Os { code: 13, kind: PermissionDenied, message: "Permission denied" }
```

This is because normal processes have 0 capabilities. To verify this, we can look at `/proc/$$/status` to see that the `CAP_NET_BIND_SERVICE` bit is not in `CapEff`.

```bash
grep Cap /proc/$$/status
# CapInh:	0000000000000000
# CapPrm:	0000000000000000
# CapEff:	0000000000000000
# CapBnd:	000001ffffffffff
# CapAmb:	0000000000000000
```

Now, let’s think about how we can grant capability to the process running the file.

Firstly, the file is clearly not capability-aware. Capability aware programs are programs that understand and manipulate capabilities through calls to [libcap](https://man7.org/linux/man-pages/man3/libcap.3.html) syscalls.

Therefore, in order for the `CAP_NET_BIND_SERVICE` capability to be inside the thread’s effective capability set after the `execve` call, one way is to add the capability to the file’s effective set and permitted set.

```
P'(effective) = F(effective) ? P'(permitted) : P'(ambient)
P'(permitted) = (P(inheritable) & F(inheritable)) | (F(permitted) & cap_bset) | P'(ambient)
```

If `F(effective)` is valid, we can perform the following algebra:

```
P'(effective) = F(effective) ? P'(permitted) : P'(ambient)
```

⇒  `P'(effective) = P'(permitted)`

⇒ `P'(effective) = (F(permitted) & cap_bset)`

Since the capability is inside `F(effective)` and `F(premitted)`, it will also be inside `P'(effective)`.

Now let’s try setting the `CAP_NET_BIND_SERVICE` to the file and re-run it.

```bash
sudo setcap 'cap_net_bind_service=+ep' target/debug/hello_world
getcap target/debug/hello_world
# target/debug/hello_world cap_net_bind_service=ep
target/debug/hello_world
# TcpListener bound to 127.0.0.1:80. Accepting incoming connection
```

To grant a capability, we will use the [setcap](https://man7.org/linux/man-pages/man8/setcap.8.html) syscall. To verify that the capability is set, we use the [getcap](https://man7.org/linux/man-pages/man8/getcap.8.html) syscall. After setting the capability, we can bound the TcpListener to port 80.

**Demo 2: Capability-aware files**

Ideally, we would like to create an environment that doesn’t require giving the process root user privileges or granting the file capabilities.

Let’s look at this equation again:

```
P'(effective) = F(effective) ? P'(permitted) : P'(ambient)
```

If we don’t set the `F(effective)` bit, then we need to ensure that `P'(ambient)` contains the capability bit. To do that, we need to create a capability-aware file.  Capability aware files can use the [prctl](https://man7.org/linux/man-pages/man2/prctl.2.html) calls to add capabilities to capability sets.

For example, `prctl` with arguments of `PR_CAP_AMBIENT` `PR_CAP_AMBIENT_RAISE` can add capabilities to the ambient set. According to prctl’s Linux doc, `PR_CAP_AMBIENT_RAISE` adds the capability specified in arg3 to the ambient set and “the specified capability must already be present in both the permitted and the inheritable sets of the process”.

As a result, we need to add the capability to the inheritable set of the thread before adding it to the ambient set of the thread. We will add the capability to `F(permitted)` manually since I can’t seem to add it with `prctl` directly (I’m still going through the docs to find out why this is happening!).

Here is the `set-ambient` program (inspired by this [blog](https://blog.container-solutions.com/linux-capabilities-in-practice)) to do that:

```rust
use std::{env, ffi::CString};

use nix::unistd::execve;

fn set_ambient() {
    caps::raise(
        None,
        caps::CapSet::Inheritable,
        caps::Capability::CAP_NET_BIND_SERVICE,
    )
    .unwrap();

    caps::raise(
        None,
        caps::CapSet::Ambient,
        caps::Capability::CAP_NET_BIND_SERVICE,
    )
    .unwrap();
}

fn main() {
    let args: Vec<String> = env::args().collect();
    set_ambient();

    println!("CAP_NET_BIND_SERVICE is in ambient capabilities. Executing file.");
    if let Err(e) = execve::<CString, CString>(&CString::new(args[1].clone()).unwrap(), &[], &[]) {
        println!("Failed to execve: {:?}", e);
    }
}
```

We use the [caps crate](https://crates.io/crates/caps) to set the capabilities. The call `caps::raise(None, Ambient, CAP_NET_BIND_SERVICE)` is a wrapper around the Linux call `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, NET_BIND_SERVICE)`.

As specified earlier, the capability must be present in both the permitted and the inheritable sets of the process. Therefore, we use `sudo setcap` to add the capability to the permitted set of the file.

After setting the capability bit for `NET_BIND_SERVICE` to the permission capability set of the file, let’s run `/bin/bash` with the `set-ambient` program. We can check the capability sets of the process via `grep Cap /proc/$$/status` and see that the effective bits for the process is `0000000000000400`. Finally, we can use `capsh --decode` to confirm that `cap_net_bind_service` is in the process’s effective set.

```bash
sudo setcap cap_net_bind_service+p target/debug/set-ambient
target/debug/set-ambient /bin/bash
# CAP_NET_BIND_SERVICE is in ambient capabilities. Executing file.
grep Cap /proc/$$/status
# CapInh:	0000000000000400
# CapPrm:	0000000000000400
# CapEff:	0000000000000400
# CapBnd:	000001ffffffffff
# CapAmb:	0000000000000400
capsh --decode=0000000000000400
# 0x0000000000000400=cap_net_bind_service
```

Finally, we can run the file with the `TcpListener` again and this time, we can bound the listener to port 80.

```bash
target/debug/set-ambient ../tcp_example/target/debug/tcp_example
# TcpListener bound to 127.0.0.1:80. Accepting incoming connection
```

### Implementation

My implementation takes in a list of capabilities to add and a list of capabilities to drop. If `ALL` is specified in `cap-drop`, then all capabilities are dropped.

```rust
sudo target/debug/mini-container /bin/ash /home/brianshih/alpine 
	--cap-drop ALL 
	--cap-add NET_BIND_SERVICE CAP_SETUID
```

Here is the pseudocode for the implementation:

- for each capabilities to drop, drop them. If the capability specified is `ALL`, then loop through any capabilities in the bounding set unless it’s inside the capabilities to add
- loop through the capabilities to add and add the capability set to the inheritable set and the ambient set.

Here is the actual code:

```rust
static CAPABILITIES: phf::Map<&'static str, Capability> = phf_map! {
    "NET_BIND_SERVICE" => caps::Capability::CAP_NET_BIND_SERVICE,
    "SETUID" => caps::Capability::CAP_SETUID,
    "CAP_SYS_TIME" => caps::Capability::CAP_SYS_TIME,
};

fn capabilities(config: &ChildConfig) -> ContainerResult {
    // compute the list of capabilities to add
    let caps_add: Vec<Capability> = match &config.cap_add {
        Some(cap_add) => {
            let mut res = vec![];
            for c in cap_add.iter() {
                match CAPABILITIES.get(c) {
                    Some(c) => {
                        res.push(c.clone());
                    }
                    None => {
                        return Err(ContainerError::CapabilityAdd);
                    }
                }
            }
            res
        }
        None => vec![],
    };

    // if ALL is inside the capabilities to drop, then drop all capabilities except
    // for the ones inside capabilities to add
    if let Some(caps) = &config.cap_drop {
        if caps.contains(&String::from("ALL")) {
            let bounding_caps = caps::read(None, caps::CapSet::Bounding).unwrap();
            for cap in bounding_caps.iter() {
                if !caps_add.contains(cap) {
                    if let Err(e) = caps::drop(None, caps::CapSet::Bounding, *cap) {
                        return Err(ContainerError::CapabilityDrop);
                    }
                }
            }
        } else {
            for c in caps.iter() {
                match CAPABILITIES.get(c) {
                    Some(c) => {
                        if let Err(e) = caps::drop(None, caps::CapSet::Bounding, *c) {
                            return Err(ContainerError::CapabilityDrop);
                        }
                        if let Err(e) = caps::drop(None, caps::CapSet::Inheritable, *c) {
                            return Err(ContainerError::CapabilityDrop);
                        }
                    }
                    None => {
                        return Err(ContainerError::CapabilityDrop);
                    }
                }
            }
        }
    }

    for cap in caps_add.iter() {
        if let Err(e) = caps::raise(None, caps::CapSet::Inheritable, *cap) {
            return Err(ContainerError::CapabilityAdd);
        }
        if let Err(e) = caps::raise(None, caps::CapSet::Ambient, *cap) {
            return Err(ContainerError::CapabilityAdd);
        }
    }
    Ok(())
}
```

### Testing the Implementation

Let’s first confirm that dropping all capabilities and adding `NET_BIND_SERVICE` works.

```bash
sudo target/debug/mini-container /bin/ash /home/brianshih/alpine 
	--cap-drop ALL 
	--cap-add NET_BIND_SERVICE
# Child pid: Pid(6517)
# ...

# host system
grep Cap /proc/6517/status
# CapInh:	0000000000000400
# CapPrm:	0000000000000400
# CapEff:	0000000000000400
# CapBnd:	000001ffffffffff
# CapAmb:	0000000000000400
capsh --decode=0000000000000400
# 0x0000000000000400=cap_net_bind_service
```

Next, I built a Rust program with this code. All it does is that it prints out the capability sets of the process and runs `setresuid`, which is granted if the `SETUID` capability is set.

```rust
use nix::unistd::{setresuid, Uid};

fn main() {
    println!("Effective {:?}", caps::read(None, caps::CapSet::Effective));
    println!("Bounding {:?}", caps::read(None, caps::CapSet::Bounding));
    println!(
        "Inherited {:?}",
        caps::read(None, caps::CapSet::Inheritable)
    );
    println!("Permitted {:?}", caps::read(None, caps::CapSet::Permitted));
    println!("Ambient {:?}", caps::read(None, caps::CapSet::Ambient));

    if let Err(e) = setresuid(Uid::from_raw(10), Uid::from_raw(10), Uid::from_raw(10)) {
        println!("Failed to setuid: {:?}", e);
    }
    println!("Finished");
}
```

Next, let’s compile it and copy it to the alpine directory. Then we run the program in the container. We get an `EPERM` error. If we look at the logged lines, we can see that `CAP_SETUID` is not in the effective set of the process.

```bash
# compile it
RUSTFLAGS="-C target-feature=+crt-static" cargo build --target="aarch64-unknown-linux-gnu"
# copy it to the alpine directory
cp target/aarch64-unknown-linux-gnu/debug/setuid_example /home/brianshih/alpine
sudo target/debug/mini-container /setuid_example /home/brianshih/alpine
# Effective Ok({})
# Bounding Ok({CAP_SETGID, CAP_AUDIT_WRITE, CAP_SYS_RESOURCE, CAP_SETFCAP, CAP_BLOCK_SUSPEND, CAP_SYS_TTY_CONFIG, CAP_AUDIT_CONTROL, CAP_SYS_NICE, CAP_CHOWN, CAP_LEASE, CAP_MAC_OVERRIDE, CAP_FOWNER, CAP_BPF, CAP_SYS_BOOT, CAP_WAKE_ALARM, CAP_NET_BIND_SERVICE, CAP_IPC_OWNER, CAP_NET_BROADCAST, CAP_PERFMON, CAP_FSETID, CAP_SYS_ADMIN, CAP_SYSLOG, CAP_LINUX_IMMUTABLE, CAP_KILL, CAP_NET_ADMIN, CAP_DAC_READ_SEARCH, CAP_SYS_CHROOT, CAP_SYS_PACCT, CAP_SYS_RAWIO, CAP_SETUID, CAP_NET_RAW, CAP_AUDIT_READ, CAP_CHECKPOINT_RESTORE, CAP_SYS_TIME, CAP_MKNOD, CAP_SYS_PTRACE, CAP_MAC_ADMIN, CAP_DAC_OVERRIDE, CAP_IPC_LOCK, CAP_SETPCAP, CAP_SYS_MODULE})
# Inherited Ok({})
# Permitted Ok({})
# Ambient Ok({})
# Failed to setuid: EPERM
 
```

However, if we rerun the program with `--cap-add SETUID`, the program runs without error. If we look at the logged lines, we can see that `CAP_SETUID` is in the effective capability set of the process.

```bash
sudo target/debug/mini-container /setuid_example /home/brianshih/alpine 
		--cap-add SETUID
# Effective Ok({CAP_SETUID})
# Bounding Ok({CAP_SETFCAP, CAP_BPF, CAP_MKNOD, CAP_CHOWN, CAP_SETUID, CAP_SYS_TIME, CAP_FSETID, CAP_NET_ADMIN, CAP_SYS_CHROOT, CAP_LINUX_IMMUTABLE, CAP_IPC_LOCK, CAP_SYS_NICE, CAP_SYS_RAWIO, CAP_SETGID, CAP_KILL, CAP_DAC_OVERRIDE, CAP_CHECKPOINT_RESTORE, CAP_SYS_PACCT, CAP_SYS_PTRACE, CAP_MAC_ADMIN, CAP_WAKE_ALARM, CAP_AUDIT_WRITE, CAP_MAC_OVERRIDE, CAP_LEASE, CAP_SYS_RESOURCE, CAP_IPC_OWNER, CAP_FOWNER, CAP_SYS_MODULE, CAP_BLOCK_SUSPEND, CAP_AUDIT_CONTROL, CAP_AUDIT_READ, CAP_PERFMON, CAP_SYSLOG, CAP_NET_RAW, CAP_SYS_ADMIN, CAP_NET_BROADCAST, CAP_SYS_TTY_CONFIG, CAP_SETPCAP, CAP_NET_BIND_SERVICE, CAP_DAC_READ_SEARCH, CAP_SYS_BOOT})
# Inherited Ok({CAP_SETUID})
# Permitted Ok({CAP_SETUID})
# Ambient Ok({CAP_SETUID})
```

### Additional Resources

- [Linux capabilities - why they exist and how they work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [Linux capabilities in practice](https://blog.container-solutions.com/linux-capabilities-in-practice)
- [Redhat blog - Linux Capabilities](https://www.redhat.com/en/blog/linux-capabilities-in-openshift)
