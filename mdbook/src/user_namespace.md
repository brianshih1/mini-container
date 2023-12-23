# User Namespace

### Goal

The best way to prevent privilege-escalation attacks from within a container is to run the container’s executable as an unprivileged user. However, some applications require the process to run as a `root` user. Therefore, our goal is to set up an environment such that the user within the container is privileged but unprivileged to the host system.

### Theory

User Namespaces isolate security-related identifiers. According to [Linux’s doc](https://man7.org/linux/man-pages/man7/user_namespaces.7.html), “a process’s user and group IDs can be different inside and outside a namespace. In particular, a process can have a normal unprivileged user ID outside a user namespace while at the same time having a user ID of 0 inside the namespace”.

Furthermore, user namespaces are nested. Apart from the root namespace, each namespace has a parent namespace, which is the user namespace of the process that created the user namespace via a call to `unshare` or `clone` with the `CLONE_NEWUSER` flag.

The user namespace is what enables a container to run as a `root` user within a container but have unprivileged access outside the container, which prevents privilege-escalation attacks.

**User mappings**

When a user namespace is created, it starts without a mapping of User IDs to the parent user namespace. The `/proc/pid/uid_map`, which resides in the parent user namespace, maps the User IDs inside the parent user namespace to the User IDs inside the child user namespace.

Each line in the `uid_map` takes the form:

```rust
ID-in-child-ns   ID-in-parent-ns   length
```

`ID-in-child-ns`,  `ID-in-parent-ns`, and `length` specifies that a range of user IDs of `length` starting from `ID-in-child-ns` are mapped to a range of user IDs of `length` in the parent user namespace starting with `ID-in-parent-ns`.

For example, a line of `0 1000 1` means that the user with `User ID 0` in the child user namespace maps to the user with `User ID 1000`.

### Demo

In the demo below, we first create a user namespace with the `-U` flag. According to the [Linux doc](https://man7.org/linux/man-pages/man7/user_namespaces.7.html), an unmapped User ID is converted to the overflow user ID which is `65534`. This is why the `uid=65534`. However, when we check the `User ID` for the process via `ps -o 'pid uid user command' -a`, we can see that the UID is `1000`, the same User as the parent process’s user.

After retrieving the `pid` of the child process via `echo $$`, we write `0 1000 1` into the `uid_map` of the parent user namespace. We then check the `user ID` of the child process and now see `0`.

Even though the User ID of the child process is `0`, if we check the `uid` from the parent user namespace, it’s still 1000. We have successfully mapped the original user ID of `1000` to `0` in the new user namespace.

```bash
id
# uid=1000(brianshih) gid=1000(brianshih) groups=1000(brianshih) ...
unshare -U
id
# uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
echo $$
# 10087

# host system
ps -o 'pid uid user command' -a
# PID   UID USER     COMMAND
10087  1000 briansh+ -bash
echo '0 1000 1' > /proc/10087/uid_map

# in the child process
id
# uid=0(root) gid=65534(nogroup) groups=65534(nogroup)

# host system
ps -o 'pid uid user command' -a
# PID    UID  USER     COMMAND
# 10087  1000 briansh+ -bash
```

### Implementation

The implementation is split into two portions:

- `user_ns`: creating a new user namespace in the child process
- `handle_child_uid_map`: updating to the `uid_map` in the parent process.

We can see that in the `run` method below, we `handle_child_uid_map` method is run after `create_child_process`. This is because to write to the `uid_map`, the parent process needs the newly created process’s `pid`.

```rust
fn run() -> ContainerResult {
    ...

    let child_pid = create_child_process(&config)?;

    handle_child_uid_map(child_pid, parent_socket.as_raw_fd(), config.user_id.clone())?;
    ...
}
```

Here is the code to create a new user namespace with `unshare`. After creating the new user namespace, the child process notifies the parent process that the child process has created a new user namespace. Next, the child process waits until the parent updates the `uid_map` before using `setresuid` to set the new `user_id`, which is likely `0`.

```rust
fn user_ns(config: &ChildConfig) -> ContainerResult {
    if let Err(e) = unshare(CloneFlags::CLONE_NEWUSER) {
        println!("Failed to unshare with new user namespace: {:?}", e);
        return Err(ContainerError::UnshareNewUser);
    }

    // Notifies the parent process that the child process has created a new user namespace
    socket_send(config.socket_fd)?;

    // Wait for the parent process to update the uid_map before setting the uid

    socket_recv(config.socket_fd)?;

    if let Some(user_id) = config.user_id {
        println!("Setting UID to: {:?}", config.user_id);
        if let Err(e) = setresuid(
            Uid::from_raw(user_id),
            Uid::from_raw(user_id),
            Uid::from_raw(user_id),
        ) {
            println!("Failed to set uid. Error: {:?}", e);
            return Err(ContainerError::SetResuid);
        };
    }

    Ok(())
```

Here is the code for how the parent updates the `uid_map`. It first waits for the user to create a user namespace via `socket_recv`. It then writes to the `uid_map` file and `gid_map` file. Finally, it uses `socket_send` to notify the child that the `uid_map` is updated.

```rust
fn handle_child_uid_map(pid: Pid, fd: i32, user_id: Option<u32>) -> ContainerResult {
    // Wait for the user to create a user namespace
    socket_recv(fd)?;

    let user_id = match user_id {
        Some(id) => id,
        None => 0, // default to run as root if no user ID is provided
    };

    println!("Updating uid_map");
    match File::create(format!("/proc/{}/{}", pid.as_raw(), "uid_map")) {
        Ok(mut uid_map) => {
            if let Err(e) = uid_map.write_all(format!("0 {} {}", 1000, 1000).as_bytes()) {
                println!("Failed to write to uid_map. Error: {:?}", e);
                return Err(ContainerError::UidMap);
            }
        }
        Err(e) => {
            println!("Failed to create uid_map. Error: {:?}", e);
            return Err(ContainerError::UidMap);
        }
    }

    match File::create(format!("/proc/{}/{}", pid.as_raw(), "gid_map")) {
        Ok(mut uid_map) => {
            if let Err(e) = uid_map.write_all(format!("0 {} {}", 1000, 1000).as_bytes()) {
                println!("Failed to write to uid_map. Error: {:?}", e);
                return Err(ContainerError::UidMap);
            }
        }
        Err(e) => {
            println!("Failed to create uid_map. Error: {:?}", e);
            return Err(ContainerError::UidMap);
        }
    }

    println!("Finished updating uid_map. Notifying child process");

    // Notify the user that the uid_map is updated
    socket_send(fd)?;
    Ok(())
}
```

### Testing the Implementation

We create the container environment and set the new user ID to 0 via `--user 0`. We then confirm that `id` inside the container is `0`.

In the host system, we confirm that the process used to run the executable, `/bin/ash` has a UID of `1000`. This confirms that the `uid_mapping` worked.

```bash
id
# uid=1000(brianshih) ...
sudo target/debug/mini-container /bin/ash /home/brianshih/alpine --user 0
id
# uid=0(root)

# host system
ps -o 'pid uid user command' -a

# PID    UID  USER     COMMAND
# 10074  0    root     target/debug/mini-container /bin/ash /home/brianshih/alpi
# 10075  1000 briansh+ /bin/ash
```

### Additional Resources

- [Blog about docker security - user namespace](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/namespaces/user-namespace)
- [Namespaces in operation, part 5: User namespaces](https://lwn.net/Articles/532593/)
- [Docker blog - Isolate containers with a user namespace](https://docs.docker.com/engine/security/userns-remap/)
- [Demo of how user namespace works with Docker](https://dockerlabs.collabnix.com/advanced/security/userns/)
