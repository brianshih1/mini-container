# Isolate Filesystem

### Goal

We want to provide a process with an isolated view of the filesystem. In other words, we want to ensure the process cannot touch any files and directories from the host’s filesystem.

### Theory

A filesystem is an organized collection of files and directories. Each directory can be backed by a different filesystem. This is the power of the UNIX filesystem abstraction - all directories and files from all filesystems reside under a single directory tree.

To attach a filesystem to a directory, we use the `mount` command. The directory that we mount to is also known as the mount point.

```bash
$ mount device directory
```

To isolate the filesystem, we need to ensure that the process cannot have access to or modify any mounts of the host system. This is achieved with the help of the mount namespace.

**Mount Namespace**

According to Linux’s [doc](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html), “mount namespaces provide isolation of the list of mounts seen by the processes in each namespace instance. All of the processes that reside in the same mount namespace will see the same view in these files”.  Each mount namespace has its own set of mount points, and modifications to the mount points in one namespace do not affect other namespaces.

A new mount namespace can be created using either `clone` or `unshare` with the `CLONE_NEWNS` flag. There are a few things to keep in mind - if the namespace is created from `clone`, the parent process’s mount namespace will be copied to the child namespace; if the namespace is created from `unshare`, the caller’s previous mount namespace will be copied to the child namespace. This means that modifying files or directories in a newly created mount namespace can affect the host system.

To achieve isolation, we can use `unmount` to tear down the root mount. This will not affect the mount list seen in the host system because modifications to the mount list (via `mount` and `unmount`) will not affect other mount namespaces.

However, unmounting the root filesystem is usually not allowed because any files open in the root filesystem would prevent the unmount. But even if we manage to unmount the root filesystem, the system would be unusable as the process won’t be able to load any executables or access any devices.

Instead, what we want is to swap out the root filesystem with a new filesystem that contains the minimal required system files and libraries. This is where `pivot_root` comes in.

**pivot_root**

`pivot_root` is a system call that allows us to change the root mount in the mount namespace of the calling process. It takes two directories as arguments - `new_root` and `put_old` and it “moves the root mount to the directory `put_old` and makes `new_root` the new root mount.” The `put_old` directory must be at or underneath `new_root`.

```bash
$ pivot_root new_root put_old
```

Here are the steps to use `pivot_root` to achieve filesystem isolation for the container:

- create the `new_root` directory that will become the new root filesystem. An empty root filesystem is useless, so we need to put any necessary files to run the application into the `new_root` directory.
  - But how do you determine the “necessary files” to run an application? This is where Docker images become useful - Docker images can be thought of as an archive of root filesystems. We can download an image (like [alpine](https://alpinelinux.org/downloads/)) and extract it into the `new_root` directory. An image like `alpine` would not download the entire OS but an essential set of files of `alpine`.
- create a `put_old` directory inside the `new_root` directory.
- create a new mount namespace with `unshare`
- mount the `new_root` as Linux requires that the new_root is a mount point before changing the root filesystem
- use `pivot_root` to make `new_root` the new root filesystem. The `put_old` directory now points to the original root filesystem.
- unmount the `put_old` filesystem and remove the `put_old` directory.

After those steps, we have an isolated filesystem. Don’t worry if this seems a bit abstract, I will walk through this in detail in **Demo 2** below.

### Demo

**Demo 1: mount namespace**

First, let’s demonstrate that within a mount namespace, mounting or unmounting a filesystem wouldn’t affect other namespaces.

```bash
mkdir /tmp/ex
mkdir /tmp/ex/one
sudo unshare -m /bin/bash
mount -t tmpfs tmpfs /tmp/ex
ls /tmp/ex
# empty
mkdir /tmp/ex/foo
ls /tmp/ex
# foo

# From the host system
ls /tmp/ex
# one
```

In the example above, we created a directory `/tmp/ex` and a directory `/one` under it.

Next, we created a new mount namespace with `unshare` and `mount`ed a `tmpfs` filesystem onto `/tmp/ex`.

At this point, `/tmp/ex` is replaced with a new filesystem. We confirm that it’s no longer related to the filesystem in `/tmp/ex` in the host system by using `ls` to list all directories inside `/tmp/ex` and not seeing the `/one` directory we created earlier.

To show that modifications to the mounted filesystem have no impact on the host system, we created a directory `foo` under `/tmp/ex`. We perform `ls /tmp/ex` to confirm that `foo` is inside the directory.

Now when we check what’s inside `/tmp/ex` from the host system, we only see the original `one` directory and not the `foo` directory. This confirms that mounting a filesystem won’t affect other namespaces.

As a side note, if you ever want to see which processes are inside which mount namespace, you can use the `ps` command or look at `/proc/self/ns/mnt` like below:

```bash
sudo unshare -m /bin/bash

echo $$
# 6766
ps -o pid,mntns,args

# PID    MNTNS     COMMAND
# 6765 4026531841 sudo unshare -m /bin/bash
# 6766 4026532469 /bin/bash
# 6772 4026532469 ps -o pid,mntns,args

ls -l /proc/self/ns/mnt
# lrwxrwxrwx 1 root root 0 Dec 19 16:13 /proc/self/ns/mnt -> 'mnt:[4026532469]'
```

**Demo 2: isolate filesystem with pivot_root**

Earlier, we outlined the steps to use `pivot_root` to achieve filesystem isolation. Let’s put that into practice. We will be using [Alpine’s mini root filesystem image](https://alpinelinux.org/downloads/) as the new root filesystem. Here are the commands:

```bash
# download the alpine image
wget <https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/alpine-minirootfs-3.19.0-aarch64.tar.gz>
# create the new_root directory
mkdir alpine
# extract the alpine image into the new_root directory
tar -xvf alpine-minirootfs-3.19.0-aarch64.tar.gz -C alpine
cd alpine
echo > I_AM_ALPINE.txt

# create the mount namespace
sudo unshare -m
# make the new_root directory a mount point
mount --bind alpine alpine
# create the put_old directory
mkdir alpine/oldrootfs
cd alpine
# swap out the root filesystem
pivot_root . oldrootfs

cd /
ls
# I_AM_ALPINE.txt.    # bin     etc       lib       mnt       opt       root      sbin      sys       usr
# dev       home      media     old_root  proc      run       srv       tmp       var

ls /oldroot/
# bin         cdrom       etc         lib         media       old         opt         root        sbin        srv         sys         usr
# boot        dev         home        lost+found  mnt         old2        proc        run         snap        swapfile    tmp         var

umount -l old_root/
rmdir old_root/
```

We first download the alpine image and extract the alpine image into a newly created `alpine` directory that will serve as the `new_root` in `pivot_root`. Next, we create a mount point from the `alpine` directory.

Next, we need to create the `put_old` directory for `pivot_root` under the `alpine` directory, which is `alpine/oldrootfs`. Finally, we use `pivot_root` to swap out the root filesystem.

If we navigate to the root directory via `cd /` and verify that the root directory is indeed the Alpine filesystem (as it contains `I_AM_ALPINE.txt`). However, we can still see the `old_root` directory which points to the original root filesystem. Therefore, we need to unmount it and remove the directory to be isolated from the original filesystem of the host.

We can also verify the mount points in the host system as follows:

```bash
# host system. 10920 is the pid of the process with the isolated filesystem
cat /proc/10920/mounts
# /dev/vda2 / ext4 rw,relatime,errors=remount-ro 0 0

cat /proc/10920/mountinfo
# 1066 985 252:2 /home/brianshih/alpine / rw,relatime - ext4 /dev/vda2 rw,errors=remount-ro
```

We can see that the process with the isolated filesystem only has one mount point whose root is `/home/brianshih/alpine`.

### Implementation

The implementation for my toy container is more-or-less just Demo 2 in the form of Rust code.

Here is a wrapper helper function around the `mount` system call. Note that according to the Linux [doc](https://man7.org/linux/man-pages/man8/mount.8.html), if only the directory is provided, then `mount` modifies an existing mount point.

```rust
// Wrapper around the mount syscall
fn mount_filesystem(
    filesystem_path: Option<&PathBuf>,
    target_directory: &PathBuf,
    flags: Vec<MsFlags>,
) -> ContainerResult {
    let mut mountflags = MsFlags::empty();
    for flag in flags {
        mountflags.insert(flag);
    }
    match mount::<PathBuf, PathBuf, PathBuf, PathBuf>(
        filesystem_path,
        target_directory,
        None,
        mountflags,
        None,
    ) {
        Ok(_) => Ok(()),
        Err(err) => {
            return Err(ContainerError::MountSysCall);
        }
    }
}
```

Here is the code that isolates the filesystem.

```rust
fn isolate_filesystem(config: &ChildConfig) -> ContainerResult {
    mount_filesystem(
        None,
        &PathBuf::from("/"),
        vec![MsFlags::MS_REC, MsFlags::MS_PRIVATE],
    )?;
    let filesystem_path = PathBuf::from("/home/brianshih/alpine");
    mount_filesystem(
        Some(&filesystem_path),
        &filesystem_path,
        vec![MsFlags::MS_BIND, MsFlags::MS_PRIVATE],
    )?;
    let root_filesystem_path = &config.root_filesystem_directory;
    let old_root_path = "oldrootfs";
    let old_root_absolute_path = PathBuf::from(format!("{root_filesystem_path}/{old_root_path}"));
    if let Err(e) = create_dir_all(&old_root_absolute_path) {
        return Err(ContainerError::CreateDir);
    }

    if let Err(e) = pivot_root(&filesystem_path, &PathBuf::from(old_root_absolute_path)) {
        return Err(ContainerError::PivotRoot);
    };
    if let Err(e) = umount2(
        &PathBuf::from(format!("/{old_root_path}")),
        MntFlags::MNT_DETACH,
    ) {
        return Err(ContainerError::Umount);
    }
    if let Err(e) = remove_dir(&PathBuf::from(format!("/{old_root_path}"))) {
        return Err(ContainerError::RemoveDir);
    };
		// Change the directory to the root directory
    if let Err(e) = chdir(&PathBuf::from("/")) {
        return Err(ContainerError::ChangeDir);
    };
    Ok(())
}
```

Something we didn’t cover is the propagation type of a mount point. Each mount point is one of four types: `MS_SHARED`, `MS_PRIVATE`, `MS_SLAVE`, and `MS_UNBINDABLE`. Mount points of type `MS_SHARED` are shared across different mounts of the same peer group (learn more about peer groups [here](https://lwn.net/Articles/689856/)). Mount points of type `MS_PRIVATE` do not propagate events to their peers.

In my code snippet, we recursively set all mount points in the root filesystem to `MS_PRIVATE` to make sure that no events are propagated to other mount namespaces.

Apart from that, the code is fairly straightforward and reproduces what we did in Demo 2.

### Testing the Implementation

To test whether the process has an isolated filesystem, we first create the `alpine` directory which will serve as the directory for the new root.

Next, we create the container environment and run `/bin/ash` via `sudo target/debug/mini-container /bin/ash /home/brianshih/alpine`. `/home/brianshih/alpine` is the path to the new root filesystem for our container.

After that, we navigate to the root directory and confirm that the root filesystem is the one created from the `alpine` directory.

```bash
# download the alpine image
wget <https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/alpine-minirootfs-3.19.0-aarch64.tar.gz>
# create the new_root directory
mkdir alpine
# extract the alpine image into the new_root directory
tar -xvf alpine-minirootfs-3.19.0-aarch64.tar.gz -C alpine
cd alpine
echo > I_AM_ALPINE.txt

sudo target/debug/mini-container /bin/ash /home/brianshih/alpine
cd /
ls
# I_AM_ALPINE.txt  lib              root             tmp
# bin              media            run              usr
# dev              mnt              sbin             var
# etc              opt              srv
# home             proc             sys
```

### Additional Resources

- [Docker Security Blog - Mount Namespace](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/namespaces/mount-namespace)
- [Building a container from scratch - part 2](https://techtalk.digitalpress.blog/building-a-container-from-scratch-part-2/)
- [Blog about mount namespaces and shared subtrees](https://lwn.net/Articles/689856/)
