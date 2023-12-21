# What exactly is a Container?

The concept of containers is rooted in Linux. Check out this [RedHat blog](https://www.redhat.com/en/blog/history-containers) about the history of containers. When people talk about containers, they are more or less talking about Linux containers.

However, the Linux Kernel doesn’t have a native object that represents a “container”. From the perspective of the kernel, containers are just processes. But what makes these processes special?

The best way to look at the properties of a process in a container is to look at some demos with the help of `Docker`, a tool that can create and run containers.

### Filesystem Isolation

Firstly, a process in a container has an isolated view of the filesystem. In the demo below, we created a container based on the `ubuntu` image.

If we navigate to the root directory via `cd /`, we notice that the root filesystem of the process in a container is not the same one as the root filesystem on the host system. Modifying the root filesystem within the container will have no impact on the host system.

```docker
docker run -it ubuntu bash
cd /
ls
# bin  boot  dev  etc  home  lib  media  mnt  opt  proc
#  root  run  sbin  srv  sys  tmp  usr  var

# host system
cd /
ls
# bin    dev   lib         mnt   opt   run   srv       tmp
# boot   etc   lost+found  proc  sbin  swapfile  usr
# cdrom  home  media       root  snap  sys       var
```

The new root filesystem comes from the `ubuntu` image. A docker image is an executable file. A docker image is made up of filesystems layered over each other. These layers form the base for a container’s root filesystem.

### Pid Isolation

Processes in a container has an isolated view of other processes running on the host. In the example below, if we perform `ps -a -u` to list all processes in the container, we only see the process running `bash` and `ps -a -u`. However, if we perform `ps -a -u`, we see a lot more processes.

Furthermore, in the example below the process perceives its `pid` as `1`. However, from the perspective of the host system the process running `bash` is `6098`.

```bash
docker run -it ubuntu bash
ps -a -u
# USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
# root           1  0.2  0.0   4136  3200 pts/0    Ss   07:19   0:00 bash
# root           9  0.0  0.0   6412  2432 pts/0    R+   07:19   0:00 ps -a -u
echo $$
# 1

# host system
ps -a -u
# USER     PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...
root       6098  0.0  0.0   4136  3200 pts/0    Ss+  15:19   0:00 bash
```

### User ID Isolation

In a container, things like the user ID and group ID are isolated. What this unlocks is that a process can run as a root user inside the container while actually being an unprivileged user on the host.

In the example below, we enable the `user namespace` via `--userns-remap=default`. The process in the container perceives its `uid` as 0. But if we look at the user corresponding to the process from the host system, the user is in fact `165536`.

```docker
sudo dockerd --userns-remap=default
sudo docker run -it --rm busybox /bin/sh
id
# uid=0(root) gid=0(root) groups=0(root),10(wheel)

# host system
ps -a -u
# USER        PID   %CPU %MEM    VSZ   RSS TTY     STAT  START TIME  COMMAND
# ...
# 165536     14154  0.0  0.0   3984  1920 pts/0    Ss+  14:33   0:00 /bin/sh
```

### Resource Restriction

In Docker, you can constrain resources on the container. For example, you can limit the amount of memory the process can take, the number of CPUs the container can run on, etc. Check out [Docker’s doc](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources) for the full list of resources that can be constrained.

As an example, here is how you can limit the container to have a memory limit of 128 mb.

```bash
docker run -it --memory 128m ubuntu bash
```

## Secret behind Docker

So how does Docker achieve all these different forms of isolation and resource restriction? It boils down to the following Linux primitives:

- Namespaces
- Capabilities
- cgroups

We will cover these in greater detail throughout the blog!
