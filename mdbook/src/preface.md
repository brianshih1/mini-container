# Preface

I’ve been using Docker for many years, but I’ve always treated it as a magical black box. I know that Docker creates containers which are isolated environments to run code. However, I don’t know what “isolated” really means. To unveil the black box, I decided to implement containers from scratch in Rust.

Luckily, there are a ton of tutorials and resources online that I can learn from. My implementation is largely based on these two blogs in particular: [Linux Containers in 500 Lines of Code](https://blog.lizzie.io/linux-containers-in-500-loc.html) & [Writing a Container in Rust](https://litchipi.github.io/series/container_in_rust). As someone who knew very little about Linux, the experience of building a container is extremely eye-opening and rewarding.

Here is a summary of what we will build:

- root filesystem isolation with mount namespace
- resource restriction with cgroups
- limit syscalls with seccomp
- isolate user IDs and group IDs with user namespace and uid mapping
- privilege control with capabilities

In this blog series, I will cover the theory behind and the implementation of a container from the perspective of someone new to Linux. I will also provide as many demos as possible to demonstrate how the Linux primitives that make up a container work.

The full source code is available [here](https://github.com/brianshih1/mini-container).
