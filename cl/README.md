Computer-Lab working dir
========================

Contains install scripts and other files

These instructions are given as executable Makefile and shell scripts, which were tested to work on a fresh Ubuntu docker container (as of 2023-09-18, on Ubuntu 20.04.5 LTS "focal", on an x86-64 machine).

Fresh build
-----------

From the Android root, run:

```make -C cl prepare```

This will install the necessary dependencies, get a modern clang binary and configure the kernel ready to be built

Now you should be able to run the build process:

```make -C cl build```

Booting in QEMU
---------------

From the Android root, run:

```./cl/run_qemu_install_disk.sh```

This will start QEMU and land you at the installation page for a modern-ish Debian distribution

Follow the install process until at the debian login

From then, you can use:

```./cl/run_qemu_debian.sh```

Which boots the previously-installed debian distribution in QEMU, landing at the debian login.
This should start up an ssh server, which can be accessed:

```ssh -p 8022 debian-username@localhost```

(substitute the `debian-username` with whatever you chose during install)


Running pKVM
------------

Once QEMU is booting a plain Debian, we can replace the kernel image with our custom-built one

First, build pKVM, e.g. with the helper:

```make -C cl build```

Then run QEMU with the new kernel, by running:

```./cl/run_pkvm.sh```
