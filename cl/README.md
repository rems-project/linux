Computer-Lab working dir
========================

Contains install scripts and other files

These instructions are given as executable Makefile and shell scripts, which were tested to work on a fresh Ubuntu docker container (as of 2023-11-01, on Ubuntu 20.04.5 LTS "focal", on a host x86-64 machine).

First time setup
----------------

If in a Docker container, run:

```make -C cl prepare-container```

This will install the usual `apt` packages for Linux and QEMU and others,
skip this step if on legion or other machine. Either way, continue with remainder of setup instructions.

From the Linux root directory, run:

```make -C cl prepare```

(5 minutes)

This will install the necessary dependencies,
download a modern clang binary,
configure the kernel ready to build pKVM,
and grab an image and firmware for QEMU.

Now you should be able to build a kernel image:

```make -C cl build```

(7 minutes, although now future re-builds are much quicker)

We now have a kernel image (as `arch/arm64/boot/Image`),
and QEMU firmware, install media, and a blank disk to install into.

Ensure `qemu-system-aarch64` is installed (tested with "QEMU emulator version 4.2.1 (Debian 1:4.2-3ubuntu6.27)")

Now run QEMU, attaching the firmware and empty disk, and the install media,
using the helper script, following the instructions to get a Debian install:

```./cl/run_qemu_install_disk.sh```

(30 minutes, this is long, but a one-time setup)

Let it run until it reboots and reaches the Debian login,
then quit QEMU (with Ctrl-A to get the QEMU console, then q to quit).

Now we can run QEMU with our fresh Debian install
(but not using the kernel we compiled earlier)
whenever we want, with the helper script:

```./cl/run_qemu_debian.sh```

Which boots the previously-installed debian distribution in QEMU, landing at the debian login.
This should start up an ssh server, which can be accessed:

```ssh -p 8022 debian-username@localhost```

(substitute the `debian-username` with whatever you chose during install)

Running pKVM
------------

Run QEMU with the new kernel, by running:

```./cl/run_pkvm.sh```

This runs QEMU with the Debian disk we made during the first time setup,
but with the Linux kernel we compiled running pKVM.


Booting a VM
------------

Once the pKVM has booted, in another terminal we can run
another helper script that sets up some binaries to run as a VM
(one-time setup):

```./cl/setup_pkvm_ssh.sh```

Then can ssh into the Debian running in QEMU and ask it to start a VM using the lkvm virtual machine manager,
by running:

```./cl/ssh_pkvm.sh```

Debugging pKVM
--------------

To attach a debugger, in one terminal run:

```./cl/run_pkvm.sh -s -S```

NOTE: lkvm requires sudo privileges to run, the default Debian user might not have sudo privileges so you may want to add the user to sudoers.

Then in another, run:

```./cl/run_gdb.sh```

GDB will start up, read a script (cl/pkvm.gdb) and read some symbols from the image.
pKVM will start to boot, then pause at a clean point (once the alternatives have been applied).
At this point one can add more breakpoints in GDB, or have it continue, and otherwise drive GDB as normal.

Configuration scripts
---------------------

There are a number of scripts for automatically configuring the Linux build for ghost checking.
See [./scripts/config/README.md](./scripts/config/README.md) for details.
