#!/bin/zsh

DIR=${0:A:h}
ROOT=${0:A:h:h:h}

aarch64-none-elf-objcopy --only-keep-debug ${ROOT}/vmlinux ${DIR}/kernel-pkvm.sym
cd ${DIR}
aarch64-none-elf-gdb -x setup.gdb
