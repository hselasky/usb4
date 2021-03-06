#!/bin/sh

# panic: crp_iv_start set when IV isn't used
# cpuid = 15
# time = 1620460567
# KDB: stack backtrace:
# db_trace_self_wrapper() at db_trace_self_wrapper+0x2b/frame 0xfffffe023ceef5d0
# vpanic() at vpanic+0x181/frame 0xfffffe023ceef620
# panic() at panic+0x43/frame 0xfffffe023ceef680
# crp_sanity() at crp_sanity+0x236/frame 0xfffffe023ceef6b0
# crypto_dispatch() at crypto_dispatch+0xf/frame 0xfffffe023ceef6d0
# crypto_ioctl() at crypto_ioctl+0x1e33/frame 0xfffffe023ceef7e0
# devfs_ioctl() at devfs_ioctl+0xcd/frame 0xfffffe023ceef830
# VOP_IOCTL_APV() at VOP_IOCTL_APV+0x59/frame 0xfffffe023ceef850
# vn_ioctl() at vn_ioctl+0x133/frame 0xfffffe023ceef960
# devfs_ioctl_f() at devfs_ioctl_f+0x1e/frame 0xfffffe023ceef980
# kern_ioctl() at kern_ioctl+0x289/frame 0xfffffe023ceef9f0
# sys_ioctl() at sys_ioctl+0x12a/frame 0xfffffe023ceefac0
# amd64_syscall() at amd64_syscall+0x147/frame 0xfffffe023ceefbf0
# fast_syscall_common() at fast_syscall_common+0xf8/frame 0xfffffe023ceefbf0
# --- syscall (0, FreeBSD ELF64, nosys), rip = 0x8003827da, rsp = 0x7fffffffe4e8, rbp = 0x7fffffffe540 ---
# KDB: enter: panic
# [ thread pid 18612 tid 109119 ]
# Stopped at      kdb_enter+0x37: movq    $0,0x1281a2e(%rip)
# db> x/s version
# version: FreeBSD 14.0-CURRENT #0 main-n246560-2018d488628: Sat May  8 08:32:52 CEST 2021
# pho@t2.osted.lan:/usr/src/sys/amd64/compile/PHO
# db>

[ `uname -p` != "amd64" ] && exit 0
[ `id -u ` -ne 0 ] && echo "Must be root!" && exit 1

. ../default.cfg
cat > /tmp/syzkaller37.c <<EOF
// https://syzkaller.appspot.com/bug?id=9c74fee9d6ceabfff73819e94328a18723217cf9
// autogenerated by syzkaller (https://github.com/google/syzkaller)
// Reported-by: syzbot+220faa5eeb4d47b23877@syzkaller.appspotmail.com

#define _GNU_SOURCE

#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/endian.h>
#include <sys/syscall.h>
#include <unistd.h>

uint64_t r[1] = {0xffffffffffffffff};

int main(void)
{
  syscall(SYS_mmap, 0x20000000ul, 0x1000000ul, 7ul, 0x1012ul, -1, 0ul);
  intptr_t res = 0;
  memcpy((void*)0x20000340, "/dev/crypto\000", 12);
  res = syscall(SYS_openat, 0xffffffffffffff9cul, 0x20000340ul, 0ul, 0ul);
  if (res != -1)
    r[0] = res;
  *(uint32_t*)0x20000040 = 0x10;
  *(uint32_t*)0x20000044 = 0x1d;
  *(uint32_t*)0x20000048 = 1;
  *(uint64_t*)0x20000050 = 0x20000080;
  memset((void*)0x20000080, 66, 1);
  *(uint32_t*)0x20000058 = 0;
  *(uint64_t*)0x20000060 = 0;
  *(uint32_t*)0x20000068 = 0;
  *(uint32_t*)0x2000006c = 0xfdffffff;
  *(uint32_t*)0x20000070 = 0;
  *(uint32_t*)0x20000074 = 0;
  *(uint32_t*)0x20000078 = 0;
  *(uint32_t*)0x2000007c = 0;
  syscall(SYS_ioctl, r[0], 0xc040636aul, 0x20000040ul);
  *(uint32_t*)0x20000000 = 0;
  *(uint16_t*)0x20000004 = 2;
  *(uint16_t*)0x20000006 = 0;
  *(uint32_t*)0x20000008 = 0;
  *(uint32_t*)0x2000000c = 0x10001;
  *(uint32_t*)0x20000010 = 0;
  *(uint64_t*)0x20000018 = 0;
  *(uint64_t*)0x20000020 = 0;
  *(uint64_t*)0x20000028 = 0x200001c0;
  *(uint64_t*)0x20000030 = 0x20000380;
  *(uint64_t*)0x20000038 = 0;
  syscall(SYS_ioctl, r[0], 0xc040636dul, 0x20000000ul);
  return 0;
}
EOF
mycc -o /tmp/syzkaller37 -Wall -Wextra -O0 /tmp/syzkaller37.c ||
    exit 1

kldload cryptodev.ko && loaded=1
(cd /tmp; timeout 3m ./syzkaller37)
[ $loaded ] && kldunload cryptodev.ko

rm -rf /tmp/syzkaller37 /tmp/syzkaller37.c /tmp/syzkaller.*
exit 0
