#![no_std]
#![no_main]

use cty::*;
use redbpf_probes::kprobe::prelude::*;
use probes::sysalloc::SysEvent;

program!(0xFFFFFFFE, "GPL");

#[map("event")]
static mut events: PerfMap<SysEvent> = PerfMap::with_max_entries(1024);

#[kprobe("__x64_sys_mmap")]
fn syscall_mmap(regs: Registers) {
    // TODO
}

#[kprobe("__x64_sys_unmmap")]
fn syscall_unmmap(regs: Registers) {
    // TODO
}

#[kprobe("__x64_sys_brk")]
fn syscall_brk(regs: Registers) {
    // TODO
}

#[kprobe("__x64_sys_sbrk")]
fn syscall_sbrk(regs: Registers) {
    // TODO
}
