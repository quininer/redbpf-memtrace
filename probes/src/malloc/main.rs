#![no_std]
#![no_main]

use cty::*;
use redbpf_probes::uprobe::prelude::*;
use probes::malloc::{ MemEvent, Type };

program!(0xFFFFFFFE, "GPL");

#[map("malloc_event")]
static mut malloc_event: PerfMap<MemEvent> = PerfMap::with_max_entries(1024);

#[map("malloc_stack")]
static mut malloc_stack: StackTrace = StackTrace::with_capacity(1024);

fn record(regs: &Registers, ty: Type) {
    let tid = unsafe { bpf_get_current_pid_tgid() & 0xffffffff };

    let mut event = MemEvent {
        ty,
        tid: tid as u32,
        stackid: 0,
        param1: regs.parm1(),
        param2: regs.parm2(),
        param3: regs.parm3(),
        rc: regs.rc(),
        _reserve: 0
    };

    unsafe {
        if let Ok(stackid) = malloc_stack.stackid(regs.ctx, BPF_F_USER_STACK as _) {
            event.stackid = stackid;
        }

        malloc_event.insert(regs.ctx, &event);
    }
}

#[uprobe]
fn malloc(regs: Registers) {
    record(&regs, Type::Malloc)
}

#[uprobe]
fn free(regs: Registers) {
    record(&regs, Type::Free)
}

#[uprobe]
fn calloc(regs: Registers) {
    record(&regs, Type::Calloc)
}

#[uprobe]
fn realloc(regs: Registers) {
    record(&regs, Type::Realloc)
}

#[uprobe]
fn reallocarray(regs: Registers) {
    record(&regs, Type::ReallocArray)
}
