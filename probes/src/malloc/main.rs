#![no_std]
#![no_main]

use paste::paste;
use cty::*;
use redbpf_probes::uprobe::prelude::*;
use probes::malloc::{ MemEvent, Type };

program!(0xFFFFFFFE, "GPL");

#[map("malloc_event")]
static mut malloc_event: PerfMap<MemEvent> = PerfMap::with_max_entries(1024);

#[map("malloc_stack")]
static mut malloc_stack: StackTrace = StackTrace::with_capacity(1024);

#[map("malloc_info")]
static mut malloc_info: HashMap<Key, MemEvent> = HashMap::with_max_entries(1024);

#[repr(C)]
struct Key {
    ty: Type,
    tid: u32
}

fn step(regs: &Registers, ty: Type) {
    let tid = unsafe { bpf_get_current_pid_tgid() & 0xffffffff } as u32;
    let key = Key { ty, tid };

    let mut event = MemEvent {
        ty, tid,
        stackid: 0,
        param1: regs.parm1(),
        param2: regs.parm2(),
        param3: regs.parm3(),
        rc: 0,
        _reserve: 0
    };

    unsafe {
        if let Ok(stackid) = malloc_stack.stackid(regs.ctx, BPF_F_USER_STACK as _) {
            event.stackid = stackid;
        }

        malloc_info.set(&key, &event);
    }
}

fn record(regs: &Registers, ty: Type) {
    let tid = unsafe { bpf_get_current_pid_tgid() & 0xffffffff } as u32;
    let key = Key { ty, tid };

    unsafe {
        if let Some(event) = malloc_info.get_mut(&key) {
            event.rc = regs.rc();

            malloc_event.insert(regs.ctx, event);
            malloc_info.delete(&key);
        }
    }
}

macro_rules! record {
    ( $name:ident = $ty:expr ) => {
        paste!{
            #[uprobe]
            fn [< $name _entry >] (regs: Registers) {
                step(&regs, $ty)
            }

            #[uretprobe]
            fn [< $name _ret >] (regs: Registers) {
                record(&regs, $ty)
            }
        }
    };
    ( $( $name:ident = $ty:expr );* ) => {
        $(
            record!($name = $ty);
        )*
    }
}

record! {
    malloc          = Type::Malloc;
    calloc          = Type::Calloc;
    realloc         = Type::Realloc;
    reallocarray    = Type::ReallocArray;
    posix_memalign  = Type::PosixMemalign;
    aligned_alloc   = Type::AlignedAlloc;
    valloc          = Type::Valloc;
    memalign        = Type::Memalign;
    pvalloc         = Type::PvAlloc
}

#[uprobe]
fn free(regs: Registers) {
    let tid = unsafe { bpf_get_current_pid_tgid() & 0xffffffff } as u32;

    let mut event = MemEvent {
        ty: Type::Free,
        tid,
        stackid: 0,
        param1: regs.parm1(),
        param2: regs.parm2(),
        param3: regs.parm3(),
        rc: 0,
        _reserve: 0
    };

    unsafe {
        if let Ok(stackid) = malloc_stack.stackid(regs.ctx, BPF_F_USER_STACK as _) {
            event.stackid = stackid;
        }

        malloc_event.insert(regs.ctx, &event);
    }
}
