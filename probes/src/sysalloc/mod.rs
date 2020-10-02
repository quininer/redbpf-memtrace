use cty::*;


#[repr(C)]
pub struct SysEvent {
    ty: Type,
    ip: u64,
    stack: [u64; 64],
    param1: u64,
    param2: u64,
    param3: u64,
    param4: u64,
    param5: u64,
    param6: u64,
    rc: u64
}

#[repr(C)]
pub enum Type {
    Mmap = 1,
    Unmmap,
    Brk,
    Sbrk
}
