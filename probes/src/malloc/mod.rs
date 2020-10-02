use cty::*;


#[repr(C)]
#[derive(Debug)]
pub struct MemEvent {
    pub ty: Type,
    pub _reserve: u32,
    pub tid: u32,
    pub stackid: c_int,
    pub param1: u64,
    pub param2: u64,
    pub param3: u64,
    pub rc: u64
}

#[repr(C)]
#[derive(Debug)]
pub enum Type {
    Malloc = 1,
    Free,
    Calloc,
    Realloc,
    ReallocArray
}
