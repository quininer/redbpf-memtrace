#![no_std]
pub mod malloc;
pub mod sysalloc;

#[cfg(feature = "probes")]
pub mod sys {
    include!(concat!(env!("OUT_DIR"), "/gen_bindings.rs"));
}
