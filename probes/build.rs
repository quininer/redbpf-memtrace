use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

use cargo_bpf_lib::bindgen as bpf_bindgen;

fn create_module(path: PathBuf, name: &str, bindings: &str) -> io::Result<()> {
    let mut file = File::create(path)?;
    writeln!(
        &mut file,
        r"
mod {name} {{
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(unused_unsafe)]
#![allow(clippy::all)]
{bindings}
}}
pub use {name}::*;
",
        name = name,
        bindings = bindings
    )
}

fn main() {
    if env::var("CARGO_FEATURE_PROBES").is_err() {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let mut bindings = bpf_bindgen::builder()
        .header_contents("bindings.h", "\
            #define KBUILD_MODNAME \"cargo_bpf_bindings\"\n\
            #include <linux/kconfig.h>\n\
            #include <linux/types.h>\n\
            #ifdef asm_volatile_goto\n\
            #undef asm_volatile_goto\n\
            #define asm_volatile_goto(x...) asm volatile(\"invalid use of asm_volatile_goto\")\n\
            #endif\n\
            #ifdef asm_inline\n\
            #undef asm_inline\n\
            #define asm_inline asm\n\
            #endif\n\
            #include <linux/sched.h>\n\
        ")
        .whitelist_type("task_struct")
        .generate()
        .expect("failed to generate bindings")
        .to_string();

    let accessors = bpf_bindgen::generate_read_accessors(&bindings, &["task_struct"]);
    bindings.push_str("use redbpf_probes::helpers::bpf_probe_read;");
    bindings.push_str(&accessors);
    create_module(out_dir.join("gen_bindings.rs"), "gen_bindings", &bindings).unwrap();
}
