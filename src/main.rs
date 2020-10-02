use std::collections::HashMap;
use argh::FromArgs;
use redbpf::{ StackTrace, BpfStackFrames };
use redbpf::load::{ Loader, Loaded };
use tokio::signal;
use tokio::stream::StreamExt;
use probes::malloc::*;


/// eBPF-based Memory tracking tools
#[derive(FromArgs, Debug)]
pub struct Options {
    /// process id
    #[argh(positional)]
    pid: libc::pid_t,

    /// libc path
    #[argh(option)]
    libc: Option<String>
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options: Options = argh::from_env();

    if unsafe { libc::getuid() } != 0 {
        anyhow::bail!("You must be root to use eBPF!");
    }

    let mut loader = Loader::load(malloc_probe_code())
        .map_err(|err| anyhow::format_err!("redbpf: {:?}", err))?;

    let libc = options.libc.as_deref().unwrap_or("/usr/lib/libc.so.6");
    for uprobe in loader.uprobes_mut() {
        let name = uprobe.name();
        let name = name.trim_end_matches("_entry").trim_end_matches("_ret");
        uprobe.attach_uprobe(Some(name), 0, libc, Some(options.pid))
            .map_err(|err| anyhow::format_err!("redbpf: {:?}", err))?;
    }

    let Loaded { module, mut events } = loader;

    tokio::spawn(async move {
        let mut stacks2: HashMap<i32, BpfStackFrames> = HashMap::with_capacity(1024);

        let stacks = module.maps.iter()
            .find(|m| m.name == "malloc_stack")
            .unwrap();
        let mut stacks = StackTrace::new(stacks);

        while let Some((name, events)) = events.next().await {
            if name != "malloc_event" {
                eprintln!("unknown event: {:?}", name);
                continue
            }

            for event in events {
                let event = event.as_ptr().cast::<MemEvent>();
                let event = unsafe { event.read() };

                println!("{:?}", event);

                if let Some(stack) = stacks.get(event.stackid) {
                    println!("{:p}", stack.ip[0] as *const u8);

                    stacks2.insert(event.stackid, stack);
                    stacks.remove(event.stackid);
                } else if let Some(stack) = stacks2.get(&event.stackid) {
                    println!("{:p}", stack.ip[0] as *const u8);
                }
            }
        }
    });

    signal::ctrl_c().await?;

    Ok(())
}

fn malloc_probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/malloc/malloc.elf"
    ))
}

fn sysalloc_probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/sysalloc/sysalloc.elf"
    ))
}
