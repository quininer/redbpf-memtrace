use std::fs::File;
use std::collections::hash_map::{ HashMap, Entry };
use argh::FromArgs;
use tokio::{ task, signal };
use tokio::stream::StreamExt;
use redbpf::{ StackTrace, BpfStackFrames };
use redbpf::load::{ Loader, Loaded };
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

    let _fd = File::open(format!("/proc/{}/exe", options.pid))?;

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

    let local = task::LocalSet::new();

    let j = local.run_until(async move {
        let mut stacks2: HashMap<i32, BpfStackFrames> = HashMap::with_capacity(1024);

        let stacks = module.maps.iter()
            .find(|m| m.name == "malloc_stack")
            .ok_or_else(|| anyhow::format_err!("not found malloc_stack"))?;
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

                let stack = if let Some(stack) = stacks.get(event.stackid) {
                    let stack = match stacks2.entry(event.stackid) {
                        Entry::Occupied(mut v) => {
                            v.insert(stack);
                            v.into_mut()
                        },
                        Entry::Vacant(v) => v.insert(stack)
                    };

                    stacks.remove(event.stackid);

                    Some(stack as &_)
                } else {
                    stacks2.get(&event.stackid)
                };

                if let Some(stack) = stack {
                    // TODO symbolize
                    eprintln!("{:#?}", &stack.ip[..5]);
                }
            }
        }

        Ok(()) as anyhow::Result<()>
    });

    tokio::select!{
        ret = signal::ctrl_c() => ret?,
        ret = j => ret?
    }

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
