use argh::FromArgs;
use redbpf::StackTrace;
use redbpf::load::{ Loader, Loaded };
use tokio::signal;
use tokio::stream::StreamExt;
use probes::malloc::*;


/// eBPF-based Memory tracking tools
#[derive(FromArgs, Debug)]
pub struct Options {
    /// process id
    #[argh(positional)]
    pid: i32
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options: Options = argh::from_env();

    if unsafe { libc::getuid() } != 0 {
        anyhow::bail!("You must be root to use eBPF!");
    }

    let mut loader = Loader::load(malloc_probe_code())
        .map_err(|err| anyhow::format_err!("redbpf: {:?}", err))?;

    for uprobe in loader.uprobes_mut() {
        // TODO find libc
        uprobe.attach_uprobe(Some(&uprobe.name()), 0, "/usr/lib/libc.so.6", Some(options.pid))
            .map_err(|err| anyhow::format_err!("redbpf: {:?}", err))?;
    }

    let Loaded { module, mut events } = loader;

    tokio::spawn(async move {
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

                let ip = stacks.get(event.stackid)
                    .map(|stack| stack.ip[0])
                    .unwrap_or(0);

                stacks.remove(event.stackid);

                println!("{:?} - {:p}", event, ip as *const u8);
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
