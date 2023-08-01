use std::sync::Arc;

use aya::maps::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use dashmap::DashMap;
use execsnoop_poc_common::Event;
use log::{debug, info, warn};
use tokio::signal;

// A smaller Event struct used in Arc<DashMap<T>> in userspace program
#[derive(Debug)]
pub struct ExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub filename: String,
}

fn bytes_to_str(bytes: &[u8]) -> Result<&str, anyhow::Error> {
    if let Some(first_null_position) = bytes.iter().position(|&x| x == 0) {
        let Ok(bytes) = std::str::from_utf8(&bytes[..first_null_position]) else {
            return Err(anyhow::anyhow!("invalid utf8"))
        };
        Ok(bytes)
    } else {
        Err(anyhow::anyhow!("no null terminator"))
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/execsnoop-poc"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/execsnoop-poc"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let mut events: AsyncPerfEventArray<_> = bpf.take_map("EVENTS").unwrap().try_into()?;
    let program: &mut KProbe = bpf.program_mut("exec_ret").unwrap().try_into()?;
    program.load()?;
    program.attach("__x64_sys_execve", 0)?;
    program.attach("__ia32_compat_sys_execve", 0)?;
    program.attach("__x64_sys_execveat", 0)?;
    program.attach("__ia32_compat_sys_execveat", 0)?;

    let program: &mut KProbe = bpf.program_mut("exec_enter").unwrap().try_into()?;
    program.load()?;
    program.attach("__x64_sys_execve", 0)?;

    let program: &mut KProbe = bpf.program_mut("exec_enter_32").unwrap().try_into()?;
    program.load()?;
    program.attach("__ia32_compat_sys_execve", 0)?;

    let program: &mut KProbe = bpf.program_mut("execat_enter").unwrap().try_into()?;
    program.load()?;
    program.attach("__x64_sys_execveat", 0)?;

    let program: &mut KProbe = bpf.program_mut("execat_enter_32").unwrap().try_into()?;
    program.load()?;
    program.attach("__ia32_compat_sys_execveat", 0)?;

    let program: &mut KProbe = bpf.program_mut("cgroup_add").unwrap().try_into()?;
    program.load()?;
    program.attach("cgroup_procs_write", 0)?;

    let program: &mut KProbe = bpf.program_mut("cgroup_add_ret").unwrap().try_into()?;
    program.load()?;
    program.attach("cgroup_procs_write", 0)?;

    let exec_map: Arc<DashMap<u32, ExecEvent>> = Arc::default();
    let cgroup_map: Arc<DashMap<u32, u32>> = Arc::default();

    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;
        let exec_map = exec_map.clone();
        let cgroup_map = cgroup_map.clone();
        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(4096))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();

                for buf in buffers.iter().take(events.read) {
                    let event = unsafe { (buf.as_ptr() as *const Event).read_unaligned() };

                    match event.type_ {
                        execsnoop_poc_common::EventType::ExecEnter => {
                            let filename = event.buffer;
                            let Ok(filename) = bytes_to_str(&filename) else {
                                continue
                            };
                            exec_map.insert(
                                event.pid,
                                ExecEvent {
                                    pid: event.pid,
                                    ppid: event.ppid,
                                    filename: filename.to_string(),
                                },
                            );
                        }
                        execsnoop_poc_common::EventType::ExecExit => {
                            let Some((_, execevent)) = exec_map.remove(&event.pid) else {
                                continue
                            };
                            if event.ret != 0 {
                                continue;
                            }
                            info!(
                                "{} (parent {}): {}",
                                execevent.pid, execevent.ppid, execevent.filename
                            );
                        }
                        execsnoop_poc_common::EventType::CgroupAddEnter => {
                            let written = event.buffer;
                            let Ok(written) = bytes_to_str(&written) else {
                                continue
                            };
                            // Is it int?
                            let Ok(written) = written.trim_end().parse::<u32>() else {
                                continue
                            };
                            cgroup_map.insert(event.pid, written);
                        }
                        execsnoop_poc_common::EventType::CgroupAddExit => {
                            let Some((_, written_pid)) = cgroup_map.remove(&event.pid) else {
                                continue
                            };
                            info!("{} has been added to some cgroup", written_pid);
                        }
                    }
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
