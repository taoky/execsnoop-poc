#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel,
        bpf_probe_read_user_str_bytes, bpf_probe_read_kernel_str_bytes, bpf_probe_read,
    },
    macros::{kprobe, kretprobe, map},
    maps::{PerCpuArray, PerfEventArray},
    programs::ProbeContext,
    PtRegs, bindings::pt_regs,
};

// use aya_log_ebpf::info;
use execsnoop_poc_common::{Event, EventType};

mod vmlinux;
use vmlinux::task_struct;

#[map]
pub static mut BUF: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);

#[inline]
unsafe fn fill_exec_info(data: &mut Event) -> Result<(), u32> {
    data.pid = bpf_get_current_pid_tgid() as u32;
    let task = bpf_get_current_task() as *const task_struct;
    let parent = bpf_probe_read_kernel(&(*task).real_parent).map_err(|x| x as u32)?;
    data.ppid = bpf_probe_read_kernel(&(*parent).tgid).map_err(|x| x as u32)? as u32;

    Ok(())
}

#[inline]
unsafe fn get_buffer() -> Result<&'static mut Event, u32> {
    Ok(&mut *(BUF.get_ptr_mut(0).ok_or(1u32)?))
}

#[kprobe]
pub fn exec_enter(ctx: ProbeContext) -> u32 {
    match unsafe { try_exec_enter(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_exec_enter(ctx: ProbeContext) -> Result<u32, u32> {
    let regs = PtRegs::new(ctx.arg(0).ok_or(1u32)?);
    let filename: *const u8 = regs.arg(0).ok_or(1u32)?;

    let data = get_buffer()?;
    fill_exec_info(data)?;
    let _ = bpf_probe_read_user_str_bytes(filename, &mut data.buffer).map_err(|x| x as u32)?;

    data.type_ = EventType::ExecEnter;

    EVENTS.output(&ctx, &data, 0);
    Ok(0)
}

#[kprobe]
pub fn exec_enter_32(ctx: ProbeContext) -> u32 {
    match unsafe { try_exec_enter_32(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// Very dirty method...
// https://github.com/iovisor/bcc/issues/3843#issuecomment-1042519676
#[repr(C)]
struct PtRegsIa32 {
    _unused: [u32; 10],
    arg1: u32,
    _unused2: [u32; 11],
    arg2: u32,
}

unsafe fn try_exec_enter_32(ctx: ProbeContext) -> Result<u32, u32> {
    let regs: *mut pt_regs = ctx.arg(0).ok_or(1u32)?;
    // Convert regs to ia32 layout
    let regs = &mut *(regs as *mut PtRegsIa32);
    let ebx = bpf_probe_read(&regs.arg1).map(|v| v as *const u32).ok().ok_or(1u32)?;

    // info!(&ctx, "ebx: 0x{:x}", ebx as u32);

    let filename: *const u8 = ebx as *const _;

    let data = get_buffer()?;
    fill_exec_info(data)?;
    let _ = bpf_probe_read_user_str_bytes(filename, &mut data.buffer).map_err(|x| x as u32)?;

    data.type_ = EventType::ExecEnter;

    EVENTS.output(&ctx, &data, 0);
    Ok(0)
}

#[kprobe]
pub fn execat_enter(ctx: ProbeContext) -> u32 {
    match unsafe { try_execat_enter(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_execat_enter(ctx: ProbeContext) -> Result<u32, u32> {
    let regs = PtRegs::new(ctx.arg(0).ok_or(1u32)?);
    let filename: *const u8 = regs.arg(1).ok_or(1u32)?;

    let data = get_buffer()?;
    fill_exec_info(data)?;
    let _ = bpf_probe_read_user_str_bytes(filename, &mut data.buffer).map_err(|x| x as u32)?;

    data.type_ = EventType::ExecEnter;

    EVENTS.output(&ctx, &data, 0);
    Ok(0)
}

#[kprobe]
pub fn execat_enter_32(ctx: ProbeContext) -> u32 {
    match unsafe { try_execat_enter_32(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_execat_enter_32(ctx: ProbeContext) -> Result<u32, u32> {
    let regs: *mut pt_regs = ctx.arg(0).ok_or(1u32)?;
    // Convert regs to ia32 layout
    let regs = &mut *(regs as *mut PtRegsIa32);
    let ecx = bpf_probe_read(&regs.arg2).map(|v| v as *const u32).ok().ok_or(1u32)?;
    let filename: *const u8 = ecx as *const _;

    let data = get_buffer()?;
    fill_exec_info(data)?;
    let _ = bpf_probe_read_user_str_bytes(filename, &mut data.buffer).map_err(|x| x as u32)?;

    data.type_ = EventType::ExecEnter;

    EVENTS.output(&ctx, &data, 0);
    Ok(0)
}

#[kretprobe]
pub fn exec_ret(ctx: ProbeContext) -> u32 {
    match unsafe { try_exec_ret(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_exec_ret(ctx: ProbeContext) -> Result<u32, u32> {
    let data = get_buffer()?;
    fill_exec_info(data)?;
    data.type_ = EventType::ExecExit;
    data.ret = ctx.ret().ok_or(1_u32)?;
    EVENTS.output(&ctx, &data, 0);
    Ok(0)
}

#[kprobe]
pub fn cgroup_add(ctx: ProbeContext) -> u32 {
    match unsafe { try_cgroup_add(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_cgroup_add(ctx: ProbeContext) -> Result<u32, u32> {
    let buf: *const u8 = ctx.arg(1).ok_or(1u32)?;
    let data = get_buffer()?;
    fill_exec_info(data)?;
    data.type_ = EventType::CgroupAddEnter;
    let _ = bpf_probe_read_kernel_str_bytes(buf, &mut data.buffer).map_err(|x| x as u32)?;
    EVENTS.output(&ctx, &data, 0);
    Ok(0)
}

#[kretprobe]
pub fn cgroup_add_ret(ctx: ProbeContext) -> u32 {
    match unsafe { try_cgroup_add_ret(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_cgroup_add_ret(ctx: ProbeContext) -> Result<u32, u32> {
    let data = get_buffer()?;
    fill_exec_info(data)?;
    data.type_ = EventType::CgroupAddExit;
    data.ret = ctx.ret().ok_or(1_u32)?;
    EVENTS.output(&ctx, &data, 0);
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
