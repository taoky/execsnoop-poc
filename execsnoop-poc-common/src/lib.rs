#![no_std]

// pub const TASK_COMM_LEN: usize = 16;
pub const ARGSIZE: usize = 128;
// pub const MAXARGS: usize = 20;

#[derive(Debug)]
pub enum EventType {
    ExecEnter,
    ExecExit,
    CgroupAddEnter,
    CgroupAddExit,
}

#[repr(C)]
#[derive(Debug)]
pub struct Event {
    pub pid: u32,
    pub ppid: u32,
    pub type_: EventType,
    pub buffer: [u8; ARGSIZE],
    pub ret: i32,
}
