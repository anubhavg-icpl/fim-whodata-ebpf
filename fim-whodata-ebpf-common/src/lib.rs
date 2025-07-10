#![no_std]

use core::mem;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WhoDataEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub path: [u8; 256],
    pub operation: u8,
    pub inode: u64,
    pub process_name: [u8; 16],
    pub path_len: u32,
}

impl WhoDataEvent {
    pub const fn new() -> Self {
        Self {
            timestamp: 0,
            pid: 0,
            tid: 0,
            uid: 0,
            gid: 0,
            path: [0; 256],
            operation: 0,
            inode: 0,
            process_name: [0; 16],
            path_len: 0,
        }
    }
}

// Ensure the struct is properly sized for eBPF
const _: () = assert!(mem::size_of::<WhoDataEvent>() <= 512);

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FimOperation {
    Add = 0,
    Modify = 1,
    Delete = 2,
    Rename = 3,
}

impl From<u8> for FimOperation {
    fn from(value: u8) -> Self {
        match value {
            0 => FimOperation::Add,
            1 => FimOperation::Modify,
            2 => FimOperation::Delete,
            3 => FimOperation::Rename,
            _ => FimOperation::Modify,
        }
    }
}