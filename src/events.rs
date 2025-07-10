use fim_whodata_ebpf_common::{WhoDataEvent as RawEvent, FimOperation as RawOperation};
use std::ffi::CStr;

#[derive(Debug, Clone)]
pub struct WhoDataEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub path: String,
    pub operation: FimOperation,
    pub inode: u64,
    pub process_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FimOperation {
    Add,
    Modify,
    Delete,
    Rename,
}

impl From<RawEvent> for WhoDataEvent {
    fn from(raw: RawEvent) -> Self {
        let path = String::from_utf8_lossy(&raw.path[..raw.path_len as usize]).to_string();
        
        let process_name = CStr::from_bytes_until_nul(&raw.process_name)
            .map(|c| c.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        Self {
            timestamp: raw.timestamp,
            pid: raw.pid,
            tid: raw.tid,
            uid: raw.uid,
            gid: raw.gid,
            path,
            operation: RawOperation::from(raw.operation).into(),
            inode: raw.inode,
            process_name,
        }
    }
}

impl From<RawOperation> for FimOperation {
    fn from(raw: RawOperation) -> Self {
        match raw {
            RawOperation::Add => FimOperation::Add,
            RawOperation::Modify => FimOperation::Modify,
            RawOperation::Delete => FimOperation::Delete,
            RawOperation::Rename => FimOperation::Rename,
        }
    }
}