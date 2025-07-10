#![no_std]
#![no_main]

use aya_bpf::{
    bindings::{BPF_F_CURRENT_CPU},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_user_str,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
    BpfContext,
};
use aya_log_ebpf::info;
use fim_whodata_ebpf_common::{FimOperation, WhoDataEvent};

#[map]
static EVENTS: PerfEventArray<WhoDataEvent> = PerfEventArray::new(0);

#[map]
static MONITORED_PATHS: HashMap<[u8; 256], u8> = HashMap::new();

#[tracepoint]
pub fn syscalls__sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_syscalls__sys_enter_openat(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_syscalls__sys_enter_openat(ctx: TracePointContext) -> Result<u32, i64> {
    let filename: *const u8 = unsafe { ctx.read_at::<*const u8>(24)? };
    let flags: i32 = unsafe { ctx.read_at::<i32>(16)? };

    let mut path_buf = [0u8; 256];
    let path_len = unsafe {
        bpf_probe_read_user_str(path_buf.as_mut_ptr(), 256, filename)?
    } as usize;

    if path_len == 0 || path_len >= 256 {
        return Ok(0);
    }

    // Check if path is monitored
    if !is_path_monitored(&path_buf) {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let mut event = WhoDataEvent::new();
    event.timestamp = unsafe { bpf_ktime_get_ns() };
    event.pid = (pid_tgid >> 32) as u32;
    event.tid = (pid_tgid & 0xFFFFFFFF) as u32;
    event.uid = (uid_gid & 0xFFFFFFFF) as u32;
    event.gid = (uid_gid >> 32) as u32;
    event.path = path_buf;
    event.path_len = path_len as u32;
    
    // Determine operation type from flags
    event.operation = if flags & 0x40 != 0 { // O_CREAT
        FimOperation::Add as u8
    } else {
        FimOperation::Modify as u8
    };

    // Get process name
    let _ = unsafe { bpf_get_current_comm(&mut event.process_name) };

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

#[tracepoint]
pub fn syscalls__sys_enter_unlinkat(ctx: TracePointContext) -> u32 {
    match try_syscalls__sys_enter_unlinkat(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_syscalls__sys_enter_unlinkat(ctx: TracePointContext) -> Result<u32, i64> {
    let pathname: *const u8 = unsafe { ctx.read_at::<*const u8>(16)? };

    let mut path_buf = [0u8; 256];
    let path_len = unsafe {
        bpf_probe_read_user_str(path_buf.as_mut_ptr(), 256, pathname)?
    } as usize;

    if path_len == 0 || path_len >= 256 {
        return Ok(0);
    }

    if !is_path_monitored(&path_buf) {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    let mut event = WhoDataEvent::new();
    event.timestamp = unsafe { bpf_ktime_get_ns() };
    event.pid = (pid_tgid >> 32) as u32;
    event.tid = (pid_tgid & 0xFFFFFFFF) as u32;
    event.uid = (uid_gid & 0xFFFFFFFF) as u32;
    event.gid = (uid_gid >> 32) as u32;
    event.path = path_buf;
    event.path_len = path_len as u32;
    event.operation = FimOperation::Delete as u8;

    let _ = unsafe { bpf_get_current_comm(&mut event.process_name) };

    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    Ok(0)
}

fn is_path_monitored(path: &[u8; 256]) -> bool {
    // Check exact path match first
    if unsafe { MONITORED_PATHS.get(path).is_some() } {
        return true;
    }

    // Check if any monitored path is a prefix of the given path
    let path_str = match core::str::from_utf8(path) {
        Ok(s) => s.trim_end_matches('\0'),
        Err(_) => return false,
    };

    if path_str.is_empty() {
        return false;
    }

    // Simple prefix checking
    // In production, you'd want a more efficient trie structure
    let mut prefix_key = [0u8; 256];
    
    // Check common prefixes like /tmp, /etc, /home, etc.
    let common_prefixes = ["/tmp", "/etc", "/home", "/var", "/usr"];
    for prefix in &common_prefixes {
        if path_str.starts_with(prefix) {
            let prefix_bytes = prefix.as_bytes();
            if prefix_bytes.len() < 256 {
                prefix_key[..prefix_bytes.len()].copy_from_slice(prefix_bytes);
                if unsafe { MONITORED_PATHS.get(&prefix_key).is_some() } {
                    return true;
                }
            }
        }
        // Reset prefix_key for next iteration
        prefix_key = [0u8; 256];
    }

    false
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}