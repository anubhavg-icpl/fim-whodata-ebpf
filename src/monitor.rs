use aya::{
    include_bytes_aligned,
    maps::{perf::AsyncPerfEventArray, HashMap},
    programs::TracePoint,
    util::online_cpus,
    Bpf, BpfLoader,
};
use aya_log::BpfLogger;
use bytes::BytesMut;
use fim_whodata_ebpf_common::WhoDataEvent as RawEvent;
use log::{debug, info, warn, error};
use std::convert::TryFrom;
use tokio::task;

use crate::events::{WhoDataEvent, FimOperation};

pub struct WhoDataMonitor {
    bpf: Bpf,
}

impl WhoDataMonitor {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Load the eBPF program
        let mut bpf = BpfLoader::new()
            .load(include_bytes_aligned!(
                "../target/bpfel-unknown-none/release/fim-whodata-ebpf"
            ))?;

        // Setup logging
        if let Err(e) = BpfLogger::init(&mut bpf) {
            warn!("Failed to initialize eBPF logger: {}", e);
        }

        // Load and attach tracepoint programs
        let openat_program: &mut TracePoint = bpf
            .program_mut("syscalls__sys_enter_openat")
            .unwrap()
            .try_into()?;
        openat_program.load()?;
        openat_program.attach("syscalls", "sys_enter_openat")?;

        let unlinkat_program: &mut TracePoint = bpf
            .program_mut("syscalls__sys_enter_unlinkat")
            .unwrap()
            .try_into()?;
        unlinkat_program.load()?;
        unlinkat_program.attach("syscalls", "sys_enter_unlinkat")?;

        info!("eBPF programs loaded and attached successfully");

        Ok(Self { bpf })
    }

    pub async fn add_monitor_path(&mut self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Adding monitor path: {}", path);
        
        let mut path_key = [0u8; 256];
        let bytes = path.as_bytes();
        let len = std::cmp::min(bytes.len(), 255);
        path_key[..len].copy_from_slice(&bytes[..len]);

        let mut monitored_paths: HashMap<_, [u8; 256], u8> =
            HashMap::try_from(self.bpf.map_mut("MONITORED_PATHS")?)?;
        monitored_paths.insert(path_key, 1, 0)?;

        info!("Added monitor path: {}", path);
        Ok(())
    }

    pub async fn start_monitoring<F>(&mut self, event_handler: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: Fn(WhoDataEvent) + Send + Sync + Clone + 'static,
    {
        let mut perf_array = AsyncPerfEventArray::try_from(self.bpf.map_mut("EVENTS")?)?;

        for cpu_id in online_cpus()? {
            let mut buf = perf_array.open(cpu_id, None)?;
            let handler = event_handler.clone();

            task::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();

                loop {
                    match buf.read_events(&mut buffers).await {
                        Ok(events) => {
                            for buf in buffers.iter().take(events.read) {
                                if buf.len() >= std::mem::size_of::<RawEvent>() {
                                    let raw_event = unsafe {
                                        std::ptr::read_unaligned(buf.as_ptr() as *const RawEvent)
                                    };
                                    let event = WhoDataEvent::from(raw_event);
                                    handler(event);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Error reading events on CPU {}: {}", cpu_id, e);
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            });
        }

        // Keep the monitor running
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}