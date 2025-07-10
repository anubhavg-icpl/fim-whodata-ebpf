use anyhow::Result;
use clap::Parser;
use fim_whodata_ebpf::{WhoDataMonitor, WhoDataEvent, FimOperation};
use log::{info, warn, error};
use std::path::PathBuf;
use tokio::signal;

#[derive(Parser)]
#[command(name = "fim-whodata-ebpf")]
#[command(about = "File Integrity Monitoring with eBPF")]
struct Cli {
    /// Paths to monitor (can specify multiple)
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,
    
    /// Output format
    #[arg(short, long, default_value = "json")]
    format: String,
    
    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    env_logger::Builder::new()
        .filter_level(if cli.verbose { log::LevelFilter::Debug } else { log::LevelFilter::Info })
        .init();

    if cli.paths.is_empty() {
        error!("At least one path must be specified");
        std::process::exit(1);
    }

    info!("Starting FIM WhoData eBPF monitor");
    
    let mut monitor = WhoDataMonitor::new().await?;
    
    // Add all specified paths to monitor
    for path in &cli.paths {
        let path_str = path.to_string_lossy();
        info!("Adding monitor path: {}", path_str);
        monitor.add_monitor_path(&path_str).await?;
    }

    // Setup event handler based on output format
    let format_clone = cli.format.clone();
    let event_handler = move |event: WhoDataEvent| {
        match format_clone.as_str() {
            "json" => {
                let json_event = serde_json::json!({
                    "timestamp": event.timestamp,
                    "pid": event.pid,
                    "tid": event.tid,
                    "uid": event.uid,
                    "gid": event.gid,
                    "path": event.path,
                    "operation": match event.operation {
                        FimOperation::Add => "add",
                        FimOperation::Modify => "modify",
                        FimOperation::Delete => "delete",
                        FimOperation::Rename => "rename",
                    },
                    "inode": event.inode,
                    "process_name": event.process_name,
                });
                println!("{}", json_event);
            }
            "text" => {
                println!("[{}] {} {} by {}({}) {}({}:{})", 
                    event.timestamp,
                    match event.operation {
                        FimOperation::Add => "ADD",
                        FimOperation::Modify => "MODIFY", 
                        FimOperation::Delete => "DELETE",
                        FimOperation::Rename => "RENAME",
                    },
                    event.path,
                    event.process_name,
                    event.pid,
                    event.uid,
                    event.gid,
                    event.tid
                );
            }
            _ => {
                warn!("Unknown format: {}, using text", format_clone);
                println!("{:?}", event);
            }
        }
    };

    info!("Starting monitoring... Press Ctrl+C to stop");
    
    // Start monitoring in background
    let monitor_handle = tokio::spawn(async move {
        if let Err(e) = monitor.start_monitoring(event_handler).await {
            error!("Monitor error: {}", e);
        }
    });

    // Wait for Ctrl+C
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("Received Ctrl+C, shutting down...");
        }
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
        }
    }

    monitor_handle.abort();
    info!("Monitor stopped");
    
    Ok(())
}
