use fim_whodata_ebpf::{WhoDataMonitor, WhoDataEvent, FimOperation};
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    let mut monitor = WhoDataMonitor::new().await?;
    
    // Monitor /tmp directory
    monitor.add_monitor_path("/tmp").await?;
    
    println!("Monitoring /tmp for file changes...");
    println!("Create, modify, or delete files in /tmp to see events");
    
    monitor.start_monitoring(|event: WhoDataEvent| {
        let timestamp = SystemTime::UNIX_EPOCH + std::time::Duration::from_nanos(event.timestamp);
        
        println!("[{}] {} {} by {}({}) - uid:{} gid:{}", 
            timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            match event.operation {
                FimOperation::Add => "CREATED",
                FimOperation::Modify => "MODIFIED", 
                FimOperation::Delete => "DELETED",
                FimOperation::Rename => "RENAMED",
            },
            event.path,
            event.process_name,
            event.pid,
            event.uid,
            event.gid
        );
    }).await;
    
    Ok(())
}