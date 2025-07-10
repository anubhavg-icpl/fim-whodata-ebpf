use anyhow::Result;
use clap::Parser;
use std::{process::Command, path::PathBuf};

#[derive(Parser)]
pub struct Options {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Parser)]
pub enum Command {
    BuildEbpf(BuildEbpfOptions),
    Run(RunOptions),
}

#[derive(Parser)]
pub struct BuildEbpfOptions {
    /// Set the endianness of the BPF target
    #[arg(default_value = "bpfel-unknown-none", long)]
    target: String,
    /// Build the release target
    #[arg(long)]
    release: bool,
}

#[derive(Parser)]
pub struct RunOptions {
    /// Build and run the release target
    #[arg(long)]
    release: bool,
    /// The command used to wrap your application
    #[arg(short, long, default_value = "sudo -E")]
    runner: String,
    /// Arguments to pass to your application
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    run_args: Vec<String>,
}

fn main() -> Result<()> {
    let opts = Options::parse();

    if let Some(command) = opts.command {
        match command {
            Command::BuildEbpf(opts) => build_ebpf(opts),
            Command::Run(opts) => run(opts),
        }
    } else {
        // Default to build-ebpf
        build_ebpf(BuildEbpfOptions {
            target: "bpfel-unknown-none".to_string(),
            release: true,
        })
    }
}

fn build_ebpf(opts: BuildEbpfOptions) -> Result<()> {
    let dir = PathBuf::from("fim-whodata-ebpf-bpf");
    let target = format!("--target={}", opts.target);
    let mut args = vec![
        "build",
        target.as_str(),
        "-Z", "build-std=core",
    ];
    if opts.release {
        args.push("--release");
    }

    let status = Command::new("cargo")
        .current_dir(&dir)
        .args(&args)
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to build eBPF program");
    }

    println!("eBPF program built successfully");
    Ok(())
}

fn run(opts: RunOptions) -> Result<()> {
    // Build eBPF program first
    build_ebpf(BuildEbpfOptions {
        target: "bpfel-unknown-none".to_string(),
        release: opts.release,
    })?;

    // Build main program
    let mut args = vec!["build"];
    if opts.release {
        args.push("--release");
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to build main program");
    }

    // Run the program
    let binary_path = if opts.release {
        "target/release/fim-whodata-ebpf"
    } else {
        "target/debug/fim-whodata-ebpf"
    };

    let mut cmd_args = opts.runner.split_whitespace().collect::<Vec<_>>();
    cmd_args.push(binary_path);
    cmd_args.extend(opts.run_args.iter().map(|s| s.as_str()));

    let status = Command::new(&cmd_args[0])
        .args(&cmd_args[1..])
        .status()?;

    if !status.success() {
        anyhow::bail!("Program exited with error");
    }

    Ok(())
}