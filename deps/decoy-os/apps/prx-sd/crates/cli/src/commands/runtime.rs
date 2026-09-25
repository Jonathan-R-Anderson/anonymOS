use anyhow::Result;
use colored::Colorize;

/// Show eBPF runtime status and metrics.
///
/// When compiled with the `ebpf` feature on Linux, this starts the eBPF
/// runtime briefly to verify functionality and prints a snapshot of the
/// current metrics.  On other platforms or without the feature, it prints
/// a diagnostic message.
#[allow(clippy::unnecessary_wraps, clippy::unused_async)]
pub async fn run_status() -> Result<()> {
    println!("{} eBPF Runtime Status", ">>>".cyan().bold());
    println!();

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        use prx_sd_realtime::ebpf;

        // 1. Capability check.
        match ebpf::loader::check_capabilities() {
            Ok(()) => {
                println!("  {} CAP_BPF / CAP_SYS_ADMIN", "Capabilities:".green().bold());
            }
            Err(e) => {
                println!(
                    "  {} {} (run with sudo or set capabilities)",
                    "Capabilities:".red().bold(),
                    e
                );
                return Ok(());
            }
        }

        // 2. Start full pipeline briefly to confirm everything loads.
        match ebpf::EbpfPipeline::start(256) {
            Ok((mut pipeline, _rx)) => {
                // Let a few events collect.
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let snap = pipeline.metrics().snapshot();
                let cache_size = pipeline.cache().len();
                println!("  {} attached", "Tracepoints:".green().bold());
                println!("  {} {cache_size} processes tracked", "Cache:".cyan().bold());
                println!();
                println!("{snap}");
                pipeline.stop();
                println!(
                    "  {} eBPF pipeline operational (events + correlation)",
                    "Result:".green().bold()
                );
            }
            Err(e) => {
                println!("  {} failed to start: {e:#}", "Runtime:".red().bold());
            }
        }
    }

    #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
    {
        println!("  {} eBPF support not available", "Status:".yellow().bold());

        #[cfg(not(target_os = "linux"))]
        println!("  eBPF requires Linux kernel 5.8+");

        #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
        println!("  Compile with --features ebpf to enable");
    }

    Ok(())
}
