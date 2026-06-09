#[cfg(windows)]
use crate::poller::{self, ProcessEvent};
#[cfg(windows)]
use tokio::sync::mpsc;

#[cfg(windows)]
pub async fn run_etw_notifier(
    tx: mpsc::Sender<ProcessEvent>,
    mut stop_rx: mpsc::Receiver<()>,
) {
    eprintln!("[probe] ETW initialization...");
    let result = start_etw_trace(tx);
    match result {
        Ok(()) => {
            eprintln!("[probe] ETW consumer active");
            let _ = stop_rx.recv().await;
            eprintln!("[probe] ETW consumer stopped");
        }
        Err(e) => {
            eprintln!("[probe] ETW unavailable ({e:?}). Falling back to polling-only.");
            let _ = stop_rx.recv().await;
        }
    }
}

#[cfg(windows)]
fn start_etw_trace(
    tx: mpsc::Sender<ProcessEvent>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use ferrisetw::native::etw_types::EventRecord;
    use ferrisetw::parser::{Parser, TryParse};
    use ferrisetw::provider::{kernel_providers, Provider};
    use ferrisetw::schema::SchemaLocator;
    use ferrisetw::trace::{KernelTrace, TraceBaseTrait, TraceTrait};

    let tx_clone = tx.clone();

    let callback = move |record: EventRecord, schema_locator: &mut SchemaLocator| {
        if let Ok(schema) = schema_locator.event_schema(record) {
            let mut parser = Parser::create(&schema);

            let pid: u32 = TryParse::<u32>::try_parse(&mut parser, "ProcessID")
                .or_else(|_| TryParse::<u32>::try_parse(&mut parser, "ProcessId"))
                .unwrap_or(0);

            if pid == 0 || pid == std::process::id() {
                return;
            }

            let img: String = TryParse::<String>::try_parse(&mut parser, "ImageName")
                .unwrap_or_default();

            if img.is_empty() {
                return;
            }

            let parent_pid: u32 = TryParse::<u32>::try_parse(&mut parser, "ParentProcessID")
                .or_else(|_| TryParse::<u32>::try_parse(&mut parser, "ParentProcessId"))
                .unwrap_or(0);

            if let Some(info) = poller::build_info(pid, &img, parent_pid) {
                let _ = tx_clone.blocking_send(ProcessEvent::Started(info));
            }
        }
    };

    let provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
        .add_callback(callback)
        .build()
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("ETW provider build error: {e:?}").into()
        })?;

    let _trace = KernelTrace::new()
        .named("AgentGuard-ProcessMonitor".to_string())
        .enable(provider)
        .start()
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("ETW trace start error: {e:?}").into()
        })?;

    eprintln!("[probe] ETW kernel trace active: AgentGuard-ProcessMonitor");

    Ok(())
}

#[cfg(not(windows))]
pub async fn run_etw_notifier(
    _tx: mpsc::Sender<ProcessEvent>,
    mut stop_rx: mpsc::Receiver<()>,
) {
    let _ = stop_rx.recv().await;
}
