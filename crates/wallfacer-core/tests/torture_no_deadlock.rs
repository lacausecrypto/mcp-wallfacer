//! Phase E acceptance: torture must complete in well under 60 s even when
//! every tool randomly crashes, hangs, or returns errors.
//!
//! The test wires a `MockClient` with four tools whose async handlers
//! independently simulate crashes (sync return), hangs (long
//! `tokio::sleep`), and successes. We then run [`TortureRun`] against
//! each tool with high concurrency and assert:
//!
//! 1. The whole sweep finishes within 30 s wall clock (way under the 60 s
//!    bound stipulated by the phase spec).
//! 2. At least one finding is produced (showing the cancellation path
//!    didn't suppress all detections).
//! 3. The hung handlers are dropped via cancellation rather than blocking
//!    `join_all` forever.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use rmcp::model::Tool;
use serde_json::Map;
use wallfacer_core::{
    client::CallOutcome,
    corpus::Corpus,
    run::{MockClient, NoopReporter, TortureMode, TortureRun},
};

fn empty_object_tool(name: &str) -> Tool {
    Tool::new(
        name.to_string(),
        format!("crash-prone fixture: {name}"),
        Arc::new(Map::new()),
    )
}

/// Returns a deterministic but caller-distinct counter so successive
/// invocations of the same handler can branch differently.
fn counter() -> Arc<AtomicU64> {
    Arc::new(AtomicU64::new(0))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn torture_completes_under_60s_with_four_crash_prone_tools() {
    let crash_counter = counter();
    let hang_counter = counter();
    let flap_counter = counter();
    let ok_counter = counter();

    // Tool #1 — crashes deterministically every two calls.
    let crash_tool = empty_object_tool("always_crashes");
    let crash_state = crash_counter.clone();
    // Tool #2 — hangs forever; only returns when cancelled by the
    // global watchdog. Wrapped in tokio::time::sleep so the hang is real.
    let hang_tool = empty_object_tool("hangs_forever");
    let hang_state = hang_counter.clone();
    // Tool #3 — flips between Ok and ProtocolError to stress reporting.
    let flap_tool = empty_object_tool("flap");
    let flap_state = flap_counter.clone();
    // Tool #4 — always succeeds.
    let ok_tool = empty_object_tool("ok");
    let ok_state = ok_counter.clone();

    let client = MockClient::new()
        .register_async(crash_tool, move |_| {
            let n = crash_state.fetch_add(1, Ordering::Relaxed);
            async move {
                if n.is_multiple_of(2) {
                    CallOutcome::Crash(format!("synthetic crash #{n}"))
                } else {
                    CallOutcome::Ok(rmcp::model::CallToolResult::success(vec![]))
                }
            }
        })
        .register_async(hang_tool, move |_| {
            hang_state.fetch_add(1, Ordering::Relaxed);
            async move {
                // Sleep way longer than the global deadline so the
                // watchdog *must* cancel us.
                tokio::time::sleep(Duration::from_secs(120)).await;
                CallOutcome::Ok(rmcp::model::CallToolResult::success(vec![]))
            }
        })
        .register_async(flap_tool, move |_| {
            let n = flap_state.fetch_add(1, Ordering::Relaxed);
            async move {
                if n.is_multiple_of(2) {
                    CallOutcome::ProtocolError(format!("flap error #{n}"))
                } else {
                    CallOutcome::Ok(rmcp::model::CallToolResult::success(vec![]))
                }
            }
        })
        .register_async(ok_tool, move |_| {
            ok_state.fetch_add(1, Ordering::Relaxed);
            async move { CallOutcome::Ok(rmcp::model::CallToolResult::success(vec![])) }
        });

    let tmp = tempfile::tempdir().unwrap();
    let corpus = Corpus::new(tmp.path().join("corpus"));
    let mut reporter = NoopReporter;

    let started = Instant::now();
    let mut total_findings = 0usize;
    for tool_name in ["always_crashes", "hangs_forever", "flap", "ok"] {
        let mut run = TortureRun::new(
            TortureMode::Parallel,
            tool_name.to_string(),
            8,
            // Per-call timeout: short enough that the hang_tool's 120 s
            // sleep is truncated; cancellation kicks in at the global
            // deadline (4 × per-call = 4 s).
            Duration::from_secs(1),
            "mock".to_string(),
        );
        // Override global_deadline explicitly so the test stays fast.
        run.global_deadline = Duration::from_secs(3);
        let report = run.execute(&client, &corpus, &mut reporter).await.unwrap();
        total_findings += report.findings_count;
    }
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(30),
        "torture sweep across 4 crash-prone tools exceeded 30 s wall clock: {elapsed:?}"
    );
    assert!(
        total_findings > 0,
        "expected at least one finding across 4 crash-prone tools (got {total_findings})"
    );
    // Sanity: the hang_forever tool should have been cancelled rather than
    // blocking the watchdog. If watchdog cancellation was broken the test
    // would have already exceeded the 30 s budget asserted above.
    assert!(hang_counter.load(Ordering::Relaxed) > 0);
}
