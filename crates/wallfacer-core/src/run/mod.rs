//! Plan-based execution layer.
//!
//! Phase C moves the orchestration logic that used to live in
//! `mcp-wallfacer-cli`'s command modules into the core, so that:
//!
//! * commands stay below 200 LOC and are limited to argument parsing,
//!   reporter selection, and exit-code mapping;
//! * plans are testable without spawning a real MCP server, via
//!   [`exec::MockClient`];
//! * alternate front-ends (web UI, library use) can drive the same plans
//!   with a custom [`reporter::Reporter`].
//!
//! Each plan owns its own input arguments and produces a typed report. The
//! plan executes against any [`exec::McpExec`] (the production [`Client`]
//! or [`exec::MockClient`]) and notifies a [`reporter::Reporter`] live as
//! findings happen.
//!
//! [`Client`]: crate::client::Client

pub mod destructive;
pub mod differential;
pub mod exec;
pub mod fuzz;
pub mod glob;
pub mod pack;
pub mod property;
pub mod reporter;
pub mod torture;

pub use destructive::{DestructiveDetector, ToolClassification};
pub use differential::{DifferentialPlan, DifferentialReport};
pub use exec::{McpExec, MockClient};
pub use fuzz::{FuzzOutcome, FuzzPlan, FuzzReport, SkippedTool};
pub use pack::{resolve as resolve_pack, PackError, PackLoader};
pub use property::{parse_invariants, PropertyPlan, PropertyReport};
pub use reporter::{NoopReporter, Reporter, RunInfo};
pub use torture::{parse_duration, TortureMode, TortureReport, TortureRun};
