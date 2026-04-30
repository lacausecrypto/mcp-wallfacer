//! Execution abstraction over the MCP client.
//!
//! Plans take a `&mut impl McpExec` rather than the concrete
//! [`crate::client::Client`] so they can be unit-tested with [`MockClient`]
//! without spawning a child process.

use std::{collections::HashMap, future::Future, pin::Pin, sync::Mutex, time::Duration};

use async_trait::async_trait;
use rmcp::model::Tool;
use serde_json::Value;

use crate::client::{CallOutcome, Client, ClientError};

/// Boxed future returned by [`MockClient`] async handlers. The future
/// returns a [`CallOutcome`].
type CallFuture = Pin<Box<dyn Future<Output = CallOutcome> + Send>>;

/// Sync closure type for [`MockClient`] tool handlers.
type SyncHandler = Box<dyn Fn(&Value) -> CallOutcome + Send + Sync>;

/// Async closure type for [`MockClient`] tool handlers.
type AsyncHandler = Box<dyn Fn(&Value) -> CallFuture + Send + Sync>;

enum MockHandler {
    Sync(SyncHandler),
    Async(AsyncHandler),
}

/// Minimum surface a plan needs from an MCP client.
///
/// All methods take `&self` so plans can drive concurrent calls
/// (`torture`-style) and recover from faults via `reconnect` without ever
/// holding an exclusive borrow. Phase E1 made this possible by moving the
/// production [`Client`] behind an internal `Arc<RwLock<...>>`.
#[async_trait]
pub trait McpExec: Send + Sync {
    /// Lists every tool exposed by the server.
    async fn list_tools(&self) -> Result<Vec<Tool>, ClientError>;

    /// Calls a tool, applying `timeout`. Returns a [`CallOutcome`] that the
    /// caller pattern-matches; this method itself never errors.
    async fn call_tool(&self, name: &str, arguments: Value, timeout: Duration) -> CallOutcome;

    /// Tears down the transport and rebuilds it. Used after a hang/crash
    /// so subsequent calls can succeed. Concurrent callers see either the
    /// old or the new transport, never a torn state.
    async fn reconnect(&self) -> Result<(), ClientError>;
}

#[async_trait]
impl McpExec for Client {
    async fn list_tools(&self) -> Result<Vec<Tool>, ClientError> {
        Client::list_tools(self).await
    }

    async fn call_tool(&self, name: &str, arguments: Value, timeout: Duration) -> CallOutcome {
        Client::call_tool(self, name, arguments, timeout).await
    }

    async fn reconnect(&self) -> Result<(), ClientError> {
        Client::reconnect(self).await
    }
}

/// In-memory MCP client used for plan unit tests. Each tool is registered
/// with a closure that maps the call arguments to a [`CallOutcome`]. The
/// mock is fully synchronous internally; concurrency is provided by `tokio`.
pub struct MockClient {
    tools: Vec<Tool>,
    handlers: Mutex<HashMap<String, MockHandler>>,
    /// Number of `reconnect` calls observed; useful for tests that assert
    /// the plan recovered after a fault.
    reconnect_count: Mutex<usize>,
}

impl MockClient {
    /// Creates an empty mock with no tools registered.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tools: Vec::new(),
            handlers: Mutex::new(HashMap::new()),
            reconnect_count: Mutex::new(0),
        }
    }

    /// Registers a tool with a synchronous handler. The handler is invoked
    /// on every `call_tool`; it can return any [`CallOutcome`] variant to
    /// simulate crashes, hangs, or protocol errors.
    pub fn register<F>(mut self, tool: Tool, handler: F) -> Self
    where
        F: Fn(&Value) -> CallOutcome + Send + Sync + 'static,
    {
        let name = tool.name.to_string();
        self.tools.push(tool);
        self.handlers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(name, MockHandler::Sync(Box::new(handler)));
        self
    }

    /// Registers a tool with an async handler. Useful when testing
    /// cancellation: the handler can `await` indefinitely and rely on
    /// the caller's cancellation to drop it.
    pub fn register_async<F, Fut>(mut self, tool: Tool, handler: F) -> Self
    where
        F: Fn(&Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = CallOutcome> + Send + 'static,
    {
        let name = tool.name.to_string();
        self.tools.push(tool);
        let boxed: AsyncHandler = Box::new(move |args| Box::pin(handler(args)));
        self.handlers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(name, MockHandler::Async(boxed));
        self
    }

    /// Returns the number of times `reconnect` has been invoked.
    #[must_use]
    pub fn reconnect_count(&self) -> usize {
        *self
            .reconnect_count
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }
}

impl Default for MockClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl McpExec for MockClient {
    async fn list_tools(&self) -> Result<Vec<Tool>, ClientError> {
        Ok(self.tools.clone())
    }

    async fn call_tool(&self, name: &str, arguments: Value, _timeout: Duration) -> CallOutcome {
        // Build the future under the mutex (cheap), then drop the guard
        // before awaiting so concurrent calls aren't serialized.
        let future = {
            let handlers = self.handlers.lock().unwrap_or_else(|p| p.into_inner());
            match handlers.get(name) {
                Some(MockHandler::Sync(handler)) => return handler(&arguments),
                Some(MockHandler::Async(handler)) => handler(&arguments),
                None => return CallOutcome::ProtocolError(format!("unknown tool `{name}`")),
            }
        };
        future.await
    }

    async fn reconnect(&self) -> Result<(), ClientError> {
        *self
            .reconnect_count
            .lock()
            .unwrap_or_else(|p| p.into_inner()) += 1;
        Ok(())
    }
}
