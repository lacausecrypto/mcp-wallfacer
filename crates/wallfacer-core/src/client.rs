//! MCP client wrapper.
//!
//! Phase E1 puts the underlying `rmcp` service behind an
//! `Arc<RwLock<...>>` so:
//!
//! * `Client` is `Clone` (cheap `Arc::clone`); torture can fan out across
//!   many tasks sharing the same connection.
//! * `list_tools` and `call_tool` take `&self` and acquire a *read* lock,
//!   allowing concurrent calls to be in flight at once.
//! * `reconnect` takes `&self` and acquires a *write* lock to atomically
//!   tear down and rebuild the underlying service. Concurrent callers see
//!   either the old or the new transport, never a torn state.

use std::{
    collections::HashMap, future::Future, path::Path, process::Stdio, sync::Arc, time::Duration,
};

use http::{HeaderName, HeaderValue};
use rmcp::{
    model::{CallToolRequestParams, CallToolResult, Prompt, Resource, ServerCapabilities, Tool},
    service::{RoleClient, RunningService, RxJsonRpcMessage, TxJsonRpcMessage},
    transport::{
        async_rw::AsyncRwTransport, streamable_http_client::StreamableHttpClientTransportConfig,
        StreamableHttpClientTransport, Transport as RmcpTransport,
    },
    ServiceExt,
};
use serde_json::Value;
use thiserror::Error;
use tokio::{
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::RwLock,
    time,
};

use crate::target::{Target, Transport as TargetTransport};

const CHILD_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("failed to spawn stdio transport: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("failed to initialize MCP client: {0}")]
    Initialize(String),
    #[error("invalid HTTP header {name}: {message}")]
    InvalidHeader { name: String, message: String },
    #[error("failed to shut down MCP client: {0}")]
    Shutdown(#[source] tokio::task::JoinError),
    #[error("MCP request failed: {0}")]
    Request(String),
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// Cheaply-cloneable MCP client. Cloning shares the same underlying
/// transport via `Arc`. After [`Client::shutdown`] the transport is gone
/// and further calls return `ClientError::Request`.
#[derive(Clone)]
pub struct Client {
    /// `Some` while the transport is live; `None` after `shutdown`.
    /// `RwLock` allows concurrent `&self` calls (read) and exclusive
    /// `reconnect` (write).
    service: Arc<RwLock<Option<RunningService<RoleClient, ()>>>>,
    target: Target,
}

#[derive(Debug)]
pub enum CallOutcome {
    Ok(CallToolResult),
    Hang(Duration),
    Crash(String),
    ProtocolError(String),
}

impl Client {
    pub async fn connect(target: &Target) -> Result<Self> {
        let service = build_service(target).await?;
        Ok(Self {
            service: Arc::new(RwLock::new(Some(service))),
            target: target.clone(),
        })
    }

    /// Tears down the current transport and opens a new one. Other tasks
    /// holding a `&self` reference will see the new transport on their
    /// next call. Phase E1 changed this from `&mut self` to `&self` so
    /// callers can recover after a fault without exclusive ownership of
    /// the `Client`.
    pub async fn reconnect(&self) -> Result<()> {
        // Build the replacement *before* dropping the old one to keep the
        // window where the client has no transport as small as possible.
        let replacement = build_service(&self.target).await?;
        let mut guard = self.service.write().await;
        if let Some(old) = guard.take() {
            let _ = old.cancel().await;
        }
        *guard = Some(replacement);
        Ok(())
    }

    pub async fn list_tools(&self) -> Result<Vec<Tool>> {
        let guard = self.service.read().await;
        let service = guard
            .as_ref()
            .ok_or_else(|| ClientError::Request("client has been shut down".into()))?;
        service
            .list_all_tools()
            .await
            .map_err(|error| ClientError::Request(error.to_string()))
    }

    /// Returns a clone of the server's announced [`ServerCapabilities`]
    /// from the initial `initialize` handshake, or `None` if the client
    /// has been shut down or the handshake hadn't completed.
    ///
    /// Per MCP spec, clients should not call `resources/list` or
    /// `prompts/list` against a server that didn't declare the
    /// corresponding capability — doing so produces a noisy
    /// `-32601 method not found` from compliant servers. Use this to
    /// gate optional listing calls.
    pub async fn server_capabilities(&self) -> Option<ServerCapabilities> {
        let guard = self.service.read().await;
        guard
            .as_ref()
            .and_then(|service| service.peer_info())
            .map(|info| info.capabilities.clone())
    }

    /// Lists the server's resources. Returns `Ok(vec![])` (silently)
    /// when the server didn't declare the `resources` capability at
    /// init time — this avoids spamming a `-32601 method not found`
    /// failure for servers that legitimately don't expose resources.
    /// Callers needing to distinguish "not advertised" from "empty"
    /// should check [`Self::server_capabilities`] first.
    pub async fn list_resources(&self) -> Result<Vec<Resource>> {
        let advertises = self
            .server_capabilities()
            .await
            .is_some_and(|caps| caps.resources.is_some());
        if !advertises {
            return Ok(Vec::new());
        }
        let guard = self.service.read().await;
        let service = guard
            .as_ref()
            .ok_or_else(|| ClientError::Request("client has been shut down".into()))?;
        service
            .list_all_resources()
            .await
            .map_err(|error| ClientError::Request(error.to_string()))
    }

    /// Lists the server's prompts. Same capability-aware short-circuit
    /// as [`Self::list_resources`]: returns `Ok(vec![])` when the
    /// server didn't declare the `prompts` capability.
    pub async fn list_prompts(&self) -> Result<Vec<Prompt>> {
        let advertises = self
            .server_capabilities()
            .await
            .is_some_and(|caps| caps.prompts.is_some());
        if !advertises {
            return Ok(Vec::new());
        }
        let guard = self.service.read().await;
        let service = guard
            .as_ref()
            .ok_or_else(|| ClientError::Request("client has been shut down".into()))?;
        service
            .list_all_prompts()
            .await
            .map_err(|error| ClientError::Request(error.to_string()))
    }

    pub async fn call_tool(&self, name: &str, arguments: Value, timeout: Duration) -> CallOutcome {
        let arguments = match arguments {
            Value::Object(map) => Some(map),
            Value::Null => None,
            other => {
                return CallOutcome::ProtocolError(format!(
                    "tool arguments must be a JSON object or null, got {other}"
                ));
            }
        };

        let request = match arguments {
            Some(arguments) => {
                CallToolRequestParams::new(name.to_owned()).with_arguments(arguments)
            }
            None => CallToolRequestParams::new(name.to_owned()),
        };

        // Snapshot the current transport for the duration of the call. We
        // hold the read lock across the await so a concurrent reconnect
        // waits until our call finishes before swapping.
        let guard = self.service.read().await;
        let Some(service) = guard.as_ref() else {
            return CallOutcome::ProtocolError("client has been shut down".into());
        };
        match time::timeout(timeout, service.call_tool(request)).await {
            Ok(Ok(result)) => CallOutcome::Ok(result),
            Ok(Err(error)) if service.is_transport_closed() => {
                CallOutcome::Crash(error.to_string())
            }
            Ok(Err(error)) => CallOutcome::ProtocolError(error.to_string()),
            Err(_) => CallOutcome::Hang(timeout),
        }
    }

    /// Shuts the underlying transport down. After this call other clones of
    /// this `Client` keep working semantically but return `ProtocolError`
    /// on every method (the transport is gone).
    pub async fn shutdown(&self) -> Result<()> {
        let mut guard = self.service.write().await;
        match guard.take() {
            Some(service) => service
                .cancel()
                .await
                .map(|_| ())
                .map_err(ClientError::Shutdown),
            None => Ok(()),
        }
    }

    pub fn target(&self) -> &Target {
        &self.target
    }
}

async fn build_service(target: &Target) -> Result<RunningService<RoleClient, ()>> {
    let service = match &target.transport {
        TargetTransport::Stdio { command, args, env } => {
            let mut process = Command::new(command);
            process.args(args).envs(env);
            let transport = StdioChildTransport::spawn(process).map_err(ClientError::Spawn)?;
            ().serve(transport)
                .await
                .map_err(|error| ClientError::Initialize(error.to_string()))?
        }
        TargetTransport::Http { url, headers } => {
            let headers = header_map(headers)?;
            let config =
                StreamableHttpClientTransportConfig::with_uri(url.clone()).custom_headers(headers);
            let transport = StreamableHttpClientTransport::from_config(config);
            ().serve(transport)
                .await
                .map_err(|error| ClientError::Initialize(error.to_string()))?
        }
    };
    Ok(service)
}

pub fn fixture_config_path(repo_root: &Path) -> std::path::PathBuf {
    repo_root.join("tests/fixtures/wallfacer.toml")
}

fn header_map(headers: &HashMap<String, String>) -> Result<HashMap<HeaderName, HeaderValue>> {
    headers
        .iter()
        .map(|(name, value)| {
            let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                ClientError::InvalidHeader {
                    name: name.clone(),
                    message: error.to_string(),
                }
            })?;
            let header_value =
                HeaderValue::from_str(value).map_err(|error| ClientError::InvalidHeader {
                    name: name.clone(),
                    message: error.to_string(),
                })?;
            Ok((header_name, header_value))
        })
        .collect()
}

struct StdioChildTransport {
    child: Option<Child>,
    transport: AsyncRwTransport<RoleClient, ChildStdout, ChildStdin>,
}

impl StdioChildTransport {
    fn spawn(mut command: Command) -> std::io::Result<Self> {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = command.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("child stdout was already taken"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("child stdin was already taken"))?;

        Ok(Self {
            child: Some(child),
            transport: AsyncRwTransport::new_client(stdout, stdin),
        })
    }

    async fn close_child(&mut self) -> std::io::Result<()> {
        self.transport.close().await?;

        if let Some(mut child) = self.child.take() {
            match time::timeout(CHILD_SHUTDOWN_TIMEOUT, child.wait()).await {
                Ok(status) => {
                    status?;
                }
                Err(_) => {
                    child.kill().await?;
                }
            }
        }

        Ok(())
    }
}

impl Drop for StdioChildTransport {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
        }
    }
}

impl RmcpTransport<RoleClient> for StdioChildTransport {
    type Error = std::io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleClient>,
    ) -> impl Future<Output = std::result::Result<(), Self::Error>> + Send + 'static {
        self.transport.send(item)
    }

    fn receive(&mut self) -> impl Future<Output = Option<RxJsonRpcMessage<RoleClient>>> + Send {
        self.transport.receive()
    }

    fn close(&mut self) -> impl Future<Output = std::result::Result<(), Self::Error>> + Send {
        self.close_child()
    }
}
