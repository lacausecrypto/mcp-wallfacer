use std::{collections::HashMap, future::Future, path::Path, process::Stdio, time::Duration};

use http::{HeaderName, HeaderValue};
use rmcp::{
    model::{CallToolRequestParams, CallToolResult, Prompt, Resource, Tool},
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

pub struct Client {
    service: RunningService<RoleClient, ()>,
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
                let config = StreamableHttpClientTransportConfig::with_uri(url.clone())
                    .custom_headers(headers);
                let transport = StreamableHttpClientTransport::from_config(config);
                ().serve(transport)
                    .await
                    .map_err(|error| ClientError::Initialize(error.to_string()))?
            }
        };

        Ok(Self {
            service,
            target: target.clone(),
        })
    }

    pub async fn reconnect(&mut self) -> Result<()> {
        let target = self.target.clone();
        let _ = self.service.close().await;
        *self = Self::connect(&target).await?;
        Ok(())
    }

    pub async fn list_tools(&self) -> Result<Vec<Tool>> {
        self.service
            .list_all_tools()
            .await
            .map_err(|error| ClientError::Request(error.to_string()))
    }

    pub async fn list_resources(&self) -> Result<Vec<Resource>> {
        self.service
            .list_all_resources()
            .await
            .map_err(|error| ClientError::Request(error.to_string()))
    }

    pub async fn list_prompts(&self) -> Result<Vec<Prompt>> {
        self.service
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

        match time::timeout(timeout, self.service.call_tool(request)).await {
            Ok(Ok(result)) => CallOutcome::Ok(result),
            Ok(Err(error)) if self.service.is_transport_closed() => {
                CallOutcome::Crash(error.to_string())
            }
            Ok(Err(error)) => CallOutcome::ProtocolError(error.to_string()),
            Err(_) => CallOutcome::Hang(timeout),
        }
    }

    pub async fn shutdown(self) -> Result<()> {
        self.service
            .cancel()
            .await
            .map(|_| ())
            .map_err(ClientError::Shutdown)
    }

    pub fn target(&self) -> &Target {
        &self.target
    }
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
