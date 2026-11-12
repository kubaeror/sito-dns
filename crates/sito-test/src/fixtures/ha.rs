//! Controllable fake HA master for slave-worker tests.
//!
//! The fixture owns one WebSocket connection. Tests can push signed bundles,
//! send heartbeats, stop sending frames while keeping the socket open
//! (partition simulation), or drop the connection entirely. It deliberately
//! does not implement the full master state machine: the tests drive exact
//! frames at exact moments, which is what master-loss/heartbeat coverage
//! needs.

use std::net::SocketAddr;
use std::time::Duration;

use crate::fixtures::net::{PortClaim, bind_claimed_tcp};
use sito_ha::HaMessage;
use sito_test_support::{Clock, ManualClock};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// How long fixture controls wait for the slave to connect and for a frame to
/// be sent before reporting a test failure.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

enum MasterCommand {
    Push(String),
    Heartbeat(u64),
    StopFrames,
    ResumeFrames,
    Partition,
    Stop,
}

/// A fake master listening on an ephemeral loopback port.
///
/// `url()` is valid immediately after [`FakeMaster::start`]; the task accepts
/// the slave connection in the background.
#[derive(Debug)]
pub struct FakeMaster {
    addr: SocketAddr,
    commands: mpsc::UnboundedSender<MasterCommand>,
    task: JoinHandle<()>,
    _claim: PortClaim,
}

impl FakeMaster {
    /// Binds an ephemeral loopback port and starts the fake master task.
    pub async fn start() -> std::io::Result<Self> {
        let (listener, claim) = bind_claimed_tcp().await?;
        let addr = listener.local_addr()?;
        let (commands, command_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(run_master(listener, command_rx));
        Ok(Self {
            addr,
            commands,
            task,
            _claim: claim,
        })
    }

    /// The bound socket address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The `ws://` URL slaves should connect to.
    #[must_use]
    pub fn url(&self) -> String {
        format!("ws://{}", self.addr)
    }

    /// Sends one JSON-encoded HA frame.
    pub fn send_raw(&self, json: String) -> Result<(), String> {
        self.send_command(MasterCommand::Push(json))
    }

    /// Sends a signed [`HaMessage`].
    pub fn send(&self, message: &HaMessage) -> Result<(), String> {
        let json = message.to_json().map_err(|error| error.to_string())?;
        self.send_raw(json)
    }

    /// Sends a heartbeat `Ping` with `ts`.
    pub fn heartbeat(&self, ts: u64) -> Result<(), String> {
        self.send_command(MasterCommand::Heartbeat(ts))
    }

    /// Stops sending pushes/heartbeats but leaves the TCP/WebSocket open.
    pub fn stop_frames(&self) -> Result<(), String> {
        self.send_command(MasterCommand::StopFrames)
    }

    /// Resumes frames after [`FakeMaster::stop_frames`].
    pub fn resume_frames(&self) -> Result<(), String> {
        self.send_command(MasterCommand::ResumeFrames)
    }

    /// Schedules a heartbeat after `after` manual-clock time.
    ///
    /// The returned task resolves only when the test advances `clock`, which
    /// makes heartbeat timing deterministic instead of a wall-clock race.
    pub fn schedule_heartbeat(
        &self,
        clock: std::sync::Arc<ManualClock>,
        after: Duration,
        ts: u64,
    ) -> tokio::task::JoinHandle<()> {
        let commands = self.commands.clone();
        tokio::spawn(async move {
            clock.sleep(after).await;
            let _ = commands.send(MasterCommand::Heartbeat(ts));
        })
    }

    /// Closes the WebSocket and ends the master task.
    pub fn partition(&self) -> Result<(), String> {
        self.send_command(MasterCommand::Partition)
    }

    /// Stops the master task.
    pub fn stop(self) {
        let _ = self.commands.send(MasterCommand::Stop);
        self.task.abort();
    }

    /// Waits for the master task to finish, failing if it is still running.
    pub async fn wait_stopped(self) -> Result<(), String> {
        let _ = self.commands.send(MasterCommand::Stop);
        match tokio::time::timeout(CONTROL_TIMEOUT, self.task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(format!("fake master task failed: {error}")),
            Err(_) => Err("fake master task did not stop".to_string()),
        }
    }

    fn send_command(&self, command: MasterCommand) -> Result<(), String> {
        self.commands
            .send(command)
            .map_err(|_| "fake master task is not running".to_string())
    }
}

async fn run_master(listener: TcpListener, mut commands: mpsc::UnboundedReceiver<MasterCommand>) {
    // Commands may arrive before the slave connects (tests often push
    // immediately after starting the fixture). Queue pushes/heartbeats, but
    // honour Stop/Partition while still waiting for a connection so
    // `wait_stopped` cannot hang in `accept()`.
    let mut queued = Vec::new();
    let accepted = loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    None | Some(MasterCommand::Stop | MasterCommand::Partition) => return,
                    Some(command) => queued.push(command),
                }
            }
            accepted = listener.accept() => break accepted,
        }
    };
    let Ok((stream, _)) = accepted else {
        return;
    };
    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
        return;
    };

    // The real slave sends `Hello` first; consume it so the fixture never
    // mistakes the handshake frame for an ACK.
    let _ = ws.next_frame().await;

    let mut sending_frames = true;
    for command in queued {
        if !apply_command(&mut ws, &mut sending_frames, command).await {
            return;
        }
    }

    loop {
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break };
                if !apply_command(&mut ws, &mut sending_frames, command).await {
                    break;
                }
            }
            frame = ws.next_frame() => {
                if frame.is_none() {
                    break;
                }
            }
        }
    }
}

/// Applies one control command. Returns false when the master task must stop.
async fn apply_command<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    sending_frames: &mut bool,
    command: MasterCommand,
) -> bool
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match command {
        MasterCommand::Push(json) => {
            if *sending_frames && send_text(ws, json).await.is_err() {
                return false;
            }
        }
        MasterCommand::Heartbeat(ts) => {
            if *sending_frames {
                let Ok(json) = (HaMessage::Ping { ts }).to_json() else {
                    return false;
                };
                if send_text(ws, json).await.is_err() {
                    return false;
                }
            }
        }
        MasterCommand::StopFrames => *sending_frames = false,
        MasterCommand::ResumeFrames => *sending_frames = true,
        MasterCommand::Partition => {
            let _ = ws.close(None).await;
            return false;
        }
        MasterCommand::Stop => return false,
    }
    true
}

async fn send_text<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    json: String,
) -> Result<(), ()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::SinkExt as _;
    ws.send(WsMessage::Text(json.into())).await.map_err(|_| ())
}

trait NextFrame {
    async fn next_frame(&mut self) -> Option<()>;
}

impl<S> NextFrame for tokio_tungstenite::WebSocketStream<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    async fn next_frame(&mut self) -> Option<()> {
        use futures_util::StreamExt as _;
        self.next().await.map(|_| ())
    }
}
