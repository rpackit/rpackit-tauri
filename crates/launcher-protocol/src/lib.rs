//! Bounded, fail-closed decoding of rpackit launcher protocol 2.
//!
//! The R launcher writes newline-delimited JSON to standard output. Only lines
//! beginning with the exact [`EVENT_PREFIX`] are protocol input. Every line,
//! including non-protocol noise, is length-bounded so an untrusted application
//! cannot grow native memory without limit.

#![forbid(unsafe_code)]

use std::mem;

use serde::Deserialize;
use thiserror::Error;

/// Exact prefix preceding one launcher lifecycle JSON object.
pub const EVENT_PREFIX: &[u8] = b"RPACKIT_EVENT ";

/// Default maximum for a complete prefixed or non-prefixed stdout line.
pub const DEFAULT_MAX_LINE_BYTES: usize = 16 * 1024;

const MAX_TIMESTAMP_BYTES: usize = 128;
const MAX_MESSAGE_BYTES: usize = 4 * 1024;

/// A validated protocol-2 launcher event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LauncherEvent {
    /// The R runtime has validated its arguments and is about to start Shiny.
    Starting(StartingEvent),
    /// Shiny has bound its loopback listener.
    Listening(ListeningEvent),
    /// The control file requested graceful shutdown.
    Stopping(StoppingEvent),
    /// Shiny returned and the R runtime is exiting normally.
    Stopped(StoppedEvent),
    /// The launcher failed before or during runtime operation.
    Error(ErrorEvent),
}

/// Validated `starting` event fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartingEvent {
    /// Launcher-provided informational UTC timestamp.
    pub timestamp: String,
    /// Positive runtime process identifier.
    pub pid: u32,
    /// Expected IPv4-loopback listener port.
    pub port: u16,
    /// Whether the launcher installed its control-file watcher.
    pub graceful_stop: bool,
}

/// Validated post-bind `listening` event fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListeningEvent {
    /// Launcher-provided informational UTC timestamp.
    pub timestamp: String,
    /// Positive runtime process identifier.
    pub pid: u32,
    /// Bound IPv4-loopback listener port.
    pub port: u16,
}

/// Validated `stopping` event fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoppingEvent {
    /// Launcher-provided informational UTC timestamp.
    pub timestamp: String,
}

/// Validated `stopped` event fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoppedEvent {
    /// Launcher-provided informational UTC timestamp.
    pub timestamp: String,
    /// Positive runtime process identifier.
    pub pid: u32,
}

/// Stable launcher failure phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorPhase {
    /// The runtime could not load the JSON dependency used for normal events.
    Bootstrap,
    /// Launcher arguments were invalid.
    Arguments,
    /// The private one-time token file or its value was invalid.
    Token,
    /// Application resources were invalid.
    App,
    /// The R or Shiny runtime failed.
    Runtime,
}

/// Validated `error` event fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorEvent {
    /// Informational UTC timestamp, absent only for the bootstrap JSON failure.
    pub timestamp: Option<String>,
    /// Stable failure phase.
    pub phase: ErrorPhase,
    /// Length-bounded single-line message supplied by the launcher.
    ///
    /// Treat this as untrusted display text. It must never enter a durable
    /// report, command line, or shell.
    pub message: String,
    /// Positive runtime PID when normal event encoding was available.
    pub pid: Option<u32>,
}

/// Streaming bounded decoder for launcher standard output.
#[derive(Debug)]
pub struct EventDecoder {
    buffer: Vec<u8>,
    maximum_line_bytes: usize,
    poisoned: bool,
    ignored_lines: u64,
}

impl EventDecoder {
    /// Creates a decoder with the secure default line bound.
    #[must_use]
    pub fn with_default_limit() -> Self {
        Self {
            buffer: Vec::new(),
            maximum_line_bytes: DEFAULT_MAX_LINE_BYTES,
            poisoned: false,
            ignored_lines: 0,
        }
    }

    /// Creates a decoder with a caller-selected nonzero line bound.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::ZeroLineLimit`] when `maximum_line_bytes` is
    /// zero.
    pub fn new(maximum_line_bytes: usize) -> Result<Self, ProtocolError> {
        if maximum_line_bytes == 0 {
            return Err(ProtocolError::ZeroLineLimit);
        }
        Ok(Self {
            buffer: Vec::new(),
            maximum_line_bytes,
            poisoned: false,
            ignored_lines: 0,
        })
    }

    /// Decodes every complete line in one arbitrary byte chunk.
    ///
    /// Non-prefixed lines are counted and discarded without exposing their
    /// content. A decoding error permanently poisons this instance.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for an overlong line, malformed prefixed line,
    /// invalid event shape, or prior decoder failure.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<LauncherEvent>, ProtocolError> {
        if self.poisoned {
            return Err(ProtocolError::DecoderPoisoned);
        }

        let mut events = Vec::new();
        for &byte in bytes {
            if byte == b'\n' {
                let line = mem::take(&mut self.buffer);
                match decode_line(&line) {
                    Ok(Some(event)) => events.push(event),
                    Ok(None) => {
                        self.ignored_lines = self.ignored_lines.saturating_add(1);
                    }
                    Err(error) => {
                        self.poisoned = true;
                        return Err(error);
                    }
                }
                continue;
            }
            if self.buffer.len() >= self.maximum_line_bytes {
                self.buffer.clear();
                self.poisoned = true;
                return Err(ProtocolError::LineTooLong);
            }
            self.buffer.push(byte);
        }
        Ok(events)
    }

    /// Confirms that the stream ended exactly on an NDJSON line boundary.
    ///
    /// # Errors
    ///
    /// Returns an error for a partial final line or prior decoder failure.
    pub fn finish(&mut self) -> Result<(), ProtocolError> {
        if self.poisoned {
            return Err(ProtocolError::DecoderPoisoned);
        }
        if !self.buffer.is_empty() {
            self.buffer.clear();
            self.poisoned = true;
            return Err(ProtocolError::TruncatedLine);
        }
        Ok(())
    }

    /// Returns the number of complete non-protocol lines discarded so far.
    #[must_use]
    pub const fn ignored_lines(&self) -> u64 {
        self.ignored_lines
    }
}

impl Default for EventDecoder {
    fn default() -> Self {
        Self::with_default_limit()
    }
}

/// Validated lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleState {
    /// No valid event has arrived.
    AwaitingStart,
    /// The launcher emitted `starting` but has not announced a bound listener.
    Starting,
    /// The launcher emitted the post-bind `listening` event.
    Listening,
    /// The launcher observed the graceful control file.
    Stopping,
    /// The launcher emitted `stopped`.
    Stopped,
    /// The launcher emitted `error`.
    Failed,
}

impl LifecycleState {
    /// Returns whether no later launcher event is valid.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed)
    }
}

/// Sequence validator tied to one expected port and control-file policy.
#[derive(Debug)]
pub struct LifecycleTracker {
    expected_port: u16,
    expected_graceful_stop: bool,
    state: LifecycleState,
    runtime_pid: Option<u32>,
}

impl LifecycleTracker {
    /// Creates a tracker for one selected upstream port.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidExpectedPort`] for port zero.
    pub fn new(expected_port: u16, expected_graceful_stop: bool) -> Result<Self, ProtocolError> {
        if expected_port == 0 {
            return Err(ProtocolError::InvalidExpectedPort);
        }
        Ok(Self {
            expected_port,
            expected_graceful_stop,
            state: LifecycleState::AwaitingStart,
            runtime_pid: None,
        })
    }

    /// Applies one validated event to the lifecycle state machine.
    ///
    /// # Errors
    ///
    /// Returns an error for an impossible transition, wrong port, changed PID,
    /// mismatched control-file policy, or an event following a terminal event.
    pub fn observe(&mut self, event: &LauncherEvent) -> Result<LifecycleState, ProtocolError> {
        if self.state.is_terminal() {
            return Err(ProtocolError::EventAfterTerminalState);
        }
        let result = self.observe_active(event);
        if result.is_err() {
            self.state = LifecycleState::Failed;
        }
        result
    }

    fn observe_active(&mut self, event: &LauncherEvent) -> Result<LifecycleState, ProtocolError> {
        if let LauncherEvent::Error(error) = event {
            if let (Some(expected), Some(observed)) = (self.runtime_pid, error.pid)
                && expected != observed
            {
                return Err(ProtocolError::RuntimePidChanged);
            }
            self.state = LifecycleState::Failed;
            return Ok(self.state);
        }

        match (self.state, event) {
            (LifecycleState::AwaitingStart, LauncherEvent::Starting(starting)) => {
                if starting.port != self.expected_port {
                    return Err(ProtocolError::UnexpectedPort);
                }
                if starting.graceful_stop != self.expected_graceful_stop {
                    return Err(ProtocolError::GracefulStopMismatch);
                }
                self.runtime_pid = Some(starting.pid);
                self.state = LifecycleState::Starting;
            }
            (LifecycleState::Starting, LauncherEvent::Listening(listening)) => {
                if listening.port != self.expected_port {
                    return Err(ProtocolError::UnexpectedPort);
                }
                if self.runtime_pid != Some(listening.pid) {
                    return Err(ProtocolError::RuntimePidChanged);
                }
                self.state = LifecycleState::Listening;
            }
            (LifecycleState::Listening, LauncherEvent::Stopping(_)) => {
                if !self.expected_graceful_stop {
                    return Err(ProtocolError::GracefulStopMismatch);
                }
                self.state = LifecycleState::Stopping;
            }
            (
                LifecycleState::Listening | LifecycleState::Stopping,
                LauncherEvent::Stopped(stopped),
            ) => {
                if self.runtime_pid != Some(stopped.pid) {
                    return Err(ProtocolError::RuntimePidChanged);
                }
                self.state = LifecycleState::Stopped;
            }
            _ => return Err(ProtocolError::UnexpectedEventSequence),
        }
        Ok(self.state)
    }

    /// Returns the current validated state.
    #[must_use]
    pub const fn state(&self) -> LifecycleState {
        self.state
    }

    /// Returns the runtime PID first reported by `starting`, when available.
    #[must_use]
    pub const fn runtime_pid(&self) -> Option<u32> {
        self.runtime_pid
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvent {
    protocol_version: String,
    event: String,
    timestamp: Option<String>,
    pid: Option<u32>,
    host: Option<String>,
    port: Option<u16>,
    token_enforced: Option<bool>,
    graceful_stop: Option<bool>,
    reason: Option<String>,
    phase: Option<String>,
    message: Option<String>,
}

fn decode_line(line: &[u8]) -> Result<Option<LauncherEvent>, ProtocolError> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let Some(json) = line.strip_prefix(EVENT_PREFIX) else {
        return Ok(None);
    };
    if json.is_empty() {
        return Err(ProtocolError::InvalidJson);
    }
    let raw: RawEvent = serde_json::from_slice(json).map_err(|_| ProtocolError::InvalidJson)?;
    parse_event(raw).map(Some)
}

#[allow(clippy::too_many_lines)]
fn parse_event(raw: RawEvent) -> Result<LauncherEvent, ProtocolError> {
    let RawEvent {
        protocol_version,
        event,
        timestamp,
        pid,
        host,
        port,
        token_enforced,
        graceful_stop,
        reason,
        phase,
        message,
    } = raw;
    if protocol_version != "2" {
        return Err(ProtocolError::UnsupportedProtocolVersion);
    }

    match event.as_str() {
        "starting" => {
            require_no_fields(&[reason.is_some(), phase.is_some(), message.is_some()])?;
            require_loopback_authentication(host.as_deref(), token_enforced)?;
            Ok(LauncherEvent::Starting(StartingEvent {
                timestamp: require_timestamp(timestamp)?,
                pid: require_pid(pid)?,
                port: require_port(port)?,
                graceful_stop: graceful_stop.ok_or(ProtocolError::InvalidEventShape)?,
            }))
        }
        "listening" => {
            require_no_fields(&[
                graceful_stop.is_some(),
                reason.is_some(),
                phase.is_some(),
                message.is_some(),
            ])?;
            require_loopback_authentication(host.as_deref(), token_enforced)?;
            Ok(LauncherEvent::Listening(ListeningEvent {
                timestamp: require_timestamp(timestamp)?,
                pid: require_pid(pid)?,
                port: require_port(port)?,
            }))
        }
        "stopping" => {
            require_no_fields(&[
                pid.is_some(),
                host.is_some(),
                port.is_some(),
                token_enforced.is_some(),
                graceful_stop.is_some(),
                phase.is_some(),
                message.is_some(),
            ])?;
            if reason.as_deref() != Some("control-file") {
                return Err(ProtocolError::InvalidEventShape);
            }
            Ok(LauncherEvent::Stopping(StoppingEvent {
                timestamp: require_timestamp(timestamp)?,
            }))
        }
        "stopped" => {
            require_no_fields(&[
                host.is_some(),
                port.is_some(),
                token_enforced.is_some(),
                graceful_stop.is_some(),
                reason.is_some(),
                phase.is_some(),
                message.is_some(),
            ])?;
            Ok(LauncherEvent::Stopped(StoppedEvent {
                timestamp: require_timestamp(timestamp)?,
                pid: require_pid(pid)?,
            }))
        }
        "error" => {
            require_no_fields(&[
                host.is_some(),
                port.is_some(),
                token_enforced.is_some(),
                graceful_stop.is_some(),
                reason.is_some(),
            ])?;
            let phase = parse_error_phase(phase.as_deref())?;
            let timestamp = match timestamp {
                Some(value) => Some(validate_timestamp(value)?),
                None if phase == ErrorPhase::Bootstrap && pid.is_none() => None,
                None => return Err(ProtocolError::InvalidEventShape),
            };
            Ok(LauncherEvent::Error(ErrorEvent {
                timestamp,
                phase,
                message: sanitize_message(
                    message.as_deref().ok_or(ProtocolError::InvalidEventShape)?,
                )?,
                pid: pid.map(validate_pid).transpose()?,
            }))
        }
        _ => Err(ProtocolError::UnknownEvent),
    }
}

fn require_loopback_authentication(
    host: Option<&str>,
    token_enforced: Option<bool>,
) -> Result<(), ProtocolError> {
    if host != Some("127.0.0.1") || token_enforced != Some(true) {
        return Err(ProtocolError::InvalidEventShape);
    }
    Ok(())
}

fn require_no_fields(fields: &[bool]) -> Result<(), ProtocolError> {
    if fields.iter().any(|present| *present) {
        return Err(ProtocolError::InvalidEventShape);
    }
    Ok(())
}

fn require_timestamp(timestamp: Option<String>) -> Result<String, ProtocolError> {
    validate_timestamp(timestamp.ok_or(ProtocolError::InvalidEventShape)?)
}

fn validate_timestamp(timestamp: String) -> Result<String, ProtocolError> {
    if timestamp.is_empty()
        || timestamp.len() > MAX_TIMESTAMP_BYTES
        || timestamp.chars().any(char::is_control)
    {
        return Err(ProtocolError::InvalidEventShape);
    }
    Ok(timestamp)
}

fn require_pid(pid: Option<u32>) -> Result<u32, ProtocolError> {
    validate_pid(pid.ok_or(ProtocolError::InvalidEventShape)?)
}

fn validate_pid(pid: u32) -> Result<u32, ProtocolError> {
    if pid == 0 {
        return Err(ProtocolError::InvalidEventShape);
    }
    Ok(pid)
}

fn require_port(port: Option<u16>) -> Result<u16, ProtocolError> {
    let port = port.ok_or(ProtocolError::InvalidEventShape)?;
    if port == 0 {
        return Err(ProtocolError::InvalidEventShape);
    }
    Ok(port)
}

fn parse_error_phase(phase: Option<&str>) -> Result<ErrorPhase, ProtocolError> {
    match phase {
        Some("bootstrap") => Ok(ErrorPhase::Bootstrap),
        Some("arguments") => Ok(ErrorPhase::Arguments),
        Some("token") => Ok(ErrorPhase::Token),
        Some("app") => Ok(ErrorPhase::App),
        Some("runtime") => Ok(ErrorPhase::Runtime),
        _ => Err(ProtocolError::InvalidEventShape),
    }
}

fn sanitize_message(message: &str) -> Result<String, ProtocolError> {
    if message.is_empty() || message.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::InvalidEventShape);
    }
    let sanitized: String = message
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let sanitized = sanitized.trim();
    if sanitized.is_empty() {
        return Err(ProtocolError::InvalidEventShape);
    }
    Ok(sanitized.to_owned())
}

/// Fail-closed launcher stream or sequence error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProtocolError {
    /// A zero line limit would reject every useful input.
    #[error("launcher event line limit must be nonzero")]
    ZeroLineLimit,
    /// One stdout line exceeded the configured memory bound.
    #[error("launcher stdout line exceeded its configured bound")]
    LineTooLong,
    /// The stream ended without the required NDJSON newline.
    #[error("launcher stdout ended with a partial line")]
    TruncatedLine,
    /// The caller reused a decoder after a hard failure.
    #[error("launcher event decoder is poisoned")]
    DecoderPoisoned,
    /// A prefixed line was not one strict JSON object.
    #[error("launcher event JSON was invalid")]
    InvalidJson,
    /// The event did not declare protocol version 2.
    #[error("launcher event protocol version was not supported")]
    UnsupportedProtocolVersion,
    /// The protocol-2 event name was unknown.
    #[error("launcher event name was not supported")]
    UnknownEvent,
    /// Required fields, types, or fixed security values did not match.
    #[error("launcher event fields did not match protocol 2")]
    InvalidEventShape,
    /// The selected upstream port cannot be zero.
    #[error("expected launcher port must be nonzero")]
    InvalidExpectedPort,
    /// An event reported a port other than the selected upstream port.
    #[error("launcher event reported an unexpected port")]
    UnexpectedPort,
    /// The runtime PID changed across lifecycle events.
    #[error("launcher runtime PID changed across events")]
    RuntimePidChanged,
    /// The launcher's control-file capability differed from native state.
    #[error("launcher graceful-stop policy did not match native state")]
    GracefulStopMismatch,
    /// An otherwise valid event arrived in an impossible order.
    #[error("launcher event arrived in an invalid sequence")]
    UnexpectedEventSequence,
    /// No event may follow `stopped` or `error`.
    #[error("launcher event arrived after a terminal state")]
    EventAfterTerminalState,
}

#[cfg(test)]
mod tests {
    use super::{
        EVENT_PREFIX, ErrorPhase, EventDecoder, LauncherEvent, LifecycleState, LifecycleTracker,
        ProtocolError,
    };

    const TIMESTAMP: &str = "2026-07-26 23:45:00 UTC";

    fn line(json: &str) -> Vec<u8> {
        let mut line = EVENT_PREFIX.to_vec();
        line.extend_from_slice(json.as_bytes());
        line.push(b'\n');
        line
    }

    fn starting(pid: u32, port: u16, graceful_stop: bool) -> Vec<u8> {
        line(&format!(
            concat!(
                "{{\"protocol_version\":\"2\",\"event\":\"starting\",",
                "\"timestamp\":\"{TIMESTAMP}\",\"pid\":{pid},",
                "\"host\":\"127.0.0.1\",\"port\":{port},",
                "\"token_enforced\":true,\"graceful_stop\":{graceful_stop}}}"
            ),
            TIMESTAMP = TIMESTAMP,
            pid = pid,
            port = port,
            graceful_stop = graceful_stop,
        ))
    }

    fn listening(pid: u32, port: u16) -> Vec<u8> {
        line(&format!(
            concat!(
                "{{\"protocol_version\":\"2\",\"event\":\"listening\",",
                "\"timestamp\":\"{TIMESTAMP}\",\"pid\":{pid},",
                "\"host\":\"127.0.0.1\",\"port\":{port},",
                "\"token_enforced\":true}}"
            ),
            TIMESTAMP = TIMESTAMP,
            pid = pid,
            port = port,
        ))
    }

    fn stopping() -> Vec<u8> {
        line(&format!(
            concat!(
                "{{\"protocol_version\":\"2\",\"event\":\"stopping\",",
                "\"timestamp\":\"{TIMESTAMP}\",\"reason\":\"control-file\"}}"
            ),
            TIMESTAMP = TIMESTAMP,
        ))
    }

    fn stopped(pid: u32) -> Vec<u8> {
        line(&format!(
            concat!(
                "{{\"protocol_version\":\"2\",\"event\":\"stopped\",",
                "\"timestamp\":\"{TIMESTAMP}\",\"pid\":{pid}}}"
            ),
            TIMESTAMP = TIMESTAMP,
            pid = pid,
        ))
    }

    fn decode_one(bytes: &[u8]) -> Result<LauncherEvent, ProtocolError> {
        let mut decoder = EventDecoder::default();
        let mut events = decoder.push(bytes)?;
        decoder.finish()?;
        if events.len() != 1 {
            return Err(ProtocolError::InvalidEventShape);
        }
        events.pop().ok_or(ProtocolError::InvalidEventShape)
    }

    #[test]
    fn decodes_fragmented_listening_event_and_discards_noise() {
        let event = listening(42, 8_765);
        let mut decoder = EventDecoder::default();
        assert!(decoder.push(b"application output\r\n").is_ok());
        let split = event.len() / 2;
        assert_eq!(decoder.push(&event[..split]), Ok(Vec::new()));
        let parsed = decoder.push(&event[split..]);
        assert!(matches!(
            parsed.as_deref(),
            Ok([LauncherEvent::Listening(event)])
                if event.pid == 42 && event.port == 8_765
        ));
        assert_eq!(decoder.ignored_lines(), 1);
        assert_eq!(decoder.finish(), Ok(()));
    }

    #[test]
    fn accepts_bootstrap_error_without_timestamp_or_pid() {
        let event = decode_one(&line(
            "{\"protocol_version\":\"2\",\"event\":\"error\",\
                 \"phase\":\"bootstrap\",\"message\":\"jsonlite missing\"}",
        ));
        assert!(matches!(
            event,
            Ok(LauncherEvent::Error(error))
                if error.phase == ErrorPhase::Bootstrap
                    && error.timestamp.is_none()
                    && error.pid.is_none()
        ));
    }

    #[test]
    fn rejects_ambiguous_or_weakened_event_shapes() {
        let cases = [
            "{\"protocol_version\":2,\"event\":\"listening\"}",
            "{\"protocol_version\":\"1\",\"event\":\"listening\"}",
            "{\"protocol_version\":\"2\",\"event\":\"future\"}",
            "{\"protocol_version\":\"2\",\"event\":\"listening\",\
             \"timestamp\":\"x\",\"pid\":1,\"host\":\"0.0.0.0\",\
             \"port\":1,\"token_enforced\":true}",
            "{\"protocol_version\":\"2\",\"event\":\"listening\",\
             \"timestamp\":\"x\",\"pid\":1,\"host\":\"127.0.0.1\",\
             \"port\":1,\"token_enforced\":false}",
            "{\"protocol_version\":\"2\",\"event\":\"listening\",\
             \"timestamp\":\"x\",\"pid\":1,\"pid\":2,\
             \"host\":\"127.0.0.1\",\"port\":1,\"token_enforced\":true}",
            "{\"protocol_version\":\"2\",\"event\":\"stopped\",\
             \"timestamp\":\"x\",\"pid\":1,\"extra\":true}",
        ];
        for json in cases {
            assert!(decode_one(&line(json)).is_err());
        }
    }

    #[test]
    fn bounds_all_stdout_lines_and_poison_after_failure() {
        let mut decoder = EventDecoder::new(8).unwrap_or_default();
        assert_eq!(decoder.push(b"123456789"), Err(ProtocolError::LineTooLong));
        assert_eq!(decoder.push(b"\n"), Err(ProtocolError::DecoderPoisoned));
        assert_eq!(decoder.finish(), Err(ProtocolError::DecoderPoisoned));
    }

    #[test]
    fn rejects_partial_final_line() {
        let mut decoder = EventDecoder::default();
        assert_eq!(decoder.push(b"partial"), Ok(Vec::new()));
        assert_eq!(decoder.finish(), Err(ProtocolError::TruncatedLine));
    }

    #[test]
    fn validates_complete_graceful_sequence() -> Result<(), ProtocolError> {
        let mut tracker = LifecycleTracker::new(8_765, true)?;
        let sequence = [
            decode_one(&starting(73, 8_765, true))?,
            decode_one(&listening(73, 8_765))?,
            decode_one(&stopping())?,
            decode_one(&stopped(73))?,
        ];
        let expected = [
            LifecycleState::Starting,
            LifecycleState::Listening,
            LifecycleState::Stopping,
            LifecycleState::Stopped,
        ];
        for (event, state) in sequence.iter().zip(expected) {
            assert_eq!(tracker.observe(event)?, state);
        }
        assert_eq!(tracker.runtime_pid(), Some(73));
        assert_eq!(
            tracker.observe(&sequence[3]),
            Err(ProtocolError::EventAfterTerminalState)
        );
        Ok(())
    }

    #[test]
    fn rejects_wrong_port_pid_policy_and_order() -> Result<(), ProtocolError> {
        let start = decode_one(&starting(73, 8_765, true))?;
        let wrong_port = decode_one(&listening(73, 8_766))?;
        let wrong_pid = decode_one(&listening(74, 8_765))?;
        let listen = decode_one(&listening(73, 8_765))?;

        let mut wrong_policy = LifecycleTracker::new(8_765, false)?;
        assert_eq!(
            wrong_policy.observe(&start),
            Err(ProtocolError::GracefulStopMismatch)
        );
        assert_eq!(wrong_policy.state(), LifecycleState::Failed);

        let mut order_tracker = LifecycleTracker::new(8_765, true)?;
        assert_eq!(
            order_tracker.observe(&listen),
            Err(ProtocolError::UnexpectedEventSequence)
        );
        assert_eq!(
            order_tracker.observe(&start),
            Err(ProtocolError::EventAfterTerminalState)
        );

        let mut port_tracker = LifecycleTracker::new(8_765, true)?;
        assert_eq!(port_tracker.observe(&start), Ok(LifecycleState::Starting));
        assert_eq!(
            port_tracker.observe(&wrong_port),
            Err(ProtocolError::UnexpectedPort)
        );

        let mut pid_tracker = LifecycleTracker::new(8_765, true)?;
        assert_eq!(pid_tracker.observe(&start), Ok(LifecycleState::Starting));
        assert_eq!(
            pid_tracker.observe(&wrong_pid),
            Err(ProtocolError::RuntimePidChanged)
        );
        Ok(())
    }

    #[test]
    fn error_is_terminal_and_sanitizes_control_characters() -> Result<(), ProtocolError> {
        let event = decode_one(&line(
            "{\"protocol_version\":\"2\",\"event\":\"error\",\
             \"timestamp\":\"x\",\"phase\":\"runtime\",\
             \"message\":\"first\\nsecond\\tline\",\"pid\":91}",
        ))?;
        let LauncherEvent::Error(error) = &event else {
            return Err(ProtocolError::InvalidEventShape);
        };
        assert_eq!(error.message, "first second line");

        let mut tracker = LifecycleTracker::new(8_765, true)?;
        assert_eq!(tracker.observe(&event)?, LifecycleState::Failed);
        assert_eq!(
            tracker.observe(&event),
            Err(ProtocolError::EventAfterTerminalState)
        );
        Ok(())
    }
}
