//! Bound and fail closed while an upstream HTTP response body is streaming.

use std::{
    future::Future as _,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use tokio::time::{Instant, Sleep, sleep};

use crate::request_body::minimum_bytes_for_window;

/// A streaming body guard that never forwards trailers and latches every
/// framing, length, timeout, rate, or upstream read error closed.
pub(crate) struct ResponseBodyGuard<B> {
    inner: B,
    declared_length: Option<u64>,
    size_hint_length: Option<u64>,
    bytes_forwarded: u64,
    max_body_bytes: u64,
    idle_timeout: Option<Duration>,
    rate_window: Duration,
    minimum_window_bytes: u64,
    window_bytes: u64,
    idle_timer: Option<Pin<Box<Sleep>>>,
    rate_timer: Option<Pin<Box<Sleep>>>,
    terminal: bool,
}

impl<B> ResponseBodyGuard<B> {
    pub(crate) fn streaming(
        inner: B,
        declared_length: Option<u64>,
        max_body_bytes: usize,
        idle_timeout: Duration,
        minimum_bytes_per_second: u64,
        rate_window: Duration,
    ) -> Self {
        Self {
            inner,
            declared_length,
            size_hint_length: declared_length,
            bytes_forwarded: 0,
            max_body_bytes: u64::try_from(max_body_bytes).unwrap_or(u64::MAX),
            idle_timeout: Some(idle_timeout),
            rate_window,
            minimum_window_bytes: minimum_bytes_for_window(minimum_bytes_per_second, rate_window),
            window_bytes: 0,
            idle_timer: None,
            rate_timer: None,
            terminal: false,
        }
    }

    pub(crate) fn forbidden(inner: B, advertised_length: Option<u64>) -> Self {
        Self {
            inner,
            declared_length: None,
            size_hint_length: advertised_length,
            bytes_forwarded: 0,
            max_body_bytes: 0,
            idle_timeout: None,
            rate_window: Duration::ZERO,
            minimum_window_bytes: 0,
            window_bytes: 0,
            idle_timer: None,
            rate_timer: None,
            terminal: false,
        }
    }

    fn start_timers(&mut self) {
        if self.idle_timer.is_none()
            && let Some(idle_timeout) = self.idle_timeout
        {
            self.idle_timer = Some(Box::pin(sleep(idle_timeout)));
            if self.minimum_window_bytes > 0 {
                self.rate_timer = Some(Box::pin(sleep(self.rate_window)));
            }
        }
    }

    fn reject(&mut self, message: &'static str) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        self.terminal = true;
        Poll::Ready(Some(Err(io::Error::other(message))))
    }

    fn timer_elapsed(timer: &mut Option<Pin<Box<Sleep>>>, context: &mut Context<'_>) -> bool {
        timer
            .as_mut()
            .is_some_and(|timer| timer.as_mut().poll(context).is_ready())
    }

    fn reset_idle_timer(&mut self, now: Instant) {
        if let (Some(timeout), Some(timer)) = (self.idle_timeout, self.idle_timer.as_mut()) {
            timer.as_mut().reset(now + timeout);
        }
    }

    fn reset_rate_window(&mut self, now: Instant) {
        self.window_bytes = 0;
        if let Some(timer) = self.rate_timer.as_mut() {
            timer.as_mut().reset(now + self.rate_window);
        }
    }
}

impl<B> Body for ResponseBodyGuard<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.terminal {
            return Poll::Ready(None);
        }
        self.start_timers();

        if Self::timer_elapsed(&mut self.idle_timer, context) {
            return self.reject("upstream response body exceeded idle timeout");
        }
        if Self::timer_elapsed(&mut self.rate_timer, context) {
            if self.window_bytes < self.minimum_window_bytes {
                return self.reject("upstream response body rate was below limit");
            }
            self.reset_rate_window(Instant::now());
        }

        match Pin::new(&mut self.inner).poll_frame(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(_))) => self.reject("upstream response body was malformed"),
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    let Ok(data_length) = u64::try_from(data.len()) else {
                        return self.reject("upstream response body exceeded limit");
                    };
                    let Some(total) = self.bytes_forwarded.checked_add(data_length) else {
                        return self.reject("upstream response body exceeded limit");
                    };
                    if total > self.max_body_bytes {
                        return self.reject("upstream response body exceeded limit");
                    }
                    if self
                        .declared_length
                        .is_some_and(|declared| total > declared)
                    {
                        return self.reject("upstream response body exceeded declared length");
                    }
                    self.bytes_forwarded = total;
                    self.window_bytes = self.window_bytes.saturating_add(data_length);
                    if data_length > 0 {
                        self.reset_idle_timer(Instant::now());
                    }
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                Err(frame) => {
                    if frame.into_trailers().is_ok() {
                        self.reject("upstream response trailers were rejected")
                    } else {
                        self.reject("upstream response body frame was rejected")
                    }
                }
            },
            Poll::Ready(None) => {
                self.terminal = true;
                if self
                    .declared_length
                    .is_some_and(|declared| declared != self.bytes_forwarded)
                {
                    return Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "upstream response body ended before its declared length",
                    ))));
                }
                Poll::Ready(None)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.terminal
    }

    fn size_hint(&self) -> SizeHint {
        if self.terminal {
            return SizeHint::with_exact(0);
        }
        let remaining_limit = self.max_body_bytes.saturating_sub(self.bytes_forwarded);
        let mut hint = SizeHint::new();
        if let Some(declared) = self.size_hint_length {
            hint.set_exact(declared.saturating_sub(self.bytes_forwarded));
        } else {
            hint.set_upper(remaining_limit);
        }
        hint
    }
}

/// A second streaming boundary over decoded content. Codec errors are
/// replaced with one fixed message and the frame crossing the decoded byte cap
/// is never forwarded.
pub(crate) struct DecodedBodyGuard<B> {
    inner: B,
    bytes_forwarded: u64,
    max_body_bytes: u64,
    terminal: bool,
}

impl<B> DecodedBodyGuard<B> {
    pub(crate) fn new(inner: B, max_body_bytes: usize) -> Self {
        Self {
            inner,
            bytes_forwarded: 0,
            max_body_bytes: u64::try_from(max_body_bytes).unwrap_or(u64::MAX),
            terminal: false,
        }
    }

    fn reject(&mut self, message: &'static str) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        self.terminal = true;
        Poll::Ready(Some(Err(io::Error::other(message))))
    }
}

impl<B> Body for DecodedBodyGuard<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.terminal {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(_))) => self.reject("upstream response content decoding failed"),
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    let Ok(data_length) = u64::try_from(data.len()) else {
                        return self.reject("decoded upstream response body exceeded limit");
                    };
                    let Some(total) = self.bytes_forwarded.checked_add(data_length) else {
                        return self.reject("decoded upstream response body exceeded limit");
                    };
                    if total > self.max_body_bytes {
                        return self.reject("decoded upstream response body exceeded limit");
                    }
                    self.bytes_forwarded = total;
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                Err(_) => self.reject("upstream response content decoding failed"),
            },
            Poll::Ready(None) => {
                self.terminal = true;
                Poll::Ready(None)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.terminal
    }

    fn size_hint(&self) -> SizeHint {
        if self.terminal {
            return SizeHint::with_exact(0);
        }
        let remaining = self.max_body_bytes.saturating_sub(self.bytes_forwarded);
        let inner_hint = self.inner.size_hint();
        let lower = inner_hint.lower().min(remaining);
        let upper = inner_hint.upper().unwrap_or(remaining).min(remaining);
        let mut hint = SizeHint::new();
        hint.set_lower(lower);
        hint.set_upper(upper.max(lower));
        hint
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        task::{Context, Poll},
    };

    use http::HeaderMap;
    use http_body_util::BodyExt as _;

    use super::*;

    struct ScriptedBody {
        frames: VecDeque<Result<Frame<Bytes>, io::Error>>,
    }

    impl ScriptedBody {
        fn new(frames: impl IntoIterator<Item = Result<Frame<Bytes>, io::Error>>) -> Self {
            Self {
                frames: frames.into_iter().collect(),
            }
        }
    }

    impl Body for ScriptedBody {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.frames.pop_front())
        }
    }

    #[tokio::test]
    async fn exact_declared_length_streams_to_completion() {
        let body = ScriptedBody::new([
            Ok(Frame::data(Bytes::from_static(b"safe"))),
            Ok(Frame::data(Bytes::from_static(b"-body"))),
        ]);
        let collected = ResponseBodyGuard::streaming(
            body,
            Some(9),
            9,
            Duration::from_secs(1),
            0,
            Duration::ZERO,
        )
        .collect()
        .await;
        assert_eq!(
            collected.ok().map(http_body_util::Collected::to_bytes),
            Some(Bytes::from_static(b"safe-body"))
        );
    }

    #[tokio::test]
    async fn truncated_declared_length_returns_a_fixed_safe_error() {
        let body = ScriptedBody::new([Ok(Frame::data(Bytes::from_static(b"safe")))]);
        let error = ResponseBodyGuard::streaming(
            body,
            Some(9),
            32,
            Duration::from_secs(1),
            0,
            Duration::ZERO,
        )
        .collect()
        .await
        .err()
        .map(|error| error.to_string());
        assert_eq!(
            error.as_deref(),
            Some("upstream response body ended before its declared length")
        );
    }

    #[tokio::test]
    async fn frame_crossing_the_limit_is_not_forwarded() {
        let body = ScriptedBody::new([
            Ok(Frame::data(Bytes::from_static(b"safe"))),
            Ok(Frame::data(Bytes::from_static(b"attacker-canary"))),
        ]);
        let mut guarded =
            ResponseBodyGuard::streaming(body, None, 4, Duration::from_secs(1), 0, Duration::ZERO);

        let first = guarded
            .frame()
            .await
            .and_then(Result::ok)
            .and_then(|frame| frame.into_data().ok());
        assert_eq!(first, Some(Bytes::from_static(b"safe")));

        let error = guarded
            .frame()
            .await
            .and_then(Result::err)
            .map(|error| error.to_string());
        assert_eq!(
            error.as_deref(),
            Some("upstream response body exceeded limit")
        );
        assert!(
            guarded.frame().await.is_none(),
            "a rejected body must remain latched closed"
        );
    }

    #[tokio::test]
    async fn frame_crossing_the_declared_length_is_not_forwarded() {
        let body = ScriptedBody::new([
            Ok(Frame::data(Bytes::from_static(b"safe"))),
            Ok(Frame::data(Bytes::from_static(b"extra"))),
        ]);
        let mut guarded = ResponseBodyGuard::streaming(
            body,
            Some(4),
            32,
            Duration::from_secs(1),
            0,
            Duration::ZERO,
        );
        let first = guarded
            .frame()
            .await
            .and_then(Result::ok)
            .and_then(|frame| frame.into_data().ok());
        assert_eq!(first, Some(Bytes::from_static(b"safe")));
        let error = guarded
            .frame()
            .await
            .and_then(Result::err)
            .map(|error| error.to_string());
        assert_eq!(
            error.as_deref(),
            Some("upstream response body exceeded declared length")
        );
    }

    #[tokio::test]
    async fn trailers_are_rejected_without_exposing_their_fields() {
        let mut trailers = HeaderMap::new();
        trailers.insert(
            "x-attacker-canary",
            http::HeaderValue::from_static("rpackit-malformed-upstream-marker"),
        );
        let body = ScriptedBody::new([
            Ok(Frame::data(Bytes::from_static(b"safe"))),
            Ok(Frame::trailers(trailers)),
        ]);
        let error =
            ResponseBodyGuard::streaming(body, None, 32, Duration::from_secs(1), 0, Duration::ZERO)
                .collect()
                .await
                .err()
                .map(|error| error.to_string());
        assert_eq!(
            error.as_deref(),
            Some("upstream response trailers were rejected")
        );
        assert!(
            !error
                .as_deref()
                .is_some_and(|message| message.contains("rpackit-malformed-upstream-marker"))
        );
    }

    #[tokio::test]
    async fn inner_errors_are_replaced_with_a_secret_free_message() {
        let body = ScriptedBody::new([Err(io::Error::other("rpackit-malformed-upstream-marker"))]);
        let error =
            ResponseBodyGuard::streaming(body, None, 32, Duration::from_secs(1), 0, Duration::ZERO)
                .collect()
                .await
                .err()
                .map(|error| error.to_string());
        assert_eq!(
            error.as_deref(),
            Some("upstream response body was malformed")
        );
    }

    #[tokio::test]
    async fn body_forbidden_drops_the_first_data_frame_and_latches_closed() {
        let body = ScriptedBody::new([Ok(Frame::data(Bytes::from_static(
            b"rpackit-malformed-upstream-marker",
        )))]);
        let mut guarded = ResponseBodyGuard::forbidden(body, Some(4096));
        assert_eq!(guarded.size_hint().exact(), Some(4096));

        let error = guarded
            .frame()
            .await
            .and_then(Result::err)
            .map(|error| error.to_string());
        assert_eq!(
            error.as_deref(),
            Some("upstream response body exceeded limit")
        );
        assert!(
            guarded.frame().await.is_none(),
            "a forbidden body must remain latched closed"
        );
    }

    #[test]
    fn body_forbidden_can_advertise_a_hypothetical_length() {
        let guarded =
            ResponseBodyGuard::forbidden(ScriptedBody::new(std::iter::empty()), Some(4096));
        assert_eq!(guarded.size_hint().exact(), Some(4096));
    }

    #[tokio::test]
    async fn decoded_frame_crossing_the_limit_is_not_forwarded() {
        let body = ScriptedBody::new([
            Ok(Frame::data(Bytes::from_static(b"safe"))),
            Ok(Frame::data(Bytes::from_static(b"overflow"))),
        ]);
        let mut guarded = DecodedBodyGuard::new(body, 4);
        let first = guarded
            .frame()
            .await
            .and_then(Result::ok)
            .and_then(|frame| frame.into_data().ok());
        assert_eq!(first, Some(Bytes::from_static(b"safe")));
        let error = guarded
            .frame()
            .await
            .and_then(Result::err)
            .map(|error| error.to_string());
        assert_eq!(
            error.as_deref(),
            Some("decoded upstream response body exceeded limit")
        );
        assert!(guarded.frame().await.is_none());
    }

    #[tokio::test]
    async fn decoded_inner_errors_are_sanitized() {
        let body = ScriptedBody::new([Err(io::Error::other("rpackit-malformed-upstream-marker"))]);
        let error = DecodedBodyGuard::new(body, 32)
            .collect()
            .await
            .err()
            .map(|error| error.to_string());
        assert_eq!(
            error.as_deref(),
            Some("upstream response content decoding failed")
        );
    }
}
