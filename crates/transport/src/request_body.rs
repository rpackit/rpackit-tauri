//! Bound authenticated request uploads before they reach the fixed upstream.

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

/// A streaming request-body guard with independent size, idle, sustained-rate,
/// and total-duration limits.
pub(crate) struct RequestBodyGuard<B> {
    inner: B,
    max_body_bytes: u64,
    bytes_forwarded: u64,
    idle_timeout: Duration,
    total_timeout: Duration,
    rate_window: Duration,
    minimum_window_bytes: u64,
    window_bytes: u64,
    idle_timer: Option<Pin<Box<Sleep>>>,
    total_timer: Option<Pin<Box<Sleep>>>,
    rate_timer: Option<Pin<Box<Sleep>>>,
    completed: bool,
    failed: bool,
}

impl<B> RequestBodyGuard<B> {
    pub(crate) fn new(
        inner: B,
        max_body_bytes: usize,
        idle_timeout: Duration,
        total_timeout: Duration,
        minimum_bytes_per_second: u64,
        rate_window: Duration,
    ) -> Self {
        Self {
            inner,
            max_body_bytes: u64::try_from(max_body_bytes).unwrap_or(u64::MAX),
            bytes_forwarded: 0,
            idle_timeout,
            total_timeout,
            rate_window,
            minimum_window_bytes: minimum_bytes_for_window(minimum_bytes_per_second, rate_window),
            window_bytes: 0,
            idle_timer: None,
            total_timer: None,
            rate_timer: None,
            completed: false,
            failed: false,
        }
    }

    fn start_timers(&mut self) {
        if self.idle_timer.is_none() {
            self.idle_timer = Some(Box::pin(sleep(self.idle_timeout)));
            self.total_timer = Some(Box::pin(sleep(self.total_timeout)));
            if self.minimum_window_bytes > 0 {
                self.rate_timer = Some(Box::pin(sleep(self.rate_window)));
            }
        }
    }

    fn reject(&mut self, message: &'static str) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        self.failed = true;
        Poll::Ready(Some(Err(io::Error::other(message))))
    }

    fn timer_elapsed(timer: &mut Option<Pin<Box<Sleep>>>, context: &mut Context<'_>) -> bool {
        timer
            .as_mut()
            .is_some_and(|timer| timer.as_mut().poll(context).is_ready())
    }

    fn reset_idle_timer(&mut self, now: Instant) {
        if let Some(timer) = self.idle_timer.as_mut() {
            timer.as_mut().reset(now + self.idle_timeout);
        }
    }

    fn reset_rate_window(&mut self, now: Instant) {
        self.window_bytes = 0;
        if let Some(timer) = self.rate_timer.as_mut() {
            timer.as_mut().reset(now + self.rate_window);
        }
    }
}

impl<B> Body for RequestBodyGuard<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        if this.failed || this.completed {
            return Poll::Ready(None);
        }
        this.start_timers();

        if Self::timer_elapsed(&mut this.total_timer, context) {
            return this.reject("downstream request body exceeded total timeout");
        }
        if Self::timer_elapsed(&mut this.idle_timer, context) {
            return this.reject("downstream request body exceeded idle timeout");
        }
        if Self::timer_elapsed(&mut this.rate_timer, context) {
            if this.window_bytes < this.minimum_window_bytes {
                return this.reject("downstream request body rate was below limit");
            }
            this.reset_rate_window(Instant::now());
        }

        match Pin::new(&mut this.inner).poll_frame(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Err(_))) => this.reject("downstream request body was malformed"),
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    let Ok(data_length) = u64::try_from(data.len()) else {
                        return this.reject("downstream request body exceeded limit");
                    };
                    let Some(total) = this.bytes_forwarded.checked_add(data_length) else {
                        return this.reject("downstream request body exceeded limit");
                    };
                    if total > this.max_body_bytes {
                        return this.reject("downstream request body exceeded limit");
                    }
                    this.bytes_forwarded = total;
                    this.window_bytes = this.window_bytes.saturating_add(data_length);
                    if data_length > 0 {
                        this.reset_idle_timer(Instant::now());
                    }
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                Err(_) => this.reject("downstream request body trailers were rejected"),
            },
            Poll::Ready(None) => {
                this.completed = true;
                Poll::Ready(None)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.failed || self.completed || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        if self.failed || self.completed {
            return SizeHint::with_exact(0);
        }
        let inner_hint = self.inner.size_hint();
        let remaining = self.max_body_bytes.saturating_sub(self.bytes_forwarded);
        let lower = inner_hint.lower().min(remaining);
        let upper = inner_hint.upper().unwrap_or(remaining).min(remaining);
        let mut hint = SizeHint::new();
        hint.set_lower(lower);
        hint.set_upper(upper.max(lower));
        hint
    }
}

fn minimum_bytes_for_window(bytes_per_second: u64, window: Duration) -> u64 {
    const NANOS_PER_SECOND: u128 = 1_000_000_000;
    let numerator = u128::from(bytes_per_second).saturating_mul(window.as_nanos());
    let rounded_up = numerator
        .saturating_add(NANOS_PER_SECOND - 1)
        .checked_div(NANOS_PER_SECOND)
        .unwrap_or(u128::MAX);
    u64::try_from(rounded_up).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

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

    fn guard(body: ScriptedBody, max_body_bytes: usize) -> RequestBodyGuard<ScriptedBody> {
        RequestBodyGuard::new(
            body,
            max_body_bytes,
            Duration::from_secs(1),
            Duration::from_secs(2),
            1,
            Duration::from_secs(1),
        )
    }

    #[tokio::test]
    async fn forwards_an_exactly_bounded_body() {
        let body = ScriptedBody::new([
            Ok(Frame::data(Bytes::from_static(b"safe"))),
            Ok(Frame::data(Bytes::from_static(b"-body"))),
        ]);
        let collected = guard(body, 9).collect().await;
        assert_eq!(
            collected.ok().map(http_body_util::Collected::to_bytes),
            Some(Bytes::from_static(b"safe-body"))
        );
    }

    #[tokio::test]
    async fn drops_a_frame_crossing_the_byte_limit() {
        let body = ScriptedBody::new([
            Ok(Frame::data(Bytes::from_static(b"safe"))),
            Ok(Frame::data(Bytes::from_static(b"-body"))),
        ]);
        let error = guard(body, 4).collect().await.err();
        assert_eq!(
            error.as_ref().map(ToString::to_string).as_deref(),
            Some("downstream request body exceeded limit")
        );
    }

    #[tokio::test]
    async fn rejects_request_trailers_without_forwarding_them() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-untrusted", http::HeaderValue::from_static("value"));
        let body = ScriptedBody::new([Ok(Frame::trailers(trailers))]);
        let error = guard(body, 64).collect().await.err();
        assert_eq!(
            error.as_ref().map(ToString::to_string).as_deref(),
            Some("downstream request body trailers were rejected")
        );
    }

    #[test]
    fn rate_threshold_rounds_up_without_floating_point() {
        assert_eq!(
            minimum_bytes_for_window(1_024, Duration::from_millis(250)),
            256
        );
        assert_eq!(minimum_bytes_for_window(1, Duration::from_nanos(1)), 1);
        assert_eq!(minimum_bytes_for_window(0, Duration::from_secs(5)), 0);
    }
}
