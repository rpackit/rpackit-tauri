//! Activity tracking and byte-rate backpressure for upgraded tunnels.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
    time::{Instant, Sleep, sleep_until},
};

const TOKEN_UNITS_PER_BYTE: u128 = 1_000_000_000;

/// An upgraded stream that records successful activity and rate-limits reads.
///
/// `copy_bidirectional` owns one wrapper for each endpoint. Limiting reads
/// therefore gives client-to-upstream and upstream-to-client traffic separate
/// token buckets without counting the same byte again when it is written.
pub(crate) struct WebSocketIo<T> {
    inner: T,
    activity: watch::Sender<u64>,
    read_rate: ByteRateLimiter,
}

impl<T> WebSocketIo<T> {
    pub(crate) fn new(
        inner: T,
        activity: watch::Sender<u64>,
        max_bytes_per_second: u64,
        burst_window: Duration,
    ) -> Self {
        Self {
            inner,
            activity,
            read_rate: ByteRateLimiter::new(max_bytes_per_second, burst_window),
        }
    }

    fn record_activity(&self) {
        self.activity
            .send_modify(|sequence| *sequence = sequence.wrapping_add(1));
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for WebSocketIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() == 0 {
            return Pin::new(&mut this.inner).poll_read(context, buffer);
        }

        let allowance = match this.read_rate.poll_allowance(context) {
            Poll::Ready(allowance) => allowance.min(buffer.remaining()),
            Poll::Pending => return Poll::Pending,
        };
        let initialized = buffer.initialize_unfilled_to(allowance);
        let mut limited = ReadBuf::new(initialized);
        let result = Pin::new(&mut this.inner).poll_read(context, &mut limited);
        if matches!(result, Poll::Ready(Ok(()))) {
            let read = limited.filled().len();
            buffer.advance(read);
            this.read_rate.consume(read);
            if read > 0 {
                this.record_activity();
            }
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for WebSocketIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(context, buffer);
        if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
            this.record_activity();
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(context)
    }
}

struct ByteRateLimiter {
    bytes_per_second: u64,
    capacity: u128,
    available: u128,
    last_refill: Instant,
    wake: Option<Pin<Box<Sleep>>>,
}

impl ByteRateLimiter {
    fn new(bytes_per_second: u64, burst_window: Duration) -> Self {
        let capacity = if bytes_per_second == 0 {
            0
        } else {
            u128::from(bytes_per_second)
                .saturating_mul(burst_window.as_nanos())
                .max(TOKEN_UNITS_PER_BYTE)
        };
        Self {
            bytes_per_second,
            capacity,
            available: capacity,
            last_refill: Instant::now(),
            wake: None,
        }
    }

    fn poll_allowance(&mut self, context: &mut Context<'_>) -> Poll<usize> {
        if self.bytes_per_second == 0 {
            return Poll::Ready(usize::MAX);
        }

        loop {
            let now = Instant::now();
            self.refill(now);
            let bytes = self.available / TOKEN_UNITS_PER_BYTE;
            if bytes > 0 {
                self.wake = None;
                return Poll::Ready(usize::try_from(bytes).unwrap_or(usize::MAX));
            }

            let missing = TOKEN_UNITS_PER_BYTE.saturating_sub(self.available);
            let wait_nanos = missing.div_ceil(u128::from(self.bytes_per_second)).max(1);
            let wait_nanos = u64::try_from(wait_nanos).unwrap_or(u64::MAX);
            let deadline = now + Duration::from_nanos(wait_nanos);
            let timer = self
                .wake
                .get_or_insert_with(|| Box::pin(sleep_until(deadline)));
            timer.as_mut().reset(deadline);
            if timer.as_mut().poll(context).is_pending() {
                return Poll::Pending;
            }
            self.wake = None;
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.last_refill = now;
        let added = u128::from(self.bytes_per_second).saturating_mul(elapsed.as_nanos());
        self.available = self.capacity.min(self.available.saturating_add(added));
    }

    fn consume(&mut self, bytes: usize) {
        if self.bytes_per_second == 0 {
            return;
        }
        let consumed = (bytes as u128).saturating_mul(TOKEN_UNITS_PER_BYTE);
        self.available = self.available.saturating_sub(consumed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_refills_without_losing_fractional_bytes() {
        let start = Instant::now();
        let mut limiter = ByteRateLimiter::new(10, Duration::from_secs(1));
        limiter.last_refill = start;
        assert_eq!(limiter.available / TOKEN_UNITS_PER_BYTE, 10);

        limiter.consume(10);
        assert_eq!(limiter.available, 0);
        limiter.refill(start + Duration::from_millis(250));
        assert_eq!(
            limiter.available,
            2 * TOKEN_UNITS_PER_BYTE + TOKEN_UNITS_PER_BYTE / 2
        );
        limiter.refill(start + Duration::from_millis(500));
        assert_eq!(limiter.available, 5 * TOKEN_UNITS_PER_BYTE);
    }

    #[test]
    fn burst_capacity_is_at_least_one_byte_and_is_saturating() {
        let tiny = ByteRateLimiter::new(1, Duration::from_nanos(1));
        assert_eq!(tiny.capacity, TOKEN_UNITS_PER_BYTE);

        let disabled = ByteRateLimiter::new(0, Duration::ZERO);
        assert_eq!(disabled.capacity, 0);
        assert_eq!(disabled.available, 0);
    }
}
