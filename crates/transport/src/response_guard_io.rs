//! Validate one upstream response head before exposing bytes to Hyper.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct ResponseGuardIo<T> {
    inner: T,
    prefix: BytesMut,
    max_header_bytes: usize,
    max_headers: usize,
    allow_switching_protocols: bool,
    validated: bool,
    rejected: bool,
}

impl<T> ResponseGuardIo<T> {
    pub(crate) fn new(
        inner: T,
        max_header_bytes: usize,
        max_headers: usize,
        allow_switching_protocols: bool,
    ) -> Self {
        Self {
            inner,
            prefix: BytesMut::with_capacity(4 * 1024),
            max_header_bytes,
            max_headers,
            allow_switching_protocols,
            validated: false,
            rejected: false,
        }
    }

    fn validate_prefix(&mut self) -> io::Result<()> {
        let end = header_end(&self.prefix)
            .ok_or_else(|| io::Error::other("upstream response head is incomplete"))?;
        validate_response_head(
            &self.prefix[..end],
            self.max_headers,
            self.allow_switching_protocols,
        )?;
        self.validated = true;
        Ok(())
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ResponseGuardIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.rejected {
            return Poll::Ready(Err(io::Error::other("upstream response head was rejected")));
        }

        while !self.validated {
            if header_end(&self.prefix).is_some() {
                if let Err(error) = self.validate_prefix() {
                    self.prefix.clear();
                    self.rejected = true;
                    return Poll::Ready(Err(error));
                }
                break;
            }
            if self.prefix.len() >= self.max_header_bytes {
                self.prefix.clear();
                self.rejected = true;
                return Poll::Ready(Err(io::Error::other(
                    "upstream response head exceeded limit",
                )));
            }

            let remaining = self.max_header_bytes - self.prefix.len();
            let mut chunk = [0_u8; 4 * 1024];
            let limit = remaining.min(chunk.len());
            let mut incoming = ReadBuf::new(&mut chunk[..limit]);
            match Pin::new(&mut self.inner).poll_read(context, &mut incoming) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    self.prefix.clear();
                    self.rejected = true;
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(())) if incoming.filled().is_empty() => {
                    self.prefix.clear();
                    self.rejected = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "upstream closed before its response head completed",
                    )));
                }
                Poll::Ready(Ok(())) => self.prefix.extend_from_slice(incoming.filled()),
            }
        }

        if self.prefix.has_remaining() {
            let count = self.prefix.remaining().min(buffer.remaining());
            buffer.put_slice(&self.prefix[..count]);
            self.prefix.advance(count);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ResponseGuardIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn validate_response_head(
    bytes: &[u8],
    max_headers: usize,
    allow_switching_protocols: bool,
) -> io::Result<()> {
    if has_bare_line_ending(bytes) {
        return Err(io::Error::other(
            "upstream response used a bare line ending",
        ));
    }
    let mut headers = vec![httparse::EMPTY_HEADER; max_headers];
    let mut response = httparse::Response::new(&mut headers);
    let parsed = response
        .parse(bytes)
        .map_err(|_| io::Error::other("upstream response head is malformed"))?;
    let status_allowed = matches!(response.code, Some(200..=599))
        || (response.code == Some(101) && allow_switching_protocols);
    if parsed != httparse::Status::Complete(bytes.len())
        || response.version != Some(1)
        || !status_allowed
    {
        return Err(io::Error::other("upstream response status is invalid"));
    }
    if response.code == Some(101) && !allow_switching_protocols {
        return Err(io::Error::other(
            "upstream protocol switch was not requested",
        ));
    }

    let content_lengths = header_values(response.headers, b"content-length");
    let transfer_encodings = header_values(response.headers, b"transfer-encoding");
    if content_lengths.len() > 1
        || transfer_encodings.len() > 1
        || (!content_lengths.is_empty() && !transfer_encodings.is_empty())
    {
        return Err(io::Error::other("upstream response framing is ambiguous"));
    }
    if let Some(value) = content_lengths.first() {
        let value = value.trim_ascii();
        if value.is_empty()
            || !value.iter().all(u8::is_ascii_digit)
            || std::str::from_utf8(value)
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .is_none()
        {
            return Err(io::Error::other("upstream content length is malformed"));
        }
    }
    if let Some(value) = transfer_encodings.first()
        && !value.trim_ascii().eq_ignore_ascii_case(b"chunked")
    {
        return Err(io::Error::other(
            "upstream transfer encoding is unsupported",
        ));
    }
    Ok(())
}

fn has_bare_line_ending(bytes: &[u8]) -> bool {
    bytes.iter().enumerate().any(|(index, byte)| {
        (*byte == b'\n' && (index == 0 || bytes[index - 1] != b'\r'))
            || (*byte == b'\r' && bytes.get(index + 1) != Some(&b'\n'))
    })
}

fn header_values<'a>(headers: &'a [httparse::Header<'a>], name: &[u8]) -> Vec<&'a [u8]> {
    headers
        .iter()
        .filter(|header| header.name.as_bytes().eq_ignore_ascii_case(name))
        .map(|header| header.value)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    struct ErrorThenResponse {
        step: u8,
    }

    impl AsyncRead for ErrorThenResponse {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.step {
                0 => {
                    buffer.put_slice(b"HTTP/1.1 200 OK\r\n");
                    self.step = 1;
                    Poll::Ready(Ok(()))
                }
                1 => {
                    self.step = 2;
                    Poll::Ready(Err(io::Error::other("scripted upstream read failure")))
                }
                _ => {
                    buffer.put_slice(b"Content-Length: 4\r\n\r\nleak");
                    Poll::Ready(Ok(()))
                }
            }
        }
    }

    async fn read_fragmented(
        wire_response: &[u8],
        fragment_size: usize,
        max_header_bytes: usize,
    ) -> (io::Result<usize>, Vec<u8>) {
        let capacity = wire_response.len().max(64);
        let (mut writer, reader) = tokio::io::duplex(capacity);
        let response = wire_response.to_vec();
        let writer_task = tokio::spawn(async move {
            for fragment in response.chunks(fragment_size) {
                writer.write_all(fragment).await?;
                tokio::task::yield_now().await;
            }
            writer.shutdown().await
        });
        let mut guarded = ResponseGuardIo::new(reader, max_header_bytes, 8, false);
        let mut output = Vec::new();
        let result = guarded.read_to_end(&mut output).await;
        assert!(writer_task.await.is_ok());
        (result, output)
    }

    #[test]
    fn accepts_one_unambiguous_http_11_response() {
        assert!(
            validate_response_head(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Test: ok\r\n\r\n",
                8,
                false,
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_ambiguous_or_lenient_framing() {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
            b"HTTP/1.1 200 OK\nContent-Length: 0\n\n",
            b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
        ] {
            assert!(validate_response_head(response, 8, false).is_err());
        }
    }

    #[test]
    fn protocol_switch_requires_the_websocket_path() {
        let response =
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        assert!(validate_response_head(response, 8, false).is_err());
        assert!(validate_response_head(response, 8, true).is_ok());
    }

    #[tokio::test]
    async fn fragmented_head_is_withheld_until_complete() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Test: safe\r\n\r\nbody";
        let (result, output) = read_fragmented(response, 1, 1024).await;
        assert_eq!(result.ok(), Some(response.len()));
        assert_eq!(output, response);
    }

    #[tokio::test]
    async fn exact_header_limit_passes_and_one_byte_over_releases_nothing() {
        let exact = b"HTTP/1.1 204 No Content\r\nX-Test: safe\r\n\r\n";
        let (exact_result, exact_output) = read_fragmented(exact, 1, exact.len()).await;
        assert_eq!(exact_result.ok(), Some(exact.len()));
        assert_eq!(exact_output, exact);

        let oversized = b"HTTP/1.1 204 No Content\r\nX-Test: xsafe\r\n\r\n";
        assert_eq!(oversized.len(), exact.len() + 1);
        let (oversized_result, oversized_output) = read_fragmented(oversized, 1, exact.len()).await;
        assert!(oversized_result.is_err());
        assert!(oversized_output.is_empty());
    }

    #[tokio::test]
    async fn rejection_error_never_echoes_attacker_bytes() {
        let response = b"HTTP/1.1 200 OK\nX-Attacker: attacker-canary\nContent-Length: 0\n\n";
        let (result, output) = read_fragmented(response, 2, 1024).await;
        let error = result.err().map(|error| error.to_string());
        assert_eq!(
            error.as_deref(),
            Some("upstream closed before its response head completed")
        );
        assert!(
            !error
                .as_deref()
                .is_some_and(|message| message.contains("attacker-canary"))
        );
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn prevalidation_read_error_is_permanently_latched() {
        let mut guarded = ResponseGuardIo::new(ErrorThenResponse { step: 0 }, 1024, 8, false);
        let mut output = [0_u8; 128];

        let first = guarded.read(&mut output).await;
        assert_eq!(
            first.err().map(|error| error.to_string()).as_deref(),
            Some("scripted upstream read failure")
        );
        assert!(output.iter().all(|byte| *byte == 0));

        let second = guarded.read(&mut output).await;
        assert_eq!(
            second.err().map(|error| error.to_string()).as_deref(),
            Some("upstream response head was rejected")
        );
        assert!(output.iter().all(|byte| *byte == 0));
    }
}
