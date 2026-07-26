//! Strict, bounded decoding of upstream HTTP content codings.

use std::{error::Error as StdError, io};

use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, ZlibDecoder, ZstdDecoder};
use bytes::Bytes;
use futures_util::StreamExt as _;
use http::{HeaderMap, header::CONTENT_ENCODING};
use http_body_util::{BodyExt as _, StreamBody, combinators::UnsyncBoxBody};
use hyper::body::{Body, Frame};
use tokio::io::{AsyncRead, BufReader};
use tokio_util::io::{ReaderStream, StreamReader};

use crate::{admission, response_body::DecodedBodyGuard};

type BoxError = Box<dyn StdError + Send + Sync>;
type BoxReader = Box<dyn AsyncRead + Send + Unpin>;

/// One supported non-identity HTTP content coding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContentCoding {
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

/// Parse every `Content-Encoding` field as one ordered list and reject
/// unsupported tokens or excessive decoding layers.
pub(crate) fn parse_content_codings(
    headers: &HeaderMap,
    max_layers: usize,
) -> io::Result<Vec<ContentCoding>> {
    let mut codings = Vec::new();
    for value in headers.get_all(CONTENT_ENCODING) {
        let value = value
            .to_str()
            .map_err(|_| io::Error::other("upstream content encoding was invalid"))?;
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() || !token.bytes().all(admission::is_token_byte) {
                return Err(io::Error::other("upstream content encoding was invalid"));
            }
            let coding = match token.to_ascii_lowercase().as_str() {
                "identity" => continue,
                "gzip" | "x-gzip" => ContentCoding::Gzip,
                "deflate" => ContentCoding::Deflate,
                "br" => ContentCoding::Brotli,
                "zstd" => ContentCoding::Zstd,
                _ => {
                    return Err(io::Error::other(
                        "upstream content encoding was unsupported",
                    ));
                }
            };
            codings.push(coding);
            if codings.len() > max_layers {
                return Err(io::Error::other(
                    "upstream content encoding layers exceeded limit",
                ));
            }
        }
    }
    Ok(codings)
}

/// Decode supported content codings in reverse application order and cap the
/// final representation before any crossing frame is released downstream.
pub(crate) fn decode_body<B>(
    body: B,
    codings: &[ContentCoding],
    max_decoded_body_bytes: usize,
) -> UnsyncBoxBody<Bytes, BoxError>
where
    B: Body<Data = Bytes, Error = io::Error> + Send + Unpin + 'static,
{
    let mut reader: BoxReader = Box::new(StreamReader::new(body.into_data_stream()));
    for coding in codings.iter().rev() {
        let buffered = BufReader::new(reader);
        reader = match coding {
            ContentCoding::Gzip => {
                let mut decoder = GzipDecoder::new(buffered);
                decoder.multiple_members(true);
                Box::new(decoder)
            }
            ContentCoding::Deflate => {
                let mut decoder = ZlibDecoder::new(buffered);
                decoder.multiple_members(true);
                Box::new(decoder)
            }
            ContentCoding::Brotli => {
                let mut decoder = BrotliDecoder::new(buffered);
                decoder.multiple_members(true);
                Box::new(decoder)
            }
            ContentCoding::Zstd => {
                let mut decoder = ZstdDecoder::new(buffered);
                decoder.multiple_members(true);
                Box::new(decoder)
            }
        };
    }
    let frames =
        ReaderStream::with_capacity(reader, 16 * 1024).map(|result| result.map(Frame::data));
    DecodedBodyGuard::new(StreamBody::new(frames), max_decoded_body_bytes)
        .map_err(|error| -> BoxError { Box::new(error) })
        .boxed_unsync()
}

#[cfg(test)]
mod tests {
    use async_compression::tokio::write::{BrotliEncoder, GzipEncoder, ZlibEncoder, ZstdEncoder};
    use http::HeaderValue;
    use http_body_util::Full;
    use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

    use super::*;

    #[test]
    fn parser_normalizes_supported_layers_and_identity() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_ENCODING, HeaderValue::from_static("identity, gzip"));
        headers.append(CONTENT_ENCODING, HeaderValue::from_static("br"));
        assert_eq!(
            parse_content_codings(&headers, 2).ok(),
            Some(vec![ContentCoding::Gzip, ContentCoding::Brotli])
        );
    }

    #[test]
    fn parser_rejects_unsupported_empty_and_excess_layers() {
        for value in ["compress", "gzip,", "gzip;level=9"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                CONTENT_ENCODING,
                HeaderValue::from_str(value).unwrap_or_else(|_| HeaderValue::from_static("")),
            );
            assert!(parse_content_codings(&headers, 2).is_err());
        }
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip, br, zstd"));
        assert!(parse_content_codings(&headers, 2).is_err());
    }

    async fn encode(content: &[u8], coding: ContentCoding) -> io::Result<Vec<u8>> {
        let capacity = content.len().saturating_mul(2).max(64 * 1024);
        let (writer, mut reader) = tokio::io::duplex(capacity);
        let mut encoder: Box<dyn AsyncWrite + Send + Unpin> = match coding {
            ContentCoding::Gzip => Box::new(GzipEncoder::new(writer)),
            ContentCoding::Deflate => Box::new(ZlibEncoder::new(writer)),
            ContentCoding::Brotli => Box::new(BrotliEncoder::new(writer)),
            ContentCoding::Zstd => Box::new(ZstdEncoder::new(writer)),
        };
        encoder.write_all(content).await?;
        encoder.shutdown().await?;
        drop(encoder);
        let mut compressed = Vec::new();
        reader.read_to_end(&mut compressed).await?;
        Ok(compressed)
    }

    #[tokio::test]
    async fn every_supported_coding_round_trips() -> Result<(), BoxError> {
        const CONTENT: &[u8] = b"safe decoded response content";
        for coding in [
            ContentCoding::Gzip,
            ContentCoding::Deflate,
            ContentCoding::Brotli,
            ContentCoding::Zstd,
        ] {
            let encoded = encode(CONTENT, coding).await?;
            let body =
                Full::new(Bytes::from(encoded)).map_err(|never| -> io::Error { match never {} });
            let decoded = decode_body(body, &[coding], 1024).collect().await?;
            assert_eq!(decoded.to_bytes().as_ref(), CONTENT);
        }
        Ok(())
    }

    #[tokio::test]
    async fn nested_codings_decode_in_reverse_application_order() -> Result<(), BoxError> {
        const CONTENT: &[u8] = b"safe nested response content";
        let gzip = encode(CONTENT, ContentCoding::Gzip).await?;
        let gzip_then_brotli = encode(&gzip, ContentCoding::Brotli).await?;
        let body = Full::new(Bytes::from(gzip_then_brotli))
            .map_err(|never| -> io::Error { match never {} });
        let decoded = decode_body(body, &[ContentCoding::Gzip, ContentCoding::Brotli], 1024)
            .collect()
            .await?;
        assert_eq!(decoded.to_bytes().as_ref(), CONTENT);
        Ok(())
    }
}
