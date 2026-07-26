//! Bounded raw HTTP/1.1 admission before Hyper can normalize the request.

use std::{collections::HashMap, str::FromStr};

use http::{HeaderName, HeaderValue, Uri};
use thiserror::Error;

use crate::TransportLimits;

const PROTECTED_HEADER: &str = "shiny-shared-secret";

/// Secret-free request rejection reasons.
#[derive(Clone, Copy, Debug, Error)]
pub(crate) enum AdmissionError {
    #[error("request headers are incomplete")]
    Incomplete,
    #[error("request header limit exceeded")]
    HeaderLimit,
    #[error("request line limit exceeded")]
    RequestLineLimit,
    #[error("malformed HTTP/1.1 request")]
    Malformed,
    #[error("request target is not origin-form")]
    Target,
    #[error("request method is not allowed")]
    Method,
    #[error("request authority is not allowed")]
    Authority,
    #[error("request framing is ambiguous")]
    Framing,
    #[error("request upgrade is not allowed")]
    Upgrade,
    #[error("protected connection token is not allowed")]
    ProtectedConnectionToken,
    #[error("ambiguous credential or origin header")]
    AmbiguousSecurityHeader,
    #[error("declared request body is too large")]
    BodyLimit,
}

#[derive(Clone, Debug)]
pub(crate) struct RawAdmission {
    pub(crate) connection_tokens: Vec<String>,
    pub(crate) websocket_upgrade: bool,
}

pub(crate) fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

pub(crate) fn validate(
    bytes: &[u8],
    expected_authority: &str,
    limits: &TransportLimits,
) -> Result<RawAdmission, AdmissionError> {
    let end = header_end(bytes).ok_or(AdmissionError::Incomplete)?;
    if end > limits.max_header_bytes {
        return Err(AdmissionError::HeaderLimit);
    }

    validate_line_endings(&bytes[..end])?;
    let first_line_end = bytes[..end]
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or(AdmissionError::Malformed)?;
    if first_line_end > limits.max_request_line_bytes {
        return Err(AdmissionError::RequestLineLimit);
    }

    let mut headers = vec![httparse::EMPTY_HEADER; limits.max_headers];
    let mut request = httparse::Request::new(&mut headers);
    let parsed = request
        .parse(&bytes[..end])
        .map_err(|_| AdmissionError::Malformed)?;
    let httparse::Status::Complete(parsed_end) = parsed else {
        return Err(AdmissionError::Incomplete);
    };
    if parsed_end != end || request.version != Some(1) {
        return Err(AdmissionError::Malformed);
    }

    let method = request.method.ok_or(AdmissionError::Malformed)?;
    let target = request.path.ok_or(AdmissionError::Malformed)?;
    validate_method(method)?;
    validate_target(target)?;

    let mut values: HashMap<String, Vec<&[u8]>> = HashMap::new();
    for header in request.headers.iter() {
        let name = HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| AdmissionError::Malformed)?;
        HeaderValue::from_bytes(header.value).map_err(|_| AdmissionError::Malformed)?;
        values
            .entry(name.as_str().to_owned())
            .or_default()
            .push(trim_ows(header.value));
    }

    require_exact_authority(&values, expected_authority)?;
    reject_ambiguous_security_headers(&values)?;
    validate_framing(&values, limits)?;

    let connection_tokens = parse_connection_tokens(&values)?;
    if connection_tokens
        .iter()
        .any(|token| is_protected_connection_target(token))
    {
        return Err(AdmissionError::ProtectedConnectionToken);
    }

    let websocket_upgrade = validate_upgrade(&values, &connection_tokens)?;
    Ok(RawAdmission {
        connection_tokens,
        websocket_upgrade,
    })
}

fn validate_line_endings(bytes: &[u8]) -> Result<(), AdmissionError> {
    if bytes.contains(&0) {
        return Err(AdmissionError::Malformed);
    }
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' && (index == 0 || bytes[index - 1] != b'\r') {
            return Err(AdmissionError::Malformed);
        }
        if *byte == b'\r' && bytes.get(index + 1) != Some(&b'\n') {
            return Err(AdmissionError::Malformed);
        }
    }

    let mut lines = bytes.split(|byte| *byte == b'\n');
    let _request_line = lines.next().ok_or(AdmissionError::Malformed)?;
    for line in lines {
        let content = line.strip_suffix(b"\r").unwrap_or(line);
        if content.is_empty() {
            break;
        }
        if matches!(content.first(), Some(b' ' | b'\t')) {
            return Err(AdmissionError::Malformed);
        }
    }
    Ok(())
}

fn validate_method(method: &str) -> Result<(), AdmissionError> {
    if !method.bytes().all(is_token_byte) {
        return Err(AdmissionError::Malformed);
    }
    if method.eq_ignore_ascii_case("CONNECT") || method.eq_ignore_ascii_case("TRACE") {
        return Err(AdmissionError::Method);
    }
    Ok(())
}

fn validate_target(target: &str) -> Result<(), AdmissionError> {
    if !target.starts_with('/') || target.starts_with("//") || target.contains('#') {
        return Err(AdmissionError::Target);
    }
    let uri = Uri::from_str(target).map_err(|_| AdmissionError::Target)?;
    if uri.scheme().is_some() || uri.authority().is_some() {
        return Err(AdmissionError::Target);
    }
    Ok(())
}

fn require_exact_authority(
    values: &HashMap<String, Vec<&[u8]>>,
    expected: &str,
) -> Result<(), AdmissionError> {
    let hosts = values.get("host").ok_or(AdmissionError::Authority)?;
    if hosts.len() != 1 || hosts[0] != expected.as_bytes() {
        return Err(AdmissionError::Authority);
    }
    Ok(())
}

fn reject_ambiguous_security_headers(
    values: &HashMap<String, Vec<&[u8]>>,
) -> Result<(), AdmissionError> {
    for name in [
        "cookie",
        "origin",
        PROTECTED_HEADER,
        "x-rpackit-bootstrap",
        "connection",
        "upgrade",
    ] {
        if values.get(name).is_some_and(|entries| entries.len() > 1) {
            return Err(AdmissionError::AmbiguousSecurityHeader);
        }
    }
    Ok(())
}

fn validate_framing(
    values: &HashMap<String, Vec<&[u8]>>,
    limits: &TransportLimits,
) -> Result<(), AdmissionError> {
    let content_lengths = values.get("content-length");
    let transfer_encodings = values.get("transfer-encoding");
    if content_lengths.is_some_and(|entries| entries.len() != 1)
        || transfer_encodings.is_some_and(|entries| entries.len() != 1)
        || (content_lengths.is_some() && transfer_encodings.is_some())
    {
        return Err(AdmissionError::Framing);
    }
    if let Some(entries) = content_lengths {
        let text = std::str::from_utf8(entries[0]).map_err(|_| AdmissionError::Framing)?;
        if text.is_empty()
            || !text.bytes().all(|byte| byte.is_ascii_digit())
            || text.parse::<usize>().map_err(|_| AdmissionError::Framing)?
                > limits.max_request_body_bytes
        {
            return Err(AdmissionError::BodyLimit);
        }
    }
    if let Some(entries) = transfer_encodings {
        let text = std::str::from_utf8(entries[0]).map_err(|_| AdmissionError::Framing)?;
        if !text.eq_ignore_ascii_case("chunked") {
            return Err(AdmissionError::Framing);
        }
    }
    Ok(())
}

fn parse_connection_tokens(
    values: &HashMap<String, Vec<&[u8]>>,
) -> Result<Vec<String>, AdmissionError> {
    let Some(entries) = values.get("connection") else {
        return Ok(Vec::new());
    };
    let text = std::str::from_utf8(entries[0]).map_err(|_| AdmissionError::Malformed)?;
    let mut tokens = Vec::new();
    for value in text.split(',') {
        let token = value.trim();
        if token.is_empty() || !token.bytes().all(is_token_byte) {
            return Err(AdmissionError::Malformed);
        }
        let lower = token.to_ascii_lowercase();
        if tokens.contains(&lower) {
            return Err(AdmissionError::Malformed);
        }
        tokens.push(lower);
    }
    Ok(tokens)
}

fn validate_upgrade(
    values: &HashMap<String, Vec<&[u8]>>,
    connection_tokens: &[String],
) -> Result<bool, AdmissionError> {
    if values.contains_key("http2-settings") {
        return Err(AdmissionError::Upgrade);
    }
    let connection_upgrade = connection_tokens.iter().any(|token| token == "upgrade");
    let Some(entries) = values.get("upgrade") else {
        if connection_upgrade {
            return Err(AdmissionError::Upgrade);
        }
        return Ok(false);
    };
    let value = std::str::from_utf8(entries[0]).map_err(|_| AdmissionError::Upgrade)?;
    if !connection_upgrade || !value.eq_ignore_ascii_case("websocket") {
        return Err(AdmissionError::Upgrade);
    }
    Ok(true)
}

pub(crate) fn is_protected_connection_target(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "cookie"
            | "origin"
            | "content-length"
            | "transfer-encoding"
            | "shiny-shared-secret"
            | "x-rpackit-bootstrap"
            | "forwarded"
            | "x-real-ip"
    ) || name.starts_with("x-forwarded-")
        || name.starts_with("x-original-")
}

pub(crate) fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> TransportLimits {
        TransportLimits::default()
    }

    #[test]
    fn accepts_strict_origin_form_request() {
        let request = b"GET /asset?q=1 HTTP/1.1\r\nHost: rpackit-a.localhost:1234\r\n\r\n";
        let admission = validate(request, "rpackit-a.localhost:1234", &limits());
        assert!(admission.is_ok());
    }

    #[test]
    fn rejects_duplicate_host_and_smuggled_framing() {
        let duplicate_host = b"GET / HTTP/1.1\r\nHost: rpackit-a.localhost:1234\r\nHost: rpackit-a.localhost:1234\r\n\r\n";
        assert!(matches!(
            validate(duplicate_host, "rpackit-a.localhost:1234", &limits()),
            Err(AdmissionError::Authority)
        ));

        let conflicting = b"POST / HTTP/1.1\r\nHost: rpackit-a.localhost:1234\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(matches!(
            validate(conflicting, "rpackit-a.localhost:1234", &limits()),
            Err(AdmissionError::Framing)
        ));
    }

    #[test]
    fn rejects_absolute_authority_and_protected_connection_tokens() {
        let absolute =
            b"GET http://example.test/ HTTP/1.1\r\nHost: rpackit-a.localhost:1234\r\n\r\n";
        assert!(matches!(
            validate(absolute, "rpackit-a.localhost:1234", &limits()),
            Err(AdmissionError::Target)
        ));

        let nominated = b"GET / HTTP/1.1\r\nHost: rpackit-a.localhost:1234\r\nConnection: Cookie\r\nCookie: a=b\r\n\r\n";
        assert!(matches!(
            validate(nominated, "rpackit-a.localhost:1234", &limits()),
            Err(AdmissionError::ProtectedConnectionToken)
        ));
    }
}
