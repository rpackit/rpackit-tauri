//! Strict proxy-session and upstream application-cookie handling.

use std::collections::HashSet;

use http::{
    HeaderMap, HeaderValue,
    header::{COOKIE, SET_COOKIE},
};
use percent_encoding::percent_decode_str;
use thiserror::Error;

use crate::{Secret, proxy::SESSION_COOKIE_NAME};

#[derive(Clone, Copy, Debug, Error)]
pub(crate) enum CookieError {
    #[error("proxy-session cookie is missing or invalid")]
    Authentication,
    #[error("cookie syntax is ambiguous")]
    Ambiguous,
    #[error("upstream cookie is not safe for the proxy origin")]
    UnsafeUpstreamCookie,
}

pub(crate) fn authenticate_and_strip(
    headers: &mut HeaderMap,
    session: &Secret,
) -> Result<(), CookieError> {
    let values: Vec<HeaderValue> = headers.get_all(COOKIE).iter().cloned().collect();
    if values.len() != 1 {
        return Err(CookieError::Authentication);
    }
    let text = values[0]
        .to_str()
        .map_err(|_| CookieError::Authentication)?;

    let mut session_seen = false;
    let mut valid_session = false;
    let mut application = Vec::new();
    let mut application_names = HashSet::new();

    for segment in text.split(';') {
        let trimmed = segment.trim();
        let Some((name, value)) = trimmed.split_once('=') else {
            return Err(CookieError::Ambiguous);
        };
        if name.is_empty()
            || !name.bytes().all(super::admission::is_token_byte)
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(CookieError::Ambiguous);
        }

        if is_reserved_name(name) {
            if session_seen {
                return Err(CookieError::Ambiguous);
            }
            session_seen = true;
            valid_session = session.matches(value.as_bytes());
        } else {
            if !application_names.insert(name) {
                return Err(CookieError::Ambiguous);
            }
            application.push(trimmed);
        }
    }

    if !session_seen || !valid_session {
        return Err(CookieError::Authentication);
    }

    headers.remove(COOKIE);
    if !application.is_empty() {
        let rebuilt =
            HeaderValue::from_str(&application.join("; ")).map_err(|_| CookieError::Ambiguous)?;
        headers.insert(COOKIE, rebuilt);
    }
    Ok(())
}

pub(crate) fn normalize_set_cookie_headers(
    headers: &mut HeaderMap,
    upstream_host: &str,
) -> Result<(), CookieError> {
    let values: Vec<HeaderValue> = headers.get_all(SET_COOKIE).iter().cloned().collect();
    if values.is_empty() {
        return Ok(());
    }
    headers.remove(SET_COOKIE);
    for value in values {
        let normalized = normalize_set_cookie(&value, upstream_host)?;
        headers.append(SET_COOKIE, normalized);
    }
    Ok(())
}

fn normalize_set_cookie(
    value: &HeaderValue,
    upstream_host: &str,
) -> Result<HeaderValue, CookieError> {
    let text = value
        .to_str()
        .map_err(|_| CookieError::UnsafeUpstreamCookie)?;
    let mut parts = text.split(';');
    let first = parts
        .next()
        .ok_or(CookieError::UnsafeUpstreamCookie)?
        .trim();
    let (name, _cookie_value) = first
        .split_once('=')
        .ok_or(CookieError::UnsafeUpstreamCookie)?;
    if name.is_empty()
        || !name.bytes().all(super::admission::is_token_byte)
        || is_reserved_name(name)
    {
        return Err(CookieError::UnsafeUpstreamCookie);
    }

    let mut attributes = HashSet::new();
    let mut rebuilt = vec![first.to_owned()];
    for raw_attribute in parts {
        let attribute = raw_attribute.trim();
        if attribute.is_empty() {
            return Err(CookieError::UnsafeUpstreamCookie);
        }
        let (attribute_name, attribute_value) = attribute
            .split_once('=')
            .map_or((attribute, None), |(name, value)| {
                (name.trim(), Some(value.trim()))
            });
        if attribute_name.is_empty() || !attribute_name.bytes().all(super::admission::is_token_byte)
        {
            return Err(CookieError::UnsafeUpstreamCookie);
        }
        let lower = attribute_name.to_ascii_lowercase();
        if !attributes.insert(lower.clone()) {
            return Err(CookieError::UnsafeUpstreamCookie);
        }
        if lower == "domain" {
            let domain = attribute_value.ok_or(CookieError::UnsafeUpstreamCookie)?;
            if domain
                .trim_start_matches('.')
                .eq_ignore_ascii_case(upstream_host)
            {
                continue;
            }
            return Err(CookieError::UnsafeUpstreamCookie);
        }
        rebuilt.push(attribute.to_owned());
    }

    HeaderValue::from_str(&rebuilt.join("; ")).map_err(|_| CookieError::UnsafeUpstreamCookie)
}

pub(crate) fn is_reserved_name(name: &str) -> bool {
    if name.eq_ignore_ascii_case(SESSION_COOKIE_NAME) {
        return true;
    }
    percent_decode_str(name)
        .decode_utf8()
        .is_ok_and(|decoded| decoded.eq_ignore_ascii_case(SESSION_COOKIE_NAME))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::COOKIE;

    fn secret() -> Secret {
        Secret::from_bytes([7; 32])
    }

    #[test]
    fn authenticates_and_removes_only_proxy_cookie() {
        let secret = secret();
        let mut headers = HeaderMap::new();
        let cookie = secret.with_exposed(|value| {
            HeaderValue::from_str(&format!("app=a; {SESSION_COOKIE_NAME}={value}; theme=dark"))
        });
        assert!(cookie.is_ok());
        if let Ok(cookie) = cookie {
            headers.insert(COOKIE, cookie);
        }
        assert!(authenticate_and_strip(&mut headers, &secret).is_ok());
        assert_eq!(
            headers.get(COOKIE),
            Some(&HeaderValue::from_static("app=a; theme=dark"))
        );
    }

    #[test]
    fn rejects_duplicate_and_encoded_reserved_names() {
        let secret = secret();
        let mut headers = HeaderMap::new();
        let cookie = secret.with_exposed(|value| {
            HeaderValue::from_str(&format!(
                "{SESSION_COOKIE_NAME}={value}; rpackit%5fproxy%5fv1={value}"
            ))
        });
        assert!(cookie.is_ok());
        if let Ok(cookie) = cookie {
            headers.insert(COOKIE, cookie);
        }
        assert!(matches!(
            authenticate_and_strip(&mut headers, &secret),
            Err(CookieError::Ambiguous)
        ));
    }

    #[test]
    fn strips_exact_upstream_domain_and_rejects_reserved_cookie() {
        let mut headers = HeaderMap::new();
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("app=v; Domain=127.0.0.1; HttpOnly"),
        );
        assert!(normalize_set_cookie_headers(&mut headers, "127.0.0.1").is_ok());
        assert_eq!(
            headers.get(SET_COOKIE),
            Some(&HeaderValue::from_static("app=v; HttpOnly"))
        );

        headers.remove(SET_COOKIE);
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("RPACKIT_PROXY_V1=bad; Path=/"),
        );
        assert!(matches!(
            normalize_set_cookie_headers(&mut headers, "127.0.0.1"),
            Err(CookieError::UnsafeUpstreamCookie)
        ));
    }
}
