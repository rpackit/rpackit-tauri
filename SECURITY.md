# Security

Please report suspected credential leakage, request-smuggling acceptance,
authentication bypass, origin confusion, open-proxy behavior, or orphaned
native/R process ownership privately through GitHub Security Advisories for
`rpackit/rpackit-tauri`.

Do not include live credentials, process dumps, private runtime bundles, or
user data in an issue. The test harness uses fresh in-memory synthetic secrets;
its report intentionally contains booleans and counters only.

## Contract version 2 boundary

Every launch uses independent values for the upstream secret (`S`), the
proxy-session secret (`P`), and the one-time bootstrap secret (`B`).

- `S` may appear only in native memory and exactly one protected field sent to
  the fixed loopback upstream.
- `P` may appear only in native memory and an HttpOnly, host-only WebView
  session cookie. It must be removed before forwarding upstream.
- `B` may appear only in the exact native initial-bootstrap request header. It
  is consumed atomically once and removed before any possible upstream dial.

None of these values may appear in JavaScript, URLs, process arguments,
environment variables, logs, errors, reports, fixtures, manifests, crash
annotations, or committed resources. A report that exposes a value rather than
a boolean or counter is itself a security defect.

The bootstrap response creates `P` with an HTTP `Set-Cookie` field that omits
`Domain`. Adding a `Domain` attribute, exposing the bootstrap route without a
valid one-time `B`, reusing `B`, or falling back to a stable loopback hostname
violates the security contract.

## Current assurance level

The repository is a pre-release Windows transport spike. Passing the current
development runtime demonstrates useful empirical behavior, but does not prove
the reviewed fixed minimum WebView2 runtime, forced-crash credential
persistence, every browser escape path, the complete resource/timeout and
malformed streamed-body matrix. Exact-address listener takeover is rejected.
The Windows development gate also tests IPv4 wildcard, IPv6 v6-only wildcard,
and IPv6 dual-stack wildcard overlap. The same dual-stack contender remains
alive while exact IPv4 and IPv6 are both tested. All four traffic paths must
return 8/8 proxy `401` responses with zero wildcard accepts. Wildcard bind
success is recorded but is not itself a failure, while an unexpected bind
error fails closed.

Upstream response heads cross a raw admission guard before Hyper can interpret
them. The guard rejects ambiguous `Content-Length`/`Transfer-Encoding`,
non-chunked transfer coding, lenient line endings or folding, invalid syntax
or status, oversized/excess headers, and an unsolicited protocol switch. The
deterministic gate also exercises parser-valid but unsafe connection,
redirect, and cookie fields. A separate raw WebSocket matrix exercises invalid
or ambiguous `101` framing and handshake fields, unoffered negotiation,
extensions, and protected connection nominations.

The gate first proves valid HTTP and WebSocket baselines. All 16 ordinary and
16 WebSocket negatives must then become an exact static secret-free `502`;
the downstream connection must not upgrade, and no attacker header canary or
WebSocket frame may pass. The oracle rejects unexpected response headers as
well as body bytes. All 34 upstream requests must have one valid synthetic
secret and all 17 WebSocket requests must have the normalized upgrade shape.
This response-head gate does not prove the remaining truncated or malformed
streamed-body cases. Do not describe the transport as Phase 1 release-ready
until the complete assigned matrix passes.
