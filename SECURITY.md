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
malformed-upstream matrix. Exact-address listener takeover is rejected. The
Windows development gate also tests IPv4 wildcard, IPv6 v6-only wildcard, and
IPv6 dual-stack wildcard overlap. The same dual-stack contender remains alive
while exact IPv4 and IPv6 are both tested. All four traffic paths must return
8/8 proxy `401` responses with zero wildcard accepts. Wildcard bind success is
recorded but is not itself a failure, while an unexpected bind error fails
closed. Do not describe the transport as Phase 1 release-ready until the
complete assigned matrix passes.
