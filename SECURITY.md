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

The repository is a pre-release Windows transport acceptance spike. Phase 1
has passed on both the development Runtime `150.0.4078.99` and the exact
reviewed x64 Fixed Version Runtime `149.0.4022.98`, in Debug and Release.
The fixed reports contain no unproven release gate and record
`phase1_release_ready: true`. This assurance does not cover the Phase 2 R
launcher lifecycle, a generated application, an installer, or code signing.
Exact-address listener takeover is rejected. The initial Phase 2 native
process-owner layer is implemented and tested separately: it creates the
wrapper suspended, allowlists only lifecycle-pipe handles, assigns it to an
unnamed non-inheritable kill-on-close Job with both breakaway policies
disabled, verifies PID/creation-time identity and Job membership, and resumes
only after those gates pass. A separate safe decoder bounds protocol-2 stdout,
rejects ambiguous or weakened event objects, and enforces a terminal lifecycle
sequence with stable PID and port. The process layer can retain a
non-inheritable PID-plus-creation-time handle only after confirming the live
process belongs to the owned Job. Windows owner-PID tables must then show one
exact IPv4-loopback listener for that PID and no same-port IPv4/IPv6
competitor, with liveness and Job membership checked around the snapshot.
A separate native layer atomically creates a protected per-launch directory
and token/control files whose exact DACL contains only current-account and
`SYSTEM` full-control allow entries. It reads each DACL back, requires the
protected bit, uses `CREATE_NEW` for fixed files, and never recursively removes
an unexpected entry. This evidence does not yet cover connecting those layers
to a real R launch, authenticated readiness, launcher consumption/deletion of
the token, or graceful close.

The private descriptor is supplied in `SECURITY_ATTRIBUTES` at object
creation, matching the documented
[`CreateDirectoryW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw)
security boundary; a null descriptor is never used for these objects. The
directory and file descriptors use protected
[`D:P` SDDL](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format).
Only the token file contains `S`. The session value, process arguments,
environment, logs, reports, and control file contain no secret value.

The newest WebView2 API used by the harness has a historical compatibility
floor of `120.0.2210.55`, but that obsolete runtime is neither publicly
supported nor accepted as the product baseline. The supported minimum was
reviewed on 2026-07-26 as the older Fixed Version still offered by Microsoft,
`149.0.4022.98`. Its manifest pins the Microsoft source, archive length and
SHA-256, full expanded tree identity, executable digest and version, signer
subject, and certificate thumbprint. Native startup re-verifies the exact tree
before Tauri injects the one trusted browser-folder environment value; every
ambient WebView2 override remains forbidden. The crash child removes inherited
override variables and independently repeats this process. A renamed,
partially copied, modified, wrong-architecture, or arbitrary runtime directory
cannot close the fixed-minimum gate.

Fixed browser engines do not update themselves. Maintainers must regularly
review and raise the supported minimum, rerun both profiles, and never keep an
old baseline merely to preserve a passing report. The CAB and extracted
runtime are temporary test inputs and must not be committed.
The Windows development gate also tests IPv4 wildcard, IPv6 v6-only wildcard,
and IPv6 dual-stack wildcard overlap. The same dual-stack contender remains
alive while exact IPv4 and IPv6 are both tested. All four traffic paths must
return 8/8 proxy `401` responses with zero wildcard accepts. Wildcard bind
success is recorded but is not itself a failure, while an unexpected bind
error fails closed.

The forced-crash persistence gate uses a separate same-executable producer
with no secret-bearing argument, environment addition, or control output. The
producer verifies `P` and its flags in a populated private profile, waits two
seconds, then publishes only the validated random hostname. The parent
forcibly terminates it; an in-process `Drop` sentinel must remain absent,
proving the normal cleanup path did not run. A new WebView must open the same
profile, find no cookie named `rpackit_proxy_v1` for the old hostname, destroy
successfully, and permit the complete profile directory to be removed. The
recorded WebView2 `150.0.4078.99` run passed every one of these checks with no
secret shape in its report.

The real-browser escape matrix actively attempts external top-level
navigation, popup creation, a download, and an external URI scheme. The native
probe creates a random per-run URL protocol in a volatile current-user
registry key, points it at a strictly scoped same-executable canary, self-tests
the handler, and requires one native-origin scheme event. External documents
are replaced with a local `403` before network access, popups and downloads
are denied, every observed external-scheme launch is cancelled, the handler
marker must remain absent, and the protocol registration must be removed and
verified absent. The isolated download directory must remain empty. Native
readback requires devtools, browser accelerator keys, and default context
menus disabled; a valid unpacked-extension install must be explicitly
rejected as unsupported. The shell fails before bootstrap on untrusted
WebView2 environment or policy-registry overrides, permits only the exact
verified fixed-runtime folder injected by Tauri, repeats the policy check
after creation, and rejects a profile containing `DevToolsActivePort`. The
recorded WebView2 `150.0.4078.99` run passed this matrix with one document network
block, one popup denial, one download cancellation, one cancelled native
external-scheme event with no canary launch, and zero external collector
requests. The reviewed fixed Debug and Release matrices passed the same gate.

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

Authenticated request uploads are bounded independently before reaching the
fixed upstream. The default guard combines a 64 MiB cap, a 15-second
non-empty-frame idle deadline, a 1 KiB/s floor in each complete 5-second
window, and a 5-minute total lifetime. It rejects request trailers and replaces
body parser errors with fixed secret-free errors. The loopback gate requires
one immediate valid upload to pass; a chunked upload to stop before crossing a
small test byte cap; idle, below-rate, and over-duration uploads that would
otherwise complete to terminate boundedly without a success response; and a
parsed chunked trailer to become a fixed `502`. The WebView2 acceptance report
retains only the six result booleans and secret-free counters; the recorded
development run passed 5/5 bounded negatives, 5/5 parsed upstream credentials,
and zero credential leaks.

Upstream response resources are bounded independently. The encoded body and
final decoded representation each default to 256 MiB. The encoded stream has
a 15-second non-empty-frame idle deadline and a 1 KiB/s floor in each complete
5-second window. At most two `gzip`/`x-gzip`, HTTP `deflate` (zlib), `br`, or
`zstd` layers are decoded with backpressure; unsupported or malformed content
codings fail closed, and the decoded frame crossing the final cap is never
forwarded. Encoded partial responses and `Cache-Control: no-transform`
responses are rejected rather than transformed inconsistently. Range,
encoding, length, validator, and digest metadata invalidated by decoding is
removed before downstream release.

The response resource gate proves identity and gzip baselines plus five
independent idle, below-rate, expansion, malformed-gzip, and unsupported-coding
negatives. Its 67-byte encoded expansion fixture decodes to 4,128 bytes
against a 32-byte cap. Passing requires all five negatives to terminate
boundedly, all seven upstream requests to carry one valid synthetic secret,
and zero proxy-cookie, bootstrap-header, or attacker-marker leakage.
The recorded WebView2 `150.0.4078.99` run passed the complete matrix and
forwarded zero decoded bytes from the expansion case.

Raw WebSocket throughput is bounded independently in each direction after a
validated upgrade. The default token buckets allow 8 MiB/s and one second of
burst capacity per direction, count framing and payload bytes together, and
pause reads when empty so `copy_bidirectional` propagates backpressure. The
proxy neither parses frames nor accumulates unbounded messages. A zero ceiling
disables only shaping; enabled zero or over-idle burst windows are rejected
before listener bind. The separate five-minute activity-idle watchdog,
connection semaphore, and tracked-task shutdown remain enforced.

The WebSocket rate gate proves a small authenticated baseline and separate
100-byte upload and download cases under a 100 B/s ceiling with a 100 ms burst.
Each shaped direction must take at least 750 ms and complete within four
seconds. All three upstream handshakes must carry one valid synthetic secret,
have the normalized upgrade shape, and leak neither the proxy cookie nor the
bootstrap header.
The recorded WebView2 `150.0.4078.99` debug and release runs both passed at
997 ms client-to-upstream and 934 ms upstream-to-client, with 3/3 valid
normalized handshakes and zero credential leakage.
The reviewed fixed Runtime `149.0.4022.98` passed at 1,007/934 ms in Debug and
1,006/921 ms in Release, also with 3/3 valid normalized handshakes and no
credential leakage.

The ordinary HTTP body gate separately proves fragmented fixed-length,
chunked, and close-delimited baselines plus bodyless `HEAD` and `304`
baselines with nonzero hypothetical lengths, a bodyless `204` baseline without
framing, and a bodyless `205` baseline with `Content-Length: 0`. Its 23
truncated, malformed, unsafe-trailer, limit, bodyless-status, and
response-splitting cases include 97 trailer fields against the configured
96-field maximum and a close-delimited body crossing a zero-byte test limit.
Declared trailers, an over-limit `Content-Length`, forbidden framing on `204`,
and a nonzero length or any `Transfer-Encoding` on `205` must become the exact
static 502 before downstream head release. Rejecting even an empty chunked
`205` avoids ambiguous stream/trailer framing on a status that must not carry
content.

Later framing/parser/trailer failures must terminate boundedly with no
downstream head or with incomplete framing and `Connection: close`; the split
among the 12 streaming cases is scheduling-dependent. The close-delimited
limit case must expose an empty body, malicious close-delimited `204` and
`205` responses must expose no content, and bytes after a complete message
must remain isolated to the first response. All 30 first upstream requests
must carry one valid synthetic secret. The client then attempts a second
authenticated request over every keep-alive downstream socket; all 30 sockets
must physically close before proxy shutdown, with zero second responses,
attacker markers, or reusable connections. Relevant response-splitting and
no-body fixtures omit upstream `Connection: close`, proving that the proxy
enforces this isolation.

The body policy gives all `HEAD`, `204`, `205`, and `304` responses a
zero-byte streaming allowance. The configured encoded cap is followed by the
independent decoded cap for transformed streaming responses. A Phase 1 claim
is valid only for reports that verify the reviewed fixed identity, load the
exact supported minimum, pass every development gate, and contain no unproven
release gate. Phase 1 now meets that boundary; do not extend the claim to
Phase 2 or later work.
