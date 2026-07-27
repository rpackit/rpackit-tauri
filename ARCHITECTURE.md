# Architecture

## Scope and authority

This repository implements the completed Windows Phase 1 spike for rpackit's
authenticated native loopback transport and the initial Phase 2 native
process-owner boundary. The authoritative security contract is
[`TAURI_SECURE_TRANSPORT.md`](https://github.com/rpackit/roadmap/blob/main/TAURI_SECURE_TRANSPORT.md).
This document describes the implementation of transport contract version 2;
it does not expand or weaken that contract.

The spike is an acceptance harness. It is not yet an application generator,
supported installer, or complete implementation of protocol-2 R process
ownership and readiness.

## Components

| Component | Responsibility | Must not own |
| --- | --- | --- |
| `crates/transport` | Secrets, strict HTTP admission, bootstrap, authenticated reverse proxy, response normalization, WebSocket validation and tunnelling | WebView UI, application-selected upstreams, persistent credentials |
| `crates/transport-testkit` | Loopback-only mock upstream and collectors, deterministic browser assets, listener-overlap probes, secret-free counters and reports | External network, real credentials, release claims |
| `crates/launcher-protocol` | Bounded protocol-2 NDJSON decoding, exact event validation, noise accounting and lifecycle sequence tracking | Process creation, secret handling, readiness network requests, untrusted output retention |
| `crates/resource-bundle` | Bounded strict schema-1 manifest loading, authenticated protocol-2 contract checks, critical-path containment, app/runtime/package topology and launcher-marker validation | Executing R or app code, downloading runtimes, package installation, process creation |
| `crates/windows-launcher` | Explicit Windows process creation, standard-I/O handle allowlisting, suspended Job assignment, process/listener identity, private DACL token/control files, Job policy readback and process-tree termination | Bundle validation, secret generation, protocol-pipe orchestration, readiness requests, browser lifecycle |
| `crates/windows-lifecycle` | Validated-resource composition, sanitized bundled-R environment, private secret handoff, protocol pipes, exact runtime/listener ownership, authenticated readiness, health polling, graceful/forced stop, Job accounting and retryable cleanup | Proxy/WebView ownership, portable-runtime acquisition, generated application UI |
| `apps/windows-spike` | Hidden hardened Tauri/WebView2 shell, one native bootstrap navigation, cookie readback, browser exercise, cleanup and acceptance report | JavaScript bridge for credentials, general request injection, R launcher lifecycle |
| `tests/run-webview2.ps1` | Starts one development- or reviewed-fixed-runtime harness profile, reusing the selected Cargo target | Runtime download, package trust decisions, installer validation |
| `tests/run-webview2-fixed.ps1` and `tests/webview2-fixed-runtime.json` | Verify the pinned Microsoft package, run Debug and Release fixed-minimum matrices, validate reports, and remove temporary runtime files | Committing runtime binaries, silently selecting another version, installer validation |
| `.github/workflows/released-runtime.yml` and `tests/prepare-released-runtime.*` | Pin and verify released portable R plus rpackit/hello-shiny sources, prepare a real bundle in runner temp, execute the ignored lifecycle matrix, retain bounded secret-free evidence, and delete all heavy inputs and build output | Local runtime caches, durable binaries, mutable source refs, release claims without a passing run |

## Resource bundle validation

Native startup first passes the bundle root to the safe
`rpackit-resource-bundle` crate. The validator reads at most 256 KiB of
`resources/rpackit.json`, uses `deny_unknown_fields` at every object level, and
accepts only schema `1`, `rpackit-desktop-resources`, the fixed Windows
`R/bin/Rscript.exe` and `R/library` topology, and the complete authenticated
launcher protocol `2` descriptor. Native launch requires package installation
and constraint verification already recorded by `prepare_desktop()`.

Manifest paths use bounded relative POSIX syntax. Each critical component is
inspected without following links, Windows reparse points are rejected, the
final canonical path must stay beneath the canonical `resources` directory,
and the required file or directory type is checked. The declared Shiny layout
must match `app.R` or `ui.R` plus `server.R`. Every unique manifest package
must have a real library directory and `DESCRIPTION` file, including
`jsonlite`, `later`, and `shiny`.

The generated launcher is also bounded to 256 KiB and must be strict UTF-8.
Current token-file consumption and deletion, protocol-2 event prefix,
loopback-only host, Shiny shared-secret setup, post-bind listening callback,
and token-enforcement markers are required; legacy argument/environment/URL
token transports and wildcard bind markers are forbidden. This is a
non-executing structural gate. Runtime identity and behavior are independently
proved later through suspended Job launch, strict lifecycle events,
owner-PID listener inspection, and authenticated readiness.

## Windows process ownership foundation

The Phase 2 native boundary calls `CreateProcessW` with an explicit absolute
application path, a separately quoted mutable command line, and
`CREATE_SUSPENDED`. It does not request `CREATE_BREAKAWAY_FROM_JOB`. A
`PROC_THREAD_ATTRIBUTE_HANDLE_LIST` admits only three standard-I/O handles:
closed stdin and the stdout/stderr lifecycle pipes. An otherwise inheritable
sentinel handle is excluded by an acceptance test.

The command can also supply its own
[`CreateProcessW`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
Unicode environment block instead of inheriting the parent block. Environment
names must be nonempty and contain neither `=` nor NUL; values cannot contain
NUL. Windows-equivalent names replace rather than duplicate one another, and
the final entries are ordered with `CompareStringOrdinal(..., TRUE)` before
exact double-NUL serialization. Debug output reveals only the entry count,
and both stored entries and the temporary serialized block are zeroized. The
real-R lifecycle owner must use this API to remove ambient R/rpackit
configuration and add only non-secret bundled-runtime paths and protocol
selection.

Before process creation, the launcher creates an unnamed Job Object with
default non-inheritable security attributes. It sets and then reads back
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; either `BREAKAWAY_OK` policy is a hard
failure. The still-suspended wrapper is assigned to that Job and queried
through its exact process handle. Native state records both PID and Windows
creation time. Only an observed member with the expected one-count suspension
is resumed.

After a validated event reports a runtime PID, the same native layer can open
that PID with query/synchronize rights and handle inheritance disabled. It
rejects zero, a process already signaled, or a process outside the owned Job,
reads creation time from the exact open handle, checks membership, and checks
liveness again before returning. Keeping this handle fixes the observed
identity across later numeric PID reuse; listener ownership must still be
proved against that same captured process.

The owner then queries the Windows
[`GetExtendedTcpTable`](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
owner-PID listener views for both `AF_INET` and `AF_INET6`. The selected port
must contain exactly one IPv4 row: `127.0.0.1`, `LISTEN`, and the captured PID.
Any other IPv4 row, any IPv6 row, a missing exact row, process exit, or lost
Job membership fails closed. The variable-length native tables are
size-bounded, layout-checked, and retrieved with a bounded retry if they grow
between the sizing and data calls.

The same crate owns a separate native private-files boundary. It reads the
current process-token SID, builds a protected `D:P` descriptor with exactly
current-account and `SYSTEM` full-control allow ACEs, and supplies that
descriptor through `SECURITY_ATTRIBUTES` at creation time. Directories use
`OICI` inheritance flags; each file receives its own protected DACL. The
descriptor is therefore present at the instant
[`CreateDirectoryW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw)
or `CreateFileW(CREATE_NEW)` publishes the object, rather than being tightened
afterward. Both expected and actual descriptors are converted to canonical
SDDL and compared after `GetNamedSecurityInfoW` readback; `P` denotes the
[`SE_DACL_PROTECTED`](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
control bit.

Each launch directory has a 128-bit cryptographically random hexadecimal leaf
under an existing normalized absolute parent. Both fixed file paths are absent
after the directory gate. Once the owner generates launch secrets and binds
listeners, the `token` file is created with one validated 16-256-character
URL-safe ASCII value plus LF; its temporary native write buffer is zeroized.
The `control` file remains absent at startup and is later created empty with
`CREATE_NEW`. Cleanup is explicit because it must follow Job termination. It
removes only these two known paths and then the exact empty directory; an
unexpected entry prevents removal and is preserved for audit.

If assignment fails, `TerminateProcess` runs while the primary thread is still
suspended and a bounded wait follows. Any later pre-resume failure terminates
the assigned Job. The owning Rust value retains both Job and wrapper handles;
closing the last Job handle kills remaining members. Tests prove an attempted
breakaway receives `ERROR_ACCESS_DENIED` and that closing the Job removes both
a fixture wrapper and its spawned descendant.

The process-creation API intentionally has no secret-bearing inputs. Fixture
callers may retain the default inherited environment, while the real-R owner
must supply the sanitized explicit environment described above. Neither form
may place `S`, `P`, or `B` there. The separate private-files API accepts `S`
only to write the protected token file and does not retain it in the session
value. The lifecycle owner passes only that file's path—not `S` itself—in the
R launcher arguments.

The separate safe protocol crate bounds and parses the prefixed NDJSON stream
and validates event ordering, fixed loopback/token claims, the selected port,
and stable runtime PID.

`crates/windows-lifecycle` now composes these boundaries for an executable
synthetic runtime. Its startup order is bundle validation, private session,
`S` token write, direct `R/bin/x64/Rscript.exe` selection, explicit sanitized
environment construction, suspended Job launch, token-consumption proof,
protocol `listening`, exact runtime/listener capture, and direct authenticated
HTTP readiness. Launching the architecture interpreter avoids the top-level
Windows R command-shell wrapper, so the created Job process and
protocol-reported runtime must have the same create-time-aware identity. Stderr
is counted and discarded without retaining text. The ready owner polls both
exact process handles. Shutdown creates the protected control file, accepts
only the validated stopping/stopped sequence during the grace bound, and
otherwise terminates the Job. It requires zero active Job members before
cleaning the known files, preserves unexpected entries, and retains the exact
session for an explicit cleanup retry. Dropping an unclean owner invokes the
same forced Job path best-effort.

Resource validation continues to use canonical Windows paths. The lifecycle
boundary derives ordinary drive or UNC aliases for R, then canonicalizes both
forms and requires identical targets before launch. Unsupported device paths
or aliases that do not resolve identically fail before process creation.

The synthetic fixture exercises these native boundaries without bundling R.
By itself it proves orchestration behavior, not compatibility with the
released portable runtime, generated `launcher.R`, Shiny, or the
proxy/WebView window-close sequence. The separate real-runtime gate below
supplies the process-owner compatibility evidence.

The released-runtime workflow supplies the next evidence layer without adding
large repository or workstation state. It verifies the immutable SHA-256 of
the existing portable-R `v4.6.1` Release, checks out immutable rpackit and
`hello-shiny` commits, installs bundle dependencies remotely, and runs the
same owner against the generated launcher and real Shiny page. The acceptance
target is ignored during ordinary Cargo tests and refuses to run outside
GitHub Actions. Its runner work root contains the archive, both runtime trees,
system and bundled package libraries, Cargo output, hostile profile probes,
and private sessions; one verified recursive cleanup removes that exact
runner-temp child after the small evidence files are uploaded.

The
[first reviewed passing run](https://github.com/rpackit/rpackit-tauri/actions/runs/30233439589)
at commit `10359b9` completed the native interpreter/package probe and the
authenticated, graceful, forced, owner-drop, runtime-crash, timeout,
occupied-port, hostile-profile, Job-empty, and session-cleanup scenarios.
This closes the real-R process-owner evidence layer, not the later
proxy/WebView composition or generated application.

## Secret and origin model

Each launch generates independent 256-bit values:

- `S` authenticates the native proxy to one fixed Shiny upstream.
- `P` authenticates browser traffic to the proxy.
- `B` authorizes exactly one cookie-bootstrap request.

An independent random nonce forms
`rpackit-<nonce>.localhost:<proxy-port>`. The nonce isolates the browser origin
between launches but is not a credential. Cookies are not port-scoped, so a
fresh hostname is required even when every proxy uses an ephemeral port.

The proxy owns compatible IPv4 and IPv6 loopback listeners and rejects a
non-loopback peer, an incorrect `Host`, an absolute or authority-form target,
ambiguous framing, protected `Connection` tokens, unsupported upgrades, and
other malformed admission before application forwarding. Windows listeners
request `SO_EXCLUSIVEADDRUSE` before bind.

## Bootstrap sequence

```text
hidden WebView2
    |
    | exact native GET + one-time B header
    v
/__rpackit_bootstrap on loopback proxy
    |
    | authenticate and consume B; no upstream dial
    | fixed HTML + host-only HttpOnly Strict Set-Cookie(P)
    v
WebView2 cookie store
    |
    | native readback, then navigate to /
    v
authenticated proxy request with P
    |
    | strip P and B; inject exactly one S
    v
fixed 127.0.0.1 Shiny upstream
```

The shell constructs only that first request with WebView2
[`CreateWebResourceRequest`](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/win32/icorewebview2environment2)
and
[`NavigateWithWebResourceRequest`](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/win32/icorewebview2_2).
The only `WebResourceRequested` filter is a credential-free top-level
document escape guard: it permits the exact proxy origin and bundled
placeholder, and replaces external HTTP or HTTPS documents with a local `403`
before network access. It does not inject headers or alter subresources. No
general credential injection or credential-bearing JavaScript bridge is
installed.

The proxy accepts only the exact bootstrap path and an exact single `B`.
Authentication uses a constant-time comparison and atomic one-time
consumption. Missing, wrong, duplicated, malformed, or replayed `B` returns a
fixed secret-free failure, creates no `P`, and does not dial the upstream.

The successful response contains a fixed non-navigating document and:

```text
Set-Cookie: rpackit_proxy_v1=<P>; Path=/; HttpOnly; SameSite=Strict
```

There is deliberately no `Domain`, `Expires`, or `Max-Age`. Processing the
response at the random proxy host creates a true host-only session cookie.

## Why HTTP creates the host-only cookie

The spike first attempted Tauri's high-level native cookie setter. On WebView2
`150.0.4078.83`, the setter did not produce a host-only cookie on readback.
WebView2 documents that
[`AddOrUpdateCookie`](https://learn.microsoft.com/en-us/dotnet/api/microsoft.web.webview2.core.corewebview2cookiemanager.addorupdatecookie)
fails when a cookie's domain is unspecified. Giving the native cookie object a
domain would change the required host-only semantics.

The HTTP bootstrap response is therefore the cookie-creation boundary. `B`
authenticates access to that response, and the narrow native WebView2 request
API transports `B` only on the initial navigation. This is both narrower than
general interception and compatible with ordinary browser host-only cookie
semantics.

## Authenticated application traffic

Every non-bootstrap HTTP request and WebSocket upgrade authenticates one
unambiguous `P` before opening an upstream connection. Unsafe HTTP methods and
WebSocket upgrades also require the exact proxy `Origin`.

Before forwarding, the proxy:

1. removes the reserved proxy cookie, the bootstrap field, any inbound
   protected secret, forwarding/spoofing fields, and validated hop-by-hop
   fields;
2. fixes the upstream authority and, when present, rewrites `Origin` to that
   fixed upstream;
3. injects exactly one `Shiny-Shared-Secret: S` as the last protected mutation;
4. streams request bodies with backpressure through independent byte, idle,
   minimum-rate, total-time, and trailer gates.

The response path rejects attempts to set the reserved proxy cookie, rewrites
only redirects that exactly target the fixed upstream, preserves external
redirects without following them, and normalizes acceptable application
cookies for the proxy origin.

WebSocket handshakes receive the same authentication and admission controls.
The proxy validates the client request and upstream `101`, strips extension
offers, verifies the accept value and selected subprotocol, then tunnels bytes
bidirectionally with an activity-based idle watchdog. Successful reads and
writes reset the watchdog; shutdown drains or aborts every tracked connection,
upstream protocol driver, and upgrade tunnel before returning.

## WebView boundary

The test shell uses a unique data directory and incognito mode, starts hidden,
and denies non-proxy top-level navigation, new windows, downloads, devtools,
browser extensions, autofill, drag-and-drop, and zoom shortcuts. It reads the
cookie only to verify flags and value equality in native code; the value is
never put in the report.

The active browser matrix does not infer these controls from configuration.
The page attempts an external document, popup, download, and `mailto:` launch;
native code separately creates a random per-run custom URL protocol as a
volatile current-user registry key. The handler is the same executable in a
strictly scoped canary mode; the harness self-tests that handler before
queuing the exact URI once through native `Navigate`. The document request is
replaced with a local `403` at `WebResourceRequested`, new windows are denied,
downloads are cancelled into an isolated directory that must stay empty, and
every `LaunchingExternalUriScheme` event is cancelled. The event's empty
`InitiatingOrigin` proves it came from the native probe rather than a delayed
page callback. Cancellation must leave the handler marker absent, after which
the registry key is explicitly removed and verified absent. Native readback
requires devtools, browser accelerator keys, and default context menus to be
disabled. A valid unpacked extension must fail installation with the Windows
`ERROR_NOT_SUPPORTED` result.

Before creation the shell rejects every untrusted WebView2 environment
override and checks both machine and user policy-registry views, including
32-bit and 64-bit views, for application-, executable-, and wildcard-scoped
runtime, channel, argument, and profile overrides. In reviewed fixed mode only,
the shell first verifies the complete package identity and then changes the
in-memory Tauri context to `WebviewInstallMode::FixedRuntime`. Tauri injects
the exact verified `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER` before it creates the
runtime. The shell checks that this is the only runtime environment change,
repeats the registry check after creation, and requires the isolated profile
to contain no `DevToolsActivePort`.

Normal cleanup deletes `P`, clears browsing data, destroys the WebView, and
recreates the same profile to test that no cookie is reusable. A separate
cross-process gate starts the same executable in a restricted producer mode
with no secret input. The producer verifies the exact session cookie inside a
populated private profile, waits two seconds, and atomically publishes only
its non-secret random hostname. The parent forcibly terminates the producer
and requires a held graceful-cleanup sentinel to remain absent. It then
recreates a WebView with the same profile and old hostname, requires `P` to be
absent, destroys that WebView, and removes the profile directory. Both clean
and forced-crash recreation gates passed on the recorded development runtime
and the reviewed fixed minimum.

## Reviewed fixed-runtime identity

The newest Win32 interface used by the native hardening probe is
`ICoreWebView2Profile7`, whose API compatibility floor is Runtime
`120.0.2210.55`. That 2023 runtime is no longer in Microsoft's public Fixed
Version support window and is not an acceptable 2026 browser-engine support
baseline. The versioned manifest therefore records the API floor separately
from the supported minimum: the older of the two Fixed Version releases
Microsoft offered at review time, x64 `149.0.4022.98`.

The committed manifest pins the official Microsoft download page and CDN URL,
CAB name, byte length and SHA-256, expanded directory name, file count, total
bytes and a domain-separated tree SHA-256, plus the browser executable's
digest, version, signer subject, and certificate thumbprint. The tree hash
sorts UTF-8 relative file names ordinally and hashes each name length, name,
file length, and complete file body. Native startup rejects a wrong package
name, architecture, count, size, digest, reparse point, excessive path shape,
or `Edge\Application` path. The PowerShell runner independently checks the
archive and Authenticode evidence before launch.

The forced-crash child does not inherit Tauri's browser-folder environment
value. Its parent removes all WebView2 override variables and passes only the
non-secret reviewed runtime path; the child repeats the complete package
verification and lets its own Tauri context inject the exact path. A fixed
report closes `fixed_minimum_webview2` only when the actual loaded version is
exactly the supported minimum and both the runtime identity and environment
selection match. Arbitrary `--fixed-runtime` paths cannot close the gate.

## Resolver evidence

Two observations are intentionally recorded separately:

1. the system/Tokio lookup classifies all returned addresses and fails if any
   address is non-loopback;
2. the actual WebView must finish the authenticated bootstrap and application
   navigation through the running proxy.

On the recorded Windows development run, the first observation was
`unavailable` for the random `.localhost` subdomain. The second succeeded.
The WebView-specific invariant comes from
[RFC 6761 section 6.3](https://www.rfc-editor.org/rfc/rfc6761.html#section-6.3)
and Chromium's source-level rule to
[`Always treat .localhost as loopback`](https://chromium.googlesource.com/chromium/src/+/5d131a1fd9b808c5fd08c45f8299e669b13ec393%5E%21/);
[WebView2 uses Microsoft Edge with Chromium bits](https://learn.microsoft.com/en-us/microsoft-edge/webview2/).
The shell rejects untrusted environment and policy-registry overrides for the
runtime, profile, channel, and browser arguments; reviewed fixed mode permits
only Tauri's exact verified runtime-folder injection. A system probe that
actually observes a non-loopback result aborts before creating a WebView or
sending `B`.

Because the proxy listens only on loopback, rejects non-loopback peers, and
requires the exact random `Host`, successful authenticated loading is
additional runtime evidence that WebView2 reached the loopback endpoint. It is
not a claim that all Windows resolver APIs support arbitrary `.localhost`
subdomains. The architecture provides no stable-host fallback.

## Listener ownership evidence

Windows exact-address exclusivity and wildcard overlap are separate
observations. After the proxy binds exact IPv4 and IPv6 loopback addresses, the
testkit creates three same-port `SO_REUSEADDR` contenders: IPv4 wildcard, IPv6
v6-only wildcard, and IPv6 dual-stack wildcard. Windows may reject a wildcard
bind or permit it while still excluding the exact interface, as described in
Microsoft's
[`SO_REUSEADDR` and `SO_EXCLUSIVEADDRUSE` binding matrix](https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse).
Wildcard bind success alone is therefore not a failed gate.

The IPv4 wildcard is tested against exact IPv4, and the IPv6 v6-only wildcard
against exact IPv6. The same dual-stack contender remains alive while the
probe tests exact IPv4 and then exact IPv6. Each of those four traffic paths
receives eight real, credential-free requests with the proxy's exact `Host`.
The request omits `P`, so only the proxy can return the expected fixed `401`;
the mock upstream must remain untouched. A variant passes only when every raw
per-target counter is 8/8 and its wildcard listener accepts zero connections.
The acceptance report records every bind outcome and raw counter without
recording any credential.

On the recorded development run all three wildcard binds succeeded. Exact
IPv4 under the IPv4 contender, exact IPv6 under the v6-only contender, and both
exact targets under the single dual-stack contender each returned 8/8 proxy
`401` responses. All three wildcard accept counts remained zero, for 32 total
exact-loopback requests.

`windows_listener_overlap_all_variants_pass` requires all three contenders and
all four traffic paths to pass from their raw counters. The report removes
`listener_overlap_matrix` from `unproven_release_gates` only for that measured
result. Unexpected bind errors fail the harness; only Windows `AddrInUse` or
`PermissionDenied` is recorded as an ordinary rejected contender. This
resolves that development-runtime gate; it does not imply Phase 1 readiness or
certify the remaining fixed-runtime matrix.

## Malformed upstream response-head evidence

The upstream socket is wrapped by a response guard before it is passed to
Hyper. The guard buffers at most the configured response-header limit and
releases no bytes until one complete response head passes strict raw checks:

- every line uses CRLF and the response is HTTP/1.1 with an allowed final
  status;
- the configured header byte and field-count bounds hold;
- when present, `Content-Length` is unique and decimal and
  `Transfer-Encoding` is unique and exactly `chunked`; the two never coexist,
  while responses that require neither remain valid;
- ordinary HTTP forwarding rejects informational or switching responses,
  while the WebSocket path permits `101` only for its later exact handshake
  validation.

Any read error before validation clears the retained prefix and permanently
latches the guard closed; retrying the wrapper cannot resume or release those
bytes.

The existing structured normalization then rejects ambiguous `Connection` and
`Location`, protected connection nominations, unsafe cookies, protected
response fields, and any WebSocket response whose upgrade, accept,
subprotocol, or extension fields do not exactly match the downstream offer.
The testkit drives both layers through real loopback sockets and both
forwarding paths:

- a valid ordinary HTTP baseline and 16 HTTP negative heads;
- a valid `101` baseline that tunnels one raw WebSocket frame and 16
  WebSocket negative heads.

The WebSocket server independently verifies that the proxy sent the normalized
upgrade request and exactly one synthetic upstream credential. Parser-valid
unsafe heads contain an attacker canary; every WebSocket negative also carries
a valid attacker frame after its head. Passing requires every one of the 32
negatives to become the exact locally generated `502`, no WebSocket negative
to switch the downstream connection, all 34 upstream requests to have one
valid synthetic credential, all 17 WebSocket requests to have the exact
normalized upgrade shape, and zero canary/frame bytes downstream.

The downstream server disables Hyper's automatic `Date` field. The fixed
oracle therefore requires exactly `Cache-Control: no-store`,
`Connection: close`, `Content-Length: 17`, and
`Content-Type: text/plain; charset=utf-8`, followed by the exact
`Upstream rejected` body; any upstream-derived or other unexpected header
fails the gate. This evidence is part of `development_gates_passed` in the
real WebView2 report. The recorded WebView2 `150.0.4078.99` report contains
both passing baselines, 32/32 exact fixed `502` results, 34/34 valid synthetic
upstream credentials, 17/17 normalized WebSocket requests, no downstream
upgrade, and zero forwarded markers.

The body guard deliberately does not claim that errors discovered after a
response head has been released can be rewritten into a `502`. A declared
trailer or over-limit `Content-Length` is rejected before downstream head
release. After release, declared/configured byte limits, upstream parser/read
errors, and trailer frames fail with a fixed secret-free internal error. The
downstream response already carries `Connection: close`, so the corresponding
gate accepts either closure before downstream head serialization or
detectably incomplete framing, and requires bounded termination with no
trailer, attacker marker, second response, or reusable connection. The split
between those two safe outcomes is scheduling-dependent. The close-delimited
over-limit case is necessarily delimited by that close; its oracle therefore
requires an empty bounded response body and no marker. The configured byte
limit applies to the proxied, encoded HTTP body. The independent decoded
boundary below limits expansion after `Content-Encoding` transformation.

The forwarder records the request method before the upstream request is moved.
Its body policy treats `HEAD`, `204`, `205`, and `304` as body-forbidden.
`HEAD` and `304` may preserve a nonzero hypothetical `Content-Length` in the
downstream head without enforcing it as streamed bytes. `204` rejects either
`Content-Length` or `Transfer-Encoding` before releasing a downstream head.
`205` accepts no framing or `Content-Length: 0`, rejects a nonzero declared
length or any `Transfer-Encoding` before release, and drops any streamed
content. Rejecting even nominally empty chunked framing avoids stream/trailer
ambiguity on a status that must not carry content. The body-forbidden guard
has a zero-byte streaming allowance, so a data frame cannot leak when no-body
semantics are in effect.

The raw body matrix proves fragmented valid fixed-length, chunked, and
close-delimited baselines plus bodyless `HEAD` and `304` responses carrying
nonzero hypothetical lengths, a bodyless `204` without framing, and a bodyless
`205` with `Content-Length: 0`. Its 23 negatives require 6 exact pre-stream
`502` responses, 12 stream fail-closed terminations, 1 empty
close-delimited-limit cutoff, 2 bodyless malicious-status terminations, and 2
response-splitting attempts isolated to the first safe response. The split
between withheld-head and incomplete-framing outcomes among the 12 streaming
failures is scheduling-dependent. The trailer set includes malformed,
protected, oversized, and 97-field cases against the configured 96-field
maximum.

All 30 first upstream requests must carry exactly one synthetic upstream
credential. After each first response head or physical close, the raw client
attempts a second authenticated request on the same keep-alive downstream
socket. Passing requires 30/30 attempts, 30/30 physical closes before proxy
shutdown, zero second responses, zero reusable connections, bounded
termination, and zero forwarded attacker markers. The response-splitting and
no-body fixtures omit upstream `Connection: close` where applicable so the
observed downstream close is enforced by the proxy.

The authenticated request-upload guard starts its clocks only when the
upstream client begins polling the body. It caps streamed data at 64 MiB by
default, resets a 15-second idle deadline only after a non-empty data frame,
requires 1 KiB/s in each completed 5-second tumbling window, and enforces a
5-minute total duration. A body that ends within its current window passes
without a minimum-size rule. Any inner-body error or trailer frame is replaced
with a fixed secret-free error, and a frame that would cross the cap is never
forwarded. The loopback matrix proves one immediate valid body, one chunked
body cut off before crossing its byte cap, three otherwise-completing bodies
cut off independently by idle, rate, and total time, and one parsed chunked
trailer converted to a fixed `502`.
Configuration validation rejects a zero enabled rate window or a rate window
longer than the total body lifetime. The real harness serializes these results
as `request_body_limits`; the
`request_body_resource_limits_fail_closed` development gate requires the valid
baseline, all five bounded negatives, every parsed probe request to carry a
valid synthetic credential, and zero proxy-cookie or bootstrap-header leaks.
The byte-cap and trailer errors can be discovered before or after the upstream
request head is serialized, so between 4 and 6 parsed probe requests are
valid; the recorded run observed 5/5 correctly authenticated heads.

The response resource guard starts its clocks only when the downstream server
polls the upstream body. It caps the encoded stream at 256 MiB by default,
resets a 15-second idle deadline only for non-empty encoded frames, and
requires 1 KiB/s in every complete 5-second tumbling window. A response that
ends inside its current rate window passes without padding. The identity path
uses the smaller of the encoded and decoded caps.

For encoded streaming responses, a maximum of two ordered `gzip`/`x-gzip`,
HTTP `deflate` (zlib), `br`, or `zstd` layers are decoded in reverse
application order through bounded readers. The decoded guard independently
caps the final representation at 256 MiB and never releases a frame that
crosses that cap. It replaces codec or inner read details with a fixed
secret-free error. Transformation removes the original content encoding and
length, range metadata, validators, and integrity digests. Encoded partial
responses and encoded responses carrying `Cache-Control: no-transform` are
rejected before downstream head release. Body-forbidden `HEAD` and `304`
metadata remains descriptive and is not transformed.

The real-loopback matrix proves exact identity and gzip baselines plus five
independent idle, below-rate, decompression-expansion, malformed-gzip, and
unsupported-coding failures. The expansion fixture maps 67 encoded bytes to
4,128 decoded bytes against a 32-byte test cap. Passing requires five bounded
terminations, 7/7 correctly authenticated upstream requests, and zero
proxy-cookie, bootstrap-header, or attacker-marker leakage. The real harness
serializes these results as `response_resource_limits`; the
`response_resource_limits_fail_closed` development gate requires the complete
matrix. The recorded WebView2 `150.0.4078.99` run passed both baselines, all
5/5 bounded negatives, 7/7 synthetic credentials, and zero credential or
marker leakage; the expansion case forwarded zero decoded bytes.

Each upgraded endpoint is wrapped in a raw-read token bucket before
`copy_bidirectional`. The downstream wrapper therefore meters
client-to-upstream bytes, while the upstream wrapper meters
upstream-to-client bytes; writes are not counted again. The default buckets
each refill at 8 MiB/s and hold one second of burst capacity. When no whole-byte
token is available, the read side waits on a monotonic timer, so kernel and
Tokio backpressure bound queued traffic without parsing WebSocket frames.
Successful reads and writes still reset the shared five-minute activity-idle
watchdog. A zero rate disables only the token buckets, and configuration
validation rejects an enabled zero burst window or one longer than the idle
deadline before listener creation.

The directional loopback evidence uses a small valid baseline plus separate
100-byte upload and download payloads at 100 B/s with a 100 ms burst. Both
shaped cases must last at least 750 ms and complete within four seconds.
Passing requires 3/3 valid synthetic upstream credentials, 3/3 normalized
WebSocket requests, and no proxy-cookie or bootstrap-header leakage. The
WebView2 report records the evidence under `websocket_rate_limits`; its
`websocket_byte_rates_bounded` gate is part of
`development_gates_passed`.
The recorded WebView2 `150.0.4078.99` debug and release runs both measured
997 ms client-to-upstream and 934 ms upstream-to-client, with all 3 handshakes
valid and normalized and no credential leakage.
The reviewed Fixed Version Runtime `149.0.4022.98` measured 1,007/934 ms in
Debug and 1,006/921 ms in Release with the same 3/3 and zero-leak result.

## Evidence and release boundary

The headless suite proves deterministic negative cases and transport
normalization. The real WebView2 harness separately proves browser cookie,
subresource, fetch, streaming, WebSocket, child-host, external-redirect,
cleanup, and secret-leakage behavior. Its JSON output contains only versions,
hostnames, booleans, counts, and route names.

The development report intentionally retains the `fixed_minimum_webview2`
gap and is not by itself a Phase 1 release claim. The complete matrix now also
passes in Debug and Release on the exact reviewed Fixed Version Runtime
`149.0.4022.98`. Both fixed reports record the loaded version, manifest and
tree identities, exact trusted environment selection, all development gates,
an empty `unproven_release_gates`, and `phase1_release_ready: true`. The active
browser-escape matrix blocked one external document before network, denied one
popup and one download, cancelled the one native external-scheme event without
launching its verified canary handler, and removed the volatile registration.
Native settings and extension rejection were verified, untrusted override
sources were absent, and no `DevToolsActivePort` or external collector request
was produced. The cross-process forced-crash profile matrix also passed on
both runtime modes.
Authenticated request-upload byte/idle/rate/total/trailer limits, encoded and
decoded response byte limits, response idle/rate/content-decoding limits,
exact-address takeover, IPv4/IPv6 wildcard overlap, strict malformed upstream
response-head rejection, streamed response-body/trailer fail-closed behavior,
WebSocket activity-idle shutdown, and independent bidirectional WebSocket
byte-rate backpressure are tested on both runtime modes. The Phase 2 Windows
resource validator, Job/process-creation, exact process/listener identity,
protocol decoder, and private DACL file foundations have their own passing
tests. A remote-only gate now implements real protocol-2 R readiness,
authenticated `hello-shiny`, graceful/forced/crash/timeout behavior, and
post-Job profile/session cleanup. Its
[reviewed passing run](https://github.com/rpackit/rpackit-tauri/actions/runs/30233439589)
now provides that evidence. It does not yet prove the combined proxy/WebView
window-close owner.

## Maintainer rules

- Change the authoritative roadmap contract before changing a security
  invariant here.
- Increment the transport contract for an incompatible boundary change.
- Keep all failure responses and empirical reports secret-free.
- Never replace a failed gate with a warning, stable-host fallback, domain
  cookie, URL credential, JavaScript handoff, or unauthenticated bootstrap.
