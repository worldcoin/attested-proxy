# attested-proxy

Verification of World App **attested-key canonical requests**, as Rust crates and as a sidecar
container that sits in front of a service.

A World App request is signed by a device key that the [Attestation Gateway] attested. The
gateway's JWT (`Integrity-Token`) carries that key as `cnf.jwk`. The app signs an [RFC 9421]
signature base covering the method, scheme, authority, path, query, body digest and the token
itself; a verifier rebuilds the same base from the request it received and checks the signature
with the attested key. The wire format is the TFH [RFC 9421 Integrity Request Signing Profile].

Verification proves that **an attested app on an attested device signed this exact request**. It
does not identify a user, a PCP owner or a relying party, and it authorizes nothing. See
[Authorized Principal] for that layer.

## Crates

| Crate | Use it to |
| --- | --- |
| [`attested-request`](crates/attested-request) | Sign and verify canonical requests without any transport. Types, `Signature-Input` parsing and canonical serialization, the signature base, Attestation Gateway token verification (ES256 only), iOS App Attest and Android signature checks, a `Signer` trait for clients, an optional replay guard. The `remote-jwks` feature adds a cached HTTPS JWKS; `test-util` adds software signers and a fake gateway. |
| [`attested-request-tower`](crates/attested-request-tower) | Verify in-process, in any tower or axum service. `AttestedRequestLayer` puts a `VerifiedAttestedKeyContext` in the request extensions; the `axum` feature adds the `AttestedKey` extractor. |
| [`attested-proxy`](crates/attested-proxy) | Verify in a sidecar, so the service itself needs no attestation code. |

A Rust service can embed the tower layer instead of running the sidecar; the sidecar is built on
that same layer.

```rust
let app = axum::Router::new()
    .route("/v1/config", axum::routing::post(handler))
    .route_layer(AttestedRequestLayer::new(Arc::new(verifier)));

async fn handler(AttestedKey(context): AttestedKey) -> String {
    format!("{} device {}", context.device.platform, context.device.key.thumbprint())
}
```

## The sidecar

The sidecar is the service's **only ingress**. For each request it:

1. forwards it unverified if its path is listed in `ATTESTED_PROXY_UNPROTECTED_PATHS` (exact
   match, meant for the load balancer's health check);
2. otherwise reads the body under a size limit and deadline, and verifies the request, answering
   `{"error": "<reason>"}` with the reason's status when verification fails;
3. forwards the verified request to the one configured upstream. Clients never choose the
   destination. WebSocket upgrades are verified on the handshake and then tunnelled byte for byte.

Everything that can fail does so closed: an unreachable JWKS, an unreachable replay store and an
unreadable body all refuse the request.

### What the upstream receives

| Header | Value |
| --- | --- |
| `x-attested-platform` | `ios` or `android` |
| `x-attested-key-thumbprint` | RFC 7638 thumbprint of the device key: a stable per-device identifier, for example to rate limit on |
| `x-attested-request-binding` | `base64(SHA-256(signature base))` of this exact request |

Client-sent copies of these headers are removed on every path, and the `Integrity-Token`,
`Signature-Input` and `Signature` headers are not forwarded. The upstream can trust these headers
only because it is reachable solely through the sidecar, so keep its port off the Service and the
load balancer.

### Configuration

Every flag has an `ATTESTED_PROXY_*` environment variable; `attested-proxy --help` lists them.

| Variable | Default | |
| --- | --- | --- |
| `ATTESTED_PROXY_UPSTREAM` | required | The sibling container, `http://127.0.0.1:8000`. |
| `ATTESTED_PROXY_AUTHORITY` | required | The host clients dial, as signed in `@authority`. |
| `ATTESTED_PROXY_SCHEME` | `https` | As signed in `@scheme`. `wss://` clients sign `https`. |
| `ATTESTED_PROXY_AUDIENCES` | required | Accepted token audiences, comma-separated. |
| `ATTESTED_PROXY_ISSUER` | required | The Attestation Gateway `iss`. |
| `ATTESTED_PROXY_JWKS_URL` | required | The Attestation Gateway HTTPS JWKS URL. |
| `ATTESTED_PROXY_UNPROTECTED_PATHS` | none | Exact paths forwarded without verification. |
| `ATTESTED_PROXY_LISTEN` | `0.0.0.0:8080` | Proxy listener. |
| `ATTESTED_PROXY_ADMIN_LISTEN` | `0.0.0.0:8081` | `/health` (liveness) and `/ready` (readiness). |
| `ATTESTED_PROXY_MAX_AGE_SECS` | `300` | Oldest accepted `created`. |
| `ATTESTED_PROXY_MAX_FUTURE_SKEW_SECS` | `60` | Furthest-ahead accepted `created`. |
| `ATTESTED_PROXY_MAX_BODY_BYTES` | `1048576` | Largest body verified. |
| `ATTESTED_PROXY_BODY_READ_TIMEOUT_SECS` | `10` | Deadline for the request body. |
| `ATTESTED_PROXY_HEADER_READ_TIMEOUT_SECS` | `10` | Deadline for the request headers. |
| `ATTESTED_PROXY_UPSTREAM_CONNECT_TIMEOUT_MS` | `2000` | Deadline for connecting upstream. |
| `ATTESTED_PROXY_UPSTREAM_RESPONSE_TIMEOUT_SECS` | `60` | Deadline for upstream response headers. Open tunnels have none; the upstream owns their idle timeout. |
| `ATTESTED_PROXY_MAX_CONNECTIONS` | `1024` | Connections and tunnels together. Beyond it, connections wait in the listen backlog. |
| `ATTESTED_PROXY_SHUTDOWN_GRACE_SECS` | `45` | How long in-flight work may finish after SIGTERM. |
| `ATTESTED_PROXY_REPLAY_REDIS_URL` | none | Enables replay tracking (`redis://` or `rediss://`). |
| `ATTESTED_PROXY_REPLAY_TIMEOUT_MS` | `250` | Deadline for one replay-store command. |

Telemetry is configured by `telemetry-batteries` (`TELEMETRY_PRESET=datadog`,
`TELEMETRY_SERVICE_NAME`, `TELEMETRY_METRICS_BACKEND=statsd`, …), as in Flamingo.

### Deploying next to a service

In a `common-app` chart, add the sidecar and move traffic to its port. For Flamingo:

```yaml
service:
  port: 8080
httpRoute:
  port: 8080
targetGroupConfigurations:
  - defaultConfiguration:
      healthCheckConfig:
        healthCheckPath: /ready   # unprotected, forwarded to Flamingo's enclave-aware /ready
        healthCheckPort: "8080"
sidecars:
  - name: attested-proxy
    image: <attested-proxy image>
    env:
      - { name: ATTESTED_PROXY_UPSTREAM, value: "http://127.0.0.1:8000" }
      - { name: ATTESTED_PROXY_AUTHORITY, value: flamingo-verifier.toolsforhumanity.com }
      - { name: ATTESTED_PROXY_AUDIENCES, value: <flamingo audience> }
      - { name: ATTESTED_PROXY_ISSUER, value: <attestation gateway issuer> }
      - { name: ATTESTED_PROXY_JWKS_URL, value: <attestation gateway>/.well-known/jwks.json }
      - { name: ATTESTED_PROXY_UNPROTECTED_PATHS, value: "/health,/ready" }
    ports:
      - { name: proxy, containerPort: 8080 }
    livenessProbe: { httpGet: { path: /health, port: 8081 } }
    readinessProbe: { httpGet: { path: /ready, port: 8081 } }
```

The pod is ready only when both containers are: the service's own probe as before, and the
sidecar's once it holds a usable JWKS. The sidecar stops reporting ready as soon as it receives
SIGTERM, then drains.

### Health, metrics and logs

| Metric | |
| --- | --- |
| `attested_request.verified` | Verified requests, by `platform`. |
| `attested_request.rejected` | Refused requests, by `reason`, `platform` and `status`. |
| `attested_request.verify.duration` | Verification latency, by `outcome`. |
| `attested_proxy.upstream.errors` | Upstream failures, by `kind` (`unavailable`, `timeout`). |
| `attested_proxy.tunnels.opened`, `.failed`, `.active` | WebSocket tunnels. |
| `attested_proxy.connections.active` | Open client connections. |
| `attested_proxy.jwks.age_seconds` | Age of the cached JWKS; alert well before it reaches six hours, when verification starts failing. |

Client rejections are counted, not logged. Failures of our own dependencies (JWKS, replay store,
upstream) are logged at `warn`. Tokens, signatures and bodies are never logged.

### Replay tracking

`created` bounds how long a captured request can be replayed (five minutes by default). Replay
tracking additionally refuses a second use inside that window, at the cost of a store on the
request path that must be up for any request to succeed. It is off unless
`ATTESTED_PROXY_REPLAY_REDIS_URL` is set. A route whose effect can be repeated needs it; a route
that only opens a session, such as Flamingo's WebSocket handshake, usually does not.

The replay store must use `maxmemory-policy noeviction`: evicting an unexpired claim allows that
request to be replayed. Provision enough memory for the acceptance window; when full, writes must
fail so verification fails closed. Losing claims during a restart or failover also permits replay
until those requests expire; configure persistence and recovery accordingly.

## Profile notes

- **`@signature-params` is serialized, not copied.** RFC 9421 §3.2 step 7 builds it by
  serializing the parsed `Signature-Input` member. Some existing verifiers copy the raw substring
  after `integrity=` instead. Current signers emit the canonical form, so both approaches accept
  their signatures today; only this one also accepts equivalent spellings, such as extra
  whitespace, that Structured Fields allows.
- **`@scheme` and `@authority` come from configuration**, never from the `Host` header.
- Reject reasons and statuses match go-sonic's canonical request middleware, so clients see one
  taxonomy across services.
- iOS assertions are checked against `cnf.jwk` only. Their rpId and counter are not checked: App
  Attest keys are app-scoped, the gateway verified the app when it attested the key, and
  freshness comes from `created`.

## Test vectors

[`test-vectors/`](test-vectors) holds vectors for any implementation of the profile:

- `signature-base.json`: signature bases and their hashes, including equivalent whitespace,
  parameter order and derived components. Generated by `generate_signature_base.py`,
  independently of the Rust code.
- `verification.json`: signed requests and the verdict a verifier must reach, from a fixed JWKS
  and clock. Generated by
  `cargo run -p attested-request --example generate-vectors --features test-util`.

CI fails if either file differs from what its generator produces.

## Development

```sh
nix develop            # or install the toolchain in rust-toolchain.toml
cargo test --workspace --all-features
nix flake check        # clippy, tests, fmt and the package, as in CI
docker build .
```

## Container image

The sidecar image is published to GHCR as `ghcr.io/worldcoin/attested-proxy`:

- every push to `main` publishes `:latest` and `:sha-<sha>`;
- a pushed `attested-proxy/vX.Y.Z` tag (or a manual run of the [release image] workflow) publishes
  `:vX.Y.Z` and opens a draft GitHub release recording the image digest;
- pull requests that touch the build inputs build without pushing.

Deploy by digest (`ghcr.io/worldcoin/attested-proxy@sha256:…`), not by tag.

```sh
gh workflow run release-image.yml -f ref=main -f version=0.1.0 -f dry_run=false
```

[Attestation Gateway]: https://github.com/worldcoin/attestation-gateway
[RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421.html
[RFC 9421 Integrity Request Signing Profile]: https://app.notion.com/p/3888614bdf8c819b8cc3f9a3a05b10a7
[Authorized Principal]: https://app.notion.com/p/36e8614bdf8c80d797fff43a85f8853d
[release image]: .github/workflows/release-image.yml
